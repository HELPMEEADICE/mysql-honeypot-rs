// SPDX-License-Identifier: GPL-3.0-only
//! The fake database: a catalog, an expression evaluator and a statement
//! router.
//!
//! Nothing here executes SQL and nothing here can reach a real database, the
//! filesystem or the network. Every statement is parsed just far enough to
//! answer plausibly and is then recorded by the caller.
//!
//! Three properties matter and are enforced deliberately:
//!
//! * **Correctness.** `WHERE` is evaluated column by column, `COUNT(*)` folds to
//!   exactly one row, `LIMIT`/`OFFSET`/`ORDER BY` follow MySQL's order of
//!   operations, and an unparsable filter yields *fewer* rows, never more.
//! * **Boundedness.** Every result set is capped by row count, column count and
//!   total bytes; every parse carries a step budget and a depth cap.
//! * **Isolation.** A session's writes land in its own
//!   [`state::SessionState`] overlay, so two attackers never observe each
//!   other's rows.

pub mod catalog;
pub mod eval;
pub mod sql;
pub mod state;

use crate::protocol::response::column_type;
use crate::util;

use self::eval::{EvalContext, RowContext};
use self::sql::{Budget, Expr, Sym, Token, Value, is_aggregate};
use self::state::StateError;

pub use self::sql::MAX_TOKENS;
pub use self::state::{SessionState, StateBudgets, StateError as VirtualStateError};

/// Hard cap on rows handed back for a single result set.
pub const MAX_RESULT_ROWS: usize = 200;

/// Hard cap on projected columns.
pub const MAX_RESULT_COLUMNS: usize = 400;

/// Hard cap on the estimated bytes of one result set.
pub const MAX_RESULT_BYTES: usize = 512 * 1024;

/// Longest single string value the virtual database will hold or produce.
pub const MAX_STRING_VALUE_BYTES: usize = 4 * 1024;

/// Steps an expression parse may consume.
const EXPRESSION_BUDGET: usize = MAX_TOKENS;

/// Maximum `ORDER BY` keys considered.
const MAX_ORDER_KEYS: usize = 8;

/// One column of a fake table.
#[derive(Debug, Clone)]
pub struct FakeColumn {
    /// Column name.
    pub name: String,
    /// Type as shown by `SHOW COLUMNS` / `DESCRIBE`.
    pub data_type: String,
    /// `IS_NULLABLE`.
    pub nullable: bool,
    /// `COLUMN_KEY`.
    pub key: String,
    /// `COLUMN_DEFAULT`.
    pub default: Option<String>,
    /// `EXTRA`.
    pub extra: String,
    /// Wire type used in column definitions.
    pub wire_type: u8,
}

impl FakeColumn {
    /// A nullable column with no key and no default.
    pub fn new(name: &str, data_type: &str, wire_type: u8) -> Self {
        Self {
            name: name.to_string(),
            data_type: data_type.to_string(),
            nullable: true,
            key: String::new(),
            default: None,
            extra: String::new(),
            wire_type,
        }
    }

    /// The `AUTO_INCREMENT` primary key column.
    pub fn primary(name: &str, data_type: &str, wire_type: u8) -> Self {
        Self {
            name: name.to_string(),
            data_type: data_type.to_string(),
            nullable: false,
            key: "PRI".to_string(),
            default: None,
            extra: "auto_increment".to_string(),
            wire_type,
        }
    }

    /// Mark the column `NOT NULL`.
    pub fn not_null(mut self) -> Self {
        self.nullable = false;
        self
    }

    /// Whether this column is the auto-increment key.
    pub fn is_auto_increment(&self) -> bool {
        self.extra.eq_ignore_ascii_case("auto_increment")
    }
}

/// One fake table with materialised rows.
#[derive(Debug, Clone)]
pub struct FakeTable {
    /// Table name.
    pub name: String,
    /// Storage engine reported by `SHOW TABLE STATUS`.
    pub engine: String,
    /// Table comment.
    pub comment: String,
    /// Column definitions.
    pub columns: Vec<FakeColumn>,
    /// Row values, aligned with `columns`.
    pub rows: Vec<Vec<Option<String>>>,
}

impl FakeTable {
    /// Index of the first auto-increment column, if any.
    fn auto_increment_column(&self) -> Option<usize> {
        self.columns.iter().position(FakeColumn::is_auto_increment)
    }

    /// Next value of the auto-increment column.
    fn next_auto_increment(&self) -> u64 {
        let Some(index) = self.auto_increment_column() else {
            return 0;
        };
        let highest = self
            .rows
            .iter()
            .filter_map(|row| row.get(index))
            .filter_map(|cell| cell.as_deref())
            .filter_map(|text| text.trim().parse::<u64>().ok())
            .max()
            .unwrap_or(0);
        highest.saturating_add(1)
    }
}

/// One fake schema.
#[derive(Debug, Clone)]
pub struct FakeSchema {
    /// Schema name.
    pub name: String,
    /// Tables in this schema.
    pub tables: Vec<FakeTable>,
}

/// One `(schema, table)` pair in the combined catalog view.
#[derive(Debug, Clone, Copy)]
pub struct TableEntry<'a> {
    /// Owning schema name.
    pub schema: &'a str,
    /// The table itself.
    pub table: &'a FakeTable,
}

/// A column of a produced result set.
#[derive(Debug, Clone)]
pub struct ResultColumn {
    /// Column label.
    pub name: String,
    /// Original column name.
    pub org_name: String,
    /// Originating table (may be empty).
    pub table: String,
    /// Originating schema (may be empty).
    pub schema: String,
    /// Wire type.
    pub wire_type: u8,
}

/// A produced result set.
#[derive(Debug, Clone, Default)]
pub struct ResultSet {
    /// Column labels.
    pub columns: Vec<ResultColumn>,
    /// Row values.
    pub rows: Vec<Vec<Option<String>>>,
    /// Set when the evaluator had to answer conservatively because the
    /// statement used a construct it does not model.
    pub degraded: bool,
}

impl ResultSet {
    /// Build a single text column result set from plain values.
    fn single_text(column: &str, schema: &str, table: &str, values: Vec<String>) -> Self {
        let rows = values
            .into_iter()
            .map(|value| vec![Some(value)])
            .collect::<Vec<_>>();
        Self {
            columns: vec![ResultColumn {
                name: column.to_string(),
                org_name: column.to_string(),
                table: table.to_string(),
                schema: schema.to_string(),
                wire_type: column_type::VAR_STRING,
            }],
            rows,
            degraded: false,
        }
    }
}

/// What the server answers for one statement.
#[derive(Debug, Clone)]
pub enum QueryResult {
    /// An OK packet (DML/DDL that is only simulated).
    Ok {
        /// Rows the statement would have touched.
        affected_rows: u64,
        /// Value for `LAST_INSERT_ID()`.
        last_insert_id: u64,
        /// Human readable info string.
        info: String,
    },
    /// A text protocol result set.
    ResultSet(ResultSet),
    /// An ERR packet.
    Error {
        /// MySQL error code.
        code: u16,
        /// SQLSTATE.
        sqlstate: &'static str,
        /// Error message.
        message: String,
    },
    /// A bare EOF packet.
    Eof,
}

impl QueryResult {
    fn ok(affected_rows: u64, last_insert_id: u64, info: &str) -> Self {
        Self::Ok {
            affected_rows,
            last_insert_id,
            info: info.to_string(),
        }
    }

    fn error(code: u16, sqlstate: &'static str, message: impl Into<String>) -> Self {
        Self::Error {
            code,
            sqlstate,
            message: message.into(),
        }
    }

    fn syntax_error(fragment: &str) -> Self {
        Self::error(
            1064,
            "42000",
            format!(
                "You have an error in your SQL syntax; check the manual that corresponds to \
                 your MySQL server version for the right syntax to use near '{}' at line 1",
                util::clip(&sanitise(fragment), 64)
            ),
        )
    }

    /// Short tag persisted in `queries.response_type`.
    pub fn kind(&self) -> String {
        match self {
            Self::Ok {
                affected_rows,
                info,
                ..
            } => {
                if info.is_empty() {
                    format!("OK(affected={affected_rows})")
                } else {
                    format!("OK(affected={affected_rows},{info})")
                }
            }
            Self::ResultSet(set) => {
                let base = format!(
                    "RESULTSET(cols={},rows={})",
                    set.columns.len(),
                    set.rows.len()
                );
                if set.degraded {
                    format!("{base},degraded")
                } else {
                    base
                }
            }
            Self::Error { code, .. } => format!("ERR({code})"),
            Self::Eof => "EOF".to_string(),
        }
    }
}

/// Per-query context.
#[derive(Debug, Clone)]
pub struct QueryContext {
    /// Schema selected by `USE` or by `CLIENT_CONNECT_WITH_DB`.
    pub current_db: String,
    /// Login name the client supplied.
    pub username: String,
    /// Peer address as text.
    pub client_host: String,
    /// Connection id reported to the client.
    pub connection_id: u32,
    /// Advertised server version.
    pub server_version: String,
    /// Values bound to the `?` placeholders of a prepared statement.
    ///
    /// Empty for a plain `COM_QUERY`. Binding happens on the token stream, so a
    /// bound value can never change the shape of the statement.
    pub params: Vec<Value>,
}

impl QueryContext {
    /// A context for a plain, unparameterised statement.
    pub fn new(
        current_db: String,
        username: String,
        client_host: String,
        connection_id: u32,
        server_version: String,
    ) -> Self {
        Self {
            current_db,
            username,
            client_host,
            connection_id,
            server_version,
            params: Vec::new(),
        }
    }

    /// The same context with prepared-statement parameters attached.
    pub fn with_params(mut self, params: Vec<Value>) -> Self {
        self.params = params;
        self
    }

    fn eval_context(&self) -> EvalContext {
        EvalContext::new(
            self.current_db.clone(),
            util::clip(&self.username, 64),
            util::clip(&self.client_host, 64),
            self.connection_id,
            self.server_version.clone(),
        )
    }
}

/// The fake instance.
#[derive(Debug, Clone)]
pub struct FakeDatabase {
    schemas: Vec<FakeSchema>,
    variables: Vec<(String, String)>,
    status: Vec<(String, String)>,
}

/// A resolved table: either borrowed from the base catalog or generated.
enum TableView<'a> {
    Borrowed(&'a FakeTable),
    Generated(FakeTable),
}

impl TableView<'_> {
    fn table(&self) -> &FakeTable {
        match self {
            Self::Borrowed(table) => table,
            Self::Generated(table) => table,
        }
    }
}

impl FakeDatabase {
    /// Build the whole fake instance, including generated `information_schema`
    /// rows.
    pub fn new(server_version: &str) -> Self {
        let mut database = Self {
            schemas: catalog::base_schemas(),
            variables: catalog::variables(server_version),
            status: catalog::status_variables(),
        };
        database.populate_information_schema(None, "root");
        database
    }

    /// `SHOW VARIABLES` / `@@name` source.
    pub fn variables(&self) -> &[(String, String)] {
        &self.variables
    }

    /// `SHOW STATUS` source.
    pub fn status_variables(&self) -> &[(String, String)] {
        &self.status
    }

    /// Schema names visible to `state`, in `SHOW DATABASES` order.
    pub fn schema_names<'a>(&'a self, state: &'a SessionState) -> Vec<&'a str> {
        let mut names: Vec<&str> = Vec::with_capacity(self.schemas.len() + 4);
        for schema in &self.schemas {
            if state.is_schema_dropped(&schema.name) {
                continue;
            }
            names.push(schema.name.as_str());
        }
        for schema in state.created_schemas() {
            if !names
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(schema))
            {
                names.push(schema);
            }
        }
        names
    }

    /// Whether a schema exists for this session.
    pub fn has_schema(&self, name: &str, state: &SessionState) -> bool {
        if state.is_schema_dropped(name) {
            return false;
        }
        self.schemas
            .iter()
            .any(|schema| schema.name.eq_ignore_ascii_case(name))
            || state.owns_schema(name)
    }

    /// Whether the *base* catalog — not the session overlay — holds `schema`.
    ///
    /// A `DROP` only needs a tombstone when there is something in the base
    /// catalog to hide; a table or schema the session invented disappears with
    /// its overlay entry alone.
    fn base_has_schema(&self, schema: &str) -> bool {
        self.schemas
            .iter()
            .any(|candidate| candidate.name.eq_ignore_ascii_case(schema))
    }

    /// Whether the base catalog holds `schema.table`.
    fn base_has_table(&self, schema: &str, table: &str) -> bool {
        self.schemas
            .iter()
            .find(|candidate| candidate.name.eq_ignore_ascii_case(schema))
            .is_some_and(|found| {
                found
                    .tables
                    .iter()
                    .any(|candidate| candidate.name.eq_ignore_ascii_case(table))
            })
    }

    /// Every `(schema, table)` pair visible to `state`.
    fn catalog_view<'a>(&'a self, state: &'a SessionState) -> Vec<TableEntry<'a>> {
        let mut entries: Vec<TableEntry<'a>> = Vec::new();
        for schema in &self.schemas {
            if state.is_schema_dropped(&schema.name) {
                continue;
            }
            for table in &schema.tables {
                if state.is_dropped(&schema.name, &table.name) {
                    continue;
                }
                match state.owned_table(&schema.name, &table.name) {
                    Some(owned) => entries.push(TableEntry {
                        schema: schema.name.as_str(),
                        table: owned,
                    }),
                    None => entries.push(TableEntry {
                        schema: schema.name.as_str(),
                        table,
                    }),
                }
            }
        }
        for schema in state.created_schemas() {
            let schema_name: &str = schema;
            for owned in state.owned_tables(schema_name) {
                // Skip tables that shadow a base table, they are already listed.
                let shadowed = self.schemas.iter().any(|base| {
                    base.name.eq_ignore_ascii_case(schema_name)
                        && base
                            .tables
                            .iter()
                            .any(|table| table.name.eq_ignore_ascii_case(&owned.name))
                });
                if !shadowed {
                    entries.push(TableEntry {
                        schema: schema_name,
                        table: owned,
                    });
                }
            }
        }
        entries
    }

    /// Recompute the cached `information_schema` rows for a pristine session.
    fn populate_information_schema(&mut self, state: Option<&SessionState>, username: &str) {
        let placeholder = SessionState::new(state::StateBudgets {
            enabled: false,
            ..state::StateBudgets::default()
        });
        let state = state.unwrap_or(&placeholder);
        let schema_names = self.schema_names(state);
        let entries = self.catalog_view(state);
        let relations: Vec<String> = self
            .schemas
            .iter()
            .find(|schema| schema.name == "information_schema")
            .map(|schema| schema.tables.iter().map(|t| t.name.clone()).collect())
            .unwrap_or_default();
        let mut generated: Vec<(String, Vec<Vec<Option<String>>>)> = Vec::new();
        for relation in relations {
            if let Some(rows) =
                catalog::information_schema_rows(&relation, &schema_names, &entries, username)
            {
                generated.push((relation, rows));
            }
        }
        if let Some(schema) = self
            .schemas
            .iter_mut()
            .find(|schema| schema.name == "information_schema")
        {
            for table in &mut schema.tables {
                if let Some((_, rows)) = generated.iter().find(|(name, _)| *name == table.name) {
                    table.rows = rows.clone();
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Table resolution
    // -----------------------------------------------------------------------

    fn base_table(
        &self,
        schema: Option<&str>,
        table: &str,
        current_db: &str,
    ) -> Option<(&str, &FakeTable)> {
        if let Some(name) = schema {
            let found = self
                .schemas
                .iter()
                .find(|s| s.name.eq_ignore_ascii_case(name))?;
            let table = found
                .tables
                .iter()
                .find(|candidate| candidate.name.eq_ignore_ascii_case(table))?;
            return Some((found.name.as_str(), table));
        }
        if !current_db.is_empty()
            && let Some(found) = self
                .schemas
                .iter()
                .find(|s| s.name.eq_ignore_ascii_case(current_db))
            && let Some(table) = found
                .tables
                .iter()
                .find(|candidate| candidate.name.eq_ignore_ascii_case(table))
        {
            return Some((found.name.as_str(), table));
        }
        for found in &self.schemas {
            if let Some(table) = found
                .tables
                .iter()
                .find(|candidate| candidate.name.eq_ignore_ascii_case(table))
            {
                return Some((found.name.as_str(), table));
            }
        }
        None
    }

    /// Resolve `schema.table` for reading, honouring the session overlay.
    fn resolve<'a>(
        &'a self,
        state: &'a SessionState,
        schema: Option<&str>,
        table: &str,
        ctx: &QueryContext,
    ) -> Option<(&'a str, TableView<'a>)> {
        // The overlay wins: a table the session created or modified is what it
        // must see back.
        if let Some(name) = schema {
            if state.is_schema_dropped(name) {
                return None;
            }
            if state.is_dropped(name, table) && state.owned_table(name, table).is_none() {
                return None;
            }
            if let Some(owned) = state.owned_table(name, table) {
                let schema_name = self
                    .schemas
                    .iter()
                    .find(|s| s.name.eq_ignore_ascii_case(name))
                    .map(|s| s.name.as_str())
                    .or_else(|| {
                        state
                            .created_schemas()
                            .into_iter()
                            .find(|s| s.eq_ignore_ascii_case(name))
                    })?;
                return Some((schema_name, self.view_for(state, schema_name, owned, ctx)));
            }
            let (found_schema, found_table) =
                self.base_table(Some(name), table, &ctx.current_db)?;
            return Some((
                found_schema,
                self.view_for(state, found_schema, found_table, ctx),
            ));
        }

        // No qualifier: prefer the current database, then the overlay, then any
        // schema that has the table.
        if !ctx.current_db.is_empty()
            && !state.is_schema_dropped(&ctx.current_db)
            && let Some(owned) = state.owned_table(&ctx.current_db, table)
        {
            let schema_name = self
                .schemas
                .iter()
                .find(|s| s.name.eq_ignore_ascii_case(&ctx.current_db))
                .map(|s| s.name.as_str())
                .or_else(|| {
                    state
                        .created_schemas()
                        .into_iter()
                        .find(|s| s.eq_ignore_ascii_case(&ctx.current_db))
                })?;
            return Some((schema_name, self.view_for(state, schema_name, owned, ctx)));
        }
        if !ctx.current_db.is_empty()
            && !state.is_schema_dropped(&ctx.current_db)
            && !state.is_dropped(&ctx.current_db, table)
            && let Some((schema_name, found)) = self.base_table(None, table, &ctx.current_db)
        {
            return Some((schema_name, self.view_for(state, schema_name, found, ctx)));
        }
        // Any schema, base or overlay.
        for schema in &self.schemas {
            if state.is_schema_dropped(&schema.name) || state.is_dropped(&schema.name, table) {
                continue;
            }
            if let Some(owned) = state.owned_table(&schema.name, table) {
                return Some((
                    schema.name.as_str(),
                    self.view_for(state, schema.name.as_str(), owned, ctx),
                ));
            }
            if let Some(found) = schema
                .tables
                .iter()
                .find(|candidate| candidate.name.eq_ignore_ascii_case(table))
            {
                return Some((
                    schema.name.as_str(),
                    self.view_for(state, schema.name.as_str(), found, ctx),
                ));
            }
        }
        for schema in state.created_schemas() {
            if let Some(owned) = state.owned_table(schema, table) {
                return Some((schema, TableView::Borrowed(owned)));
            }
        }
        None
    }

    /// Wrap a base `information_schema` table in a freshly generated view when
    /// the session's overlay could have changed the catalog.
    fn view_for<'a>(
        &'a self,
        state: &'a SessionState,
        schema_name: &str,
        table: &'a FakeTable,
        ctx: &QueryContext,
    ) -> TableView<'a> {
        if !schema_name.eq_ignore_ascii_case("information_schema") {
            return TableView::Borrowed(table);
        }
        // The privilege/processlist relations name the logged-in account, and
        // the catalog relations change as soon as the session writes anything.
        let always = matches!(table.name.as_str(), "USER_PRIVILEGES" | "PROCESSLIST");
        if !always && !state.is_dirty() {
            return TableView::Borrowed(table);
        }
        let schema_names = self.schema_names(state);
        let entries = self.catalog_view(state);
        match catalog::information_schema_rows(&table.name, &schema_names, &entries, &ctx.username)
        {
            Some(rows) => TableView::Generated(FakeTable {
                name: table.name.clone(),
                engine: table.engine.clone(),
                comment: table.comment.clone(),
                columns: table.columns.clone(),
                rows,
            }),
            None => TableView::Borrowed(table),
        }
    }

    // -----------------------------------------------------------------------
    // Dispatch
    // -----------------------------------------------------------------------

    /// Tokenize a statement fragment and bind its `?` placeholders.
    ///
    /// Binding is a token-level rewrite of [`Token::Placeholder`] into the typed
    /// literal that was sent in the binary protocol, never a textual
    /// `replace("?", value)`.
    fn tokens(&self, text: &str, ctx: &QueryContext) -> Option<Vec<Token>> {
        let tokens = sql::tokenize(text)?;
        if ctx.params.is_empty() {
            Some(tokens)
        } else {
            Some(sql::bind_placeholders(&tokens, &ctx.params))
        }
    }

    /// Route one statement to a plausible response.
    pub fn dispatch(&self, sql: &str, ctx: &QueryContext, state: &mut SessionState) -> QueryResult {
        let trimmed = sql.trim().trim_end_matches(';').trim();
        let clean = strip_leading_comments(trimmed).trim();
        if clean.is_empty() {
            return QueryResult::error(1065, "42000", "Query was empty");
        }
        let (keyword, keyword_end) = first_keyword(clean);
        let rest = clean[keyword_end..].trim_start();
        match keyword.as_str() {
            "SELECT" => self.select(rest, ctx, state),
            "SHOW" => self.show(rest, ctx, state),
            "USE" => match unquote_ident(rest) {
                name if self.has_schema(&name, state) => QueryResult::ok(0, 0, ""),
                name => QueryResult::error(1049, "42000", format!("Unknown database '{name}'")),
            },
            "DESCRIBE" | "DESC" | "EXPLAIN" => self.describe(rest, ctx, state),
            "SET" => self.set(rest, ctx, state),
            "BEGIN" | "START" | "COMMIT" | "ROLLBACK" | "SAVEPOINT" | "RELEASE" => {
                QueryResult::ok(0, 0, "")
            }
            "INSERT" | "REPLACE" => self.insert(rest, ctx, state, keyword == "REPLACE"),
            "UPDATE" => self.update(rest, ctx, state),
            "DELETE" => self.delete(rest, ctx, state),
            "TRUNCATE" => self.truncate(rest, ctx, state),
            "CREATE" => self.create(rest, ctx, state),
            "DROP" => self.drop(rest, ctx, state),
            "ALTER" | "RENAME" => QueryResult::ok(0, 0, ""),
            "GRANT" | "REVOKE" | "FLUSH" | "KILL" | "PREPARE" | "DEALLOCATE" | "EXECUTE"
            | "CALL" | "DO" | "HANDLER" | "LOCK" | "UNLOCK" | "ANALYZE" | "OPTIMIZE" | "CHECK"
            | "REPAIR" | "CHECKSUM" | "RESET" | "PURGE" | "INSTALL" | "UNINSTALL" | "CHANGE"
            | "STOP" | "XA" => QueryResult::ok(0, 0, ""),
            // A honeypot must never look like a file transport.
            "LOAD" => QueryResult::error(
                1148,
                "42000",
                "The used command is not allowed with this MySQL version",
            ),
            "INFO" | "HELP" => QueryResult::ok(0, 0, ""),
            _ => QueryResult::syntax_error(clean),
        }
    }

    // -----------------------------------------------------------------------
    // SELECT
    // -----------------------------------------------------------------------

    fn select(&self, rest: &str, ctx: &QueryContext, state: &mut SessionState) -> QueryResult {
        let Some(tokens) = self.tokens(rest, ctx) else {
            return QueryResult::syntax_error(rest);
        };
        let Some(from_index) = find_top_level_keyword(&tokens, "FROM") else {
            // `SELECT <expr>, ...` with no relation: one output row.
            return match build_projection(&tokens, None, ctx, state) {
                Ok(items) => {
                    QueryResult::ResultSet(materialise_expressions(self, &items, ctx, state, 1))
                }
                Err(result) => result,
            };
        };

        let list_tokens = &tokens[..from_index];
        let tail = &tokens[from_index + 1..];
        let Some((schema_name, table_name, mut cursor)) = parse_table_ref(tail) else {
            return QueryResult::syntax_error(rest);
        };
        if table_name.eq_ignore_ascii_case("dual") {
            return match build_projection(list_tokens, None, ctx, state) {
                Ok(items) => {
                    QueryResult::ResultSet(materialise_expressions(self, &items, ctx, state, 1))
                }
                Err(result) => result,
            };
        }

        let clauses = parse_clauses(tail, &mut cursor);
        let Some((schema, view)) = self.resolve(state, schema_name.as_deref(), &table_name, ctx)
        else {
            let qualifier = schema_name
                .clone()
                .or_else(|| Some(ctx.current_db.clone()))
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| "mysql".to_string());
            return QueryResult::error(
                1146,
                "42S02",
                format!("Table '{qualifier}.{table_name}' doesn't exist"),
            );
        };
        let table = view.table();
        let projection = match build_projection(list_tokens, Some(table), ctx, state) {
            Ok(items) => items,
            Err(result) => return result,
        };
        execute_select(self, schema, table, projection, clauses, ctx, &*state)
    }

    fn describe(&self, rest: &str, ctx: &QueryContext, state: &mut SessionState) -> QueryResult {
        let (keyword, _) = first_keyword(rest);
        if matches!(
            keyword.as_str(),
            "SELECT" | "INSERT" | "UPDATE" | "DELETE" | "REPLACE"
        ) {
            return QueryResult::ResultSet(ResultSet {
                columns: vec![
                    numeric_column("id", "", ""),
                    text_column("select_type", "", ""),
                    text_column("table", "", ""),
                    text_column("type", "", ""),
                    text_column("possible_keys", "", ""),
                    text_column("key", "", ""),
                    text_column("key_len", "", ""),
                    text_column("ref", "", ""),
                    numeric_column("rows", "", ""),
                    text_column("Extra", "", ""),
                ],
                rows: vec![catalog::row(&[
                    "1",
                    "SIMPLE",
                    "users",
                    "ALL",
                    "",
                    "",
                    "",
                    "",
                    "3",
                    "Using where",
                ])],
                degraded: false,
            });
        }
        self.show_columns(rest, ctx, state)
    }

    // -----------------------------------------------------------------------
    // SHOW
    // -----------------------------------------------------------------------

    fn show(&self, rest: &str, ctx: &QueryContext, state: &mut SessionState) -> QueryResult {
        let mut rest = rest.trim();
        loop {
            let mut stripped = false;
            for prefix in [
                "GLOBAL ", "global ", "SESSION ", "session ", "LOCAL ", "local ", "FULL ", "full ",
            ] {
                if let Some(tail) = rest.strip_prefix(prefix) {
                    rest = tail.trim_start();
                    stripped = true;
                    break;
                }
            }
            if !stripped {
                break;
            }
        }
        let (keyword, keyword_end) = first_keyword(rest);
        let tail = rest[keyword_end..].trim();
        match keyword.as_str() {
            "DATABASES" | "SCHEMAS" => {
                let rows = self
                    .schema_names(state)
                    .into_iter()
                    .map(str::to_string)
                    .collect();
                QueryResult::ResultSet(ResultSet::single_text(
                    "Database",
                    "information_schema",
                    "SCHEMATA",
                    rows,
                ))
            }
            "TABLES" => self.show_tables(tail, ctx, state),
            "COLUMNS" | "FIELDS" => self.show_columns(tail, ctx, state),
            "CREATE" => self.show_create(tail, ctx, state),
            "VARIABLES" => self.show_variable_table(&self.variables, tail),
            "STATUS" => self.show_variable_table(&self.status, tail),
            "PROCESSLIST" => self.table_result(state, ctx, "PROCESSLIST", None),
            "GRANTS" => {
                let owner = util::clip(&ctx.username, 64);
                let column = format!("Grants for {owner}@%");
                QueryResult::ResultSet(ResultSet::single_text(
                    &column,
                    "",
                    "",
                    vec![format!(
                        "GRANT ALL PRIVILEGES ON *.* TO `{owner}`@`%` WITH GRANT OPTION"
                    )],
                ))
            }
            "ENGINES" => self.table_result(state, ctx, "ENGINES", None),
            "WARNINGS" | "ERRORS" => QueryResult::ResultSet(ResultSet {
                columns: vec![
                    text_column("Level", "", ""),
                    numeric_column("Code", "", ""),
                    text_column("Message", "", ""),
                ],
                rows: vec![vec![
                    Some("Note".to_string()),
                    Some("0".to_string()),
                    Some(String::new()),
                ]],
                degraded: false,
            }),
            "INDEX" | "INDEXES" | "KEYS" => self.show_index(tail, ctx, state),
            "CHARACTER" => self.table_result(state, ctx, "CHARACTER_SETS", None),
            "COLLATION" => QueryResult::ResultSet(ResultSet {
                columns: vec![
                    text_column("Collation", "", ""),
                    text_column("Charset", "", ""),
                    numeric_column("Id", "", ""),
                    text_column("Default", "", ""),
                    text_column("Compiled", "", ""),
                    numeric_column("Sortlen", "", ""),
                ],
                rows: vec![
                    catalog::row(&["utf8mb4_0900_ai_ci", "utf8mb4", "255", "Yes", "Yes", "0"]),
                    catalog::row(&["utf8mb4_general_ci", "utf8mb4", "45", "", "Yes", "1"]),
                    catalog::row(&["latin1_swedish_ci", "latin1", "8", "", "Yes", "1"]),
                ],
                degraded: false,
            }),
            "PRIVILEGES" => QueryResult::ResultSet(ResultSet {
                columns: vec![
                    text_column("Privilege", "", ""),
                    text_column("Context", "", ""),
                    text_column("Comment", "", ""),
                ],
                rows: vec![
                    catalog::row(&["Alter", "Tables", "To alter the table"]),
                    catalog::row(&[
                        "Create",
                        "Databases,Tables,Indexes",
                        "To create new databases and tables",
                    ]),
                    catalog::row(&["Delete", "Tables", "To delete existing rows"]),
                    catalog::row(&[
                        "Drop",
                        "Databases,Tables",
                        "To drop databases, tables, and views",
                    ]),
                    catalog::row(&[
                        "Grant option",
                        "Databases,Tables,Functions,Procedures",
                        "To give to other users those privileges you possess",
                    ]),
                    catalog::row(&["Insert", "Tables", "To insert data into tables"]),
                    catalog::row(&["Select", "Tables", "To retrieve rows from table"]),
                    catalog::row(&["Update", "Tables", "To update existing rows"]),
                ],
                degraded: false,
            }),
            "TABLE" => self.show_table_status(tail, ctx, state),
            "TRIGGERS" | "EVENTS" | "FUNCTION" | "PROCEDURE" | "OPEN" | "PLUGINS" | "SLAVE"
            | "REPLICA" | "BINARY" | "MASTER" => QueryResult::ResultSet(ResultSet::default()),
            _ => QueryResult::ResultSet(ResultSet::single_text(
                &format!("SHOW {keyword}"),
                "",
                "",
                Vec::new(),
            )),
        }
    }

    fn table_result(
        &self,
        state: &mut SessionState,
        ctx: &QueryContext,
        relation: &str,
        schema: Option<&str>,
    ) -> QueryResult {
        let schema_name = schema.unwrap_or("information_schema");
        match self.resolve(state, Some(schema_name), relation, ctx) {
            Some((name, view)) => {
                let table = view.table();
                QueryResult::ResultSet(ResultSet {
                    columns: table
                        .columns
                        .iter()
                        .map(|column| ResultColumn {
                            name: column.name.clone(),
                            org_name: column.name.clone(),
                            table: table.name.clone(),
                            schema: name.to_string(),
                            wire_type: column.wire_type,
                        })
                        .collect(),
                    rows: table.rows.iter().take(MAX_RESULT_ROWS).cloned().collect(),
                    degraded: false,
                })
            }
            None => QueryResult::ResultSet(ResultSet::default()),
        }
    }

    fn show_tables(&self, tail: &str, ctx: &QueryContext, state: &mut SessionState) -> QueryResult {
        let (schema_name, pattern) = parse_show_scope(tail);
        let schema_name = schema_name.or_else(|| {
            if ctx.current_db.is_empty() {
                None
            } else {
                Some(ctx.current_db.clone())
            }
        });
        let Some(schema_name) = schema_name else {
            return QueryResult::error(1046, "3D000", "No database selected");
        };
        if !self.has_schema(&schema_name, state) {
            return QueryResult::error(1049, "42000", format!("Unknown database '{schema_name}'"));
        }
        let canonical = self
            .schemas
            .iter()
            .find(|schema| schema.name.eq_ignore_ascii_case(&schema_name))
            .map(|schema| schema.name.clone())
            .or_else(|| {
                state
                    .created_schemas()
                    .into_iter()
                    .find(|name| name.eq_ignore_ascii_case(&schema_name))
                    .map(str::to_string)
            })
            .unwrap_or(schema_name);
        let mut names: Vec<String> = Vec::new();
        if let Some(base) = self.schemas.iter().find(|schema| schema.name == canonical) {
            for table in &base.tables {
                if state.is_dropped(&canonical, &table.name) {
                    continue;
                }
                if pattern_matches(pattern.as_deref(), &table.name) {
                    names.push(table.name.clone());
                }
            }
        }
        for owned in state.owned_tables(&canonical) {
            if !names
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&owned.name))
                && pattern_matches(pattern.as_deref(), &owned.name)
            {
                names.push(owned.name.clone());
            }
        }
        names.sort();
        QueryResult::ResultSet(ResultSet::single_text(
            &format!("Tables_in_{canonical}"),
            &canonical,
            "",
            names,
        ))
    }

    fn show_columns(
        &self,
        tail: &str,
        ctx: &QueryContext,
        state: &mut SessionState,
    ) -> QueryResult {
        let tail = tail
            .strip_prefix("FROM ")
            .or_else(|| tail.strip_prefix("from "))
            .or_else(|| tail.strip_prefix("IN "))
            .or_else(|| tail.strip_prefix("in "))
            .unwrap_or(tail);
        let (schema_name, table_name, remainder) = parse_table_ref_str(tail);
        let schema_name = schema_name.or_else(|| {
            if ctx.current_db.is_empty() {
                None
            } else {
                Some(ctx.current_db.clone())
            }
        });
        let Some((schema, view)) = self.resolve(state, schema_name.as_deref(), &table_name, ctx)
        else {
            return QueryResult::error(
                1146,
                "42S02",
                format!("Table '{table_name}' doesn't exist"),
            );
        };
        let table = view.table();
        let pattern = parse_like(remainder);
        let rows = table
            .columns
            .iter()
            .filter(|column| pattern_matches(pattern.as_deref(), &column.name))
            .map(|column| {
                vec![
                    Some(column.name.clone()),
                    Some(column.data_type.clone()),
                    Some(if column.nullable { "YES" } else { "NO" }.to_string()),
                    Some(column.key.clone()),
                    Some(column.default.clone().unwrap_or_else(|| "NULL".to_string())),
                    Some(column.extra.clone()),
                ]
            })
            .collect();
        QueryResult::ResultSet(ResultSet {
            columns: vec![
                text_column("Field", schema, &table.name),
                text_column("Type", schema, &table.name),
                text_column("Null", schema, &table.name),
                text_column("Key", schema, &table.name),
                text_column("Default", schema, &table.name),
                text_column("Extra", schema, &table.name),
            ],
            rows,
            degraded: false,
        })
    }

    fn show_create(&self, tail: &str, ctx: &QueryContext, state: &mut SessionState) -> QueryResult {
        let (kind, kind_end) = first_keyword(tail);
        let name = unquote_ident(tail[kind_end..].trim());
        match kind.as_str() {
            "TABLE" => {
                let Some((_, view)) = self.resolve(state, None, &name, ctx) else {
                    return QueryResult::error(
                        1146,
                        "42S02",
                        format!("Table '{name}' doesn't exist"),
                    );
                };
                let table = view.table();
                let primary = table
                    .columns
                    .iter()
                    .find(|column| column.key.eq_ignore_ascii_case("PRI"))
                    .map(|column| column.name.clone());
                let mut ddl = format!("CREATE TABLE `{}` (\n", table.name);
                let mut lines: Vec<String> = Vec::new();
                for column in &table.columns {
                    let mut line = format!("  `{}` {}", column.name, column.data_type);
                    if column.nullable {
                        line.push_str(" DEFAULT NULL");
                    } else {
                        line.push_str(" NOT NULL");
                    }
                    if column.is_auto_increment() {
                        line.push_str(" AUTO_INCREMENT");
                    }
                    lines.push(line);
                }
                if let Some(primary) = &primary {
                    lines.push(format!("  PRIMARY KEY (`{primary}`)"));
                }
                ddl.push_str(&lines.join(",\n"));
                ddl.push_str(&format!(
                    "\n) ENGINE={} DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci",
                    table.engine
                ));
                QueryResult::ResultSet(ResultSet {
                    columns: vec![
                        text_column("Table", "", ""),
                        text_column("Create Table", "", ""),
                    ],
                    rows: vec![vec![Some(table.name.clone()), Some(ddl)]],
                    degraded: false,
                })
            }
            "DATABASE" | "SCHEMA" => {
                if !self.has_schema(&name, state) {
                    return QueryResult::error(1049, "42000", format!("Unknown database '{name}'"));
                }
                QueryResult::ResultSet(ResultSet {
                    columns: vec![
                        text_column("Database", "", ""),
                        text_column("Create Database", "", ""),
                    ],
                    rows: vec![vec![
                        Some(name.clone()),
                        Some(format!(
                            "CREATE DATABASE `{name}` /*!40100 DEFAULT CHARACTER SET utf8mb4 */"
                        )),
                    ]],
                    degraded: false,
                })
            }
            _ => QueryResult::syntax_error(tail),
        }
    }

    fn show_variable_table(&self, source: &[(String, String)], tail: &str) -> QueryResult {
        let pattern = parse_like(tail);
        let rows = source
            .iter()
            .filter(|(key, _)| pattern_matches(pattern.as_deref(), key))
            .map(|(key, value)| vec![Some(key.clone()), Some(value.clone())])
            .collect();
        QueryResult::ResultSet(ResultSet {
            columns: vec![
                text_column("Variable_name", "", ""),
                text_column("Value", "", ""),
            ],
            rows,
            degraded: false,
        })
    }

    fn show_index(&self, tail: &str, ctx: &QueryContext, state: &mut SessionState) -> QueryResult {
        let tail = tail
            .strip_prefix("FROM ")
            .or_else(|| tail.strip_prefix("from "))
            .or_else(|| tail.strip_prefix("IN "))
            .or_else(|| tail.strip_prefix("in "))
            .unwrap_or(tail);
        let (_, table_name, _) = parse_table_ref_str(tail);
        let columns = match self.resolve(state, None, &table_name, ctx) {
            Some((_, view)) => view.table().columns.clone(),
            None => Vec::new(),
        };
        let mut rows = Vec::new();
        for column in columns.iter().filter(|column| !column.key.is_empty()) {
            rows.push(vec![
                Some(table_name.clone()),
                Some("0".to_string()),
                Some("PRIMARY".to_string()),
                Some("1".to_string()),
                Some(column.name.clone()),
                Some("A".to_string()),
                Some("0".to_string()),
                Some("BTREE".to_string()),
                Some("YES".to_string()),
            ]);
        }
        QueryResult::ResultSet(ResultSet {
            columns: vec![
                text_column("Table", "", ""),
                numeric_column("Non_unique", "", ""),
                text_column("Key_name", "", ""),
                numeric_column("Seq_in_index", "", ""),
                text_column("Column_name", "", ""),
                text_column("Collation", "", ""),
                numeric_column("Cardinality", "", ""),
                text_column("Index_type", "", ""),
                text_column("Visible", "", ""),
            ],
            rows,
            degraded: false,
        })
    }

    fn show_table_status(
        &self,
        tail: &str,
        ctx: &QueryContext,
        state: &mut SessionState,
    ) -> QueryResult {
        let (schema_name, pattern) = parse_show_scope(tail);
        let schema_name = schema_name.or_else(|| {
            if ctx.current_db.is_empty() {
                None
            } else {
                Some(ctx.current_db.clone())
            }
        });
        let Some(schema_name) = schema_name else {
            return QueryResult::error(1046, "3D000", "No database selected");
        };
        if !self.has_schema(&schema_name, state) {
            return QueryResult::error(1049, "42000", format!("Unknown database '{schema_name}'"));
        }
        let entries: Vec<TableEntry<'_>> = self
            .catalog_view(state)
            .into_iter()
            .filter(|entry| entry.schema.eq_ignore_ascii_case(&schema_name))
            .filter(|entry| pattern_matches(pattern.as_deref(), &entry.table.name))
            .collect();
        let rows = entries
            .iter()
            .map(|entry| {
                let table = entry.table;
                catalog::row(&[
                    &table.name,
                    &table.engine,
                    "10",
                    "Dynamic",
                    &table.rows.len().to_string(),
                    "0",
                    "16384",
                    "0",
                    "0",
                    "16384",
                    "0",
                    "2024-01-01 00:00:00",
                    "",
                    "",
                    "utf8mb4_0900_ai_ci",
                    "",
                    "",
                    &table.comment,
                ])
            })
            .collect();
        QueryResult::ResultSet(ResultSet {
            columns: vec![
                text_column("Name", "", ""),
                text_column("Engine", "", ""),
                numeric_column("Version", "", ""),
                text_column("Row_format", "", ""),
                numeric_column("Rows", "", ""),
                numeric_column("Avg_row_length", "", ""),
                numeric_column("Data_length", "", ""),
                numeric_column("Max_data_length", "", ""),
                numeric_column("Index_length", "", ""),
                numeric_column("Data_free", "", ""),
                numeric_column("Auto_increment", "", ""),
                text_column("Create_time", "", ""),
                text_column("Update_time", "", ""),
                text_column("Check_time", "", ""),
                text_column("Collation", "", ""),
                text_column("Checksum", "", ""),
                text_column("Create_options", "", ""),
                text_column("Comment", "", ""),
            ],
            rows,
            degraded: false,
        })
    }

    // -----------------------------------------------------------------------
    // SET
    // -----------------------------------------------------------------------

    fn set(&self, rest: &str, ctx: &QueryContext, state: &mut SessionState) -> QueryResult {
        let Some(tokens) = self.tokens(rest, ctx) else {
            return QueryResult::syntax_error(rest);
        };
        // `SET @name = expr` is the only assignment worth keeping: it is what
        // injection probes read back.
        let mut cursor = 0usize;
        // Skip a `SESSION` / `GLOBAL` / `PERSIST` prefix.
        while matches!(
            tokens.get(cursor).and_then(Token::keyword).as_deref(),
            Some("SESSION") | Some("GLOBAL") | Some("LOCAL") | Some("PERSIST")
        ) {
            cursor += 1;
        }
        let Some(Token::UserVar(name)) = tokens.get(cursor) else {
            // Any other SET (NAMES, autocommit, sql_mode, ...) is accepted
            // without state: the honeypot has no session variables for them.
            return QueryResult::ok(0, 0, "");
        };
        cursor += 1;
        if !matches!(tokens.get(cursor), Some(Token::Sym(Sym::Eq))) {
            return QueryResult::ok(0, 0, "");
        }
        cursor += 1;
        let mut budget = Budget::new(EXPRESSION_BUDGET);
        let Some(expression) = sql::parse_expression(&tokens[cursor..], &mut budget) else {
            return QueryResult::ok(0, 0, "");
        };
        let eval_ctx = ctx.eval_context();
        let context = RowContext {
            columns: &[],
            row: &[],
            session: &eval_ctx,
            state,
            variables: &self.variables,
        };
        let value = match eval::evaluate(&expression, &context) {
            Ok(value) => value.to_wire().unwrap_or_default(),
            Err(err) => {
                return QueryResult::error(err.code(), err.sqlstate(), err.message("set clause"));
            }
        };
        if let Err(err) = state.set_user_variable(name, value) {
            return QueryResult::error(err.code(), err.sqlstate(), err.message());
        }
        QueryResult::ok(0, 0, "")
    }

    // -----------------------------------------------------------------------
    // DML
    // -----------------------------------------------------------------------

    /// Give the session a mutable copy of `schema.table`.
    ///
    /// Returns `Ok(Some((schema, canonical table name)))` when the overlay now
    /// owns the table, and `Ok(None)` when stateful simulation is switched off —
    /// in that mode every write is answered with a plain OK and nothing is kept.
    /// The copy is attached once and never re-charged, so an `INSERT` loop cannot
    /// inflate the byte budget.
    fn materialise(
        &self,
        state: &mut SessionState,
        schema: Option<&str>,
        table: &str,
        ctx: &QueryContext,
    ) -> std::result::Result<Option<(String, String)>, QueryResult> {
        let resolved = self
            .resolve(state, schema, table, ctx)
            .map(|(name, view)| (name.to_string(), view.table().clone()));
        let Some((schema_name, base)) = resolved else {
            return Err(unknown_table(schema, table, ctx));
        };
        match state.attach(&schema_name, &base) {
            Ok(()) => Ok(Some((schema_name, base.name))),
            Err(StateError::Disabled) => Ok(None),
            Err(err) => Err(state_error_result(err)),
        }
    }

    fn insert(
        &self,
        rest: &str,
        ctx: &QueryContext,
        state: &mut SessionState,
        replace: bool,
    ) -> QueryResult {
        let Some(tokens) = self.tokens(rest, ctx) else {
            return QueryResult::syntax_error(rest);
        };
        let mut cursor = 0usize;
        skip_keyword(&tokens, &mut cursor, "LOW_PRIORITY");
        skip_keyword(&tokens, &mut cursor, "DELAYED");
        skip_keyword(&tokens, &mut cursor, "HIGH_PRIORITY");
        let ignore = skip_keyword(&tokens, &mut cursor, "IGNORE");
        skip_keyword(&tokens, &mut cursor, "INTO");
        let Some((schema_name, table_name, next)) = parse_table_ref(&tokens[cursor..]) else {
            return QueryResult::syntax_error(rest);
        };
        cursor += next;

        let mut column_names: Option<Vec<String>> = None;
        if matches!(tokens.get(cursor), Some(Token::Sym(Sym::LParen))) {
            cursor += 1;
            let mut names = Vec::new();
            while let Some(token) = tokens.get(cursor) {
                match token {
                    Token::Word(name) | Token::Quoted(name) => names.push(name.clone()),
                    Token::Sym(Sym::RParen) => break,
                    Token::Sym(Sym::Comma) => {}
                    _ => return QueryResult::syntax_error(rest),
                }
                cursor += 1;
            }
            cursor += 1;
            column_names = Some(names);
        }

        if skip_keyword(&tokens, &mut cursor, "SET") {
            // `INSERT ... SET a = 1`
            let Some(table) = self.peek_table(state, schema_name.as_deref(), &table_name, ctx)
            else {
                return unknown_table(schema_name.as_deref(), &table_name, ctx);
            };
            let mut row = vec![None; table.columns.len()];
            loop {
                let (Some(Token::Word(column)), Some(Token::Sym(Sym::Eq))) =
                    (tokens.get(cursor), tokens.get(cursor + 1))
                else {
                    return QueryResult::syntax_error(rest);
                };
                cursor += 2;
                let Some(index) = table
                    .columns
                    .iter()
                    .position(|candidate| candidate.name.eq_ignore_ascii_case(column))
                else {
                    return QueryResult::error(
                        1054,
                        "42S22",
                        format!(
                            "Unknown column '{}' in 'field list'",
                            util::clip(column, 64)
                        ),
                    );
                };
                let end = split_value_end(&tokens[cursor..]);
                let Some(value) =
                    literal_from_tokens(&tokens[cursor..cursor + end], ctx, state, &self.variables)
                else {
                    return QueryResult::syntax_error(rest);
                };
                row[index] = value;
                cursor += end;
                if !matches!(tokens.get(cursor), Some(Token::Sym(Sym::Comma))) {
                    break;
                }
                cursor += 1;
            }
            return apply_insert(
                self,
                state,
                ctx,
                schema_name.as_deref(),
                &table_name,
                vec![(column_names, row)],
                replace,
                ignore,
            );
        }

        if !skip_keyword(&tokens, &mut cursor, "VALUES") {
            skip_keyword(&tokens, &mut cursor, "VALUE");
        }
        skip_keyword(&tokens, &mut cursor, "VALUES");
        skip_keyword(&tokens, &mut cursor, "VALUE");

        let mut rows: Vec<InsertRow> = Vec::new();
        while cursor < tokens.len() {
            if !matches!(tokens.get(cursor), Some(Token::Sym(Sym::LParen))) {
                cursor += 1;
                continue;
            }
            cursor += 1;
            let start = cursor;
            let mut depth = 1i32;
            while cursor < tokens.len() {
                match tokens[cursor] {
                    Token::Sym(Sym::LParen) => depth += 1,
                    Token::Sym(Sym::RParen) => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                cursor += 1;
            }
            let inner = &tokens[start..cursor.min(tokens.len())];
            cursor += 1;
            let mut row = Vec::new();
            for part in sql::split_top_level(inner) {
                match literal_from_tokens(part, ctx, state, &self.variables) {
                    Some(value) => row.push(value),
                    None => return QueryResult::syntax_error(rest),
                }
            }
            rows.push((column_names.clone(), row));
            if rows.len() >= MAX_RESULT_ROWS {
                break;
            }
        }
        if rows.is_empty() {
            return QueryResult::syntax_error(rest);
        }
        apply_insert(
            self,
            state,
            ctx,
            schema_name.as_deref(),
            &table_name,
            rows,
            replace,
            ignore,
        )
    }

    fn peek_table(
        &self,
        state: &SessionState,
        schema: Option<&str>,
        table: &str,
        ctx: &QueryContext,
    ) -> Option<FakeTable> {
        self.resolve(state, schema, table, ctx)
            .map(|(_, view)| view.table().clone())
    }

    fn update(&self, rest: &str, ctx: &QueryContext, state: &mut SessionState) -> QueryResult {
        let Some(tokens) = self.tokens(rest, ctx) else {
            return QueryResult::syntax_error(rest);
        };
        let mut cursor = 0usize;
        skip_keyword(&tokens, &mut cursor, "LOW_PRIORITY");
        skip_keyword(&tokens, &mut cursor, "IGNORE");
        let Some((schema_name, table_name, next)) = parse_table_ref(&tokens[cursor..]) else {
            return QueryResult::syntax_error(rest);
        };
        cursor += next;
        if !skip_keyword(&tokens, &mut cursor, "SET") {
            return QueryResult::syntax_error(rest);
        }
        // The assignment list ends at the first top level WHERE / ORDER / LIMIT.
        let mut end = cursor;
        let mut depth = 0i32;
        while end < tokens.len() {
            match &tokens[end] {
                Token::Sym(Sym::LParen) => depth += 1,
                Token::Sym(Sym::RParen) => depth -= 1,
                Token::Word(word)
                    if depth == 0
                        && matches!(
                            word.to_ascii_uppercase().as_str(),
                            "WHERE" | "ORDER" | "LIMIT"
                        ) =>
                {
                    break;
                }
                _ => {}
            }
            end += 1;
        }

        let Some(table_columns) = self.peek_table(state, schema_name.as_deref(), &table_name, ctx)
        else {
            return unknown_table(schema_name.as_deref(), &table_name, ctx);
        };
        let mut assignments: Vec<(usize, Expr)> = Vec::new();
        for part in sql::split_top_level(&tokens[cursor..end]) {
            if part.is_empty() {
                continue;
            }
            let column_name = match (part.first(), part.get(1)) {
                (Some(Token::Word(name) | Token::Quoted(name)), Some(Token::Sym(Sym::Eq))) => name,
                _ => return QueryResult::syntax_error(rest),
            };
            let Some(index) = table_columns
                .columns
                .iter()
                .position(|column| column.name.eq_ignore_ascii_case(column_name))
            else {
                return QueryResult::error(
                    1054,
                    "42S22",
                    format!(
                        "Unknown column '{}' in 'field list'",
                        util::clip(column_name, 64)
                    ),
                );
            };
            let mut budget = Budget::new(EXPRESSION_BUDGET);
            let Some(expression) = sql::parse_expression(&part[2..], &mut budget) else {
                return QueryResult::syntax_error(rest);
            };
            assignments.push((index, expression));
        }
        if assignments.is_empty() {
            return QueryResult::syntax_error(rest);
        }

        let clauses = parse_clauses(&tokens, &mut end);
        if !clauses.group_by.is_empty() {
            return unsupported_clause("group by on update");
        }
        let where_expr = match &clauses.where_expr {
            ClauseState::Missing => None,
            ClauseState::Parsed(expression) => Some(expression.clone()),
            // A zero-column result set is not a legal DML answer: drivers and
            // ORMs read it as a truncated result set and lose the stream.
            ClauseState::Unsupported => return unsupported_clause("this WHERE clause"),
        };

        // Evaluate the predicate and the new values against the *original* rows,
        // so a column can reference its own previous value inside one statement.
        let eval_ctx = ctx.eval_context();
        let mut selected: Vec<usize> = Vec::new();
        for (index, row) in table_columns.rows.iter().enumerate() {
            let active = match &where_expr {
                None => true,
                Some(expression) => {
                    let context = RowContext {
                        columns: &table_columns.columns,
                        row,
                        session: &eval_ctx,
                        state,
                        variables: &self.variables,
                    };
                    match eval::matches_where(expression, &context) {
                        Ok(flag) => flag,
                        Err(err) => {
                            return QueryResult::error(
                                err.code(),
                                err.sqlstate(),
                                err.message("where clause"),
                            );
                        }
                    }
                }
            };
            if active {
                selected.push(index);
            }
        }
        // `UPDATE ... ORDER BY ... LIMIT` touches rows in sorted order, not in
        // storage order. Ignoring the sort while reporting success would update
        // the wrong rows silently.
        if let Err(result) = sort_rows_by_order(
            self,
            &table_columns,
            &mut selected,
            &clauses.order_by,
            &eval_ctx,
            state,
        ) {
            return result;
        }
        if let Some(limit) = clauses.limit {
            let count = usize::try_from(limit.count).unwrap_or(usize::MAX);
            let offset = usize::try_from(limit.offset).unwrap_or(usize::MAX);
            selected = selected.into_iter().skip(offset).take(count).collect();
        }
        let matched = selected.len();

        let mut planned: Vec<self::state::PendingRowUpdate> = Vec::with_capacity(selected.len());
        for index in selected {
            let row = &table_columns.rows[index];
            let context = RowContext {
                columns: &table_columns.columns,
                row,
                session: &eval_ctx,
                state,
                variables: &self.variables,
            };
            let mut changes = Vec::with_capacity(assignments.len());
            for (position, expression) in &assignments {
                match eval::evaluate(expression, &context) {
                    Ok(value) => changes.push((*position, value.to_wire())),
                    Err(err) => {
                        return QueryResult::error(
                            err.code(),
                            err.sqlstate(),
                            err.message("field list"),
                        );
                    }
                }
            }
            planned.push((index, changes));
        }

        let owned = match self.materialise(state, schema_name.as_deref(), &table_name, ctx) {
            Ok(owned) => owned,
            Err(result) => return result,
        };
        let Some((schema, canonical)) = owned else {
            // Simulation is off: acknowledge without touching anything.
            return QueryResult::ok(0, 0, "");
        };
        let outcome = match state.update_rows(&schema, &canonical, &planned) {
            Ok(outcome) => outcome,
            Err(err) => return state_error_result(err),
        };
        state.set_row_count(outcome.changed as i64);
        QueryResult::ok(
            outcome.changed as u64,
            0,
            &format!(
                "Rows matched: {matched}  Changed: {}  Warnings: 0",
                outcome.changed
            ),
        )
    }

    fn delete(&self, rest: &str, ctx: &QueryContext, state: &mut SessionState) -> QueryResult {
        let Some(tokens) = self.tokens(rest, ctx) else {
            return QueryResult::syntax_error(rest);
        };
        let mut cursor = 0usize;
        skip_keyword(&tokens, &mut cursor, "LOW_PRIORITY");
        skip_keyword(&tokens, &mut cursor, "QUICK");
        skip_keyword(&tokens, &mut cursor, "IGNORE");
        if !skip_keyword(&tokens, &mut cursor, "FROM") {
            return QueryResult::syntax_error(rest);
        }
        let Some((schema_name, table_name, next)) = parse_table_ref(&tokens[cursor..]) else {
            return QueryResult::syntax_error(rest);
        };
        cursor += next;
        let Some(table_columns) = self.peek_table(state, schema_name.as_deref(), &table_name, ctx)
        else {
            return unknown_table(schema_name.as_deref(), &table_name, ctx);
        };
        let clauses = parse_clauses(&tokens, &mut cursor);
        if !clauses.group_by.is_empty() {
            return unsupported_clause("group by on delete");
        }
        let where_expr = match &clauses.where_expr {
            ClauseState::Missing => None,
            ClauseState::Parsed(expression) => Some(expression.clone()),
            ClauseState::Unsupported => return unsupported_clause("this WHERE clause"),
        };
        let eval_ctx = ctx.eval_context();
        let mut selected: Vec<usize> = Vec::with_capacity(table_columns.rows.len());
        for (index, row) in table_columns.rows.iter().enumerate() {
            let matched = match &where_expr {
                None => true,
                Some(expression) => {
                    let context = RowContext {
                        columns: &table_columns.columns,
                        row,
                        session: &eval_ctx,
                        state,
                        variables: &self.variables,
                    };
                    match eval::matches_where(expression, &context) {
                        Ok(flag) => flag,
                        Err(err) => {
                            return QueryResult::error(
                                err.code(),
                                err.sqlstate(),
                                err.message("where clause"),
                            );
                        }
                    }
                }
            };
            if matched {
                selected.push(index);
            }
        }
        // `DELETE ... ORDER BY ... LIMIT` removes the lowest/highest keys first.
        if let Err(result) = sort_rows_by_order(
            self,
            &table_columns,
            &mut selected,
            &clauses.order_by,
            &eval_ctx,
            state,
        ) {
            return result;
        }
        if let Some(limit) = clauses.limit {
            let count = usize::try_from(limit.count).unwrap_or(usize::MAX);
            let offset = usize::try_from(limit.offset).unwrap_or(usize::MAX);
            selected = selected.into_iter().skip(offset).take(count).collect();
        }

        let owned = match self.materialise(state, schema_name.as_deref(), &table_name, ctx) {
            Ok(owned) => owned,
            Err(result) => return result,
        };
        let Some((schema, canonical)) = owned else {
            return QueryResult::ok(0, 0, "");
        };
        let removed = match state.delete_rows(&schema, &canonical, &selected) {
            Ok(removed) => removed,
            Err(err) => return state_error_result(err),
        };
        state.set_row_count(removed as i64);
        QueryResult::ok(removed as u64, 0, "")
    }

    fn truncate(&self, rest: &str, ctx: &QueryContext, state: &mut SessionState) -> QueryResult {
        let mut rest = rest.trim();
        for prefix in ["TABLE ", "table "] {
            if let Some(tail) = rest.strip_prefix(prefix) {
                rest = tail.trim_start();
            }
        }
        let table_name = unquote_ident(rest);
        if table_name.is_empty() {
            return QueryResult::syntax_error(rest);
        }
        if self.peek_table(state, None, &table_name, ctx).is_none() {
            return unknown_table(None, &table_name, ctx);
        }
        let owned = match self.materialise(state, None, &table_name, ctx) {
            Ok(owned) => owned,
            Err(result) => return result,
        };
        let Some((schema, canonical)) = owned else {
            return QueryResult::ok(0, 0, "");
        };
        match state.truncate_table(&schema, &canonical) {
            Ok(_) => {
                state.set_row_count(0);
                QueryResult::ok(0, 0, "")
            }
            Err(err) => state_error_result(err),
        }
    }

    // -----------------------------------------------------------------------
    // DDL
    // -----------------------------------------------------------------------

    fn create(&self, rest: &str, ctx: &QueryContext, state: &mut SessionState) -> QueryResult {
        let Some(tokens) = self.tokens(rest, ctx) else {
            return QueryResult::syntax_error(rest);
        };
        let mut cursor = 0usize;
        let temporary = skip_keyword(&tokens, &mut cursor, "TEMPORARY");
        let _ = temporary;
        if skip_keyword(&tokens, &mut cursor, "DATABASE")
            || skip_keyword(&tokens, &mut cursor, "SCHEMA")
        {
            let if_not_exists = skip_if_not_exists(&tokens, &mut cursor);
            let Some(name) = token_name(tokens.get(cursor)) else {
                return QueryResult::syntax_error(rest);
            };
            if state.is_schema_dropped(&name) {
                // Re-creating a dropped schema is a fresh empty schema.
                state.revive_schema(&name);
                return QueryResult::ok(1, 0, "");
            }
            if self.has_schema(&name, state) {
                if if_not_exists {
                    return QueryResult::ok(0, 0, "");
                }
                return QueryResult::error(
                    1007,
                    "HY000",
                    format!(
                        "Can't create database '{}'; database exists",
                        util::clip(&name, 64)
                    ),
                );
            }
            if let Err(err) = state.create_schema(&name) {
                return state_error_result(err);
            }
            return QueryResult::ok(1, 0, "");
        }
        if !skip_keyword(&tokens, &mut cursor, "TABLE") {
            // Views, indexes, procedures: accepted, never materialised.
            return QueryResult::ok(0, 0, "");
        }
        let if_not_exists = skip_if_not_exists(&tokens, &mut cursor);
        let Some((schema_name, table_name, next)) = parse_table_ref(&tokens[cursor..]) else {
            return QueryResult::syntax_error(rest);
        };
        cursor += next;
        let schema_name = schema_name
            .or_else(|| {
                if ctx.current_db.is_empty() {
                    None
                } else {
                    Some(ctx.current_db.clone())
                }
            })
            .unwrap_or_else(|| "app_prod".to_string());
        if !self.has_schema(&schema_name, state) {
            return QueryResult::error(1049, "42000", format!("Unknown database '{schema_name}'"));
        }
        if self
            .peek_table(state, Some(&schema_name), &table_name, ctx)
            .is_some()
        {
            if if_not_exists {
                return QueryResult::ok(0, 0, "");
            }
            return QueryResult::error(
                1050,
                "42S01",
                format!("Table '{}' already exists", util::clip(&table_name, 64)),
            );
        }

        if !matches!(tokens.get(cursor), Some(Token::Sym(Sym::LParen))) {
            return QueryResult::syntax_error(rest);
        }
        cursor += 1;
        let mut depth = 1i32;
        let start = cursor;
        while cursor < tokens.len() {
            match tokens[cursor] {
                Token::Sym(Sym::LParen) => depth += 1,
                Token::Sym(Sym::RParen) => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            cursor += 1;
        }
        if depth != 0 {
            return QueryResult::syntax_error(rest);
        }
        let definitions = &tokens[start..cursor];
        let mut columns: Vec<FakeColumn> = Vec::new();
        for part in sql::split_top_level(definitions) {
            if part.is_empty() {
                continue;
            }
            let first = part.first().and_then(Token::keyword).unwrap_or_default();
            if matches!(
                first.as_str(),
                "PRIMARY"
                    | "UNIQUE"
                    | "KEY"
                    | "INDEX"
                    | "CONSTRAINT"
                    | "FOREIGN"
                    | "FULLTEXT"
                    | "SPATIAL"
                    | "CHECK"
            ) {
                // Table level constraints: only a primary key is modelled.
                if first == "PRIMARY"
                    && let Some(Token::Sym(Sym::LParen)) = part.get(1)
                {
                    for name in part[2..].iter() {
                        if let Token::Word(name) | Token::Quoted(name) = name
                            && let Some(column) = columns
                                .iter_mut()
                                .find(|c| c.name.eq_ignore_ascii_case(name))
                        {
                            column.key = "PRI".to_string();
                            column.nullable = false;
                        }
                    }
                }
                continue;
            }
            let Some(name) = token_name(part.first()) else {
                continue;
            };
            let Some(data_type) = part.get(1).and_then(Token::keyword) else {
                continue;
            };
            let mut data_type = data_type.to_ascii_lowercase();
            if let Some(Token::Sym(Sym::LParen)) = part.get(2) {
                // Keep `varchar(64)` / `decimal(10,2)` as written.
                let mut text = String::new();
                for token in &part[2..] {
                    match token {
                        Token::Sym(Sym::LParen) => text.push('('),
                        Token::Sym(Sym::RParen) => text.push(')'),
                        Token::Sym(Sym::Comma) => text.push(','),
                        Token::Num(Value::Int(number)) => text.push_str(&number.to_string()),
                        Token::Word(word) => text.push_str(word),
                        _ => {}
                    }
                    if text.ends_with(')') {
                        break;
                    }
                }
                data_type.push_str(&text);
            }
            let mut nullable = true;
            let mut auto_increment = false;
            let mut primary = false;
            for window in part.windows(2) {
                if let [Token::Word(first), Token::Word(second)] = window
                    && first.eq_ignore_ascii_case("NOT")
                    && second.eq_ignore_ascii_case("NULL")
                {
                    nullable = false;
                }
            }
            for token in part {
                if let Token::Word(word) = token {
                    if word.eq_ignore_ascii_case("AUTO_INCREMENT") {
                        auto_increment = true;
                    } else if word.eq_ignore_ascii_case("PRIMARY") {
                        primary = true;
                        nullable = false;
                    }
                }
            }
            let base = data_type.split('(').next().unwrap_or(&data_type);
            let wire_type = wire_type_for(base);
            let mut column = FakeColumn::new(&name, &data_type, wire_type);
            column.nullable = nullable;
            if primary {
                column.key = "PRI".to_string();
            }
            if auto_increment {
                column.extra = "auto_increment".to_string();
            }
            columns.push(column);
        }
        if columns.is_empty() {
            return QueryResult::syntax_error(rest);
        }
        let new_table = FakeTable {
            name: table_name.clone(),
            engine: "InnoDB".to_string(),
            comment: String::new(),
            columns,
            rows: Vec::new(),
        };
        if let Err(err) = state.create_table(&schema_name, new_table) {
            return state_error_result(err);
        }
        QueryResult::ok(0, 0, "")
    }

    fn drop(&self, rest: &str, ctx: &QueryContext, state: &mut SessionState) -> QueryResult {
        let Some(tokens) = self.tokens(rest, ctx) else {
            return QueryResult::syntax_error(rest);
        };
        let mut cursor = 0usize;
        if skip_keyword(&tokens, &mut cursor, "DATABASE")
            || skip_keyword(&tokens, &mut cursor, "SCHEMA")
        {
            let if_exists = skip_keyword(&tokens, &mut cursor, "IF")
                && skip_keyword(&tokens, &mut cursor, "EXISTS");
            let Some(name) = token_name(tokens.get(cursor)) else {
                return QueryResult::syntax_error(rest);
            };
            if !self.has_schema(&name, state) {
                if if_exists {
                    return QueryResult::ok(0, 0, "");
                }
                return QueryResult::error(
                    1008,
                    "HY000",
                    format!(
                        "Can't drop database '{}'; database doesn't exist",
                        util::clip(&name, 64)
                    ),
                );
            }
            // Only a schema that exists in the base catalog needs a tombstone;
            // a session-created one is simply removed from the overlay.
            let base_schema = self.base_has_schema(&name);
            if let Err(err) = state.drop_schema(&name, base_schema) {
                return state_error_result(err);
            }
            return QueryResult::ok(1, 0, "");
        }
        if !skip_keyword(&tokens, &mut cursor, "TABLE") {
            return QueryResult::ok(0, 0, "");
        }
        let if_exists = skip_keyword(&tokens, &mut cursor, "IF")
            && skip_keyword(&tokens, &mut cursor, "EXISTS");
        let mut dropped = 0u64;
        while let Some((schema_name, table_name, next)) = parse_table_ref(&tokens[cursor..]) {
            cursor += next;
            let exists = self
                .resolve(state, schema_name.as_deref(), &table_name, ctx)
                .is_some();
            if !exists {
                if if_exists {
                    // Skip silently, exactly like `DROP TABLE IF EXISTS`.
                } else {
                    return unknown_table(schema_name.as_deref(), &table_name, ctx);
                }
            } else {
                let canonical = self
                    .resolve(state, schema_name.as_deref(), &table_name, ctx)
                    .map(|(name, _)| name.to_string())
                    .unwrap_or_else(|| ctx.current_db.clone());
                // A tombstone is only needed for a table the base catalog still
                // holds; dropping a session-created table is pure bookkeeping and
                // must not leave a marker behind, or a CREATE/DROP loop over ever
                // new names would grow the overlay without bound.
                let base_table = self.base_has_table(&canonical, &table_name);
                if let Err(err) = state.drop_table(&canonical, &table_name, base_table) {
                    return state_error_result(err);
                }
                dropped += 1;
            }
            if !matches!(tokens.get(cursor), Some(Token::Sym(Sym::Comma))) {
                break;
            }
            cursor += 1;
        }
        QueryResult::ok(dropped, 0, "")
    }
}

// ---------------------------------------------------------------------------
// SELECT plumbing
// ---------------------------------------------------------------------------

/// One projected column.
enum Projection {
    /// A physical column of the table, by index.
    Column(usize),
    /// A scalar expression.
    Expression(Expr, String),
    /// An aggregate call.
    Aggregate {
        kind: AggregateKind,
        argument: Option<Expr>,
        distinct: bool,
        label: String,
    },
}

/// Aggregate functions the selector folds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AggregateKind {
    Count,
    Min,
    Max,
    Sum,
    Avg,
}

/// How a clause parsed.
enum ClauseState<T> {
    /// The clause was absent.
    Missing,
    /// The clause parsed.
    Parsed(T),
    /// The clause was present but outside the grammar: degrade conservatively.
    Unsupported,
}

/// Parsed trailing clauses of a `SELECT`/`UPDATE`/`DELETE`.
struct Clauses {
    where_expr: ClauseState<Expr>,
    group_by: Vec<Expr>,
    order_by: Vec<(Expr, bool)>,
    limit: Option<Limit>,
}

#[derive(Debug, Clone, Copy)]
struct Limit {
    offset: u64,
    count: u64,
}

fn parse_clauses(tokens: &[Token], cursor: &mut usize) -> Clauses {
    let mut clauses = Clauses {
        where_expr: ClauseState::Missing,
        group_by: Vec::new(),
        order_by: Vec::new(),
        limit: None,
    };
    let mut index = *cursor;
    while index < tokens.len() {
        let keyword = tokens[index].keyword();
        match keyword.as_deref() {
            Some("WHERE") => {
                index += 1;
                let end = find_clause_end(tokens, index);
                let mut budget = Budget::new(EXPRESSION_BUDGET);
                clauses.where_expr = match sql::parse_expression(&tokens[index..end], &mut budget) {
                    Some(expression) => ClauseState::Parsed(expression),
                    None => ClauseState::Unsupported,
                };
                index = end;
            }
            Some("GROUP") => {
                index += 1;
                skip_keyword(tokens, &mut index, "BY");
                let end = find_clause_end(tokens, index);
                for part in sql::split_top_level(&tokens[index..end]) {
                    let mut budget = Budget::new(EXPRESSION_BUDGET);
                    if let Some(expression) = sql::parse_expression(part, &mut budget) {
                        if clauses.group_by.len() < MAX_ORDER_KEYS {
                            clauses.group_by.push(expression);
                        }
                    } else {
                        clauses.where_expr = ClauseState::Unsupported;
                    }
                }
                index = end;
            }
            Some("HAVING") => {
                // Modelling HAVING over aggregate output is out of scope; the
                // conservative answer is an empty result, never a superset.
                index = find_clause_end(tokens, index + 1);
                clauses.where_expr = ClauseState::Unsupported;
            }
            Some("ORDER") => {
                index += 1;
                skip_keyword(tokens, &mut index, "BY");
                let end = find_sort_end(tokens, index);
                for part in sql::split_top_level(&tokens[index..end]) {
                    if part.is_empty() {
                        continue;
                    }
                    let mut ascending = true;
                    let mut expression_tokens = part;
                    if let Some(Token::Word(last)) = part.last() {
                        if last.eq_ignore_ascii_case("DESC") {
                            ascending = false;
                            expression_tokens = &part[..part.len() - 1];
                        } else if last.eq_ignore_ascii_case("ASC") {
                            expression_tokens = &part[..part.len() - 1];
                        }
                    }
                    let mut budget = Budget::new(EXPRESSION_BUDGET);
                    if let Some(expression) = sql::parse_expression(expression_tokens, &mut budget)
                        && clauses.order_by.len() < MAX_ORDER_KEYS
                    {
                        clauses.order_by.push((expression, ascending));
                    }
                }
                index = end;
            }
            Some("LIMIT") => {
                index += 1;
                let (limit, next) = parse_limit(tokens, index);
                clauses.limit = limit;
                index = next;
            }
            _ => index += 1,
        }
    }
    *cursor = index;
    clauses
}

fn find_clause_end(tokens: &[Token], from: usize) -> usize {
    let mut depth = 0i32;
    let mut index = from;
    while index < tokens.len() {
        match &tokens[index] {
            Token::Sym(Sym::LParen) => depth += 1,
            Token::Sym(Sym::RParen) => depth -= 1,
            Token::Word(word) if depth == 0 => {
                let upper = word.to_ascii_uppercase();
                if matches!(
                    upper.as_str(),
                    "GROUP" | "ORDER" | "LIMIT" | "HAVING" | "UNION" | "PROCEDURE" | "INTO"
                ) {
                    return index;
                }
            }
            _ => {}
        }
        index += 1;
    }
    tokens.len()
}

fn find_sort_end(tokens: &[Token], from: usize) -> usize {
    let mut depth = 0i32;
    let mut index = from;
    while index < tokens.len() {
        match &tokens[index] {
            Token::Sym(Sym::LParen) => depth += 1,
            Token::Sym(Sym::RParen) => depth -= 1,
            Token::Word(word) if depth == 0 => {
                let upper = word.to_ascii_uppercase();
                if matches!(upper.as_str(), "LIMIT" | "UNION" | "PROCEDURE" | "INTO") {
                    return index;
                }
            }
            _ => {}
        }
        index += 1;
    }
    tokens.len()
}

/// Parse `LIMIT n`, `LIMIT offset, n` or `LIMIT n OFFSET offset`.
fn parse_limit(tokens: &[Token], from: usize) -> (Option<Limit>, usize) {
    let mut numbers: Vec<u64> = Vec::new();
    let mut offset: Option<u64> = None;
    let mut index = from;
    while index < tokens.len() {
        match &tokens[index] {
            Token::Num(Value::Int(value)) if *value >= 0 => numbers.push(*value as u64),
            Token::Word(word) if word.eq_ignore_ascii_case("OFFSET") => {
                if let Some(Token::Num(Value::Int(value))) = tokens.get(index + 1)
                    && *value >= 0
                {
                    offset = Some(*value as u64);
                    index += 1;
                }
            }
            Token::Sym(Sym::Comma) => {}
            Token::Num(Value::Float(value)) if *value >= 0.0 => {
                // `LIMIT 1e3` — saturate rather than overflow.
                numbers.push(*value as u64);
            }
            _ => break,
        }
        index += 1;
    }
    let limit = match (numbers.len(), offset) {
        (0, _) => None,
        (1, None) => Some(Limit {
            offset: 0,
            count: numbers[0],
        }),
        (1, Some(offset)) => Some(Limit {
            offset,
            count: numbers[0],
        }),
        (_, Some(offset)) => Some(Limit {
            offset,
            count: numbers[0],
        }),
        (_, None) => Some(Limit {
            offset: numbers[0],
            count: numbers[1],
        }),
    };
    (limit, index)
}

fn build_projection(
    tokens: &[Token],
    table: Option<&FakeTable>,
    ctx: &QueryContext,
    state: &SessionState,
) -> std::result::Result<Vec<Projection>, QueryResult> {
    let mut projection = Vec::new();
    let items = sql::split_top_level(tokens);
    let mut names: Vec<(String, String, String, u8)> = Vec::new();
    let mut expressions: Vec<Option<Expr>> = Vec::new();

    for item in items {
        if item.is_empty() {
            continue;
        }
        // `*`
        if item.len() == 1 && item[0] == Token::Sym(Sym::Star) {
            let Some(table) = table else {
                return Err(QueryResult::syntax_error("*"));
            };
            for (index, column) in table.columns.iter().enumerate() {
                projection.push(Projection::Column(index));
                names.push((
                    column.name.clone(),
                    column.name.clone(),
                    table.name.clone(),
                    column.wire_type,
                ));
                expressions.push(None);
            }
            continue;
        }
        // `t.*`
        if item.len() == 3
            && matches!(item[1], Token::Sym(Sym::Dot))
            && item[2] == Token::Sym(Sym::Star)
            && matches!(item[0], Token::Word(_) | Token::Quoted(_))
        {
            let Some(table) = table else {
                return Err(QueryResult::syntax_error("*"));
            };
            for (index, column) in table.columns.iter().enumerate() {
                projection.push(Projection::Column(index));
                names.push((
                    column.name.clone(),
                    column.name.clone(),
                    table.name.clone(),
                    column.wire_type,
                ));
                expressions.push(None);
            }
            continue;
        }

        // `expr [AS] alias`
        let (expression_tokens, alias) = split_alias(item);
        let mut budget = Budget::new(EXPRESSION_BUDGET);
        let Some(expression) = sql::parse_expression(expression_tokens, &mut budget) else {
            return Err(QueryResult::syntax_error(&render_tokens(expression_tokens)));
        };
        if projection.len() >= MAX_RESULT_COLUMNS {
            return Err(QueryResult::error(
                1117,
                "42000",
                "Too many fields in 'field list'",
            ));
        }
        // A bare column keeps its own wire type, everything else is text.
        if let Expr::Column(name) = &expression
            && let Some(table) = table
            && let Some(index) = table
                .columns
                .iter()
                .position(|column| column.name.eq_ignore_ascii_case(name))
        {
            let column = &table.columns[index];
            projection.push(Projection::Column(index));
            names.push((
                alias.clone().unwrap_or_else(|| column.name.clone()),
                column.name.clone(),
                table.name.clone(),
                column.wire_type,
            ));
            expressions.push(None);
            continue;
        }
        let label = alias
            .clone()
            .unwrap_or_else(|| render_tokens(expression_tokens));
        if let Expr::Func {
            name,
            args,
            distinct,
            star,
        } = &expression
            && is_aggregate(name)
        {
            let kind = match name.as_str() {
                "COUNT" => AggregateKind::Count,
                "MIN" => AggregateKind::Min,
                "MAX" => AggregateKind::Max,
                "SUM" => AggregateKind::Sum,
                "AVG" => AggregateKind::Avg,
                _ => AggregateKind::Count,
            };
            projection.push(Projection::Aggregate {
                kind,
                argument: if *star { None } else { args.first().cloned() },
                distinct: *distinct,
                label: label.clone(),
            });
            names.push((label, String::new(), String::new(), column_type::VAR_STRING));
            expressions.push(None);
            continue;
        }
        if expression.contains_aggregate() {
            // `SUM(x) + 1`: the aggregate layer only folds a bare call.
            return Err(QueryResult::error(
                1111,
                "HY000",
                "Invalid use of group function",
            ));
        }
        let wire_type = match &expression {
            Expr::Literal(Value::Int(_)) => column_type::LONGLONG,
            Expr::Literal(Value::Float(_)) => column_type::DOUBLE,
            _ => column_type::VAR_STRING,
        };
        projection.push(Projection::Expression(expression.clone(), label.clone()));
        names.push((label, String::new(), String::new(), wire_type));
        expressions.push(Some(expression));
    }
    let _ = (ctx, state);
    if projection.is_empty() {
        return Err(QueryResult::syntax_error(""));
    }
    let _ = expressions;
    // Stash the labels so the caller can build the header.
    names.shrink_to_fit();
    build_projection_with_names(projection, names)
}

fn build_projection_with_names(
    projection: Vec<Projection>,
    names: Vec<(String, String, String, u8)>,
) -> std::result::Result<Vec<Projection>, QueryResult> {
    // The labels travel with the projections; `Projection` already carries the
    // alias for expressions and aggregates, so this only validates the shape.
    if projection.len() != names.len() {
        return Err(QueryResult::error(1105, "HY000", "Unknown error"));
    }
    Ok(projection)
}

fn render_tokens(tokens: &[Token]) -> String {
    let mut out = String::new();
    for token in tokens {
        match token {
            Token::Word(word) => out.push_str(word),
            Token::Quoted(word) => {
                out.push('`');
                out.push_str(word);
                out.push('`');
            }
            Token::Str(text) => {
                out.push('\'');
                out.push_str(text);
                out.push('\'');
            }
            Token::Num(value) => out.push_str(&value.to_wire().unwrap_or_default()),
            Token::UserVar(name) => {
                out.push('@');
                out.push_str(name);
            }
            Token::SysVar(name) => {
                out.push_str("@@");
                out.push_str(name);
            }
            Token::Placeholder(_) => out.push('?'),
            Token::Sym(symbol) => out.push_str(match symbol {
                Sym::LParen => "(",
                Sym::RParen => ")",
                Sym::Comma => ",",
                Sym::Dot => ".",
                Sym::Star => "*",
                Sym::Plus => "+",
                Sym::Minus => "-",
                Sym::Slash => "/",
                Sym::Percent => "%",
                Sym::Eq => "=",
                Sym::NotEq => "<>",
                Sym::Lt => "<",
                Sym::Le => "<=",
                Sym::Gt => ">",
                Sym::Ge => ">=",
                Sym::Semicolon => ";",
            }),
        }
    }
    util::clip(&sanitise(&out), 64)
}

fn split_alias(item: &[Token]) -> (&[Token], Option<String>) {
    // `expr AS alias`
    let mut depth = 0i32;
    for (index, token) in item.iter().enumerate() {
        match token {
            Token::Sym(Sym::LParen) => depth += 1,
            Token::Sym(Sym::RParen) => depth -= 1,
            Token::Word(word) if depth == 0 && word.eq_ignore_ascii_case("AS") => {
                if let Some(Token::Word(alias) | Token::Quoted(alias)) = item.get(index + 1) {
                    return (&item[..index], Some(alias.clone()));
                }
            }
            _ => {}
        }
    }
    // `expr alias`
    if item.len() >= 2
        && let Some(Token::Word(alias) | Token::Quoted(alias)) = item.last()
        && !matches!(item[item.len() - 2], Token::Sym(Sym::Dot))
        && matches!(
            item[item.len() - 2],
            Token::Sym(Sym::RParen)
                | Token::Word(_)
                | Token::Quoted(_)
                | Token::Str(_)
                | Token::Num(_)
        )
    {
        // Only treat the last word as an alias when the preceding token cannot
        // continue an expression.
        let previous_is_word = matches!(item[item.len() - 2], Token::Word(_) | Token::Quoted(_));
        if !previous_is_word {
            return (&item[..item.len() - 1], Some(alias.clone()));
        }
    }
    (item, None)
}

fn execute_select(
    database: &FakeDatabase,
    schema: &str,
    table: &FakeTable,
    projection: Vec<Projection>,
    clauses: Clauses,
    ctx: &QueryContext,
    state: &SessionState,
) -> QueryResult {
    let degraded = matches!(clauses.where_expr, ClauseState::Unsupported);
    if degraded {
        // The filter could not be modelled: answer with no rows rather than
        // risk returning rows that do not match.
        return QueryResult::ResultSet(ResultSet {
            columns: header_for(&projection, schema, table),
            rows: Vec::new(),
            degraded: true,
        });
    }

    let eval_ctx = ctx.eval_context();
    let mut selected: Vec<usize> = Vec::new();
    match &clauses.where_expr {
        ClauseState::Missing => selected.extend(0..table.rows.len()),
        ClauseState::Parsed(expression) => {
            for (index, row) in table.rows.iter().enumerate() {
                let context = RowContext {
                    columns: &table.columns,
                    row,
                    session: &eval_ctx,
                    state,
                    variables: &database.variables,
                };
                match eval::matches_where(expression, &context) {
                    Ok(true) => selected.push(index),
                    Ok(false) => {}
                    Err(err) => {
                        return QueryResult::error(
                            err.code(),
                            err.sqlstate(),
                            err.message("where clause"),
                        );
                    }
                }
            }
        }
        ClauseState::Unsupported => unreachable!("handled above"),
    }

    let has_aggregate = projection
        .iter()
        .any(|item| matches!(item, Projection::Aggregate { .. }));

    if has_aggregate {
        return QueryResult::ResultSet(aggregate_select(
            database,
            schema,
            table,
            &projection,
            &clauses,
            &selected,
            &eval_ctx,
            state,
        ));
    }

    // ORDER BY before pagination, exactly like MySQL. The comparison is type
    // aware: sorting a `varchar` column by its declared type is what makes
    // `ORDER BY username` a dictionary order instead of collapsing every
    // non-numeric string to zero.
    if let Err(result) = sort_rows_by_order(
        database,
        table,
        &mut selected,
        &clauses.order_by,
        &eval_ctx,
        state,
    ) {
        return result;
    }

    let offset = clauses.limit.map_or(0, |limit| limit.offset);
    let count = clauses
        .limit
        .map_or(MAX_RESULT_ROWS as u64, |limit| limit.count)
        .min(MAX_RESULT_ROWS as u64);
    let offset = usize::try_from(offset).unwrap_or(usize::MAX);
    let count = usize::try_from(count).unwrap_or(MAX_RESULT_ROWS);

    let mut result = ResultSet {
        columns: header_for(&projection, schema, table),
        rows: Vec::new(),
        degraded: false,
    };
    let mut budget = MAX_RESULT_BYTES;
    for index in selected.into_iter().skip(offset).take(count) {
        let row = &table.rows[index];
        let mut values = Vec::with_capacity(projection.len());
        let mut cost = 0usize;
        for item in &projection {
            let value = match item {
                Projection::Column(position) => row.get(*position).cloned().flatten(),
                Projection::Expression(expression, _) => {
                    let context = RowContext {
                        columns: &table.columns,
                        row,
                        session: &eval_ctx,
                        state,
                        variables: &database.variables,
                    };
                    match eval::evaluate(expression, &context) {
                        Ok(value) => value.to_wire(),
                        Err(err) => {
                            return QueryResult::error(
                                err.code(),
                                err.sqlstate(),
                                err.message("field list"),
                            );
                        }
                    }
                }
                Projection::Aggregate { .. } => None,
            };
            cost += value.as_ref().map_or(0, String::len) + 1;
            values.push(value);
        }
        if cost > budget {
            break;
        }
        budget -= cost;
        result.rows.push(values);
    }
    QueryResult::ResultSet(result)
}

#[allow(clippy::too_many_arguments)]
fn aggregate_select(
    database: &FakeDatabase,
    schema: &str,
    table: &FakeTable,
    projection: &[Projection],
    clauses: &Clauses,
    selected: &[usize],
    eval_ctx: &EvalContext,
    state: &SessionState,
) -> ResultSet {
    let mut result = ResultSet {
        columns: header_for(projection, schema, table),
        rows: Vec::new(),
        degraded: false,
    };
    // Group the selected rows by the evaluated GROUP BY key. Grouping uses the
    // same type-aware collation as `ORDER BY`, so `GROUP BY username` folds
    // `Admin` and `admin` together under the advertised `ai_ci` collation
    // instead of treating every non-numeric string as `0`.
    let group_numeric: Vec<bool> = clauses
        .group_by
        .iter()
        .map(|expression| eval::sort_is_numeric(expression, &table.columns))
        .collect();
    let mut groups: Vec<(Vec<eval::SortKey>, Vec<usize>)> = Vec::new();
    if clauses.group_by.is_empty() {
        groups.push((Vec::new(), selected.to_vec()));
    } else {
        for index in selected {
            let row = &table.rows[*index];
            let context = RowContext {
                columns: &table.columns,
                row,
                session: eval_ctx,
                state,
                variables: &database.variables,
            };
            let mut key = Vec::with_capacity(clauses.group_by.len());
            let mut failed = false;
            for (position, expression) in clauses.group_by.iter().enumerate() {
                match eval::evaluate(expression, &context) {
                    Ok(value) => {
                        key.push(eval::SortKey::new(&value, group_numeric[position]));
                    }
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }
            if failed {
                result.degraded = true;
                return result;
            }
            match groups
                .iter_mut()
                .find(|(existing, _)| group_keys_match(existing, &key))
            {
                Some((_, rows)) => rows.push(*index),
                None => {
                    if groups.len() < MAX_RESULT_ROWS {
                        groups.push((key, vec![*index]));
                    }
                }
            }
        }
    }
    // MySQL emits grouped output in ascending group-key order.
    groups.sort_by(|left, right| {
        for (position, value) in left.0.iter().enumerate() {
            let Some(other) = right.0.get(position) else {
                continue;
            };
            let ordering = value.cmp(other);
            if ordering != std::cmp::Ordering::Equal {
                return ordering;
            }
        }
        std::cmp::Ordering::Equal
    });

    let mut budget = MAX_RESULT_BYTES;
    for (_, rows) in groups.iter().take(MAX_RESULT_ROWS) {
        let mut values = Vec::with_capacity(projection.len());
        let mut cost = 0usize;
        for item in projection {
            let value = match item {
                Projection::Column(position) => rows
                    .first()
                    .and_then(|index| table.rows[*index].get(*position).cloned().flatten()),
                Projection::Expression(expression, _) => {
                    let Some(first) = rows.first() else {
                        values.push(None);
                        continue;
                    };
                    let row = &table.rows[*first];
                    let context = RowContext {
                        columns: &table.columns,
                        row,
                        session: eval_ctx,
                        state,
                        variables: &database.variables,
                    };
                    match eval::evaluate(expression, &context) {
                        Ok(value) => value.to_wire(),
                        Err(_) => None,
                    }
                }
                Projection::Aggregate {
                    kind,
                    argument,
                    distinct,
                    ..
                } => {
                    // `MIN`/`MAX` follow the declared type of their argument, so
                    // `MIN(username)` is a dictionary minimum instead of `0`.
                    let numeric = argument
                        .as_ref()
                        .is_none_or(|arg| eval::sort_is_numeric(arg, &table.columns));
                    fold_aggregate(
                        database,
                        table,
                        *kind,
                        argument.as_ref(),
                        *distinct,
                        numeric,
                        rows,
                        eval_ctx,
                        state,
                    )
                    .map(|value| value.to_wire())
                    .unwrap_or(None)
                }
            };
            cost += value.as_ref().map_or(0, String::len) + 1;
            values.push(value);
        }
        if cost > budget {
            break;
        }
        budget -= cost;
        result.rows.push(values);
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn fold_aggregate(
    database: &FakeDatabase,
    table: &FakeTable,
    kind: AggregateKind,
    argument: Option<&Expr>,
    distinct: bool,
    numeric: bool,
    rows: &[usize],
    eval_ctx: &EvalContext,
    state: &SessionState,
) -> Option<Value> {
    // Collect the argument values once; `COUNT(*)` needs none.
    let mut values: Vec<Value> = Vec::new();
    if let Some(expression) = argument {
        for index in rows {
            let row = &table.rows[*index];
            let context = RowContext {
                columns: &table.columns,
                row,
                session: eval_ctx,
                state,
                variables: &database.variables,
            };
            match eval::evaluate(expression, &context) {
                Ok(value) => values.push(value),
                Err(_) => return None,
            }
        }
        if distinct {
            let mut unique: Vec<Value> = Vec::new();
            for value in values {
                if !unique.contains(&value) {
                    unique.push(value);
                }
            }
            values = unique;
        }
    }
    match kind {
        AggregateKind::Count => Some(Value::Int(if argument.is_none() {
            rows.len() as i64
        } else {
            values
                .iter()
                .filter(|value| !matches!(value, Value::Null))
                .count() as i64
        })),
        AggregateKind::Min | AggregateKind::Max => {
            let mut best: Option<(eval::SortKey, Value)> = None;
            for value in values {
                if matches!(value, Value::Null) {
                    continue;
                }
                let key = eval::SortKey::new(&value, numeric);
                best = Some(match best {
                    None => (key, value),
                    Some((current_key, current)) => {
                        let ordering = key.cmp(&current_key);
                        match (kind, ordering) {
                            (AggregateKind::Min, std::cmp::Ordering::Less)
                            | (AggregateKind::Max, std::cmp::Ordering::Greater) => (key, value),
                            _ => (current_key, current),
                        }
                    }
                });
            }
            Some(best.map_or(Value::Null, |(_, value)| value))
        }
        AggregateKind::Sum | AggregateKind::Avg => {
            let numbers: Vec<f64> = values.iter().filter_map(Value::as_f64).collect();
            if numbers.is_empty() {
                return Some(Value::Null);
            }
            let total: f64 = numbers.iter().sum();
            if kind == AggregateKind::Avg {
                Some(Value::Float(total / numbers.len() as f64))
            } else if numbers.iter().all(|number| number.fract() == 0.0) {
                Some(Value::Int(total as i64))
            } else {
                Some(Value::Float(total))
            }
        }
    }
}

fn header_for(projection: &[Projection], schema: &str, table: &FakeTable) -> Vec<ResultColumn> {
    projection
        .iter()
        .map(|item| match item {
            Projection::Column(position) => {
                let column = &table.columns[*position];
                ResultColumn {
                    name: column.name.clone(),
                    org_name: column.name.clone(),
                    table: table.name.clone(),
                    schema: schema.to_string(),
                    wire_type: column.wire_type,
                }
            }
            Projection::Expression(expression, label) => ResultColumn {
                name: label.clone(),
                org_name: render_tokens(&[]).clone() + &expr_name(expression),
                table: String::new(),
                schema: String::new(),
                wire_type: match expression {
                    Expr::Literal(Value::Int(_)) => column_type::LONGLONG,
                    Expr::Literal(Value::Float(_)) => column_type::DOUBLE,
                    _ => column_type::VAR_STRING,
                },
            },
            Projection::Aggregate { label, .. } => ResultColumn {
                name: label.clone(),
                org_name: String::new(),
                table: String::new(),
                schema: String::new(),
                wire_type: column_type::VAR_STRING,
            },
        })
        .collect()
}

fn expr_name(expression: &Expr) -> String {
    match expression {
        Expr::Column(name) => name.clone(),
        Expr::Literal(value) => value.to_wire().unwrap_or_else(|| "NULL".to_string()),
        other => format!("{other:?}"),
    }
}

fn materialise_expressions(
    database: &FakeDatabase,
    projection: &[Projection],
    ctx: &QueryContext,
    state: &SessionState,
    row_count: usize,
) -> ResultSet {
    let eval_ctx = ctx.eval_context();
    let mut columns = Vec::with_capacity(projection.len());
    let mut values = Vec::with_capacity(projection.len());
    for item in projection {
        match item {
            Projection::Expression(expression, label) => {
                let context = RowContext {
                    columns: &[],
                    row: &[],
                    session: &eval_ctx,
                    state,
                    variables: &database.variables,
                };
                let value = eval::evaluate(expression, &context).ok();
                let rendered = value.as_ref().and_then(Value::to_wire);
                columns.push(ResultColumn {
                    name: label.clone(),
                    org_name: expr_name(expression),
                    table: String::new(),
                    schema: String::new(),
                    wire_type: match &rendered {
                        Some(text) if text.parse::<i64>().is_ok() => column_type::LONGLONG,
                        Some(_) => column_type::VAR_STRING,
                        None => column_type::NULL,
                    },
                });
                values.push(rendered);
            }
            Projection::Aggregate {
                kind,
                argument,
                distinct,
                label,
            } => {
                // Against the empty table a `MIN`/`MAX` has no key to compare, so
                // the numeric flag only has to be well defined, not meaningful.
                let numeric = argument
                    .as_ref()
                    .is_none_or(|arg| eval::sort_is_numeric(arg, &[]));
                let value = fold_aggregate(
                    database,
                    &EMPTY_TABLE.with(|table| table.clone()),
                    *kind,
                    argument.as_ref(),
                    *distinct,
                    numeric,
                    &(0..row_count).collect::<Vec<_>>(),
                    &eval_ctx,
                    state,
                );
                columns.push(ResultColumn {
                    name: label.clone(),
                    org_name: String::new(),
                    table: String::new(),
                    schema: String::new(),
                    wire_type: column_type::LONGLONG,
                });
                values.push(value.and_then(|value| value.to_wire()));
            }
            Projection::Column(_) => {}
        }
    }
    ResultSet {
        columns,
        rows: vec![values],
        degraded: false,
    }
}

thread_local! {
    /// An empty relation used when an aggregate appears without `FROM`.
    static EMPTY_TABLE: FakeTable = const {
        FakeTable {
            name: String::new(),
            engine: String::new(),
            comment: String::new(),
            columns: Vec::new(),
            rows: Vec::new(),
        }
    };
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn skip_keyword(tokens: &[Token], cursor: &mut usize, keyword: &str) -> bool {
    if matches!(tokens.get(*cursor).and_then(Token::keyword).as_deref(), Some(found) if found == keyword)
    {
        *cursor += 1;
        return true;
    }
    false
}

fn skip_if_not_exists(tokens: &[Token], cursor: &mut usize) -> bool {
    let saved = *cursor;
    if skip_keyword(tokens, cursor, "IF")
        && skip_keyword(tokens, cursor, "NOT")
        && skip_keyword(tokens, cursor, "EXISTS")
    {
        return true;
    }
    *cursor = saved;
    false
}

fn token_name(token: Option<&Token>) -> Option<String> {
    match token? {
        Token::Word(name) | Token::Quoted(name) => Some(name.clone()),
        _ => None,
    }
}

fn find_top_level_keyword(tokens: &[Token], keyword: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            Token::Sym(Sym::LParen) => depth += 1,
            Token::Sym(Sym::RParen) => depth -= 1,
            Token::Word(word) if depth == 0 && word.eq_ignore_ascii_case(keyword) => {
                return Some(index);
            }
            _ => {}
        }
    }
    None
}

fn parse_table_ref(tokens: &[Token]) -> Option<(Option<String>, String, usize)> {
    let mut cursor = 0usize;
    let first = token_name(tokens.get(cursor))?;
    cursor += 1;
    let mut schema = None;
    let mut table = first;
    if matches!(tokens.get(cursor), Some(Token::Sym(Sym::Dot))) {
        cursor += 1;
        let second = token_name(tokens.get(cursor))?;
        cursor += 1;
        schema = Some(table);
        table = second;
    }
    // Skip the alias (`FROM users u`, `FROM users AS u`).
    let mut look = cursor;
    skip_keyword(tokens, &mut look, "AS");
    if token_name(tokens.get(look)).is_some()
        && !matches!(
            tokens.get(look).and_then(Token::keyword).as_deref(),
            Some("WHERE")
                | Some("ORDER")
                | Some("GROUP")
                | Some("LIMIT")
                | Some("HAVING")
                | Some("JOIN")
                | Some("INNER")
                | Some("LEFT")
                | Some("RIGHT")
                | Some("CROSS")
                | Some("STRAIGHT_JOIN")
                | Some("ON")
                | Some("USING")
                | Some("UNION")
                | Some("SET")
                | Some("VALUES")
                | Some("VALUE")
                | Some("PARTITION")
        )
        && !matches!(tokens.get(look), Some(Token::Sym(Sym::Comma)))
    {
        cursor = look + 1;
    }
    Some((schema, table, cursor))
}

fn parse_table_ref_str(text: &str) -> (Option<String>, String, &str) {
    let text = text.trim_start();
    let bytes = text.as_bytes();
    let mut index = 0usize;
    let mut in_backtick = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'`' {
            in_backtick = !in_backtick;
            index += 1;
            continue;
        }
        if !in_backtick
            && !(byte.is_ascii_alphanumeric()
                || byte == b'_'
                || byte == b'$'
                || byte == b'.'
                || byte >= 0x80)
        {
            break;
        }
        index += 1;
    }
    let reference = &text[..index];
    let remainder = &text[index..];
    let cleaned = reference.replace('`', "");
    if cleaned.is_empty() {
        return (None, String::new(), remainder.trim_start());
    }
    let (schema, table) = match cleaned.split_once('.') {
        Some((schema, table)) => (Some(schema.to_string()), table.to_string()),
        None => (None, cleaned),
    };
    (schema, table, remainder.trim_start())
}

fn unknown_table(schema: Option<&str>, table: &str, ctx: &QueryContext) -> QueryResult {
    let qualifier = schema
        .map(str::to_string)
        .or_else(|| Some(ctx.current_db.clone()))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "mysql".to_string());
    QueryResult::error(
        1146,
        "42S02",
        format!(
            "Table '{}.{}' doesn't exist",
            util::clip(&qualifier, 64),
            util::clip(table, 64)
        ),
    )
}

fn state_error_result(err: StateError) -> QueryResult {
    if matches!(err, StateError::Disabled) {
        return QueryResult::ok(0, 0, "");
    }
    QueryResult::error(err.code(), err.sqlstate(), err.message())
}

/// `ER_NOT_SUPPORTED_YET` for a clause the virtual engine cannot model.
///
/// A zero-column result set is never a legal answer to a DML statement: a driver
/// or ORM reads it as a result set with no columns and then mis-frames the rest
/// of the packet stream. Reporting the MySQL error is both honest and
/// protocol-safe.
fn unsupported_clause(feature: &str) -> QueryResult {
    QueryResult::error(
        1235,
        "42000",
        format!(
            "This version of MySQL doesn't yet support '{}'",
            util::clip(feature, 128)
        ),
    )
}

/// Sort `indices` the way `ORDER BY` prescribes.
///
/// The comparison is type aware: a numeric column sorts by value, a text column
/// by the advertised case-insensitive collation, and `NULL` sorts before every
/// other value. Keys are materialised once per row so the comparator itself does
/// no allocation and is a genuine total order — `slice::sort_by` is allowed to
/// panic on a comparator that is not.
fn sort_rows_by_order(
    database: &FakeDatabase,
    table: &FakeTable,
    indices: &mut Vec<usize>,
    order_by: &[(Expr, bool)],
    eval_ctx: &EvalContext,
    state: &SessionState,
) -> std::result::Result<(), QueryResult> {
    if order_by.is_empty() || indices.len() < 2 {
        return Ok(());
    }
    let numeric: Vec<bool> = order_by
        .iter()
        .map(|(expression, _)| eval::sort_is_numeric(expression, &table.columns))
        .collect();
    let mut keyed: Vec<(usize, Vec<eval::SortKey>)> = Vec::with_capacity(indices.len());
    for index in indices.iter().copied() {
        let Some(row) = table.rows.get(index) else {
            continue;
        };
        let context = RowContext {
            columns: &table.columns,
            row,
            session: eval_ctx,
            state,
            variables: &database.variables,
        };
        let mut keys = Vec::with_capacity(order_by.len());
        for (position, (expression, _)) in order_by.iter().enumerate() {
            match eval::evaluate(expression, &context) {
                Ok(value) => keys.push(eval::SortKey::new(&value, numeric[position])),
                Err(err) => {
                    return Err(QueryResult::error(
                        err.code(),
                        err.sqlstate(),
                        err.message("order clause"),
                    ));
                }
            }
        }
        keyed.push((index, keys));
    }
    keyed.sort_by(|left, right| {
        for (position, (_, ascending)) in order_by.iter().enumerate() {
            let (Some(a), Some(b)) = (left.1.get(position), right.1.get(position)) else {
                continue;
            };
            let ordering = a.cmp(b);
            if ordering != std::cmp::Ordering::Equal {
                return if *ascending {
                    ordering
                } else {
                    ordering.reverse()
                };
            }
        }
        std::cmp::Ordering::Equal
    });
    *indices = keyed.into_iter().map(|(index, _)| index).collect();
    Ok(())
}

/// Whether two group keys describe the same group.
fn group_keys_match(left: &[eval::SortKey], right: &[eval::SortKey]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(a, b)| a.cmp(b) == std::cmp::Ordering::Equal)
}

fn split_value_end(tokens: &[Token]) -> usize {
    let mut depth = 0i32;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            Token::Sym(Sym::LParen) => depth += 1,
            Token::Sym(Sym::RParen) => depth -= 1,
            Token::Sym(Sym::Comma) if depth == 0 => return index,
            _ => {}
        }
    }
    tokens.len()
}

fn literal_from_tokens(
    tokens: &[Token],
    ctx: &QueryContext,
    state: &SessionState,
    variables: &[(String, String)],
) -> Option<Option<String>> {
    if tokens.is_empty() {
        return None;
    }
    let mut budget = Budget::new(EXPRESSION_BUDGET);
    let expression = sql::parse_expression(tokens, &mut budget)?;
    let eval_ctx = ctx.eval_context();
    let context = RowContext {
        columns: &[],
        row: &[],
        session: &eval_ctx,
        state,
        variables,
    };
    match eval::evaluate(&expression, &context) {
        Ok(value) => Some(value.to_wire()),
        // An expression the virtual evaluator cannot fold becomes NULL, which is
        // what an unknown function argument would end up as anyway.
        Err(_) => Some(None),
    }
}

/// One row of an `INSERT`: the optional column list plus the values.
type InsertRow = (Option<Vec<String>>, Vec<Option<String>>);

#[allow(clippy::too_many_arguments)]
fn apply_insert(
    database: &FakeDatabase,
    state: &mut SessionState,
    ctx: &QueryContext,
    schema: Option<&str>,
    table_name: &str,
    rows: Vec<InsertRow>,
    replace: bool,
    ignore: bool,
) -> QueryResult {
    let Some(definition) = database.peek_table(state, schema, table_name, ctx) else {
        return unknown_table(schema, table_name, ctx);
    };
    // Map each value onto a full row of the target table.
    let mut prepared: Vec<Vec<Option<String>>> = Vec::new();
    let mut next_id = definition.next_auto_increment();
    let mut first_generated = 0u64;
    for (columns, values) in &rows {
        let mut row = vec![None; definition.columns.len()];
        match columns {
            Some(names) => {
                for (position, name) in names.iter().enumerate() {
                    let Some(index) = definition
                        .columns
                        .iter()
                        .position(|column| column.name.eq_ignore_ascii_case(name))
                    else {
                        if ignore {
                            continue;
                        }
                        return QueryResult::error(
                            1054,
                            "42S22",
                            format!("Unknown column '{}' in 'field list'", util::clip(name, 64)),
                        );
                    };
                    row[index] = values.get(position).cloned().flatten();
                }
            }
            None => {
                if values.len() > definition.columns.len() {
                    if ignore {
                        continue;
                    }
                    return QueryResult::error(
                        1136,
                        "21S01",
                        "Column count doesn't match value count at row 1",
                    );
                }
                for (position, value) in values.iter().enumerate() {
                    row[position] = value.clone();
                }
            }
        }
        // Fill an auto-increment key the client left out.
        if let Some(index) = definition.auto_increment_column()
            && row[index].is_none()
        {
            if first_generated == 0 {
                first_generated = next_id;
            }
            row[index] = Some(next_id.to_string());
            next_id = next_id.saturating_add(1);
        }
        prepared.push(row);
    }

    // Materialise the session's copy of the table first: the state layer only
    // mutates tables the overlay owns.
    let owned = match database.materialise(state, schema, table_name, ctx) {
        Ok(owned) => owned,
        Err(result) => return result,
    };
    let Some((schema_name, canonical)) = owned else {
        // Simulation is off: acknowledge the statement without keeping anything.
        let inserted = prepared.len() as u64;
        return QueryResult::ok(inserted, 0, "");
    };
    let auto_index = definition.auto_increment_column();
    // The key each row will be stored under, used for `LAST_INSERT_ID()`.
    let keys: Vec<Option<u64>> = prepared
        .iter()
        .map(|row| auto_key(row, auto_index))
        .collect();
    let reported_id = if first_generated > 0 {
        first_generated
    } else {
        keys.iter().rev().find_map(|key| *key).unwrap_or(0)
    };

    // `REPLACE` reports the rows it deleted plus the rows it inserted, which is
    // what MySQL does; a plain `INSERT` reports what it stored.
    let (affected, info) = if replace {
        // `REPLACE` deletes the conflicting rows and inserts the batch as one
        // unit: a refused batch must not leave the old rows deleted.
        match state.replace_rows(&schema_name, &canonical, auto_index, prepared) {
            Ok(outcome) => (
                (outcome.removed + outcome.inserted) as u64,
                format!(
                    "Records: {}  Duplicates: {}  Warnings: 0",
                    outcome.inserted, outcome.removed
                ),
            ),
            Err(err) => return state_error_result(err),
        }
    } else if ignore {
        // `INSERT IGNORE` is partial *by definition*: the offending rows are
        // skipped and the rest are stored, which is exactly what a per-row
        // commit produces. The reported count matches what was really stored.
        let mut stored = 0u64;
        for row in prepared {
            match state.insert_rows(&schema_name, &canonical, vec![row]) {
                Ok(_) => stored += 1,
                Err(_) => continue,
            }
        }
        (stored, record_info(stored))
    } else {
        // A plain multi-row `INSERT` is atomic: every row is validated before
        // the first one is stored, so the client never sees a partial write
        // together with an error.
        match state.insert_rows(&schema_name, &canonical, prepared) {
            Ok(count) => (count as u64, record_info(count as u64)),
            Err(err) => return state_error_result(err),
        }
    };
    state.set_row_count(affected as i64);
    state.set_last_insert_id(reported_id);
    QueryResult::ok(affected, reported_id, &info)
}

/// The `info` string MySQL sends for an `INSERT`.
fn record_info(rows: u64) -> String {
    format!("({rows} row{})", if rows == 1 { "" } else { "s" })
}

/// The auto-increment value a prepared row will be stored under.
fn auto_key(row: &[Option<String>], index: Option<usize>) -> Option<u64> {
    let index = index?;
    row.get(index)
        .and_then(|cell| cell.as_deref())
        .and_then(|text| text.trim().parse::<u64>().ok())
}

/// Replace control characters so a hostile statement cannot forge log lines.
pub fn sanitise(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() {
                '.'
            } else {
                character
            }
        })
        .collect()
}

fn strip_leading_comments(sql: &str) -> &str {
    let mut rest = sql;
    loop {
        let trimmed = rest.trim_start();
        if let Some(tail) = trimmed.strip_prefix("--") {
            match tail.find('\n') {
                Some(index) => rest = &tail[index + 1..],
                None => return "",
            }
        } else if let Some(tail) = trimmed.strip_prefix('#') {
            match tail.find('\n') {
                Some(index) => rest = &tail[index + 1..],
                None => return "",
            }
        } else if let Some(tail) = trimmed.strip_prefix("/*") {
            match tail.find("*/") {
                Some(index) => rest = &tail[index + 2..],
                None => return "",
            }
        } else {
            return trimmed;
        }
    }
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$' || byte >= 0x80
}

/// First word of a statement plus the byte offset just past it.
fn first_keyword(sql: &str) -> (String, usize) {
    let bytes = sql.as_bytes();
    let mut index = 0;
    while index < bytes.len() && !is_ident_byte(bytes[index]) {
        index += 1;
    }
    let start = index;
    while index < bytes.len() && is_ident_byte(bytes[index]) {
        index += 1;
    }
    (sql[start..index].to_ascii_uppercase(), index)
}

fn unquote_ident(text: &str) -> String {
    let text = text.trim();
    let text = text
        .split_whitespace()
        .next()
        .unwrap_or(text)
        .trim_end_matches(';');
    let stripped = text.trim_matches(|c| c == '`' || c == '"' || c == '\'');
    stripped
        .rsplit('.')
        .next()
        .unwrap_or(stripped)
        .trim_matches(|c| c == '`' || c == '"')
        .to_string()
}

fn parse_like(remainder: &str) -> Option<String> {
    let upper = remainder.to_ascii_uppercase();
    let index = upper.find("LIKE")?;
    let tail = remainder[index + 4..].trim_start();
    let quote = tail.as_bytes().first().copied()?;
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    let end = tail[1..].find(quote as char)?;
    Some(tail[1..1 + end].to_string())
}

fn parse_show_scope(tail: &str) -> (Option<String>, Option<String>) {
    let mut rest = tail.trim();
    let mut schema = None;
    for prefix in ["FROM ", "from ", "IN ", "in "] {
        if let Some(after) = rest.strip_prefix(prefix) {
            let (reference_schema, reference, remaining) = parse_table_ref_str(after);
            schema = reference_schema.or(Some(reference));
            rest = remaining;
            break;
        }
    }
    (schema, parse_like(rest))
}

fn pattern_matches(pattern: Option<&str>, candidate: &str) -> bool {
    match pattern {
        None => true,
        Some(pattern) => eval::like_match(pattern, candidate),
    }
}

fn text_column(name: &str, schema: &str, table: &str) -> ResultColumn {
    ResultColumn {
        name: name.to_string(),
        org_name: name.to_string(),
        table: table.to_string(),
        schema: schema.to_string(),
        wire_type: column_type::VAR_STRING,
    }
}

fn numeric_column(name: &str, schema: &str, table: &str) -> ResultColumn {
    ResultColumn {
        name: name.to_string(),
        org_name: name.to_string(),
        table: table.to_string(),
        schema: schema.to_string(),
        wire_type: column_type::LONGLONG,
    }
}

fn wire_type_for(data_type: &str) -> u8 {
    match data_type.split('(').next().unwrap_or(data_type) {
        "int" | "integer" | "mediumint" | "smallint" | "tinyint" | "bigint" | "bit" => {
            column_type::LONGLONG
        }
        "decimal" | "numeric" | "double" | "float" | "real" => column_type::DOUBLE,
        "date" => column_type::DATE,
        "datetime" | "timestamp" => column_type::DATETIME,
        "text" | "longtext" | "mediumtext" | "tinytext" | "blob" => column_type::BLOB,
        _ => column_type::VAR_STRING,
    }
}

/// Schema named by a `USE <name>` statement, if that is what the text is.
pub fn use_target(sql: &str) -> Option<String> {
    let clean = strip_leading_comments(sql.trim()).trim();
    let (keyword, keyword_end) = first_keyword(clean);
    if keyword != "USE" {
        return None;
    }
    let name = unquote_ident(clean[keyword_end..].trim());
    if name.is_empty() { None } else { Some(name) }
}

/// Classify a statement for logging.
pub fn classify(sql: &str) -> &'static str {
    let clean = strip_leading_comments(sql.trim()).trim();
    if clean.is_empty() {
        return "EMPTY";
    }
    let (keyword, _) = first_keyword(clean);
    match keyword.as_str() {
        "SELECT" => "SELECT",
        "INSERT" => "INSERT",
        "REPLACE" => "REPLACE",
        "UPDATE" => "UPDATE",
        "DELETE" => "DELETE",
        "DROP" => "DROP",
        "CREATE" => "CREATE",
        "ALTER" => "ALTER",
        "TRUNCATE" => "TRUNCATE",
        "RENAME" => "RENAME",
        "SHOW" => "SHOW",
        "USE" => "USE",
        "SET" => "SET",
        "DESCRIBE" | "DESC" => "DESCRIBE",
        "EXPLAIN" => "EXPLAIN",
        "GRANT" => "GRANT",
        "REVOKE" => "REVOKE",
        "CALL" => "CALL",
        "LOAD" => "LOAD",
        "PREPARE" => "PREPARE",
        "EXECUTE" => "EXECUTE",
        "DEALLOCATE" => "DEALLOCATE",
        "BEGIN" | "START" => "BEGIN",
        "COMMIT" => "COMMIT",
        "ROLLBACK" => "ROLLBACK",
        "SAVEPOINT" | "RELEASE" => "SAVEPOINT",
        "FLUSH" => "FLUSH",
        "KILL" => "KILL",
        "ANALYZE" => "ANALYZE",
        "OPTIMIZE" => "OPTIMIZE",
        "CHECK" => "CHECK",
        "REPAIR" => "REPAIR",
        "LOCK" => "LOCK",
        "UNLOCK" => "UNLOCK",
        "HANDLER" => "HANDLER",
        "DO" => "DO",
        "" => "EMPTY",
        _ => "OTHER",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> QueryContext {
        QueryContext::new(
            "app_prod".to_string(),
            "root".to_string(),
            "203.0.113.9".to_string(),
            42,
            "8.0.36".to_string(),
        )
    }

    fn database() -> FakeDatabase {
        FakeDatabase::new("8.0.36")
    }

    fn run(sql: &str) -> QueryResult {
        database().dispatch(sql, &ctx(), &mut SessionState::default())
    }

    fn rows_of(sql: &str) -> Vec<Vec<Option<String>>> {
        match run(sql) {
            QueryResult::ResultSet(set) => set.rows,
            other => panic!("{sql} -> {other:?}"),
        }
    }

    fn single_value(sql: &str) -> Option<String> {
        let rows = rows_of(sql);
        assert_eq!(rows.len(), 1, "{sql} must return exactly one row");
        rows[0].first().cloned().flatten()
    }

    #[test]
    fn catalog_contains_the_documented_schemas() {
        let database = database();
        let state = SessionState::default();
        let names = database.schema_names(&state);
        for expected in [
            "information_schema",
            "mysql",
            "performance_schema",
            "sys",
            "app_prod",
            "backup",
        ] {
            assert!(names.contains(&expected), "missing schema {expected}");
        }
        assert!(database.has_schema("APP_PROD", &state));
        assert!(!database.has_schema("nope", &state));
    }

    #[test]
    fn show_databases_lists_every_schema() {
        match run("SHOW DATABASES") {
            QueryResult::ResultSet(set) => {
                assert_eq!(set.columns.len(), 1);
                assert_eq!(set.columns[0].name, "Database");
                assert_eq!(set.rows.len(), 6);
                let flat: Vec<String> =
                    set.rows.iter().map(|row| row[0].clone().unwrap()).collect();
                assert!(flat.contains(&"app_prod".to_string()));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn select_one_returns_single_row() {
        assert_eq!(single_value("SELECT 1"), Some("1".to_string()));
        assert_eq!(single_value("SELECT 1;"), Some("1".to_string()));
    }

    #[test]
    fn scalar_functions_answer_consistently() {
        assert_eq!(single_value("SELECT VERSION()").as_deref(), Some("8.0.36"));
        assert_eq!(single_value("SELECT @@version").as_deref(), Some("8.0.36"));
        assert_eq!(
            single_value("SELECT @@global.version_comment").as_deref(),
            Some("MySQL Community Server - GPL")
        );
        assert_eq!(
            single_value("SELECT DATABASE()").as_deref(),
            Some("app_prod")
        );
        assert_eq!(
            single_value("SELECT USER()").as_deref(),
            Some("root@203.0.113.9")
        );
        assert_eq!(
            single_value("SELECT CURRENT_USER()").as_deref(),
            Some("root@%")
        );
        assert_eq!(
            single_value("SELECT CONNECTION_ID()").as_deref(),
            Some("42")
        );
    }

    #[test]
    fn identity_follows_the_login_not_a_constant() {
        let database = database();
        let mut context = ctx();
        context.username = "attacker".to_string();
        match database.dispatch(
            "SELECT CURRENT_USER(), USER()",
            &context,
            &mut SessionState::default(),
        ) {
            QueryResult::ResultSet(set) => {
                assert_eq!(set.rows[0][0].as_deref(), Some("attacker@%"));
                assert_eq!(set.rows[0][1].as_deref(), Some("attacker@203.0.113.9"));
            }
            other => panic!("unexpected {other:?}"),
        }
        match database.dispatch("SHOW GRANTS", &context, &mut SessionState::default()) {
            QueryResult::ResultSet(set) => {
                assert_eq!(set.columns[0].name, "Grants for attacker@%");
                assert!(
                    set.rows[0][0]
                        .as_deref()
                        .unwrap()
                        .contains("`attacker`@`%`")
                );
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn count_star_returns_exactly_one_row() {
        assert_eq!(
            single_value("SELECT COUNT(*) FROM users"),
            Some("3".to_string())
        );
        assert_eq!(
            single_value("SELECT COUNT(*) FROM users WHERE role = 'user'"),
            Some("2".to_string())
        );
        assert_eq!(
            single_value("SELECT COUNT(*) AS total FROM users"),
            Some("3".to_string())
        );
        // The alias must reach the column header.
        match run("SELECT COUNT(*) AS total FROM users") {
            QueryResult::ResultSet(set) => assert_eq!(set.columns[0].name, "total"),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            single_value("SELECT COUNT(*) FROM users WHERE username = 'nobody'"),
            Some("0".to_string())
        );
    }

    #[test]
    fn count_of_an_empty_table_is_zero_not_no_rows() {
        let database = database();
        let mut state = SessionState::default();
        let mut context = ctx();
        context.current_db = "app_prod".to_string();
        assert!(matches!(
            database.dispatch("DELETE FROM users", &context, &mut state),
            QueryResult::Ok {
                affected_rows: 3,
                ..
            }
        ));
        match database.dispatch("SELECT COUNT(*) FROM users", &context, &mut state) {
            QueryResult::ResultSet(set) => {
                assert_eq!(set.rows.len(), 1, "an aggregate always yields one row");
                assert_eq!(set.rows[0][0].as_deref(), Some("0"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn count_variants_follow_mysql_semantics() {
        assert_eq!(
            single_value("SELECT COUNT(role) FROM users"),
            Some("3".to_string())
        );
        assert_eq!(
            single_value("SELECT COUNT(DISTINCT role) FROM users"),
            Some("2".to_string())
        );
        assert_eq!(
            single_value("SELECT COUNT(*) FROM users WHERE role = 'nope'"),
            Some("0".to_string())
        );
    }

    #[test]
    fn aggregates_are_not_truncated_by_the_row_cap() {
        let database = database();
        let mut state = SessionState::default();
        let mut context = ctx();
        // Insert more rows than MAX_RESULT_ROWS.
        for index in 0..(MAX_RESULT_ROWS + 50) {
            let sql = format!("INSERT INTO users (username, role) VALUES ('u{index}', 'bulk')");
            assert!(matches!(
                database.dispatch(&sql, &context, &mut state),
                QueryResult::Ok { .. }
            ));
        }
        context.current_db = "app_prod".to_string();
        match database.dispatch("SELECT COUNT(*) FROM users", &context, &mut state) {
            QueryResult::ResultSet(set) => {
                assert_eq!(set.rows.len(), 1);
                assert_eq!(
                    set.rows[0][0].as_deref(),
                    Some((3 + MAX_RESULT_ROWS + 50).to_string().as_str()),
                    "the count must cover every row, not the capped page"
                );
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn count_without_from_returns_one() {
        assert_eq!(single_value("SELECT COUNT(*)"), Some("1".to_string()));
    }

    #[test]
    fn where_filters_on_the_named_column_only() {
        // `admin` lives in `username`, so filtering on `email` must not match it.
        assert_eq!(
            rows_of("SELECT * FROM users WHERE email = 'admin'").len(),
            0
        );
        assert_eq!(
            rows_of("SELECT * FROM users WHERE username = 'admin'").len(),
            1
        );
        // A username that does not exist yields nothing at all.
        assert_eq!(
            rows_of("SELECT * FROM users WHERE username = 'no-such-user'").len(),
            0
        );
    }

    #[test]
    fn where_supports_the_common_grammar() {
        assert_eq!(rows_of("SELECT * FROM users WHERE id = 1").len(), 1);
        assert_eq!(rows_of("SELECT * FROM users WHERE id <> 1").len(), 2);
        assert_eq!(rows_of("SELECT * FROM users WHERE id >= 2").len(), 2);
        assert_eq!(
            rows_of("SELECT * FROM users WHERE id > 1 AND id < 3").len(),
            1
        );
        assert_eq!(
            rows_of("SELECT * FROM users WHERE id = 1 OR id = 2").len(),
            2
        );
        assert_eq!(rows_of("SELECT * FROM users WHERE NOT id = 1").len(), 2);
        assert_eq!(
            rows_of("SELECT * FROM users WHERE role IN ('administrator')").len(),
            1
        );
        assert_eq!(
            rows_of("SELECT * FROM users WHERE username LIKE 'a%'").len(),
            2
        );
        assert_eq!(
            rows_of("SELECT * FROM users WHERE created_at IS NOT NULL").len(),
            3
        );
        assert_eq!(rows_of("SELECT * FROM users WHERE email IS NULL").len(), 0);
        assert_eq!(
            rows_of("SELECT * FROM users WHERE (id = 1 OR id = 3) AND role = 'user'").len(),
            1
        );
    }

    #[test]
    fn unsupported_where_degrades_to_no_rows() {
        for sql in [
            "SELECT * FROM users WHERE id BETWEEN 1 AND 2",
            "SELECT * FROM users WHERE id = (SELECT 1)",
            "SELECT * FROM users WHERE id XOR id",
        ] {
            match run(sql) {
                QueryResult::ResultSet(set) => {
                    assert!(set.rows.is_empty(), "{sql} must not return rows");
                    assert!(set.degraded, "{sql} must be reported as degraded");
                }
                other => panic!("{sql} -> {other:?}"),
            }
        }
    }

    #[test]
    fn unknown_columns_raise_the_mysql_error() {
        match run("SELECT * FROM users WHERE nope = 'x'") {
            QueryResult::Error { code, message, .. } => {
                assert_eq!(code, 1054);
                assert!(message.contains("nope"), "got {message}");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn pagination_offsets_agree_between_the_two_spellings() {
        let first = rows_of("SELECT id FROM users ORDER BY id ASC LIMIT 1, 2");
        let second = rows_of("SELECT id FROM users ORDER BY id ASC LIMIT 2 OFFSET 1");
        assert_eq!(first, second);
        assert_eq!(first.len(), 2);
        assert_eq!(first[0][0].as_deref(), Some("2"));
        assert_eq!(first[1][0].as_deref(), Some("3"));
    }

    #[test]
    fn order_by_and_limit_compose() {
        let rows = rows_of("SELECT id FROM users ORDER BY id DESC LIMIT 2");
        assert_eq!(rows[0][0].as_deref(), Some("3"));
        assert_eq!(rows[1][0].as_deref(), Some("2"));
        let rows = rows_of("SELECT id FROM users ORDER BY id ASC");
        assert_eq!(rows[0][0].as_deref(), Some("1"));
    }

    #[test]
    fn limit_overflow_is_saturating() {
        for sql in [
            "SELECT * FROM users LIMIT 18446744073709551616",
            "SELECT * FROM users LIMIT 99999999999999999999999999",
            "SELECT * FROM users LIMIT 1e400",
        ] {
            let rows = rows_of(sql);
            assert_eq!(rows.len(), 3, "{sql} must not lose rows");
        }
        assert!(rows_of("SELECT * FROM users LIMIT 0").is_empty());
    }

    #[test]
    fn result_sets_are_capped() {
        let rows = rows_of("SELECT * FROM information_schema.columns LIMIT 100000");
        assert!(rows.len() <= MAX_RESULT_ROWS);
    }

    #[test]
    fn projection_width_is_bounded() {
        let items = (0..(MAX_RESULT_COLUMNS + 5))
            .map(|index| index.to_string())
            .collect::<Vec<_>>()
            .join(",");
        match run(&format!("SELECT {items}")) {
            QueryResult::Error { code, .. } => assert_eq!(code, 1117),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn information_schema_is_queryable() {
        match run(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'app_prod'",
        ) {
            QueryResult::ResultSet(set) => {
                assert_eq!(set.columns[0].name, "TABLE_NAME");
                let names: Vec<String> = set
                    .rows
                    .iter()
                    .map(|row| row[0].clone().unwrap_or_default())
                    .collect();
                assert!(names.contains(&"users".to_string()), "got {names:?}");
                assert!(!names.contains(&"SCHEMATA".to_string()));
            }
            other => panic!("unexpected {other:?}"),
        }
        let total = single_value("SELECT COUNT(*) FROM information_schema.columns").expect("count");
        assert!(total.parse::<usize>().expect("number") > 10, "got {total}");
    }

    #[test]
    fn show_tables_and_columns() {
        match run("SHOW TABLES") {
            QueryResult::ResultSet(set) => {
                assert_eq!(set.columns[0].name, "Tables_in_app_prod");
                assert_eq!(set.rows.len(), 4);
            }
            other => panic!("unexpected {other:?}"),
        }
        match run("SHOW TABLES FROM mysql LIKE 'u%'") {
            QueryResult::ResultSet(set) => {
                assert_eq!(set.columns[0].name, "Tables_in_mysql");
                assert_eq!(set.rows.len(), 1);
                assert_eq!(set.rows[0][0].as_deref(), Some("user"));
            }
            other => panic!("unexpected {other:?}"),
        }
        match run("SHOW COLUMNS FROM users") {
            QueryResult::ResultSet(set) => {
                let names: Vec<String> = set.columns.iter().map(|c| c.name.clone()).collect();
                assert_eq!(names, ["Field", "Type", "Null", "Key", "Default", "Extra"]);
                assert_eq!(set.rows.len(), 6);
            }
            other => panic!("unexpected {other:?}"),
        }
        match run("DESCRIBE orders") {
            QueryResult::ResultSet(set) => assert_eq!(set.rows.len(), 5),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn use_statement_resolves_schemas() {
        assert!(matches!(run("USE mysql"), QueryResult::Ok { .. }));
        match run("USE does_not_exist") {
            QueryResult::Error { code, .. } => assert_eq!(code, 1049),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn inserts_are_visible_to_the_same_session_only() {
        let database = database();
        let mut attacker = SessionState::default();
        let victim = SessionState::default();
        assert!(matches!(
            database.dispatch(
                "INSERT INTO users (id, username, role) VALUES (99, 'mallory', 'user')",
                &ctx(),
                &mut attacker
            ),
            QueryResult::Ok {
                affected_rows: 1,
                ..
            }
        ));
        match database.dispatch(
            "SELECT username FROM users WHERE id = 99",
            &ctx(),
            &mut attacker,
        ) {
            QueryResult::ResultSet(set) => {
                assert_eq!(set.rows.len(), 1);
                assert_eq!(set.rows[0][0].as_deref(), Some("mallory"));
            }
            other => panic!("unexpected {other:?}"),
        }
        // A different session never sees it.
        let mut other = SessionState::default();
        match database.dispatch(
            "SELECT username FROM users WHERE id = 99",
            &ctx(),
            &mut other,
        ) {
            QueryResult::ResultSet(set) => assert!(set.rows.is_empty()),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(victim.rows(), 0);
    }

    #[test]
    fn update_and_delete_change_the_session_view() {
        let database = database();
        let mut state = SessionState::default();
        assert!(matches!(
            database.dispatch(
                "UPDATE users SET role = 'admin' WHERE id = 2",
                &ctx(),
                &mut state
            ),
            QueryResult::Ok {
                affected_rows: 1,
                ..
            }
        ));
        // The modified value must be readable back in the same session.
        assert_eq!(
            single_value_with(&database, &mut state, "SELECT role FROM users WHERE id = 2"),
            Some("admin".to_string())
        );
        // A statement that matches nothing changes nothing.
        assert!(matches!(
            database.dispatch(
                "UPDATE users SET role = 'nobody' WHERE id = 999",
                &ctx(),
                &mut state
            ),
            QueryResult::Ok {
                affected_rows: 0,
                ..
            }
        ));
        // An assignment that references the old value reads the original row.
        assert!(matches!(
            database.dispatch(
                "UPDATE products SET stock = stock - 1 WHERE id = 11",
                &ctx(),
                &mut state
            ),
            QueryResult::Ok {
                affected_rows: 1,
                ..
            }
        ));
        assert_eq!(
            single_value_with(
                &database,
                &mut state,
                "SELECT stock FROM products WHERE id = 11"
            ),
            Some("998".to_string())
        );

        assert!(matches!(
            database.dispatch("DELETE FROM users WHERE id = 1", &ctx(), &mut state),
            QueryResult::Ok {
                affected_rows: 1,
                ..
            }
        ));
        match database.dispatch("SELECT id FROM users ORDER BY id", &ctx(), &mut state) {
            QueryResult::ResultSet(set) => {
                let ids: Vec<String> = set
                    .rows
                    .iter()
                    .map(|row| row[0].clone().unwrap_or_default())
                    .collect();
                assert_eq!(ids, ["2", "3"]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn create_and_drop_table_are_visible_in_show_tables() {
        let database = database();
        let mut state = SessionState::default();
        assert!(matches!(
            database.dispatch(
                "CREATE TABLE evil (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, note varchar(64))",
                &ctx(),
                &mut state
            ),
            QueryResult::Ok { .. }
        ));
        match database.dispatch("SHOW TABLES", &ctx(), &mut state) {
            QueryResult::ResultSet(set) => {
                let names: Vec<String> = set
                    .rows
                    .iter()
                    .map(|row| row[0].clone().unwrap_or_default())
                    .collect();
                assert!(names.contains(&"evil".to_string()), "got {names:?}");
            }
            other => panic!("unexpected {other:?}"),
        }
        // information_schema agrees with SHOW TABLES.
        match database.dispatch(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'app_prod'",
            &ctx(),
            &mut state,
        ) {
            QueryResult::ResultSet(set) => {
                let names: Vec<String> = set
                    .rows
                    .iter()
                    .map(|row| row[0].clone().unwrap_or_default())
                    .collect();
                assert!(names.contains(&"evil".to_string()), "got {names:?}");
            }
            other => panic!("unexpected {other:?}"),
        }
        // Rows can be inserted and read back.
        assert!(matches!(
            database.dispatch("INSERT INTO evil (note) VALUES ('x')", &ctx(), &mut state),
            QueryResult::Ok {
                affected_rows: 1,
                last_insert_id: 1,
                ..
            }
        ));
        assert_eq!(
            single_value_with(&database, &mut state, "SELECT COUNT(*) FROM evil"),
            Some("1".to_string())
        );
        assert!(matches!(
            database.dispatch("DROP TABLE evil", &ctx(), &mut state),
            QueryResult::Ok {
                affected_rows: 1,
                ..
            }
        ));
        match database.dispatch("SHOW TABLES", &ctx(), &mut state) {
            QueryResult::ResultSet(set) => {
                let names: Vec<String> = set
                    .rows
                    .iter()
                    .map(|row| row[0].clone().unwrap_or_default())
                    .collect();
                assert!(!names.contains(&"evil".to_string()));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    fn single_value_with(
        database: &FakeDatabase,
        state: &mut SessionState,
        sql: &str,
    ) -> Option<String> {
        match database.dispatch(sql, &ctx(), state) {
            QueryResult::ResultSet(set) => {
                assert_eq!(set.rows.len(), 1, "{sql}");
                set.rows[0].first().cloned().flatten()
            }
            other => panic!("{sql} -> {other:?}"),
        }
    }

    #[test]
    fn dropping_a_base_table_only_affects_that_session() {
        let database = database();
        let mut state = SessionState::default();
        assert!(matches!(
            database.dispatch("DROP TABLE users", &ctx(), &mut state),
            QueryResult::Ok { .. }
        ));
        assert!(matches!(
            database.dispatch("SELECT * FROM users", &ctx(), &mut state),
            QueryResult::Error { code: 1146, .. }
        ));
        match database.dispatch("SELECT * FROM users", &ctx(), &mut SessionState::default()) {
            QueryResult::ResultSet(set) => assert_eq!(set.rows.len(), 3),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn delete_from_an_unknown_table_errors() {
        match run("DELETE FROM nope") {
            QueryResult::Error { code, .. } => assert_eq!(code, 1146),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn load_data_is_refused() {
        match run("LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE users") {
            QueryResult::Error { code, .. } => assert_eq!(code, 1148),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn garbage_returns_a_parse_error() {
        match run("!!! not sql") {
            QueryResult::Error { code, .. } => assert_eq!(code, 1064),
            other => panic!("unexpected {other:?}"),
        }
        match run("   ") {
            QueryResult::Error { code, .. } => assert_eq!(code, 1065),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn explain_and_show_create() {
        match run("EXPLAIN SELECT * FROM users") {
            QueryResult::ResultSet(set) => assert_eq!(set.rows.len(), 1),
            other => panic!("unexpected {other:?}"),
        }
        match run("SHOW CREATE TABLE users") {
            QueryResult::ResultSet(set) => {
                let ddl = set.rows[0][1].clone().unwrap();
                assert!(ddl.contains("CREATE TABLE `users`"), "got {ddl}");
                assert!(ddl.contains("PRIMARY KEY (`id`)"), "got {ddl}");
            }
            other => panic!("unexpected {other:?}"),
        }
        // A table whose primary key is not called `id` must not claim one.
        match run("SHOW CREATE TABLE mysql.user") {
            QueryResult::ResultSet(set) => {
                let ddl = set.rows[0][1].clone().unwrap();
                assert!(!ddl.contains("PRIMARY KEY"), "got {ddl}");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn set_stores_user_variables() {
        let database = database();
        let mut state = SessionState::default();
        assert!(matches!(
            database.dispatch("SET @a = 7", &ctx(), &mut state),
            QueryResult::Ok { .. }
        ));
        assert_eq!(state.user_variable("a"), Some("7"));
        assert!(matches!(
            database.dispatch("SET NAMES utf8mb4", &ctx(), &mut state),
            QueryResult::Ok { .. }
        ));
    }

    #[test]
    fn comments_are_ignored_for_classification() {
        assert_eq!(classify("/* hi */ SELECT 1"), "SELECT");
        assert_eq!(classify("-- hi\nDELETE FROM users"), "DELETE");
        assert_eq!(classify("# hi\nDROP TABLE x"), "DROP");
        assert_eq!(classify(""), "EMPTY");
        assert_eq!(classify("show databases"), "SHOW");
        assert_eq!(classify("wibble"), "OTHER");
        assert_eq!(classify("START TRANSACTION"), "BEGIN");
    }

    #[test]
    fn statement_routing_never_panics_on_hostile_input() {
        let database = database();
        let context = ctx();
        let mut state = SessionState::default();
        let hostile = [
            "SELECT * FROM",
            "SELECT (((((",
            "SELECT 'unterminated",
            "SELECT `unterminated",
            "SHOW",
            "USE",
            "SELECT @@",
            "SELECT @@@@version",
            "SELECT * FROM `` ``",
            "SELECT 1 FROM a.b.c.d",
            "  \u{0000} ",
            "SELECT ??????????",
            "SHOW COLUMNS FROM",
            "DESC",
            "SELECT * FROM information_schema.tables WHERE table_schema = ",
            "SELECT * FROM users WHERE",
            "SELECT * FROM users ORDER BY",
            "SELECT * FROM users LIMIT",
            "INSERT INTO",
            "INSERT INTO users VALUES",
            "UPDATE users SET",
            "DELETE FROM",
            "CREATE TABLE",
            "DROP TABLE",
            "SELECT COUNT(*) FROM users WHERE username IN ()",
            "SELECT * FROM users WHERE username LIKE '%%%%'",
            "SELECT * FROM (SELECT 1) x",
        ];
        for sql in hostile {
            let _ = database.dispatch(sql, &context, &mut state);
        }
    }

    #[test]
    fn hostile_expressions_never_trap_the_evaluator() {
        // The release profile is `panic = "abort"`, so any of these reaching a
        // panic would end the process for every connection at once. Each entry is
        // a shape that has historically trapped a hand-written evaluator:
        // saturating casts, byte slicing and arithmetic overflow.
        let database = database();
        let context = ctx();
        let mut state = SessionState::default();
        let hostile = [
            "SELECT SUBSTRING('abcdef', 1, 1e300)",
            "SELECT SUBSTRING('abcdef', -1e300, 1e300)",
            "SELECT SUBSTRING('äöü', 2, 1e300)",
            "SELECT LEFT('abc', 1e300)",
            "SELECT RIGHT('abc', 1e300)",
            "SELECT ROUND(1e308, -30)",
            "SELECT ROUND(-1e308, -30)",
            "SELECT ROUND(1e308, 30)",
            "SELECT REPEAT('x', 1e18)",
            "SELECT REPEAT('', 0)",
            "SELECT POW(1e308, 1e308)",
            "SELECT MOD(1, 0)",
            "SELECT 1/0",
            "SELECT 9223372036854775807 * 9223372036854775807",
            "SELECT -9223372036854775808 / -1",
            "SELECT CONCAT('a', REPEAT('b', 1024), REPEAT('c', 1024))",
            "SELECT HEX(REPEAT('x', 1024))",
            "SELECT UNHEX('zz')",
            "SELECT CAST(1e309 AS SIGNED)",
            "SELECT CURDATE(), CURTIME(), NOW()",
            "SELECT * FROM app_prod.users ORDER BY SUBSTRING(username, 1, 1e300)",
            "SELECT * FROM app_prod.users ORDER BY ROUND(id, -1e9)",
            "SELECT * FROM app_prod.users WHERE SUBSTRING(username, 1, 1e300) = 'a'",
            "SELECT * FROM app_prod.users WHERE username LIKE '%%a%%a%%a%%a%%b'",
            "SELECT MIN(username), MAX(username), SUM(id), AVG(id) FROM app_prod.users",
            "SELECT * FROM app_prod.users GROUP BY SUBSTRING(username, 1, 1e300)",
            "SELECT * FROM app_prod.users LIMIT 18446744073709551615 OFFSET 18446744073709551615",
            "SELECT * FROM app_prod.users LIMIT 0.5",
            "SELECT `\u{1F600}`, '\u{1F600}'",
            "SELECT * FROM app_prod.users WHERE username = '\u{1F600}'",
            "SELECT '\u{0000}\u{0001}\u{001b}[31m'",
        ];
        for sql in hostile {
            // Any answer is acceptable; not returning is not.
            let _ = database.dispatch(sql, &context, &mut state);
        }
        // The session is still coherent after all of that.
        let (rows, bytes) = state.recount();
        assert_eq!(state.rows(), rows);
        assert_eq!(state.bytes(), bytes);
    }

    #[test]
    fn hostile_ddl_never_grows_the_session_without_bound() {
        let database = database();
        let context = ctx();
        let mut state = SessionState::default();
        // A thousand unusable DDL statements, then a check that the overlay is
        // still empty and the error paths did not leak bookkeeping.
        for round in 0..1_000u32 {
            let statements: Vec<String> = vec![
                "CREATE TABLE app_prod.users (id bigint)".to_string(),
                format!("DROP TABLE app_prod.nope{round}"),
                format!("CREATE TABLE app_prod.x{round} (id bigint, id bigint)"),
                format!("DROP DATABASE app_prod{round}"),
                "CREATE TABLE app_prod (id bigint)".to_string(),
                "DROP TABLE app_prod.users, app_prod.users, app_prod.users".to_string(),
            ];
            for sql in statements {
                let _ = database.dispatch(&sql, &context, &mut state);
            }
        }
        let (rows, bytes) = state.recount();
        assert_eq!(state.rows(), rows);
        assert_eq!(state.bytes(), bytes);
        assert!(
            state.tombstones() <= 64,
            "tombstones are unbounded: {}",
            state.tombstones()
        );
    }

    #[test]
    fn deeply_nested_where_does_not_blow_the_stack() {
        let deep = format!(
            "SELECT * FROM users WHERE {}id = 1{}",
            "(".repeat(5_000),
            ")".repeat(5_000)
        );
        let database = database();
        let mut state = SessionState::default();
        // Must terminate quickly and answer conservatively.
        let started = std::time::Instant::now();
        match database.dispatch(&deep, &ctx(), &mut state) {
            QueryResult::ResultSet(set) => assert!(set.rows.is_empty() || set.degraded),
            QueryResult::Error { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "deep nesting took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn response_kind_is_descriptive() {
        assert!(QueryResult::ok(1, 0, "").kind().starts_with("OK"));
        assert!(
            QueryResult::error(1064, "42000", "x")
                .kind()
                .starts_with("ERR")
        );
        let set = QueryResult::ResultSet(ResultSet {
            columns: vec![text_column("a", "", "")],
            rows: vec![vec![Some("1".to_string())]],
            degraded: false,
        });
        assert_eq!(set.kind(), "RESULTSET(cols=1,rows=1)");
        let degraded = QueryResult::ResultSet(ResultSet {
            columns: Vec::new(),
            rows: Vec::new(),
            degraded: true,
        });
        assert_eq!(degraded.kind(), "RESULTSET(cols=0,rows=0),degraded");
    }

    #[test]
    fn dml_never_outputs_unbounded_rows() {
        let database = database();
        let mut state = SessionState::default();
        for index in 0..500 {
            let sql = format!("INSERT INTO products (sku, name) VALUES ('s{index}', 'n{index}')");
            let _ = database.dispatch(&sql, &context_current_db("app_prod"), &mut state);
        }
        match database.dispatch(
            "SELECT * FROM products",
            &context_current_db("app_prod"),
            &mut state,
        ) {
            QueryResult::ResultSet(set) => assert!(set.rows.len() <= MAX_RESULT_ROWS),
            other => panic!("unexpected {other:?}"),
        }
    }

    fn context_current_db(name: &str) -> QueryContext {
        let mut context = ctx();
        context.current_db = name.to_string();
        context
    }

    // -- ORDER BY and GROUP BY correctness ----------------------------------

    #[test]
    fn string_columns_sort_dictionary_wise() {
        // The regression this guards: a hard-coded numeric comparison made every
        // non-numeric string read as 0, so all of them compared equal and the
        // order collapsed to storage order.
        let ascending: Vec<String> =
            rows_of("SELECT username FROM app_prod.users ORDER BY username ASC")
                .into_iter()
                .map(|row| row[0].clone().unwrap_or_default())
                .collect();
        assert_eq!(ascending, vec!["admin", "alice", "bob"]);

        let descending: Vec<String> =
            rows_of("SELECT username FROM app_prod.users ORDER BY username DESC")
                .into_iter()
                .map(|row| row[0].clone().unwrap_or_default())
                .collect();
        assert_eq!(descending, vec!["bob", "alice", "admin"]);
    }

    #[test]
    fn a_string_limit_takes_the_first_or_last_in_dictionary_order() {
        assert_eq!(
            single_value("SELECT username FROM app_prod.users ORDER BY username ASC LIMIT 1")
                .as_deref(),
            Some("admin")
        );
        assert_eq!(
            single_value("SELECT username FROM app_prod.users ORDER BY username DESC LIMIT 1")
                .as_deref(),
            Some("bob")
        );
        // The documented example shape: `ORDER BY id DESC` starts at the highest
        // key, and `LIMIT 1` narrows it to one row.
        assert_eq!(
            single_value("SELECT id FROM app_prod.users ORDER BY id DESC LIMIT 1").as_deref(),
            Some("3")
        );
    }

    #[test]
    fn numeric_columns_sort_by_value_not_by_text() {
        let database = database();
        let mut state = SessionState::default();
        assert!(matches!(
            database.dispatch("CREATE TABLE app_prod.n (id bigint)", &ctx(), &mut state),
            QueryResult::Ok { .. }
        ));
        for value in ["9", "10", "100", "2"] {
            match database.dispatch(
                &format!("INSERT INTO app_prod.n (id) VALUES ({value})"),
                &ctx(),
                &mut state,
            ) {
                QueryResult::Ok { .. } => {}
                other => panic!("insert {value} -> {other:?}"),
            }
        }
        let values: Vec<String> = match database.dispatch(
            "SELECT id FROM app_prod.n ORDER BY id ASC",
            &ctx(),
            &mut state,
        ) {
            QueryResult::ResultSet(set) => set
                .rows
                .iter()
                .map(|row| row[0].clone().unwrap_or_default())
                .collect(),
            other => panic!("{other:?}"),
        };
        assert_eq!(
            values,
            vec!["2", "9", "10", "100"],
            "text order would put 10 before 9"
        );
    }

    #[test]
    fn null_sorts_first_ascending_and_last_descending() {
        let database = database();
        let mut state = SessionState::default();
        match database.dispatch(
            "UPDATE app_prod.users SET username = NULL WHERE id = 2",
            &ctx(),
            &mut state,
        ) {
            QueryResult::Ok { .. } => {}
            other => panic!("{other:?}"),
        }
        let ascending: Vec<Option<String>> = match database.dispatch(
            "SELECT username FROM app_prod.users ORDER BY username ASC",
            &ctx(),
            &mut state,
        ) {
            QueryResult::ResultSet(set) => set.rows.iter().map(|row| row[0].clone()).collect(),
            other => panic!("{other:?}"),
        };
        assert_eq!(
            ascending,
            vec![None, Some("admin".to_string()), Some("bob".to_string())]
        );

        let descending: Vec<Option<String>> = match database.dispatch(
            "SELECT username FROM app_prod.users ORDER BY username DESC",
            &ctx(),
            &mut state,
        ) {
            QueryResult::ResultSet(set) => set.rows.iter().map(|row| row[0].clone()).collect(),
            other => panic!("{other:?}"),
        };
        assert_eq!(
            descending,
            vec![Some("bob".to_string()), Some("admin".to_string()), None]
        );
    }

    #[test]
    fn multi_column_order_by_respects_precedence() {
        let rows =
            rows_of("SELECT role, username FROM app_prod.users ORDER BY role ASC, username DESC");
        assert_eq!(rows.len(), 3);
        // `administrator` sorts before `user`, and within `user` bob precedes alice.
        assert_eq!(rows[0][1].as_deref(), Some("admin"));
        assert_eq!(rows[1][1].as_deref(), Some("bob"));
        assert_eq!(rows[2][1].as_deref(), Some("alice"));
    }

    #[test]
    fn group_by_and_aggregates_agree_with_the_column_types() {
        let rows = rows_of("SELECT role, COUNT(*) FROM app_prod.users GROUP BY role ORDER BY role");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0][0].as_deref(), Some("administrator"));
        assert_eq!(rows[0][1].as_deref(), Some("1"));
        assert_eq!(rows[1][0].as_deref(), Some("user"));
        assert_eq!(rows[1][1].as_deref(), Some("2"));

        // MIN/MAX follow the declared type of their argument.
        assert_eq!(
            single_value("SELECT MIN(username) FROM app_prod.users").as_deref(),
            Some("admin")
        );
        assert_eq!(
            single_value("SELECT MAX(username) FROM app_prod.users").as_deref(),
            Some("bob")
        );
        assert_eq!(
            single_value("SELECT MIN(id) FROM app_prod.users").as_deref(),
            Some("1")
        );
        assert_eq!(
            single_value("SELECT MAX(id) FROM app_prod.users").as_deref(),
            Some("3")
        );
    }

    #[test]
    fn group_by_folds_case_under_the_advertised_collation() {
        let database = database();
        let mut state = SessionState::default();
        for sql in [
            "CREATE TABLE app_prod.t (name varchar(32))",
            "INSERT INTO app_prod.t (name) VALUES ('Admin')",
            "INSERT INTO app_prod.t (name) VALUES ('admin')",
            "INSERT INTO app_prod.t (name) VALUES ('Admin')",
        ] {
            match database.dispatch(sql, &ctx(), &mut state) {
                QueryResult::Ok { .. } => {}
                other => panic!("{sql} -> {other:?}"),
            }
        }
        let rows = match database.dispatch(
            "SELECT name, COUNT(*) FROM app_prod.t GROUP BY name",
            &ctx(),
            &mut state,
        ) {
            QueryResult::ResultSet(set) => set.rows,
            other => panic!("{other:?}"),
        };
        assert_eq!(rows.len(), 1, "ai_ci must fold Admin and admin together");
        assert_eq!(rows[0][1].as_deref(), Some("3"));
    }

    // -- DML response contract ----------------------------------------------

    #[test]
    fn dml_with_an_unsupported_where_returns_an_error_not_an_empty_result_set() {
        let database = database();
        let mut state = SessionState::default();
        for sql in [
            "UPDATE app_prod.users SET role = 'x' WHERE id BETWEEN 1 AND 2",
            "DELETE FROM app_prod.users WHERE id = (SELECT 1)",
            "UPDATE app_prod.users SET role = 'x' WHERE id XOR id",
            "DELETE FROM app_prod.users WHERE CASE WHEN id = 1 THEN 1 END",
        ] {
            match database.dispatch(sql, &ctx(), &mut state) {
                QueryResult::Error { code, .. } => {
                    assert_eq!(code, 1235, "{sql} must report ER_NOT_SUPPORTED_YET");
                }
                other => panic!("{sql} -> {other:?} is not a legal DML answer"),
            }
        }
        assert!(!state.is_dirty(), "a refused DML statement changed state");
    }

    #[test]
    fn a_zero_column_result_set_is_never_returned_for_dml() {
        let database = database();
        let mut state = SessionState::default();
        for sql in [
            "UPDATE app_prod.users SET role = 'x' WHERE id BETWEEN 1 AND 2",
            "DELETE FROM app_prod.users WHERE id BETWEEN 1 AND 2",
        ] {
            match database.dispatch(sql, &ctx(), &mut state) {
                QueryResult::ResultSet(set) => {
                    assert!(
                        !set.columns.is_empty(),
                        "{sql} returned a result set with no columns"
                    );
                }
                QueryResult::Error { .. } | QueryResult::Ok { .. } => {}
                other => panic!("{sql} -> {other:?}"),
            }
        }
    }

    #[test]
    fn dml_affected_rows_and_row_count_agree() {
        let database = database();
        let mut state = SessionState::default();
        match database.dispatch(
            "UPDATE app_prod.users SET role = 'user' WHERE id = 1",
            &ctx(),
            &mut state,
        ) {
            QueryResult::Ok { affected_rows, .. } => assert_eq!(affected_rows, 1),
            other => panic!("{other:?}"),
        }
        assert_eq!(state.row_count(), 1);
        assert_eq!(
            single_value_with(&database, &mut state, "SELECT ROW_COUNT()").as_deref(),
            Some("1")
        );
        // Matching a row without changing it reports zero changed rows.
        match database.dispatch(
            "UPDATE app_prod.users SET role = 'user' WHERE id = 1",
            &ctx(),
            &mut state,
        ) {
            QueryResult::Ok { affected_rows, .. } => assert_eq!(affected_rows, 0),
            other => panic!("{other:?}"),
        }
        assert_eq!(state.row_count(), 0);
    }

    #[test]
    fn update_over_the_string_budget_returns_data_too_long() {
        let database = database();
        let mut state = SessionState::default();
        let long = "x".repeat(2_000);
        match database.dispatch(
            &format!("UPDATE app_prod.users SET username = '{long}' WHERE id = 1"),
            &ctx(),
            &mut state,
        ) {
            QueryResult::Error { code, .. } => assert_eq!(code, 1406),
            other => panic!("{other:?}"),
        }
        // The row is untouched.
        assert_eq!(
            single_value_with(
                &database,
                &mut state,
                "SELECT username FROM app_prod.users WHERE id = 1"
            )
            .as_deref(),
            Some("admin")
        );
    }

    #[test]
    fn delete_and_truncate_return_the_budget() {
        let database = database();
        let mut state = SessionState::default();
        assert!(matches!(
            database.dispatch(
                "INSERT INTO app_prod.users (username) VALUES ('extra')",
                &ctx(),
                &mut state
            ),
            QueryResult::Ok { .. }
        ));
        let grown = state.bytes();
        assert!(matches!(
            database.dispatch(
                "DELETE FROM app_prod.users WHERE username = 'extra'",
                &ctx(),
                &mut state
            ),
            QueryResult::Ok {
                affected_rows: 1,
                ..
            }
        ));
        assert!(state.bytes() < grown, "the deleted row kept its bytes");
        let after_delete = state.bytes();
        assert!(matches!(
            database.dispatch("TRUNCATE TABLE app_prod.users", &ctx(), &mut state),
            QueryResult::Ok { .. }
        ));
        assert!(
            state.bytes() < after_delete,
            "truncate kept the rows' bytes"
        );
        let (rows, bytes) = state.recount();
        assert_eq!(state.rows(), rows);
        assert_eq!(state.bytes(), bytes);
    }

    #[test]
    fn delete_honours_order_by_and_limit() {
        let database = database();
        let mut state = SessionState::default();
        match database.dispatch(
            "DELETE FROM app_prod.users ORDER BY id DESC LIMIT 1",
            &ctx(),
            &mut state,
        ) {
            QueryResult::Ok { affected_rows, .. } => assert_eq!(affected_rows, 1),
            other => panic!("{other:?}"),
        }
        // `ORDER BY id DESC LIMIT 1` removes the highest key, not the first row.
        let remaining: Vec<String> = match database.dispatch(
            "SELECT username FROM app_prod.users ORDER BY id",
            &ctx(),
            &mut state,
        ) {
            QueryResult::ResultSet(set) => set
                .rows
                .iter()
                .map(|row| row[0].clone().unwrap_or_default())
                .collect(),
            other => panic!("{other:?}"),
        };
        assert_eq!(remaining, vec!["admin", "alice"]);
    }

    #[test]
    fn multi_row_insert_is_atomic_through_the_executor() {
        let database = database();
        let mut state = SessionState::new(StateBudgets {
            max_string_bytes: 8,
            ..StateBudgets::default()
        });
        match database.dispatch(
            "INSERT INTO app_prod.users (username) VALUES ('ok'), ('this-is-way-too-long')",
            &ctx(),
            &mut state,
        ) {
            QueryResult::Error { code, .. } => assert_eq!(code, 1406),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            single_value_with(&database, &mut state, "SELECT COUNT(*) FROM app_prod.users")
                .as_deref(),
            Some("3"),
            "a rejected batch must not insert a prefix of its rows"
        );
    }

    #[test]
    fn insert_ignore_skips_only_the_offending_rows() {
        let database = database();
        let mut state = SessionState::new(StateBudgets {
            max_string_bytes: 8,
            ..StateBudgets::default()
        });
        match database.dispatch(
            "INSERT IGNORE INTO app_prod.users (username) VALUES ('ok'), ('this-is-way-too-long')",
            &ctx(),
            &mut state,
        ) {
            QueryResult::Ok { affected_rows, .. } => assert_eq!(affected_rows, 1),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            single_value_with(&database, &mut state, "SELECT COUNT(*) FROM app_prod.users")
                .as_deref(),
            Some("4")
        );
    }

    #[test]
    fn replace_keeps_one_row_per_primary_key() {
        let database = database();
        let mut state = SessionState::default();
        match database.dispatch(
            "REPLACE INTO app_prod.users (id, username) VALUES (1, 'root')",
            &ctx(),
            &mut state,
        ) {
            // MySQL reports two rows affected: one deleted, one inserted.
            QueryResult::Ok { affected_rows, .. } => assert_eq!(affected_rows, 2),
            other => panic!("{other:?}"),
        }
        let rows = match database.dispatch(
            "SELECT username FROM app_prod.users WHERE id = 1",
            &ctx(),
            &mut state,
        ) {
            QueryResult::ResultSet(set) => set.rows,
            other => panic!("{other:?}"),
        };
        assert_eq!(rows.len(), 1, "REPLACE duplicated the primary key");
        assert_eq!(rows[0][0].as_deref(), Some("root"));
        let (row_count, bytes) = state.recount();
        assert_eq!(state.rows(), row_count);
        assert_eq!(state.bytes(), bytes);
    }

    #[test]
    fn insert_with_a_column_count_mismatch_is_refused() {
        let database = database();
        let mut state = SessionState::default();
        match database.dispatch(
            "INSERT INTO app_prod.users VALUES ('1', 'a', 'b', 'c', 'd', 'e', 'f')",
            &ctx(),
            &mut state,
        ) {
            QueryResult::Error { code, .. } => assert_eq!(code, 1136),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_create_drop_cycle_cannot_grow_the_session() {
        let database = database();
        let mut state = SessionState::default();
        for round in 0..500u32 {
            let name = format!("t{round}");
            assert!(matches!(
                database.dispatch(
                    &format!("CREATE TABLE app_prod.{name} (id bigint)"),
                    &ctx(),
                    &mut state
                ),
                QueryResult::Ok { .. }
            ));
            assert!(matches!(
                database.dispatch(&format!("DROP TABLE app_prod.{name}"), &ctx(), &mut state),
                QueryResult::Ok { .. }
            ));
        }
        assert!(
            state.bytes() < 4_096,
            "500 create/drop cycles left {} bytes of overlay",
            state.bytes()
        );
        assert_eq!(state.tombstones(), 0, "session tables need no tombstones");
        let (rows, bytes) = state.recount();
        assert_eq!(state.rows(), rows);
        assert_eq!(state.bytes(), bytes);
    }

    #[test]
    fn dropping_a_session_table_then_recreating_it_works() {
        let database = database();
        let mut state = SessionState::default();
        for _ in 0..3 {
            assert!(matches!(
                database.dispatch(
                    "CREATE TABLE app_prod.cycle (id bigint)",
                    &ctx(),
                    &mut state
                ),
                QueryResult::Ok { .. }
            ));
            assert!(matches!(
                database.dispatch("DROP TABLE app_prod.cycle", &ctx(), &mut state),
                QueryResult::Ok { .. }
            ));
            assert!(matches!(
                database.dispatch("SELECT * FROM app_prod.cycle", &ctx(), &mut state),
                QueryResult::Error { code: 1146, .. }
            ));
        }
        assert!(state.bytes() < 4_096);
    }
}
