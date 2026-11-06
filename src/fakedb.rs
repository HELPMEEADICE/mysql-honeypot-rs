// SPDX-License-Identifier: GPL-3.0-only
//! The fake database: an in-memory catalog plus a statement router.
//!
//! Nothing here executes SQL. Every statement is classified, answered with a
//! plausible response and recorded by the caller. The catalog is deliberately
//! small but shaped like a real MySQL 8.0 instance so that automation
//! (`SHOW DATABASES`, `information_schema` probing, `SELECT ... LIMIT`) keeps
//! talking instead of disconnecting.

use crate::protocol::response::column_type;
use crate::util;

/// Hard cap on rows handed back for a single result set.
pub const MAX_RESULT_ROWS: usize = 200;

/// One column of a fake table.
#[derive(Debug, Clone)]
pub struct FakeColumn {
    /// Column name.
    pub name: &'static str,
    /// Type as shown by `SHOW COLUMNS` / `DESCRIBE`.
    pub data_type: &'static str,
    /// `IS_NULLABLE`.
    pub nullable: bool,
    /// `COLUMN_KEY`.
    pub key: &'static str,
    /// `COLUMN_DEFAULT`.
    pub default: Option<&'static str>,
    /// `EXTRA`.
    pub extra: &'static str,
    /// Wire type used in column definitions.
    pub wire_type: u8,
}

impl FakeColumn {
    const fn new(name: &'static str, data_type: &'static str, wire_type: u8) -> Self {
        Self {
            name,
            data_type,
            nullable: true,
            key: "",
            default: None,
            extra: "",
            wire_type,
        }
    }

    const fn primary(name: &'static str, data_type: &'static str, wire_type: u8) -> Self {
        Self {
            name,
            data_type,
            nullable: false,
            key: "PRI",
            default: None,
            extra: "auto_increment",
            wire_type,
        }
    }

    const fn not_null(mut self) -> Self {
        self.nullable = false;
        self
    }
}

/// One fake table with materialised rows.
#[derive(Debug, Clone)]
pub struct FakeTable {
    /// Table name.
    pub name: &'static str,
    /// Storage engine reported by `SHOW TABLE STATUS`.
    pub engine: &'static str,
    /// Table comment.
    pub comment: &'static str,
    /// Column definitions.
    pub columns: Vec<FakeColumn>,
    /// Row values, aligned with `columns`.
    pub rows: Vec<Vec<Option<String>>>,
}

/// One fake schema.
#[derive(Debug, Clone)]
pub struct FakeSchema {
    /// Schema name.
    pub name: &'static str,
    /// Tables in this schema.
    pub tables: Vec<FakeTable>,
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
            Self::ResultSet(set) => format!(
                "RESULTSET(cols={},rows={})",
                set.columns.len(),
                set.rows.len()
            ),
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
    /// Connection id reported to the client.
    pub connection_id: u32,
    /// Advertised server version.
    pub server_version: String,
}

/// The fake instance.
#[derive(Debug, Clone)]
pub struct FakeDatabase {
    schemas: Vec<FakeSchema>,
    variables: Vec<(String, String)>,
    status: Vec<(String, String)>,
}

impl FakeDatabase {
    /// Build the whole fake instance, including generated `information_schema`
    /// rows.
    pub fn new(server_version: &str) -> Self {
        let schemas = vec![
            FakeSchema {
                name: "information_schema",
                tables: information_schema_tables(),
            },
            mysql_schema(),
            performance_schema(),
            sys_schema(),
            app_prod_schema(),
            backup_schema(),
        ];
        let mut database = Self {
            schemas,
            variables: variables(server_version),
            status: status_variables(),
        };
        database.populate_information_schema();
        database
    }

    /// Schema names in `SHOW DATABASES` order.
    pub fn schema_names(&self) -> Vec<&'static str> {
        self.schemas.iter().map(|schema| schema.name).collect()
    }

    /// Whether a schema exists (case insensitive, like MySQL on Linux).
    pub fn has_schema(&self, name: &str) -> bool {
        self.schemas
            .iter()
            .any(|schema| schema.name.eq_ignore_ascii_case(name))
    }

    fn schema(&self, name: &str) -> Option<&FakeSchema> {
        self.schemas
            .iter()
            .find(|schema| schema.name.eq_ignore_ascii_case(name))
    }

    fn lookup(
        &self,
        schema_name: Option<&str>,
        table: &str,
        ctx: &QueryContext,
    ) -> Option<(&FakeSchema, &FakeTable)> {
        if let Some(name) = schema_name {
            return self.schema(name).and_then(|schema| find_in(schema, table));
        }
        if !ctx.current_db.is_empty()
            && let Some(schema) = self.schema(&ctx.current_db)
            && let Some(hit) = find_in(schema, table)
        {
            return Some(hit);
        }
        self.schemas
            .iter()
            .find_map(|schema| find_in(schema, table))
    }

    /// Regenerate `information_schema` contents from the current catalog.
    fn populate_information_schema(&mut self) {
        let schemata: Vec<Vec<Option<String>>> = self
            .schemas
            .iter()
            .map(|schema| {
                row(&[
                    "def",
                    schema.name,
                    "utf8mb4",
                    "utf8mb4_0900_ai_ci",
                    "",
                    "NO",
                ])
            })
            .collect();

        let mut tables = Vec::new();
        let mut columns = Vec::new();
        let mut statistics = Vec::new();
        for schema in &self.schemas {
            for table in &schema.tables {
                tables.push(row(&[
                    "def",
                    schema.name,
                    table.name,
                    "BASE TABLE",
                    table.engine,
                    "10",
                    "Dynamic",
                    &(8 + table.rows.len() * 3).to_string(),
                    "16384",
                    "16384",
                    "0",
                    "0",
                    "0",
                    "16",
                    "2024-01-01 00:00:00",
                    "",
                    "",
                    "utf8mb4_0900_ai_ci",
                    "0",
                    "",
                    table.comment,
                ]));
                for (index, column) in table.columns.iter().enumerate() {
                    columns.push(row(&[
                        "def",
                        schema.name,
                        table.name,
                        column.name,
                        &(index + 1).to_string(),
                        column.default.unwrap_or("NULL"),
                        if column.nullable { "YES" } else { "NO" },
                        column.data_type,
                        "NULL",
                        "NULL",
                        "NULL",
                        "NULL",
                        "NULL",
                        "utf8mb4",
                        "utf8mb4_0900_ai_ci",
                        column.data_type,
                        column.key,
                        column.extra,
                        "select,insert,update,references",
                        "",
                        "",
                    ]));
                    if !column.key.is_empty() {
                        statistics.push(row(&[
                            "def",
                            schema.name,
                            table.name,
                            "0",
                            schema.name,
                            "PRIMARY",
                            "1",
                            column.name,
                            "A",
                            "0",
                            "NULL",
                            "",
                            "YES",
                            "BTREE",
                            "",
                        ]));
                    }
                }
            }
        }

        let processlist = vec![row(&[
            "1",
            "app",
            "localhost:3306",
            "app_prod",
            "Sleep",
            "0",
            "",
            "",
        ])];

        let engines = vec![
            row(&[
                "InnoDB",
                "DEFAULT",
                "Supports transactions, row-level locking, and foreign keys",
                "YES",
                "YES",
                "YES",
            ]),
            row(&["MyISAM", "YES", "MyISAM storage engine", "NO", "NO", "NO"]),
            row(&[
                "MEMORY",
                "YES",
                "Hash based, stored in memory, useful for temporary tables",
                "NO",
                "NO",
                "NO",
            ]),
            row(&["CSV", "YES", "CSV storage engine", "NO", "NO", "NO"]),
        ];

        let privileges = vec![
            row(&["'root'@'%'", "def", "SELECT", "NO"]),
            row(&["'root'@'%'", "def", "INSERT", "NO"]),
            row(&["'root'@'%'", "def", "UPDATE", "NO"]),
            row(&["'root'@'%'", "def", "FILE", "NO"]),
        ];

        let character_sets = vec![
            row(&["utf8mb4", "utf8mb4_0900_ai_ci", "UTF-8 Unicode", "4"]),
            row(&["utf8mb3", "utf8mb3_general_ci", "UTF-8 Unicode", "3"]),
            row(&["latin1", "latin1_swedish_ci", "cp1252 West European", "1"]),
            row(&["binary", "binary", "Binary pseudo charset", "1"]),
        ];

        let key_column_usage = vec![
            row(&[
                "def", "mysql", "PRIMARY", "def", "mysql", "user", "Host", "1", "None", "", "", "",
            ]),
            row(&[
                "def", "app_prod", "PRIMARY", "def", "app_prod", "users", "id", "1", "None", "",
                "", "",
            ]),
            row(&[
                "def", "app_prod", "PRIMARY", "def", "app_prod", "orders", "id", "1", "None", "",
                "", "",
            ]),
        ];

        let generated: [(&str, Vec<Vec<Option<String>>>); 9] = [
            ("SCHEMATA", schemata),
            ("TABLES", tables),
            ("COLUMNS", columns),
            ("STATISTICS", statistics),
            ("PROCESSLIST", processlist),
            ("ENGINES", engines),
            ("USER_PRIVILEGES", privileges),
            ("CHARACTER_SETS", character_sets),
            ("KEY_COLUMN_USAGE", key_column_usage),
        ];

        if let Some(schema) = self
            .schemas
            .iter_mut()
            .find(|schema| schema.name == "information_schema")
        {
            for table in &mut schema.tables {
                for (name, rows) in &generated {
                    if *name == table.name {
                        table.rows = rows.clone();
                        break;
                    }
                }
            }
        }
    }

    /// Route one statement to a plausible response.
    pub fn dispatch(&self, sql: &str, ctx: &QueryContext) -> QueryResult {
        let trimmed = sql.trim().trim_end_matches(';').trim();
        let clean = strip_leading_comments(trimmed).trim();
        if clean.is_empty() {
            return QueryResult::error(1065, "42000", "Query was empty");
        }
        let (keyword, keyword_end) = first_keyword(clean);
        let rest = clean[keyword_end..].trim_start();
        match keyword.as_str() {
            "SELECT" => self.select(rest, ctx),
            "SHOW" => self.show(rest, ctx),
            "USE" => match self.use_schema(rest) {
                Some(_) => QueryResult::ok(0, 0, ""),
                None => QueryResult::error(
                    1049,
                    "42000",
                    format!("Unknown database '{}'", unquote_ident(rest)),
                ),
            },
            "DESCRIBE" | "DESC" | "EXPLAIN" => self.describe(rest, ctx),
            "SET" | "BEGIN" | "START" | "COMMIT" | "ROLLBACK" | "SAVEPOINT" | "RELEASE" => {
                QueryResult::ok(0, 0, "")
            }
            "INSERT" => QueryResult::ok(1, 0, "(1 row affected)"),
            "REPLACE" => QueryResult::ok(1, 0, "(1 row affected)"),
            "UPDATE" => QueryResult::ok(1, 0, "(1 row affected)"),
            "DELETE" => QueryResult::ok(1, 0, "(1 row affected)"),
            "TRUNCATE" => QueryResult::ok(0, 0, ""),
            "CREATE" | "DROP" | "ALTER" | "RENAME" => QueryResult::ok(0, 0, ""),
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
            _ => QueryResult::error(
                1064,
                "42000",
                format!(
                    "You have an error in your SQL syntax; check the manual that corresponds to \
                     your MySQL server version for the right syntax to use near '{}' at line 1",
                    util::truncate_to(clean, 64).0
                ),
            ),
        }
    }

    fn use_schema(&self, rest: &str) -> Option<String> {
        let name = unquote_ident(rest);
        if self.has_schema(&name) {
            Some(name)
        } else {
            None
        }
    }

    // -----------------------------------------------------------------------
    // SELECT
    // -----------------------------------------------------------------------
    fn select(&self, rest: &str, ctx: &QueryContext) -> QueryResult {
        let (list, from_part) = match find_keyword(rest, "FROM") {
            Some(index) => (&rest[..index], Some(&rest[index + 4..])),
            None => (rest, None),
        };
        let items = split_top_level(list, ',');
        if items.iter().all(|item| item.trim().is_empty()) {
            return QueryResult::error(1064, "42000", "You have an error in your SQL syntax");
        }

        let Some(from_part) = from_part else {
            return QueryResult::ResultSet(self.expression_result_set(&items, ctx, None));
        };

        let (schema_name, table_name, remainder) = parse_table_ref(from_part);
        if table_name.eq_ignore_ascii_case("dual") {
            return QueryResult::ResultSet(self.expression_result_set(&items, ctx, None));
        }
        let Some((schema, table)) = self.lookup(schema_name.as_deref(), &table_name, ctx) else {
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

        // A WHERE clause made only of literals is honoured as a coarse filter so
        // that `information_schema` probes still return plausible rows.
        let literals = extract_string_literals(remainder);
        let selected = filter_rows(&table.rows, &literals);
        let limit = parse_limit(remainder).unwrap_or(selected.len());

        let row_count = selected.len();
        let mut result = ResultSet::default();
        let mut projections: Vec<Projection> = Vec::new();
        for item in &items {
            let (expression, alias) = split_alias(item);
            let expression = expression.trim();
            if expression == "*" || expression.ends_with(".*") {
                for (index, column) in table.columns.iter().enumerate() {
                    result.columns.push(ResultColumn {
                        name: column.name.to_string(),
                        org_name: column.name.to_string(),
                        table: table.name.to_string(),
                        schema: schema.name.to_string(),
                        wire_type: column.wire_type,
                    });
                    projections.push(Projection::Column(index));
                }
                continue;
            }
            let bare = unquote_ident(expression);
            if let Some(index) = table
                .columns
                .iter()
                .position(|column| column.name.eq_ignore_ascii_case(&bare))
            {
                let column = &table.columns[index];
                result.columns.push(ResultColumn {
                    name: alias.unwrap_or_else(|| column.name.to_string()),
                    org_name: column.name.to_string(),
                    table: table.name.to_string(),
                    schema: schema.name.to_string(),
                    wire_type: column.wire_type,
                });
                projections.push(Projection::Column(index));
            } else {
                result.columns.push(ResultColumn {
                    name: alias.unwrap_or_else(|| expression.to_string()),
                    org_name: expression.to_string(),
                    table: String::new(),
                    schema: String::new(),
                    wire_type: if is_numeric_expression(expression) {
                        column_type::LONGLONG
                    } else {
                        column_type::VAR_STRING
                    },
                });
                projections.push(Projection::Expression(self.eval_expression(
                    expression,
                    ctx,
                    Some(row_count),
                )));
            }
        }

        for row in selected.into_iter().take(limit.min(MAX_RESULT_ROWS)) {
            let mut values = Vec::with_capacity(projections.len());
            for projection in &projections {
                match projection {
                    Projection::Column(index) => {
                        values.push(row.get(*index).cloned().flatten());
                    }
                    Projection::Expression(value) => values.push(value.clone()),
                }
            }
            result.rows.push(values);
        }
        QueryResult::ResultSet(result)
    }

    fn expression_result_set(
        &self,
        items: &[&str],
        ctx: &QueryContext,
        row_count: Option<usize>,
    ) -> ResultSet {
        let mut result = ResultSet::default();
        let mut values = Vec::with_capacity(items.len());
        for item in items {
            let (expression, alias) = split_alias(item);
            let expression = expression.trim();
            if expression.is_empty() {
                continue;
            }
            let value = self.eval_expression(expression, ctx, row_count);
            result.columns.push(ResultColumn {
                name: alias.unwrap_or_else(|| expression.to_string()),
                org_name: expression.to_string(),
                table: String::new(),
                schema: String::new(),
                wire_type: if value
                    .as_deref()
                    .is_some_and(|text| text.parse::<i64>().is_ok())
                {
                    column_type::LONGLONG
                } else {
                    column_type::VAR_STRING
                },
            });
            values.push(value);
        }
        result.rows.push(values);
        result
    }

    /// Best effort evaluation of a scalar expression. Never executes anything.
    fn eval_expression(
        &self,
        expression: &str,
        ctx: &QueryContext,
        row_count: Option<usize>,
    ) -> Option<String> {
        let expression = expression.trim();
        if expression.is_empty() {
            return None;
        }
        let upper = expression.to_ascii_uppercase();
        if upper == "NULL" {
            return None;
        }
        if let Some(literal) = strip_string_literal(expression) {
            return Some(literal);
        }
        if expression.parse::<i64>().is_ok() || expression.parse::<f64>().is_ok() {
            return Some(expression.to_string());
        }
        if upper == "TRUE" {
            return Some("1".to_string());
        }
        if upper == "FALSE" {
            return Some("0".to_string());
        }
        if let Some(name) = expression.strip_prefix("@@") {
            return self
                .variable(strip_variable_scope(name))
                .map(str::to_string);
        }
        if let Some(name) = expression.strip_prefix('@') {
            return self.variable(name).map(str::to_string);
        }

        let (function, argument) = match expression.split_once('(') {
            Some((name, rest)) => {
                let rest = rest.trim_end();
                let inner = rest.strip_suffix(')').unwrap_or(rest);
                (name.trim().to_ascii_uppercase(), inner.trim())
            }
            None => (upper.clone(), ""),
        };
        let args = split_top_level(argument, ',');

        match function.as_str() {
            "VERSION" => Some(ctx.server_version.clone()),
            "DATABASE" | "SCHEMA" => {
                if ctx.current_db.is_empty() {
                    None
                } else {
                    Some(ctx.current_db.clone())
                }
            }
            "USER" | "SESSION_USER" | "SYSTEM_USER" => Some(format!("{}@%", ctx.username)),
            "CURRENT_USER" => Some("root@localhost".to_string()),
            "CONNECTION_ID" => Some(ctx.connection_id.to_string()),
            "NOW" | "CURRENT_TIMESTAMP" | "SYSDATE" | "LOCALTIME" | "LOCALTIMESTAMP" => {
                Some(sql_datetime(&util::utc_now()))
            }
            "CURDATE" | "CURRENT_DATE" => Some(util::utc_now()[..10].to_string()),
            "CURTIME" | "CURRENT_TIME" => Some(util::utc_now()[11..19].to_string()),
            "UNIX_TIMESTAMP" => Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|delta| delta.as_secs())
                    .unwrap_or(0)
                    .to_string(),
            ),
            "PASSWORD" => Some(format!(
                "*{}",
                util::hex_lower(&[0x5fu8; 20]).to_uppercase()
            )),
            "MD5" => Some(util::hex_lower(&[0x33u8; 16])),
            "SHA" | "SHA1" => Some(util::hex_lower(&[0x44u8; 20])),
            "SHA2" => Some(util::hex_lower(&[0x55u8; 32])),
            "LENGTH" | "OCTET_LENGTH" => Some(
                args.first()
                    .map(|value| text_of(value).len())
                    .unwrap_or(0)
                    .to_string(),
            ),
            "CHAR_LENGTH" | "CHARACTER_LENGTH" => Some(
                args.first()
                    .map(|value| text_of(value).chars().count())
                    .unwrap_or(0)
                    .to_string(),
            ),
            "UPPER" | "UCASE" => args.first().map(|value| text_of(value).to_uppercase()),
            "LOWER" | "LCASE" => args.first().map(|value| text_of(value).to_lowercase()),
            "HEX" => args
                .first()
                .map(|value| util::hex_lower(text_of(value).as_bytes()).to_uppercase()),
            "ASCII" => args.first().map(|value| {
                text_of(value)
                    .as_bytes()
                    .first()
                    .copied()
                    .unwrap_or(0)
                    .to_string()
            }),
            "CONCAT" => Some(
                args.iter()
                    .map(|value| text_of(value))
                    .collect::<Vec<_>>()
                    .join(""),
            ),
            "COUNT" if row_count.is_some() => Some(row_count.unwrap_or(0).to_string()),
            "SLEEP" => Some("0".to_string()),
            "EXISTS" => Some("1".to_string()),
            "IFNULL" | "COALESCE" | "CAST" | "CONVERT" => args.first().map(|value| text_of(value)),
            "SUBSTRING" | "SUBSTR" | "LEFT" | "RIGHT" | "TRIM" | "REPLACE" | "UNHEX" => {
                args.first().map(|value| text_of(value))
            }
            // Unknown functions fall back to their own text, which keeps
            // injection probes answering without ever doing work.
            _ => Some(expression.to_string()),
        }
    }

    fn variable(&self, name: &str) -> Option<&str> {
        let name = name.trim();
        self.variables
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    // -----------------------------------------------------------------------
    // SHOW
    // -----------------------------------------------------------------------
    fn show(&self, rest: &str, ctx: &QueryContext) -> QueryResult {
        // `SHOW GLOBAL VARIABLES` / `SHOW FULL TABLES` — drop the modifiers.
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
                    .schema_names()
                    .into_iter()
                    .map(|name| name.to_string())
                    .collect();
                QueryResult::ResultSet(ResultSet::single_text(
                    "Database",
                    "information_schema",
                    "SCHEMATA",
                    rows,
                ))
            }
            "TABLES" => self.show_tables(tail, ctx),
            "COLUMNS" | "FIELDS" => self.show_columns(tail, ctx),
            "CREATE" => self.show_create(tail, ctx),
            "VARIABLES" => self.show_variable_table(&self.variables, tail),
            "STATUS" => self.show_variable_table(&self.status, tail),
            "PROCESSLIST" => self.show_processlist(),
            "GRANTS" => {
                let column = format!("Grants for {}@%", ctx.username);
                QueryResult::ResultSet(ResultSet::single_text(
                    &column,
                    "",
                    "",
                    vec!["GRANT ALL PRIVILEGES ON *.* TO `root`@`%` WITH GRANT OPTION".to_string()],
                ))
            }
            "ENGINES" => self.table_result("ENGINES", None),
            "WARNINGS" | "ERRORS" => {
                let mut set = ResultSet {
                    columns: vec![
                        text_column("Level", "", ""),
                        numeric_column("Code", "", ""),
                        text_column("Message", "", ""),
                    ],
                    rows: Vec::new(),
                };
                set.rows.push(vec![
                    Some("Note".to_string()),
                    Some("0".to_string()),
                    Some(String::new()),
                ]);
                QueryResult::ResultSet(set)
            }
            "INDEX" | "INDEXES" | "KEYS" => self.show_index(tail),
            "CHARACTER" => self.table_result("CHARACTER_SETS", Some("information_schema")),
            "COLLATION" => {
                let set = ResultSet {
                    columns: vec![
                        text_column("Collation", "", ""),
                        text_column("Charset", "", ""),
                        numeric_column("Id", "", ""),
                        text_column("Default", "", ""),
                        text_column("Compiled", "", ""),
                        numeric_column("Sortlen", "", ""),
                    ],
                    rows: vec![
                        row(&["utf8mb4_0900_ai_ci", "utf8mb4", "255", "Yes", "Yes", "0"]),
                        row(&["utf8mb4_general_ci", "utf8mb4", "45", "", "Yes", "1"]),
                        row(&["latin1_swedish_ci", "latin1", "8", "", "Yes", "1"]),
                    ],
                };
                QueryResult::ResultSet(set)
            }
            "PRIVILEGES" => {
                let set = ResultSet {
                    columns: vec![
                        text_column("Privilege", "", ""),
                        text_column("Context", "", ""),
                        text_column("Comment", "", ""),
                    ],
                    rows: vec![
                        row(&["Alter", "Tables", "To alter the table"]),
                        row(&[
                            "Create",
                            "Databases,Tables,Indexes",
                            "To create new databases and tables",
                        ]),
                        row(&["Delete", "Tables", "To delete existing rows"]),
                        row(&[
                            "Drop",
                            "Databases,Tables",
                            "To drop databases, tables, and views",
                        ]),
                        row(&[
                            "Grant option",
                            "Databases,Tables,Functions,Procedures",
                            "To give to other users those privileges you possess",
                        ]),
                        row(&["Insert", "Tables", "To insert data into tables"]),
                        row(&["Select", "Tables", "To retrieve rows from table"]),
                        row(&["Update", "Tables", "To update existing rows"]),
                    ],
                };
                QueryResult::ResultSet(set)
            }
            "TABLE" => self.show_table_status(tail, ctx),
            "TRIGGERS" | "EVENTS" | "FUNCTION" | "PROCEDURE" | "OPEN" | "PLUGINS" | "SLAVE"
            | "REPLICA" | "BINARY" | "MASTER" => QueryResult::ResultSet(ResultSet::default()),
            _ => {
                // Unknown SHOW: an empty single column set keeps clients alive.
                QueryResult::ResultSet(ResultSet::single_text(
                    &format!("SHOW {keyword}"),
                    "",
                    "",
                    Vec::new(),
                ))
            }
        }
    }

    fn table_result(&self, table: &str, schema: Option<&str>) -> QueryResult {
        let schema = schema.unwrap_or("information_schema");
        match self.schema(schema) {
            Some(found) => match found
                .tables
                .iter()
                .find(|candidate| candidate.name == table)
            {
                Some(fake) => QueryResult::ResultSet(self.materialise(schema, fake, None)),
                None => QueryResult::ResultSet(ResultSet::default()),
            },
            None => QueryResult::ResultSet(ResultSet::default()),
        }
    }

    fn materialise(
        &self,
        schema: &str,
        table: &FakeTable,
        literals: Option<&[String]>,
    ) -> ResultSet {
        let rows = match literals {
            Some(literals) => filter_rows(&table.rows, literals),
            None => table.rows.iter().collect(),
        };
        ResultSet {
            columns: table
                .columns
                .iter()
                .map(|column| ResultColumn {
                    name: column.name.to_string(),
                    org_name: column.name.to_string(),
                    table: table.name.to_string(),
                    schema: schema.to_string(),
                    wire_type: column.wire_type,
                })
                .collect(),
            rows: rows.into_iter().take(MAX_RESULT_ROWS).cloned().collect(),
        }
    }

    fn show_tables(&self, tail: &str, ctx: &QueryContext) -> QueryResult {
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
        let Some(schema) = self.schema(&schema_name) else {
            return QueryResult::error(1049, "42000", format!("Unknown database '{schema_name}'"));
        };
        let names: Vec<String> = schema
            .tables
            .iter()
            .filter(|table| pattern_matches(pattern.as_deref(), table.name))
            .map(|table| table.name.to_string())
            .collect();
        QueryResult::ResultSet(ResultSet::single_text(
            &format!("Tables_in_{}", schema.name),
            schema.name,
            "",
            names,
        ))
    }

    fn show_columns(&self, tail: &str, ctx: &QueryContext) -> QueryResult {
        let tail = tail
            .strip_prefix("FROM ")
            .or_else(|| tail.strip_prefix("from "))
            .or_else(|| tail.strip_prefix("IN "))
            .or_else(|| tail.strip_prefix("in "))
            .unwrap_or(tail);
        let (schema_name, table_name, remainder) = parse_table_ref(tail);
        let schema_name = schema_name.or_else(|| {
            if ctx.current_db.is_empty() {
                None
            } else {
                Some(ctx.current_db.clone())
            }
        });
        let Some((schema, table)) = self.lookup(schema_name.as_deref(), &table_name, ctx) else {
            return QueryResult::error(
                1146,
                "42S02",
                format!("Table '{}' doesn't exist", table_name),
            );
        };
        let pattern = parse_like(remainder);
        let rows = table
            .columns
            .iter()
            .filter(|column| pattern_matches(pattern.as_deref(), column.name))
            .map(|column| {
                vec![
                    Some(column.name.to_string()),
                    Some(column.data_type.to_string()),
                    Some(if column.nullable { "YES" } else { "NO" }.to_string()),
                    Some(column.key.to_string()),
                    Some(column.default.unwrap_or("NULL").to_string()),
                    Some(column.extra.to_string()),
                ]
            })
            .collect();
        QueryResult::ResultSet(ResultSet {
            columns: vec![
                text_column("Field", schema.name, table.name),
                text_column("Type", schema.name, table.name),
                text_column("Null", schema.name, table.name),
                text_column("Key", schema.name, table.name),
                text_column("Default", schema.name, table.name),
                text_column("Extra", schema.name, table.name),
            ],
            rows,
        })
    }

    fn show_create(&self, tail: &str, ctx: &QueryContext) -> QueryResult {
        let (kind, kind_end) = first_keyword(tail);
        let name = unquote_ident(tail[kind_end..].trim());
        match kind.as_str() {
            "TABLE" => {
                let Some((_, table)) = self.lookup(None, &name, ctx) else {
                    return QueryResult::error(
                        1146,
                        "42S02",
                        format!("Table '{name}' doesn't exist"),
                    );
                };
                let mut ddl = format!("CREATE TABLE `{}` (\n", table.name);
                for (index, column) in table.columns.iter().enumerate() {
                    ddl.push_str(&format!(
                        "  `{}` {} {},",
                        column.name,
                        column.data_type,
                        if column.nullable {
                            "DEFAULT NULL"
                        } else {
                            "NOT NULL"
                        }
                    ));
                    if index + 1 < table.columns.len() {
                        ddl.push('\n');
                    }
                }
                ddl.push_str("\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
                QueryResult::ResultSet(ResultSet {
                    columns: vec![
                        text_column("Table", "", ""),
                        text_column("Create Table", "", ""),
                    ],
                    rows: vec![vec![Some(table.name.to_string()), Some(ddl)]],
                })
            }
            "DATABASE" | "SCHEMA" => {
                if !self.has_schema(&name) {
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
                })
            }
            _ => QueryResult::error(1064, "42000", "You have an error in your SQL syntax"),
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
        })
    }

    fn show_processlist(&self) -> QueryResult {
        let rows = self
            .schema("information_schema")
            .and_then(|schema| schema.tables.iter().find(|t| t.name == "PROCESSLIST"))
            .map(|table| table.rows.clone())
            .unwrap_or_default();
        QueryResult::ResultSet(ResultSet {
            columns: vec![
                numeric_column("Id", "information_schema", "PROCESSLIST"),
                text_column("User", "information_schema", "PROCESSLIST"),
                text_column("Host", "information_schema", "PROCESSLIST"),
                text_column("db", "information_schema", "PROCESSLIST"),
                text_column("Command", "information_schema", "PROCESSLIST"),
                numeric_column("Time", "information_schema", "PROCESSLIST"),
                text_column("State", "information_schema", "PROCESSLIST"),
                text_column("Info", "information_schema", "PROCESSLIST"),
            ],
            rows,
        })
    }

    fn show_index(&self, tail: &str) -> QueryResult {
        let tail = tail
            .strip_prefix("FROM ")
            .or_else(|| tail.strip_prefix("from "))
            .or_else(|| tail.strip_prefix("IN "))
            .or_else(|| tail.strip_prefix("in "))
            .unwrap_or(tail);
        let table_name = unquote_ident(tail.split_whitespace().next().unwrap_or(""));
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
            rows: vec![vec![
                Some(table_name.clone()),
                Some("0".to_string()),
                Some("PRIMARY".to_string()),
                Some("1".to_string()),
                Some("id".to_string()),
                Some("A".to_string()),
                Some("0".to_string()),
                Some("BTREE".to_string()),
                Some("YES".to_string()),
            ]],
        })
    }

    fn show_table_status(&self, tail: &str, ctx: &QueryContext) -> QueryResult {
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
        let Some(schema) = self.schema(&schema_name) else {
            return QueryResult::error(1049, "42000", format!("Unknown database '{schema_name}'"));
        };
        let rows = schema
            .tables
            .iter()
            .filter(|table| pattern_matches(pattern.as_deref(), table.name))
            .map(|table| {
                row(&[
                    table.name,
                    table.engine,
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
                    table.comment,
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
        })
    }

    // -----------------------------------------------------------------------
    // DESCRIBE / EXPLAIN
    // -----------------------------------------------------------------------
    fn describe(&self, rest: &str, ctx: &QueryContext) -> QueryResult {
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
                rows: vec![row(&[
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
            });
        }
        self.show_columns(rest, ctx)
    }
}

/// One projected column of a `SELECT`.
enum Projection {
    Column(usize),
    Expression(Option<String>),
}

fn find_in<'a>(schema: &'a FakeSchema, table: &str) -> Option<(&'a FakeSchema, &'a FakeTable)> {
    schema
        .tables
        .iter()
        .find(|candidate| candidate.name.eq_ignore_ascii_case(table))
        .map(|found| (schema, found))
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
// Text helpers
// ---------------------------------------------------------------------------

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$' || byte >= 0x80
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
    // Strip a schema qualifier: `db`.`tbl` -> tbl
    stripped
        .rsplit('.')
        .next()
        .unwrap_or(stripped)
        .trim_matches(|c| c == '`' || c == '"')
        .to_string()
}

fn strip_string_literal(text: &str) -> Option<String> {
    let text = text.trim();
    let quote = text.as_bytes().first().copied()?;
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    if text.len() < 2 || text.as_bytes().last().copied() != Some(quote) {
        return None;
    }
    Some(text[1..text.len() - 1].to_string())
}

fn text_of(argument: &str) -> String {
    let trimmed = argument.trim();
    if let Some(literal) = strip_string_literal(trimmed) {
        return literal;
    }
    trimmed.to_string()
}

/// Drop a `GLOBAL.` / `SESSION.` / `LOCAL.` scope qualifier from a system
/// variable reference, ignoring case (`@@GLOBAL.version` == `@@global.version`).
fn strip_variable_scope(name: &str) -> &str {
    if let Some((head, tail)) = name.split_once('.') {
        let head = head.trim();
        if head.eq_ignore_ascii_case("global")
            || head.eq_ignore_ascii_case("session")
            || head.eq_ignore_ascii_case("local")
        {
            return tail.trim();
        }
    }
    name.trim()
}

/// Split on a separator that is not nested in parentheses or quotes.
fn split_top_level(text: &str, separator: char) -> Vec<&str> {
    let bytes = text.as_bytes();
    let separator = separator as u8;
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    let mut depth = 0i32;
    let mut in_single = false;
    let mut in_double = false;
    let mut in_backtick = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_single {
            if byte == b'\\' && index + 1 < bytes.len() {
                index += 2;
                continue;
            }
            if byte == b'\'' {
                in_single = false;
            }
            index += 1;
            continue;
        }
        if in_double {
            if byte == b'\\' && index + 1 < bytes.len() {
                index += 2;
                continue;
            }
            if byte == b'"' {
                in_double = false;
            }
            index += 1;
            continue;
        }
        if in_backtick {
            if byte == b'`' {
                in_backtick = false;
            }
            index += 1;
            continue;
        }
        match byte {
            b'\'' => in_single = true,
            b'"' => in_double = true,
            b'`' => in_backtick = true,
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && byte == separator {
            parts.push(&text[start..index]);
            start = index + 1;
        }
        index += 1;
    }
    parts.push(&text[start..]);
    parts
}

/// Byte offset of the first top-level occurrence of `keyword`, if any.
fn find_keyword(haystack: &str, keyword: &str) -> Option<usize> {
    let upper = haystack.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    let needle = keyword.to_ascii_uppercase();
    let needle = needle.as_bytes();
    if needle.is_empty() || bytes.len() < needle.len() {
        return None;
    }
    let mut index = 0usize;
    let mut depth = 0i32;
    let mut in_single = false;
    let mut in_double = false;
    let mut in_backtick = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_single {
            if byte == b'\\' && index + 1 < bytes.len() {
                index += 2;
                continue;
            }
            if byte == b'\'' {
                in_single = false;
            }
            index += 1;
            continue;
        }
        if in_double {
            if byte == b'\\' && index + 1 < bytes.len() {
                index += 2;
                continue;
            }
            if byte == b'"' {
                in_double = false;
            }
            index += 1;
            continue;
        }
        if in_backtick {
            if byte == b'`' {
                in_backtick = false;
            }
            index += 1;
            continue;
        }
        match byte {
            b'\'' => in_single = true,
            b'"' => in_double = true,
            b'`' => in_backtick = true,
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        if depth == 0
            && bytes[index..].starts_with(needle)
            && (index == 0 || !is_ident_byte(bytes[index - 1]))
            && (index + needle.len() >= bytes.len() || !is_ident_byte(bytes[index + needle.len()]))
        {
            return Some(index);
        }
        index += 1;
    }
    None
}

/// Split a select item into its expression and optional alias.
fn split_alias(item: &str) -> (&str, Option<String>) {
    let item = item.trim();
    if let Some(index) = find_keyword(item, "AS") {
        let expression = item[..index].trim();
        let alias = unquote_ident(item[index + 2..].trim());
        if !expression.is_empty() && !alias.is_empty() {
            return (expression, Some(alias));
        }
    }
    // `expr alias` form: no operators, exactly two whitespace separated tokens.
    let parts: Vec<&str> = item.split_whitespace().collect();
    if parts.len() == 2 && !parts[0].contains('(') && !parts[0].contains('@') {
        return (parts[0], Some(unquote_ident(parts[1])));
    }
    (item, None)
}

/// Parse `[schema.]table` plus whatever follows it.
fn parse_table_ref(text: &str) -> (Option<String>, String, &str) {
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
        if !in_backtick && !(is_ident_byte(byte) || byte == b'.') {
            break;
        }
        index += 1;
    }
    let reference = &text[..index];
    let remainder = &text[index..];
    let cleaned = reference.replace('`', "");
    let (schema, table) = match cleaned.split_once('.') {
        Some((schema, table)) => (Some(schema.to_string()), table.to_string()),
        None => (None, cleaned),
    };
    (schema, table, remainder.trim_start())
}

fn parse_limit(remainder: &str) -> Option<usize> {
    let index = find_keyword(remainder, "LIMIT")?;
    let tail = remainder[index + 5..].trim_start();
    let digits: String = tail
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == ',' || *c == ' ')
        .collect();
    let first = digits.split(',').next()?.trim();
    first.parse::<usize>().ok()
}

fn extract_string_literals(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut literals = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() && literals.len() < 8 {
        if bytes[index] == b'\'' {
            let mut content = Vec::new();
            let mut cursor = index + 1;
            while cursor < bytes.len() {
                if bytes[cursor] == b'\\' && cursor + 1 < bytes.len() {
                    content.push(bytes[cursor + 1]);
                    cursor += 2;
                    continue;
                }
                if bytes[cursor] == b'\'' {
                    break;
                }
                content.push(bytes[cursor]);
                cursor += 1;
            }
            literals.push(String::from_utf8_lossy(&content).into_owned());
            index = cursor + 1;
        } else {
            index += 1;
        }
    }
    literals
}

/// Keep rows that mention one of the literals; if none of them occur anywhere
/// the filter is dropped rather than returning nothing.
fn filter_rows<'a>(
    rows: &'a [Vec<Option<String>>],
    literals: &[String],
) -> Vec<&'a Vec<Option<String>>> {
    if literals.is_empty() {
        return rows.iter().collect();
    }
    let relevant: Vec<&String> = literals
        .iter()
        .filter(|literal| {
            rows.iter().any(|row| {
                row.iter().any(|cell| {
                    cell.as_deref()
                        .is_some_and(|value| value.eq_ignore_ascii_case(literal))
                })
            })
        })
        .collect();
    if relevant.is_empty() {
        return rows.iter().collect();
    }
    rows.iter()
        .filter(|row| {
            row.iter().any(|cell| {
                cell.as_deref().is_some_and(|value| {
                    relevant
                        .iter()
                        .any(|literal| value.eq_ignore_ascii_case(literal))
                })
            })
        })
        .collect()
}

fn parse_like(remainder: &str) -> Option<String> {
    let index = find_keyword(remainder, "LIKE")?;
    let tail = remainder[index + 4..].trim_start();
    strip_string_literal(tail)
}

fn parse_show_scope(tail: &str) -> (Option<String>, Option<String>) {
    let mut rest = tail.trim();
    let mut schema = None;
    for prefix in ["FROM ", "from ", "IN ", "in "] {
        if let Some(after) = rest.strip_prefix(prefix) {
            let (reference_schema, reference, remaining) = parse_table_ref(after);
            schema = reference_schema.or(Some(reference));
            rest = remaining;
            break;
        }
    }
    let pattern = parse_like(rest);
    (schema, pattern)
}

fn pattern_matches(pattern: Option<&str>, candidate: &str) -> bool {
    let Some(pattern) = pattern else {
        return true;
    };
    let lowered_candidate = candidate.to_lowercase();
    let lowered_pattern = pattern.to_lowercase();
    if let Some(prefix) = lowered_pattern.strip_suffix('%') {
        return lowered_candidate.starts_with(prefix);
    }
    lowered_candidate == lowered_pattern
}

fn is_numeric_expression(expression: &str) -> bool {
    expression
        .chars()
        .all(|c| c.is_ascii_digit() || c == '.' || c == '-' || c == '+')
}

fn sql_datetime(iso_timestamp: &str) -> String {
    if iso_timestamp.len() >= 19 {
        format!("{} {}", &iso_timestamp[0..10], &iso_timestamp[11..19])
    } else {
        iso_timestamp.to_string()
    }
}

// ---------------------------------------------------------------------------
// Catalog construction
// ---------------------------------------------------------------------------

fn row(values: &[&str]) -> Vec<Option<String>> {
    values
        .iter()
        .map(|value| Some((*value).to_string()))
        .collect()
}

fn variables(version: &str) -> Vec<(String, String)> {
    let entries: &[(&str, &str)] = &[
        ("version", version),
        ("version_comment", "MySQL Community Server - GPL"),
        ("version_compile_os", "Linux"),
        ("version_compile_machine", "x86_64"),
        ("protocol_version", "10"),
        ("hostname", "db-prod-01"),
        ("port", "3306"),
        ("socket", "/var/lib/mysql/mysql.sock"),
        ("datadir", "/var/lib/mysql/"),
        ("basedir", "/usr/"),
        ("tmpdir", "/tmp"),
        ("innodb_version", version),
        ("character_set_server", "utf8mb4"),
        ("character_set_client", "utf8mb4"),
        ("character_set_connection", "utf8mb4"),
        ("character_set_results", "utf8mb4"),
        ("collation_server", "utf8mb4_0900_ai_ci"),
        ("collation_connection", "utf8mb4_0900_ai_ci"),
        ("max_connections", "151"),
        ("max_allowed_packet", "67108864"),
        ("max_connect_errors", "100"),
        ("wait_timeout", "28800"),
        ("interactive_timeout", "28800"),
        ("net_write_timeout", "60"),
        ("net_read_timeout", "30"),
        (
            "sql_mode",
            "ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION",
        ),
        ("lower_case_table_names", "0"),
        ("system_time_zone", "UTC"),
        ("time_zone", "SYSTEM"),
        ("transaction_isolation", "REPEATABLE-READ"),
        ("tx_isolation", "REPEATABLE-READ"),
        ("autocommit", "ON"),
        ("have_ssl", "DISABLED"),
        ("have_openssl", "DISABLED"),
        ("license", "GPL"),
        ("server_id", "1"),
        ("auto_increment_increment", "1"),
        ("auto_increment_offset", "1"),
        ("default_storage_engine", "InnoDB"),
        ("secure_auth", "ON"),
        ("local_infile", "OFF"),
        ("skip_networking", "OFF"),
        ("pid_file", "/var/run/mysqld/mysqld.pid"),
        ("log_error", "/var/log/mysql/error.log"),
        ("performance_schema", "ON"),
        ("innodb_buffer_pool_size", "134217728"),
    ];
    entries
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

fn status_variables() -> Vec<(String, String)> {
    let entries: &[(&str, &str)] = &[
        ("Uptime", "864000"),
        ("Threads_connected", "3"),
        ("Threads_running", "1"),
        ("Threads_created", "12"),
        ("Connections", "1842"),
        ("Aborted_connects", "7"),
        ("Questions", "91234"),
        ("Slow_queries", "0"),
        ("Queries_per_second_avg", "0.105"),
        ("Bytes_received", "8842133"),
        ("Bytes_sent", "192834771"),
        ("Innodb_buffer_pool_reads", "1283"),
        ("Innodb_rows_read", "99213"),
        ("Com_select", "81233"),
        ("Com_insert", "412"),
        ("Com_update", "98"),
        ("Com_delete", "21"),
        ("Open_tables", "112"),
        ("Opened_tables", "1533"),
        ("Table_locks_waited", "0"),
        ("Ssl_cipher", ""),
    ];
    entries
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

fn table(
    name: &'static str,
    engine: &'static str,
    comment: &'static str,
    columns: Vec<FakeColumn>,
    rows: Vec<Vec<Option<String>>>,
) -> FakeTable {
    FakeTable {
        name,
        engine,
        comment,
        columns,
        rows,
    }
}

fn information_schema_tables() -> Vec<FakeTable> {
    let string = column_type::VAR_STRING;
    let number = column_type::LONGLONG;
    vec![
        table(
            "SCHEMATA",
            "MEMORY",
            "",
            vec![
                FakeColumn::new("CATALOG_NAME", "varchar(512)", string),
                FakeColumn::new("SCHEMA_NAME", "varchar(64)", string),
                FakeColumn::new("DEFAULT_CHARACTER_SET_NAME", "varchar(64)", string),
                FakeColumn::new("DEFAULT_COLLATION_NAME", "varchar(64)", string),
                FakeColumn::new("SQL_PATH", "varchar(512)", string),
                FakeColumn::new("DEFAULT_ENCRYPTION", "varchar(3)", string),
            ],
            Vec::new(),
        ),
        table(
            "TABLES",
            "MEMORY",
            "",
            vec![
                FakeColumn::new("TABLE_CATALOG", "varchar(512)", string),
                FakeColumn::new("TABLE_SCHEMA", "varchar(64)", string),
                FakeColumn::new("TABLE_NAME", "varchar(64)", string),
                FakeColumn::new("TABLE_TYPE", "varchar(64)", string),
                FakeColumn::new("ENGINE", "varchar(64)", string),
                FakeColumn::new("VERSION", "int", number),
                FakeColumn::new("ROW_FORMAT", "varchar(10)", string),
                FakeColumn::new("TABLE_ROWS", "bigint unsigned", number),
                FakeColumn::new("AVG_ROW_LENGTH", "bigint unsigned", number),
                FakeColumn::new("DATA_LENGTH", "bigint unsigned", number),
                FakeColumn::new("MAX_DATA_LENGTH", "bigint unsigned", number),
                FakeColumn::new("INDEX_LENGTH", "bigint unsigned", number),
                FakeColumn::new("DATA_FREE", "bigint unsigned", number),
                FakeColumn::new("AUTO_INCREMENT", "bigint unsigned", number),
                FakeColumn::new("CREATE_TIME", "datetime", string),
                FakeColumn::new("UPDATE_TIME", "datetime", string),
                FakeColumn::new("CHECK_TIME", "datetime", string),
                FakeColumn::new("TABLE_COLLATION", "varchar(64)", string),
                FakeColumn::new("CHECKSUM", "bigint", number),
                FakeColumn::new("CREATE_OPTIONS", "varchar(256)", string),
                FakeColumn::new("TABLE_COMMENT", "text", string),
            ],
            Vec::new(),
        ),
        table(
            "COLUMNS",
            "MEMORY",
            "",
            vec![
                FakeColumn::new("TABLE_CATALOG", "varchar(512)", string),
                FakeColumn::new("TABLE_SCHEMA", "varchar(64)", string),
                FakeColumn::new("TABLE_NAME", "varchar(64)", string),
                FakeColumn::new("COLUMN_NAME", "varchar(64)", string),
                FakeColumn::new("ORDINAL_POSITION", "bigint unsigned", number),
                FakeColumn::new("COLUMN_DEFAULT", "text", string),
                FakeColumn::new("IS_NULLABLE", "varchar(3)", string),
                FakeColumn::new("DATA_TYPE", "varchar(64)", string),
                FakeColumn::new("CHARACTER_MAXIMUM_LENGTH", "bigint", number),
                FakeColumn::new("CHARACTER_OCTET_LENGTH", "bigint", number),
                FakeColumn::new("NUMERIC_PRECISION", "bigint unsigned", number),
                FakeColumn::new("NUMERIC_SCALE", "bigint unsigned", number),
                FakeColumn::new("DATETIME_PRECISION", "int unsigned", number),
                FakeColumn::new("CHARACTER_SET_NAME", "varchar(64)", string),
                FakeColumn::new("COLLATION_NAME", "varchar(64)", string),
                FakeColumn::new("COLUMN_TYPE", "text", string),
                FakeColumn::new("COLUMN_KEY", "varchar(3)", string),
                FakeColumn::new("EXTRA", "varchar(256)", string),
                FakeColumn::new("PRIVILEGES", "varchar(154)", string),
                FakeColumn::new("COLUMN_COMMENT", "text", string),
                FakeColumn::new("GENERATION_EXPRESSION", "text", string),
            ],
            Vec::new(),
        ),
        table(
            "STATISTICS",
            "MEMORY",
            "",
            vec![
                FakeColumn::new("TABLE_CATALOG", "varchar(512)", string),
                FakeColumn::new("TABLE_SCHEMA", "varchar(64)", string),
                FakeColumn::new("TABLE_NAME", "varchar(64)", string),
                FakeColumn::new("NON_UNIQUE", "int", number),
                FakeColumn::new("INDEX_SCHEMA", "varchar(64)", string),
                FakeColumn::new("INDEX_NAME", "varchar(64)", string),
                FakeColumn::new("SEQ_IN_INDEX", "bigint unsigned", number),
                FakeColumn::new("COLUMN_NAME", "varchar(64)", string),
                FakeColumn::new("COLLATION", "varchar(1)", string),
                FakeColumn::new("CARDINALITY", "bigint", number),
                FakeColumn::new("SUB_PART", "bigint", number),
                FakeColumn::new("PACKED", "varchar(10)", string),
                FakeColumn::new("NULLABLE", "varchar(3)", string),
                FakeColumn::new("INDEX_TYPE", "varchar(16)", string),
                FakeColumn::new("COMMENT", "varchar(16)", string),
            ],
            Vec::new(),
        ),
        table(
            "ENGINES",
            "MEMORY",
            "",
            vec![
                FakeColumn::new("ENGINE", "varchar(64)", string),
                FakeColumn::new("SUPPORT", "varchar(8)", string),
                FakeColumn::new("COMMENT", "varchar(80)", string),
                FakeColumn::new("TRANSACTIONS", "varchar(3)", string),
                FakeColumn::new("XA", "varchar(3)", string),
                FakeColumn::new("SAVEPOINTS", "varchar(3)", string),
            ],
            Vec::new(),
        ),
        table(
            "PROCESSLIST",
            "MEMORY",
            "",
            vec![
                FakeColumn::new("ID", "bigint unsigned", number),
                FakeColumn::new("USER", "varchar(32)", string),
                FakeColumn::new("HOST", "varchar(261)", string),
                FakeColumn::new("DB", "varchar(64)", string),
                FakeColumn::new("COMMAND", "varchar(16)", string),
                FakeColumn::new("TIME", "int", number),
                FakeColumn::new("STATE", "varchar(64)", string),
                FakeColumn::new("INFO", "longtext", string),
            ],
            Vec::new(),
        ),
        table(
            "USER_PRIVILEGES",
            "MEMORY",
            "",
            vec![
                FakeColumn::new("GRANTEE", "varchar(292)", string),
                FakeColumn::new("TABLE_CATALOG", "varchar(512)", string),
                FakeColumn::new("PRIVILEGE_TYPE", "varchar(64)", string),
                FakeColumn::new("IS_GRANTABLE", "varchar(3)", string),
            ],
            Vec::new(),
        ),
        table(
            "CHARACTER_SETS",
            "MEMORY",
            "",
            vec![
                FakeColumn::new("CHARACTER_SET_NAME", "varchar(64)", string),
                FakeColumn::new("DEFAULT_COLLATE_NAME", "varchar(64)", string),
                FakeColumn::new("DESCRIPTION", "varchar(60)", string),
                FakeColumn::new("MAXLEN", "int", number),
            ],
            Vec::new(),
        ),
        table(
            "KEY_COLUMN_USAGE",
            "MEMORY",
            "",
            vec![
                FakeColumn::new("CONSTRAINT_CATALOG", "varchar(64)", string),
                FakeColumn::new("CONSTRAINT_SCHEMA", "varchar(64)", string),
                FakeColumn::new("CONSTRAINT_NAME", "varchar(64)", string),
                FakeColumn::new("TABLE_CATALOG", "varchar(64)", string),
                FakeColumn::new("TABLE_SCHEMA", "varchar(64)", string),
                FakeColumn::new("TABLE_NAME", "varchar(64)", string),
                FakeColumn::new("COLUMN_NAME", "varchar(64)", string),
                FakeColumn::new("ORDINAL_POSITION", "bigint unsigned", number),
                FakeColumn::new("POSITION_IN_UNIQUE_CONSTRAINT", "bigint unsigned", number),
                FakeColumn::new("REFERENCED_TABLE_SCHEMA", "varchar(64)", string),
                FakeColumn::new("REFERENCED_TABLE_NAME", "varchar(64)", string),
                FakeColumn::new("REFERENCED_COLUMN_NAME", "varchar(64)", string),
            ],
            Vec::new(),
        ),
        table(
            "VIEWS",
            "MEMORY",
            "",
            vec![
                FakeColumn::new("TABLE_CATALOG", "varchar(64)", string),
                FakeColumn::new("TABLE_SCHEMA", "varchar(64)", string),
                FakeColumn::new("TABLE_NAME", "varchar(64)", string),
                FakeColumn::new("VIEW_DEFINITION", "longtext", string),
            ],
            Vec::new(),
        ),
    ]
}

fn mysql_schema() -> FakeSchema {
    let string = column_type::VAR_STRING;
    let number = column_type::LONGLONG;
    FakeSchema {
        name: "mysql",
        tables: vec![
            table(
                "user",
                "InnoDB",
                "Users and global privileges",
                vec![
                    FakeColumn::new("Host", "char(255)", string).not_null(),
                    FakeColumn::new("User", "char(32)", string).not_null(),
                    FakeColumn::new("Select_priv", "enum('N','Y')", string),
                    FakeColumn::new("Insert_priv", "enum('N','Y')", string),
                    FakeColumn::new("Update_priv", "enum('N','Y')", string),
                    FakeColumn::new("Delete_priv", "enum('N','Y')", string),
                    FakeColumn::new("Create_priv", "enum('N','Y')", string),
                    FakeColumn::new("Drop_priv", "enum('N','Y')", string),
                    FakeColumn::new("plugin", "char(64)", string),
                    FakeColumn::new("authentication_string", "text", string),
                ],
                vec![
                    row(&[
                        "localhost",
                        "root",
                        "Y",
                        "Y",
                        "Y",
                        "Y",
                        "Y",
                        "Y",
                        "caching_sha2_password",
                        "$A$005$abcdefghijklmnopqrstuvwxyz0123456789ABCDEF",
                    ]),
                    row(&[
                        "%",
                        "root",
                        "Y",
                        "Y",
                        "Y",
                        "Y",
                        "Y",
                        "Y",
                        "caching_sha2_password",
                        "$A$005$abcdefghijklmnopqrstuvwxyz0123456789ABCDEF",
                    ]),
                    row(&[
                        "%",
                        "app",
                        "Y",
                        "Y",
                        "Y",
                        "N",
                        "N",
                        "N",
                        "mysql_native_password",
                        "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19",
                    ]),
                ],
            ),
            table(
                "db",
                "InnoDB",
                "Database privileges",
                vec![
                    FakeColumn::new("Host", "char(255)", string),
                    FakeColumn::new("Db", "char(64)", string),
                    FakeColumn::new("User", "char(32)", string),
                    FakeColumn::new("Select_priv", "enum('N','Y')", string),
                    FakeColumn::new("Insert_priv", "enum('N','Y')", string),
                ],
                vec![
                    row(&["%", "app_prod", "app", "Y", "Y"]),
                    row(&["%", "backup", "app", "Y", "N"]),
                ],
            ),
            table(
                "tables_priv",
                "InnoDB",
                "Table privileges",
                vec![
                    FakeColumn::new("Host", "char(255)", string),
                    FakeColumn::new("Db", "char(64)", string),
                    FakeColumn::new("User", "char(32)", string),
                    FakeColumn::new("Table_name", "char(64)", string),
                    FakeColumn::new(
                        "Table_priv",
                        "set('Select','Insert','Update','Delete')",
                        string,
                    ),
                ],
                vec![row(&[
                    "%",
                    "app_prod",
                    "app",
                    "users",
                    "Select,Insert,Update",
                ])],
            ),
            table(
                "columns_priv",
                "InnoDB",
                "Column privileges",
                vec![
                    FakeColumn::new("Host", "char(255)", string),
                    FakeColumn::new("Db", "char(64)", string),
                    FakeColumn::new("User", "char(32)", string),
                    FakeColumn::new("Table_name", "char(64)", string),
                    FakeColumn::new("Column_name", "char(64)", string),
                ],
                Vec::new(),
            ),
            table(
                "proc",
                "InnoDB",
                "Stored procedures",
                vec![
                    FakeColumn::new("db", "char(64)", string),
                    FakeColumn::new("name", "char(64)", string),
                    FakeColumn::new("type", "enum('FUNCTION','PROCEDURE')", string),
                ],
                Vec::new(),
            ),
            table(
                "func",
                "InnoDB",
                "User defined functions",
                vec![
                    FakeColumn::new("name", "char(64)", string),
                    FakeColumn::new("ret", "tinyint", number),
                ],
                Vec::new(),
            ),
        ],
    }
}

fn performance_schema() -> FakeSchema {
    let string = column_type::VAR_STRING;
    let number = column_type::LONGLONG;
    FakeSchema {
        name: "performance_schema",
        tables: vec![
            table(
                "threads",
                "PERFORMANCE_SCHEMA",
                "",
                vec![
                    FakeColumn::new("THREAD_ID", "bigint unsigned", number),
                    FakeColumn::new("NAME", "varchar(128)", string),
                    FakeColumn::new("TYPE", "varchar(10)", string),
                    FakeColumn::new("PROCESSLIST_ID", "bigint unsigned", number),
                    FakeColumn::new("PROCESSLIST_USER", "varchar(32)", string),
                    FakeColumn::new("PROCESSLIST_HOST", "varchar(261)", string),
                    FakeColumn::new("PROCESSLIST_DB", "varchar(64)", string),
                ],
                vec![
                    row(&[
                        "1",
                        "thread/sql/main",
                        "BACKGROUND",
                        "NULL",
                        "NULL",
                        "NULL",
                        "NULL",
                    ]),
                    row(&[
                        "42",
                        "thread/sql/one_connection",
                        "FOREGROUND",
                        "9",
                        "app",
                        "localhost",
                        "app_prod",
                    ]),
                ],
            ),
            table(
                "global_status",
                "PERFORMANCE_SCHEMA",
                "",
                vec![
                    FakeColumn::new("VARIABLE_NAME", "varchar(64)", string),
                    FakeColumn::new("VARIABLE_VALUE", "varchar(1024)", string),
                ],
                vec![
                    row(&["Uptime", "864000"]),
                    row(&["Threads_connected", "3"]),
                    row(&["Questions", "91234"]),
                ],
            ),
            table(
                "events_statements_summary_by_digest",
                "PERFORMANCE_SCHEMA",
                "",
                vec![
                    FakeColumn::new("SCHEMA_NAME", "varchar(64)", string),
                    FakeColumn::new("DIGEST_TEXT", "longtext", string),
                    FakeColumn::new("COUNT_STAR", "bigint unsigned", number),
                ],
                vec![
                    row(&["app_prod", "SELECT * FROM `users` WHERE `id` = ?", "812"]),
                    row(&[
                        "app_prod",
                        "SELECT * FROM `orders` WHERE `user_id` = ?",
                        "2331",
                    ]),
                ],
            ),
            table(
                "setup_consumers",
                "PERFORMANCE_SCHEMA",
                "",
                vec![
                    FakeColumn::new("NAME", "varchar(64)", string),
                    FakeColumn::new("ENABLED", "enum('YES','NO')", string),
                ],
                vec![row(&["global_instrumentation", "YES"])],
            ),
        ],
    }
}

fn sys_schema() -> FakeSchema {
    let string = column_type::VAR_STRING;
    let number = column_type::LONGLONG;
    FakeSchema {
        name: "sys",
        tables: vec![
            table(
                "version",
                "InnoDB",
                "Sys schema version",
                vec![
                    FakeColumn::new("sys_version", "varchar(128)", string),
                    FakeColumn::new("mysql_version", "varchar(128)", string),
                ],
                vec![row(&["2.1.1", "8.0.36"])],
            ),
            table(
                "schema_table_statistics",
                "InnoDB",
                "",
                vec![
                    FakeColumn::new("table_schema", "varchar(64)", string),
                    FakeColumn::new("table_name", "varchar(64)", string),
                    FakeColumn::new("total_latency", "varchar(11)", string),
                    FakeColumn::new("rows_fetched", "bigint unsigned", number),
                ],
                vec![
                    row(&["app_prod", "users", "1.23 s", "812"]),
                    row(&["app_prod", "orders", "3.11 s", "2331"]),
                ],
            ),
        ],
    }
}

fn app_prod_schema() -> FakeSchema {
    let string = column_type::VAR_STRING;
    let number = column_type::LONGLONG;
    let decimal = column_type::DOUBLE;
    let datetime = column_type::DATETIME;
    FakeSchema {
        name: "app_prod",
        tables: vec![
            table(
                "users",
                "InnoDB",
                "",
                vec![
                    FakeColumn::primary("id", "bigint unsigned", number),
                    FakeColumn::new("username", "varchar(64)", string),
                    FakeColumn::new("password", "varchar(255)", string),
                    FakeColumn::new("email", "varchar(128)", string),
                    FakeColumn::new("role", "varchar(32)", string),
                    FakeColumn::new("created_at", "datetime", datetime),
                ],
                vec![
                    row(&[
                        "1",
                        "admin",
                        "$2y$10$Qm9ndXNDb25jYXZlbm9uY2UwMTIzNDU2Nzg5",
                        "admin@example.com",
                        "administrator",
                        "2023-04-11 08:12:41",
                    ]),
                    row(&[
                        "2",
                        "alice",
                        "$2y$10$YWxpY2Vub25jZTAxMjM0NTY3ODkwYWJjZGVm",
                        "alice@example.com",
                        "user",
                        "2023-06-02 14:33:07",
                    ]),
                    row(&[
                        "3",
                        "bob",
                        "$2y$10$Ym9ibm9uY2UwMTIzNDU2Nzg5MGFiY2RlZmdo",
                        "bob@example.com",
                        "user",
                        "2023-11-19 22:05:55",
                    ]),
                ],
            ),
            table(
                "orders",
                "InnoDB",
                "",
                vec![
                    FakeColumn::primary("id", "bigint unsigned", number),
                    FakeColumn::new("user_id", "bigint unsigned", number),
                    FakeColumn::new("amount", "decimal(10,2)", decimal),
                    FakeColumn::new("status", "varchar(32)", string),
                    FakeColumn::new("created_at", "datetime", datetime),
                ],
                vec![
                    row(&["1001", "1", "199.00", "paid", "2024-01-03 10:11:12"]),
                    row(&["1002", "2", "49.90", "paid", "2024-01-04 11:22:33"]),
                    row(&["1003", "3", "0.00", "refunded", "2024-02-15 09:00:01"]),
                ],
            ),
            table(
                "sessions",
                "InnoDB",
                "",
                vec![
                    FakeColumn::primary("id", "bigint unsigned", number),
                    FakeColumn::new("user_id", "bigint unsigned", number),
                    FakeColumn::new("token", "varchar(128)", string),
                    FakeColumn::new("ip", "varchar(45)", string),
                ],
                vec![
                    row(&["9001", "1", "b7f1c0a1d9e04f4a8f4d0a5b6c7d8e9f", "10.0.0.5"]),
                    row(&["9002", "2", "0a1b2c3d4e5f60718293a4b5c6d7e8f9", "10.0.0.9"]),
                ],
            ),
            table(
                "products",
                "InnoDB",
                "",
                vec![
                    FakeColumn::primary("id", "bigint unsigned", number),
                    FakeColumn::new("sku", "varchar(64)", string),
                    FakeColumn::new("name", "varchar(128)", string),
                    FakeColumn::new("price", "decimal(10,2)", decimal),
                    FakeColumn::new("stock", "int", number),
                ],
                vec![
                    row(&["11", "SKU-1001", "Starter plan", "9.90", "999"]),
                    row(&["12", "SKU-1002", "Pro plan", "49.90", "499"]),
                ],
            ),
        ],
    }
}

fn backup_schema() -> FakeSchema {
    let string = column_type::VAR_STRING;
    let number = column_type::LONGLONG;
    FakeSchema {
        name: "backup",
        tables: vec![
            table(
                "users_backup",
                "MyISAM",
                "nightly dump",
                vec![
                    FakeColumn::primary("id", "bigint unsigned", number),
                    FakeColumn::new("username", "varchar(64)", string),
                    FakeColumn::new("password_hash", "varchar(255)", string),
                    FakeColumn::new("created_at", "datetime", string),
                ],
                vec![
                    row(&[
                        "1",
                        "admin",
                        "5f4dcc3b5aa765d61d8327deb882cf99",
                        "2023-04-11 08:12:41",
                    ]),
                    row(&[
                        "2",
                        "alice",
                        "098f6bcd4621d373cade4e832627b4f6",
                        "2023-06-02 14:33:07",
                    ]),
                    row(&[
                        "3",
                        "bob",
                        "e10adc3949ba59abbe56e057f20f883e",
                        "2023-11-19 22:05:55",
                    ]),
                ],
            ),
            table(
                "orders_2024",
                "MyISAM",
                "",
                vec![
                    FakeColumn::primary("id", "bigint unsigned", number),
                    FakeColumn::new("user_id", "bigint unsigned", number),
                    FakeColumn::new("amount", "decimal(10,2)", column_type::DOUBLE),
                    FakeColumn::new("status", "varchar(32)", string),
                ],
                vec![
                    row(&["1001", "1", "199.00", "paid"]),
                    row(&["1002", "2", "49.90", "paid"]),
                ],
            ),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ctx() -> QueryContext {
        QueryContext {
            current_db: "app_prod".to_string(),
            username: "root".to_string(),
            connection_id: 42,
            server_version: "8.0.36".to_string(),
        }
    }

    fn database() -> FakeDatabase {
        FakeDatabase::new("8.0.36")
    }

    #[test]
    fn catalog_contains_the_documented_schemas() {
        let database = database();
        let names = database.schema_names();
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
        assert!(database.has_schema("APP_PROD"));
        assert!(!database.has_schema("nope"));
    }

    #[test]
    fn show_databases_lists_every_schema() {
        let database = database();
        match database.dispatch("SHOW DATABASES", &ctx()) {
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
        let database = database();
        match database.dispatch("SELECT 1", &ctx()) {
            QueryResult::ResultSet(set) => {
                assert_eq!(set.columns.len(), 1);
                assert_eq!(set.rows.len(), 1);
                assert_eq!(set.rows[0][0].as_deref(), Some("1"));
            }
            other => panic!("unexpected {other:?}"),
        }
        match database.dispatch("SELECT 1;", &ctx()) {
            QueryResult::ResultSet(set) => assert_eq!(set.rows[0][0].as_deref(), Some("1")),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn scalar_functions_answer() {
        let database = database();
        let cases = [
            ("SELECT VERSION()", "8.0.36"),
            ("SELECT @@version", "8.0.36"),
            (
                "SELECT @@global.version_comment",
                "MySQL Community Server - GPL",
            ),
            ("SELECT DATABASE()", "app_prod"),
            ("SELECT USER()", "root@%"),
            ("SELECT CURRENT_USER()", "root@localhost"),
            ("SELECT CONNECTION_ID()", "42"),
            ("SELECT 1,2", "1"),
        ];
        for (sql, expected) in cases {
            match database.dispatch(sql, &ctx()) {
                QueryResult::ResultSet(set) => {
                    assert_eq!(set.rows.len(), 1, "{sql}");
                    assert_eq!(set.rows[0][0].as_deref(), Some(expected), "{sql}");
                }
                other => panic!("{sql} -> {other:?}"),
            }
        }
    }

    #[test]
    fn multi_column_select() {
        let database = database();
        match database.dispatch("SELECT 1, VERSION(), USER()", &ctx()) {
            QueryResult::ResultSet(set) => {
                assert_eq!(set.columns.len(), 3);
                assert_eq!(set.rows[0][2].as_deref(), Some("root@%"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn select_from_fake_table_with_projection_and_limit() {
        let database = database();
        match database.dispatch("SELECT username FROM users LIMIT 2", &ctx()) {
            QueryResult::ResultSet(set) => {
                assert_eq!(set.columns.len(), 1);
                assert_eq!(set.columns[0].name, "username");
                assert_eq!(set.rows.len(), 2);
                assert_eq!(set.rows[0][0].as_deref(), Some("admin"));
            }
            other => panic!("unexpected {other:?}"),
        }
        match database.dispatch("SELECT * FROM users", &ctx()) {
            QueryResult::ResultSet(set) => {
                assert_eq!(set.columns.len(), 6);
                assert_eq!(set.rows.len(), 3);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn information_schema_is_queryable() {
        let database = database();
        match database.dispatch(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'app_prod'",
            &ctx(),
        ) {
            QueryResult::ResultSet(set) => {
                assert_eq!(set.columns.len(), 1);
                assert_eq!(
                    set.columns[0].name, "TABLE_NAME",
                    "information_schema keeps its upper case column names, like MySQL"
                );
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
        match database.dispatch("SELECT COUNT(*) FROM information_schema.columns", &ctx()) {
            QueryResult::ResultSet(set) => {
                let value = set.rows[0][0].clone().unwrap_or_default();
                assert!(value.parse::<usize>().expect("number") > 10, "got {value}");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn show_tables_and_columns() {
        let database = database();
        match database.dispatch("SHOW TABLES", &ctx()) {
            QueryResult::ResultSet(set) => {
                assert_eq!(set.columns[0].name, "Tables_in_app_prod");
                assert_eq!(set.rows.len(), 4);
            }
            other => panic!("unexpected {other:?}"),
        }
        match database.dispatch("SHOW TABLES FROM mysql LIKE 'u%'", &ctx()) {
            QueryResult::ResultSet(set) => {
                assert_eq!(set.columns[0].name, "Tables_in_mysql");
                assert_eq!(set.rows.len(), 1);
                assert_eq!(set.rows[0][0].as_deref(), Some("user"));
            }
            other => panic!("unexpected {other:?}"),
        }
        match database.dispatch("SHOW COLUMNS FROM users", &ctx()) {
            QueryResult::ResultSet(set) => {
                let names: Vec<String> = set.columns.iter().map(|c| c.name.clone()).collect();
                assert_eq!(names, ["Field", "Type", "Null", "Key", "Default", "Extra"]);
                assert_eq!(set.rows.len(), 6);
            }
            other => panic!("unexpected {other:?}"),
        }
        match database.dispatch("DESCRIBE orders", &ctx()) {
            QueryResult::ResultSet(set) => assert_eq!(set.rows.len(), 5),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn show_variables_and_status() {
        let database = database();
        match database.dispatch("SHOW VARIABLES", &ctx()) {
            QueryResult::ResultSet(set) => assert!(set.rows.len() > 20),
            other => panic!("unexpected {other:?}"),
        }
        match database.dispatch("SHOW VARIABLES LIKE 'version%'", &ctx()) {
            QueryResult::ResultSet(set) => {
                assert!(set.rows.len() >= 2);
                assert!(
                    set.rows
                        .iter()
                        .all(|row| row[0].as_deref().unwrap().starts_with("version"))
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        match database.dispatch("SHOW GLOBAL STATUS", &ctx()) {
            QueryResult::ResultSet(set) => assert!(set.rows.len() > 10),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn use_statement_resolves_schemas() {
        let database = database();
        assert!(matches!(
            database.dispatch("USE mysql", &ctx()),
            QueryResult::Ok { .. }
        ));
        match database.dispatch("USE does_not_exist", &ctx()) {
            QueryResult::Error { code, .. } => assert_eq!(code, 1049),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn dml_is_simulated_never_executed() {
        for sql in [
            "INSERT INTO users VALUES (1,'x')",
            "UPDATE users SET role='admin'",
            "DELETE FROM users",
            "DROP TABLE users",
            "CREATE TABLE evil (id int)",
            "TRUNCATE users",
            "SET @a = 1",
            "BEGIN",
            "COMMIT",
        ] {
            match database().dispatch(sql, &ctx()) {
                QueryResult::Ok { .. } => {}
                other => panic!("{sql} -> {other:?}"),
            }
        }
        // And the catalog is untouched afterwards.
        let database = database();
        match database.dispatch("SELECT * FROM users", &ctx()) {
            QueryResult::ResultSet(set) => assert_eq!(set.rows.len(), 3),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn load_data_is_refused() {
        match database().dispatch(
            "LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE users",
            &ctx(),
        ) {
            QueryResult::Error { code, .. } => assert_eq!(code, 1148),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn garbage_returns_a_parse_error() {
        match database().dispatch("!!! not sql", &ctx()) {
            QueryResult::Error { code, .. } => assert_eq!(code, 1064),
            other => panic!("unexpected {other:?}"),
        }
        match database().dispatch("   ", &ctx()) {
            QueryResult::Error { code, .. } => assert_eq!(code, 1065),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn explain_and_show_create() {
        let database = database();
        match database.dispatch("EXPLAIN SELECT * FROM users", &ctx()) {
            QueryResult::ResultSet(set) => assert_eq!(set.rows.len(), 1),
            other => panic!("unexpected {other:?}"),
        }
        match database.dispatch("SHOW CREATE TABLE users", &ctx()) {
            QueryResult::ResultSet(set) => {
                let ddl = set.rows[0][1].clone().unwrap();
                assert!(ddl.contains("CREATE TABLE `users`"));
            }
            other => panic!("unexpected {other:?}"),
        }
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
        ];
        for sql in hostile {
            let _ = database.dispatch(sql, &context);
        }
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
        });
        assert_eq!(set.kind(), "RESULTSET(cols=1,rows=1)");
    }

    #[test]
    fn unbounded_result_sets_are_capped() {
        let database = database();
        match database.dispatch(
            "SELECT * FROM information_schema.columns LIMIT 100000",
            &ctx(),
        ) {
            QueryResult::ResultSet(set) => assert!(set.rows.len() <= MAX_RESULT_ROWS),
            other => panic!("unexpected {other:?}"),
        }
    }
}
