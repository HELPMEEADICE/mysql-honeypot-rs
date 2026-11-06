// SPDX-License-Identifier: GPL-3.0-only
//! The per-session virtual database layer.
//!
//! Every session gets its own copy-on-write view of the catalog. A session that
//! never writes pays nothing at all ([`SessionState::overlay`] stays `None`); the
//! first `INSERT`, `UPDATE`, `DELETE` or DDL clones exactly one table into the
//! session's overlay and mutates that copy. Two attackers therefore never see
//! each other's rows, and a `DROP TABLE` in one session cannot break another.
//!
//! Strict budgets bound what a single session may create: table count, rows per
//! table, total rows, individual string length and total overlay bytes. Without
//! them, `CREATE TABLE`/`INSERT` loops would be a trivially cheap memory
//! exhaustion attack against a long-lived process.
//!
//! # Accounting contract
//!
//! SQL executors never touch [`FakeTable::rows`] directly. Every write goes
//! through one of [`SessionState::insert_rows`], [`SessionState::replace_rows`],
//! [`SessionState::update_rows`], [`SessionState::delete_rows`] or
//! [`SessionState::truncate_table`], and each of those upholds two invariants:
//!
//! * **After success** the byte and row counters equal the real content of the
//!   overlay — including row containers, cell slots, column definitions, schema
//!   shells, `DROP` tombstones and `SET @var` values. [`SessionState::recount`]
//!   recomputes both from scratch and must always agree;
//! * **After failure** nothing changed at all. Every limit is validated against
//!   the *would-be* state before the first byte is written, so a rejected
//!   statement can never leave a half-applied row set behind.

use super::FakeTable;

/// Bytes charged for the container of one stored row, on top of its cells.
const ROW_OVERHEAD: usize = 8;

/// Bytes charged for one cell slot, on top of its string payload.
const CELL_OVERHEAD: usize = 8;

/// Bytes charged for one column definition, on top of its strings.
const COLUMN_OVERHEAD: usize = 8;

/// Bytes charged for one table shell, on top of its name and columns.
const TABLE_OVERHEAD: usize = 16;

/// Bytes charged for one schema shell, on top of its name.
const SCHEMA_OVERHEAD: usize = 16;

/// Bytes charged for one tombstone, on top of the two names it stores.
const TOMBSTONE_OVERHEAD: usize = 16;

/// Everything the state layer may create for one session.
#[derive(Debug, Clone, Copy)]
pub struct StateBudgets {
    /// Whether writes are simulated at all.
    pub enabled: bool,
    /// Maximum number of tables the session may create, per schema, and also the
    /// maximum number of schemas the overlay may hold.
    pub max_tables: usize,
    /// Maximum rows a single table may reach.
    pub max_rows_per_table: usize,
    /// Maximum rows across the whole overlay.
    pub max_total_rows: usize,
    /// Maximum bytes in one stored string.
    pub max_string_bytes: usize,
    /// Maximum bytes of overlay storage, tombstones included.
    pub max_total_bytes: usize,
    /// Maximum number of `SET @var` values.
    pub max_user_variables: usize,
    /// Maximum number of `DROP` tombstones a session may accumulate.
    pub max_tombstones: usize,
    /// Maximum columns one `CREATE TABLE` may define.
    pub max_columns_per_table: usize,
}

impl Default for StateBudgets {
    fn default() -> Self {
        Self {
            enabled: true,
            max_tables: 32,
            max_rows_per_table: 1_000,
            max_total_rows: 2_000,
            max_string_bytes: 1_024,
            max_total_bytes: 64 * 1_024,
            max_user_variables: 64,
            max_tombstones: 64,
            max_columns_per_table: 128,
        }
    }
}

/// Why a write could not be simulated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    /// Stateful simulation is switched off; the write is answered with OK but
    /// never applied.
    Disabled,
    /// `ER_TOO_MANY_TABLES`
    TooManyTables,
    /// `ER_RECORD_FILE_FULL`
    TableFull(String),
    /// `ER_DATA_TOO_LONG`
    ValueTooLong(String, usize),
    /// The overlay byte, tombstone or row budget is exhausted.
    BudgetExhausted,
    /// `ER_TOO_MANY_USER_LEVEL_VARS`
    TooManyVariables,
    /// `ER_TOO_MANY_FIELDS`
    TooManyColumns,
    /// `ER_NO_SUCH_TABLE`
    NoTable(String),
    /// `ER_CANT_CREATE_DB` / schema budget exhausted.
    NoSchema(String),
}

impl StateError {
    /// MySQL error code.
    pub fn code(&self) -> u16 {
        match self {
            // Reported as a plain OK with no state change; never an error frame.
            Self::Disabled => 0,
            Self::TooManyTables => 1116,
            Self::TableFull(_) | Self::BudgetExhausted => 1114,
            Self::ValueTooLong(_, _) => 1406,
            Self::TooManyVariables => 1769,
            Self::TooManyColumns => 1117,
            Self::NoTable(_) => 1146,
            Self::NoSchema(_) => 1049,
        }
    }

    /// `SQLSTATE` for the error.
    pub fn sqlstate(&self) -> &'static str {
        match self {
            Self::Disabled => "00000",
            Self::TooManyTables | Self::TableFull(_) | Self::BudgetExhausted => "HY000",
            Self::ValueTooLong(_, _) => "22001",
            Self::TooManyVariables => "HY000",
            Self::TooManyColumns => "42000",
            Self::NoTable(_) => "42S02",
            Self::NoSchema(_) => "42000",
        }
    }

    /// Message MySQL would print.
    pub fn message(&self) -> String {
        match self {
            Self::Disabled => String::new(),
            Self::TooManyTables => "Too many tables".to_string(),
            Self::TableFull(name) => {
                format!("The table '{}' is full", crate::util::clip(name, 64))
            }
            Self::ValueTooLong(column, limit) => format!(
                "Data too long for column '{}' at row 1 (limit {limit} bytes)",
                crate::util::clip(column, 64)
            ),
            Self::BudgetExhausted => "The table is full".to_string(),
            Self::TooManyVariables => "Variable @{} can't be set to the value of NULL".to_string(),
            Self::TooManyColumns => "Too many columns".to_string(),
            Self::NoTable(name) => {
                format!("Table '{}' doesn't exist", crate::util::clip(name, 128))
            }
            Self::NoSchema(name) => {
                format!("Unknown database '{}'", crate::util::clip(name, 64))
            }
        }
    }
}

/// What an `UPDATE` actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UpdateOutcome {
    /// Rows the `WHERE` clause selected.
    pub matched: usize,
    /// Rows whose stored content actually changed.
    pub changed: usize,
}

/// The cells one `UPDATE` rewrites in one row: `(column index, new value)`.
pub type RowChanges = Vec<(usize, Option<String>)>;

/// One planned row rewrite: the row index and the cells to replace.
///
/// The state layer applies a whole `UPDATE` as one unit, so a statement either
/// rewrites every planned row or none of them.
pub type PendingRowUpdate = (usize, RowChanges);

/// What a `REPLACE` actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReplaceOutcome {
    /// Pre-existing rows removed because their key collided.
    pub removed: usize,
    /// Rows stored by this statement.
    pub inserted: usize,
}

/// One schema held by an overlay.
#[derive(Debug, Clone)]
struct OverlaySchema {
    name: String,
    tables: Vec<FakeTable>,
}

/// Tables the session created or modified.
#[derive(Debug, Clone, Default)]
struct Overlay {
    schemas: Vec<OverlaySchema>,
    /// `(schema, table)` pairs the session dropped, lowercased.
    dropped: Vec<(String, String)>,
    /// Schema names the session dropped, lowercased.
    dropped_schemas: Vec<String>,
    total_rows: usize,
    total_bytes: usize,
}

impl Overlay {
    fn schema_pos(&self, name: &str) -> Option<usize> {
        self.schemas
            .iter()
            .position(|schema| schema.name.eq_ignore_ascii_case(name))
    }

    fn schema(&self, name: &str) -> Option<&OverlaySchema> {
        self.schemas
            .iter()
            .find(|schema| schema.name.eq_ignore_ascii_case(name))
    }

    fn table_pos(&self, schema_pos: usize, table: &str) -> Option<usize> {
        self.schemas[schema_pos]
            .tables
            .iter()
            .position(|candidate| candidate.name.eq_ignore_ascii_case(table))
    }

    fn is_dropped(&self, schema: &str, table: &str) -> bool {
        self.dropped.iter().any(|(dropped_schema, dropped_table)| {
            dropped_schema.eq_ignore_ascii_case(schema) && dropped_table.eq_ignore_ascii_case(table)
        })
    }

    fn is_schema_dropped(&self, schema: &str) -> bool {
        self.dropped_schemas
            .iter()
            .any(|dropped| dropped.eq_ignore_ascii_case(schema))
    }

    fn tombstone_bytes(&self) -> usize {
        let tables = self.dropped.iter().fold(0usize, |total, (schema, table)| {
            total + TOMBSTONE_OVERHEAD + schema.len() + table.len()
        });
        let schemas = self.dropped_schemas.iter().fold(0usize, |total, name| {
            total + TOMBSTONE_OVERHEAD + name.len()
        });
        tables + schemas
    }
}

/// Bytes held by one cell slot.
fn measure_cell(cell: &Option<String>) -> usize {
    CELL_OVERHEAD + cell.as_ref().map_or(0, String::len)
}

/// Bytes held by one row container, cells included.
fn measure_row(row: &[Option<String>]) -> usize {
    ROW_OVERHEAD + row.iter().map(measure_cell).sum::<usize>()
}

/// Bytes held by one column definition.
fn measure_column(column: &super::FakeColumn) -> usize {
    COLUMN_OVERHEAD
        + column.name.len()
        + column.data_type.len()
        + column.key.len()
        + column.extra.len()
        + column.default.as_ref().map_or(0, String::len)
}

/// Bytes held by a table without its rows.
fn measure_table_structure(table: &FakeTable) -> usize {
    TABLE_OVERHEAD
        + table.name.len()
        + table.engine.len()
        + table.comment.len()
        + table.columns.iter().map(measure_column).sum::<usize>()
}

/// Bytes held by a whole table, rows included.
fn measure_table(table: &FakeTable) -> usize {
    measure_table_structure(table) + table.rows.iter().map(|row| measure_row(row)).sum::<usize>()
}

/// Session-scoped simulated state.
#[derive(Debug, Clone)]
pub struct SessionState {
    overlay: Option<Box<Overlay>>,
    budgets: StateBudgets,
    last_insert_id: u64,
    row_count: i64,
    user_variables: Vec<(String, String)>,
}

impl Default for SessionState {
    fn default() -> Self {
        Self::new(StateBudgets::default())
    }
}

impl SessionState {
    /// Create an empty session state with explicit budgets.
    pub fn new(budgets: StateBudgets) -> Self {
        Self {
            overlay: None,
            budgets,
            last_insert_id: 0,
            row_count: 0,
            user_variables: Vec::new(),
        }
    }

    /// The budgets this session enforces.
    pub fn budgets(&self) -> StateBudgets {
        self.budgets
    }

    /// Whether anything was written in this session.
    pub fn is_dirty(&self) -> bool {
        self.overlay.as_ref().is_some_and(|overlay| {
            !overlay.schemas.is_empty()
                || !overlay.dropped.is_empty()
                || !overlay.dropped_schemas.is_empty()
                || overlay.total_rows > 0
        })
    }

    /// Bytes currently held by the overlay (zero for a pristine session).
    pub fn bytes(&self) -> usize {
        self.overlay
            .as_ref()
            .map_or(0, |overlay| overlay.total_bytes)
    }

    /// Rows currently held by the overlay.
    pub fn rows(&self) -> usize {
        self.overlay
            .as_ref()
            .map_or(0, |overlay| overlay.total_rows)
    }

    /// Number of `DROP` tombstones currently held.
    pub fn tombstones(&self) -> usize {
        self.overlay.as_ref().map_or(0, |overlay| {
            overlay.dropped.len() + overlay.dropped_schemas.len()
        })
    }

    /// Recompute both counters from the live overlay.
    ///
    /// This is the reference implementation the incremental counters are checked
    /// against; tests assert equality after every mutation shape, so a missed
    /// decrement can never stay hidden.
    pub fn recount(&self) -> (usize, usize) {
        let mut rows = 0usize;
        let mut bytes = 0usize;
        if let Some(overlay) = self.overlay.as_ref() {
            for schema in &overlay.schemas {
                for table in &schema.tables {
                    rows += table.rows.len();
                    bytes += measure_table(table);
                }
            }
            bytes += overlay.schemas.len() * SCHEMA_OVERHEAD;
            bytes += overlay
                .schemas
                .iter()
                .map(|schema| schema.name.len())
                .sum::<usize>();
            bytes += overlay.tombstone_bytes();
        }
        bytes += self
            .user_variables
            .iter()
            .map(|(name, value)| name.len() + value.len() + 2 * CELL_OVERHEAD)
            .sum::<usize>();
        (rows, bytes)
    }

    /// `LAST_INSERT_ID()`.
    pub fn last_insert_id(&self) -> u64 {
        self.last_insert_id
    }

    /// Record a generated id.
    pub fn set_last_insert_id(&mut self, value: u64) {
        self.last_insert_id = value;
    }

    /// `ROW_COUNT()` of the previous statement.
    pub fn row_count(&self) -> i64 {
        self.row_count
    }

    /// Record the affected-row count of a statement.
    pub fn set_row_count(&mut self, value: i64) {
        self.row_count = value;
    }

    /// A `SET @name = value` binding.
    pub fn user_variable(&self, name: &str) -> Option<&str> {
        self.user_variables
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Store `SET @name = value`, replacing an existing binding.
    pub fn set_user_variable(&mut self, name: &str, value: String) -> Result<(), StateError> {
        let clipped = crate::util::truncate_to(&value, self.budgets.max_string_bytes).0;
        if let Some(entry) = self
            .user_variables
            .iter_mut()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
        {
            entry.1 = clipped;
            return Ok(());
        }
        if self.user_variables.len() >= self.budgets.max_user_variables {
            return Err(StateError::TooManyVariables);
        }
        // A variable is session memory like any other: charge it before storing.
        let extra = name.len() + clipped.len() + 2 * CELL_OVERHEAD;
        let total = self.bytes().saturating_add(extra);
        if total > self.budgets.max_total_bytes {
            return Err(StateError::BudgetExhausted);
        }
        self.user_variables
            .push((name.to_ascii_lowercase(), clipped));
        if let Some(overlay) = self.overlay.as_mut() {
            overlay.total_bytes = overlay.total_bytes.saturating_add(extra);
        } else if extra > 0 {
            // Keep the counter meaningful even when no overlay exists yet.
            self.overlay = Some(Box::new(Overlay {
                total_bytes: extra,
                ..Overlay::default()
            }));
        }
        Ok(())
    }

    /// Reset the session the way `COM_RESET_CONNECTION` does.
    pub fn reset(&mut self) {
        self.overlay = None;
        self.last_insert_id = 0;
        self.row_count = 0;
        self.user_variables.clear();
    }

    // -- overlay access -----------------------------------------------------

    /// A table this session created or cloned, if any.
    pub fn owned_table(&self, schema: &str, table: &str) -> Option<&FakeTable> {
        self.overlay
            .as_ref()?
            .schema(schema)?
            .tables
            .iter()
            .find(|candidate| candidate.name.eq_ignore_ascii_case(table))
    }

    /// Whether the session dropped `schema.table`.
    pub fn is_dropped(&self, schema: &str, table: &str) -> bool {
        self.overlay
            .as_ref()
            .is_some_and(|overlay| overlay.is_dropped(schema, table))
    }

    /// Whether the session created the named schema.
    pub fn owns_schema(&self, schema: &str) -> bool {
        self.overlay
            .as_ref()
            .is_some_and(|overlay| overlay.schema(schema).is_some())
    }

    /// Whether the session dropped the named schema.
    pub fn is_schema_dropped(&self, schema: &str) -> bool {
        self.overlay
            .as_ref()
            .is_some_and(|overlay| overlay.is_schema_dropped(schema))
    }

    /// Create an empty schema in the overlay.
    pub fn create_schema(&mut self, name: &str) -> Result<(), StateError> {
        self.ensure_schema(name).map(|_| ())
    }

    /// Drop a schema, its tables and — for a base schema — its tombstone.
    pub fn drop_schema(&mut self, name: &str, base_schema: bool) -> Result<(), StateError> {
        if !self.budgets.enabled {
            return Err(StateError::Disabled);
        }
        let budgets = self.budgets;
        let overlay = self
            .overlay
            .get_or_insert_with(|| Box::new(Overlay::default()));
        if let Some(position) = overlay.schema_pos(name) {
            let removed = overlay.schemas.remove(position);
            // Releasing the schema entry releases its name and every table with
            // it; the counters must follow the structure exactly.
            let released_rows: usize = removed.tables.iter().map(|table| table.rows.len()).sum();
            let released_bytes = SCHEMA_OVERHEAD
                + removed.name.len()
                + removed.tables.iter().map(measure_table).sum::<usize>();
            overlay.total_rows = overlay.total_rows.saturating_sub(released_rows);
            overlay.total_bytes = overlay.total_bytes.saturating_sub(released_bytes);
        }
        // Table tombstones inside a dropped schema are implied by the schema
        // tombstone while it stands, so they are released instead of kept — and
        // their bytes have to come back out of the counter with them.
        let mut released_tombstones = 0usize;
        overlay.dropped.retain(|(schema, table)| {
            if schema.eq_ignore_ascii_case(name) {
                released_tombstones += TOMBSTONE_OVERHEAD + schema.len() + table.len();
                false
            } else {
                true
            }
        });
        overlay.total_bytes = overlay.total_bytes.saturating_sub(released_tombstones);
        if !base_schema {
            // A schema the session invented disappears with its tables; there is
            // nothing in the base catalog to hide, so no tombstone is needed.
            return Ok(());
        }
        if overlay.is_schema_dropped(name) {
            return Ok(());
        }
        if overlay.dropped.len() + overlay.dropped_schemas.len() >= budgets.max_tombstones {
            return Err(StateError::BudgetExhausted);
        }
        let extra = TOMBSTONE_OVERHEAD + name.len();
        if overlay.total_bytes.saturating_add(extra) > budgets.max_total_bytes {
            return Err(StateError::BudgetExhausted);
        }
        overlay.dropped_schemas.push(name.to_ascii_lowercase());
        overlay.total_bytes = overlay.total_bytes.saturating_add(extra);
        Ok(())
    }

    /// Undo a `DROP DATABASE` so it can be created again.
    pub fn revive_schema(&mut self, name: &str) {
        if let Some(overlay) = self.overlay.as_mut() {
            let mut released = 0usize;
            overlay.dropped_schemas.retain(|dropped| {
                if dropped.eq_ignore_ascii_case(name) {
                    released += TOMBSTONE_OVERHEAD + dropped.len();
                    false
                } else {
                    true
                }
            });
            overlay.total_bytes = overlay.total_bytes.saturating_sub(released);
        }
    }

    /// Schema names the session created, in creation order.
    pub fn created_schemas(&self) -> Vec<&str> {
        self.overlay
            .as_ref()
            .map(|overlay| {
                overlay
                    .schemas
                    .iter()
                    .map(|schema| schema.name.as_str())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Tables the session created or cloned inside one schema.
    pub fn owned_tables(&self, schema: &str) -> &[FakeTable] {
        match self
            .overlay
            .as_ref()
            .and_then(|overlay| overlay.schema(schema))
        {
            Some(found) => &found.tables,
            None => &[],
        }
    }

    // -- overlay construction ----------------------------------------------

    /// Ensure `schema` exists in the overlay and return its position.
    fn ensure_schema(&mut self, schema: &str) -> Result<usize, StateError> {
        if !self.budgets.enabled {
            return Err(StateError::Disabled);
        }
        if self.overlay.is_none() {
            self.overlay = Some(Box::new(Overlay::default()));
        }
        let budgets = self.budgets;
        let overlay = self.overlay.as_mut().expect("overlay was just created");
        if let Some(position) = overlay.schema_pos(schema) {
            return Ok(position);
        }
        if overlay.schemas.len() >= budgets.max_tables {
            return Err(StateError::TooManyTables);
        }
        let extra = SCHEMA_OVERHEAD + schema.len();
        if overlay.total_bytes.saturating_add(extra) > budgets.max_total_bytes {
            return Err(StateError::BudgetExhausted);
        }
        overlay.schemas.push(OverlaySchema {
            name: schema.to_string(),
            tables: Vec::new(),
        });
        overlay.total_bytes = overlay.total_bytes.saturating_add(extra);
        Ok(overlay.schemas.len() - 1)
    }

    /// Copy `table` into the overlay so it can be mutated.
    ///
    /// Idempotent: attaching a table the overlay already owns is a no-op that
    /// charges nothing, so a repeated `attach` can never inflate the byte
    /// budget.
    pub fn attach(&mut self, schema: &str, table: &FakeTable) -> Result<(), StateError> {
        if !self.budgets.enabled {
            return Err(StateError::Disabled);
        }
        if self.owned_table(schema, &table.name).is_some() {
            return Ok(());
        }
        let budgets = self.budgets;
        // Validate the table shape before it can cost anything.
        if table.columns.len() > budgets.max_columns_per_table {
            return Err(StateError::TooManyColumns);
        }
        if table.rows.len() > budgets.max_rows_per_table {
            return Err(StateError::TableFull(table.name.clone()));
        }
        let cost = measure_table(table);
        let row_count = table.rows.len();
        if let Some(overlay) = self.overlay.as_ref() {
            if overlay
                .schema(schema)
                .is_some_and(|existing| existing.tables.len() >= budgets.max_tables)
            {
                return Err(StateError::TooManyTables);
            }
            if overlay.total_bytes.saturating_add(cost) > budgets.max_total_bytes {
                return Err(StateError::BudgetExhausted);
            }
            if overlay.total_rows.saturating_add(row_count) > budgets.max_total_rows {
                return Err(StateError::BudgetExhausted);
            }
        }
        let position = self.ensure_schema(schema)?;
        let overlay = self.overlay.as_mut().expect("ensure_schema created it");
        if overlay.schema_pos(schema) != Some(position) {
            return Err(StateError::BudgetExhausted);
        }
        overlay.total_bytes = overlay.total_bytes.saturating_add(cost);
        overlay.total_rows = overlay.total_rows.saturating_add(row_count);
        overlay.schemas[position].tables.push(table.clone());
        Ok(())
    }

    /// Register a brand new table created by the client.
    pub fn create_table(&mut self, schema: &str, table: FakeTable) -> Result<(), StateError> {
        if table.columns.len() > self.budgets.max_columns_per_table {
            return Err(StateError::TooManyColumns);
        }
        self.attach(schema, &table)?;
        // A freshly created table must not carry the "dropped" tombstone.
        if let Some(overlay) = self.overlay.as_mut() {
            let name = table.name.clone();
            let mut released = 0usize;
            overlay.dropped.retain(|(dropped_schema, dropped_table)| {
                if dropped_schema.eq_ignore_ascii_case(schema)
                    && dropped_table.eq_ignore_ascii_case(&name)
                {
                    released += TOMBSTONE_OVERHEAD + dropped_schema.len() + dropped_table.len();
                    false
                } else {
                    true
                }
            });
            overlay.total_bytes = overlay.total_bytes.saturating_sub(released);
        }
        Ok(())
    }

    /// Remove a table from the overlay and remember that it is gone.
    ///
    /// `base_table` says whether the base catalog still holds this table. A
    /// table the session invented itself needs no tombstone at all — removing it
    /// from the overlay already makes it invisible — so a `CREATE`/`DROP` loop
    /// over ever new names cannot accumulate markers. Only a table that exists in
    /// the base catalog needs one, and repeated drops of the same table are
    /// deduplicated.
    pub fn drop_table(
        &mut self,
        schema: &str,
        table: &str,
        base_table: bool,
    ) -> Result<(), StateError> {
        if !self.budgets.enabled {
            return Err(StateError::Disabled);
        }
        let budgets = self.budgets;
        let overlay = self
            .overlay
            .get_or_insert_with(|| Box::new(Overlay::default()));
        if let Some(position) = overlay.schema_pos(schema)
            && let Some(table_position) = overlay.table_pos(position, table)
        {
            let removed = overlay.schemas[position].tables.remove(table_position);
            overlay.total_rows = overlay.total_rows.saturating_sub(removed.rows.len());
            overlay.total_bytes = overlay.total_bytes.saturating_sub(measure_table(&removed));
        }
        if !base_table {
            // Nothing in the base catalog to hide: drop any stale tombstone and
            // reclaim its bytes.
            let mut released = 0usize;
            overlay.dropped.retain(|(dropped_schema, dropped_table)| {
                if dropped_schema.eq_ignore_ascii_case(schema)
                    && dropped_table.eq_ignore_ascii_case(table)
                {
                    released += TOMBSTONE_OVERHEAD + dropped_schema.len() + dropped_table.len();
                    false
                } else {
                    true
                }
            });
            overlay.total_bytes = overlay.total_bytes.saturating_sub(released);
            return Ok(());
        }
        if overlay.is_dropped(schema, table) {
            return Ok(());
        }
        if overlay.dropped.len() + overlay.dropped_schemas.len() >= budgets.max_tombstones {
            return Err(StateError::BudgetExhausted);
        }
        let extra = TOMBSTONE_OVERHEAD + schema.len() + table.len();
        if overlay.total_bytes.saturating_add(extra) > budgets.max_total_bytes {
            return Err(StateError::BudgetExhausted);
        }
        overlay
            .dropped
            .push((schema.to_ascii_lowercase(), table.to_ascii_lowercase()));
        overlay.total_bytes = overlay.total_bytes.saturating_add(extra);
        Ok(())
    }

    // -- unified row mutation ----------------------------------------------

    /// Resolve `(schema position, table position)` for a mutation.
    fn locate(&self, schema: &str, table: &str) -> Result<(usize, usize), StateError> {
        let overlay = self
            .overlay
            .as_ref()
            .ok_or_else(|| StateError::NoTable(table.to_string()))?;
        let schema_position = overlay
            .schema_pos(schema)
            .ok_or_else(|| StateError::NoSchema(schema.to_string()))?;
        let table_position = overlay
            .table_pos(schema_position, table)
            .ok_or_else(|| StateError::NoTable(table.to_string()))?;
        Ok((schema_position, table_position))
    }

    /// Column name used in a "data too long" message.
    fn column_label(table: &FakeTable, position: usize) -> String {
        table.columns.get(position).map_or_else(
            || format!("column {position}"),
            |column| column.name.clone(),
        )
    }

    /// Validate one incoming row and return the bytes it will occupy.
    fn validate_row(&self, table: &FakeTable, row: &[Option<String>]) -> Result<usize, StateError> {
        let limit = self.budgets.max_string_bytes;
        for (position, cell) in row.iter().enumerate() {
            if let Some(text) = cell
                && text.len() > limit
            {
                return Err(StateError::ValueTooLong(
                    Self::column_label(table, position),
                    limit,
                ));
            }
        }
        Ok(measure_row(row))
    }

    /// Append a batch of rows.
    ///
    /// The whole batch is validated against the would-be final state first, so a
    /// multi-row `INSERT` either lands completely or not at all.
    pub fn insert_rows(
        &mut self,
        schema: &str,
        table: &str,
        rows: Vec<Vec<Option<String>>>,
    ) -> Result<usize, StateError> {
        if !self.budgets.enabled {
            return Err(StateError::Disabled);
        }
        let (schema_position, table_position) = self.locate(schema, table)?;
        let budgets = self.budgets;
        let overlay = self.overlay.as_ref().expect("locate found it");
        let target = &overlay.schemas[schema_position].tables[table_position];
        let mut cost = 0usize;
        for row in &rows {
            cost = cost.saturating_add(self.validate_row(target, row)?);
        }
        let final_rows = target.rows.len() + rows.len();
        if final_rows > budgets.max_rows_per_table {
            return Err(StateError::TableFull(target.name.clone()));
        }
        if overlay.total_rows.saturating_add(rows.len()) > budgets.max_total_rows {
            return Err(StateError::TableFull(target.name.clone()));
        }
        if overlay.total_bytes.saturating_add(cost) > budgets.max_total_bytes {
            return Err(StateError::BudgetExhausted);
        }
        let inserted = rows.len();
        let overlay = self.overlay.as_mut().expect("locate found it");
        let target = &mut overlay.schemas[schema_position].tables[table_position];
        target.rows.extend(rows);
        overlay.total_rows = overlay.total_rows.saturating_add(inserted);
        overlay.total_bytes = overlay.total_bytes.saturating_add(cost);
        Ok(inserted)
    }

    /// Apply `REPLACE` semantics to a batch, deleting key collisions first.
    ///
    /// Conflicts and their byte releases are resolved before anything is written,
    /// so the counters and the row set change together or not at all.
    pub fn replace_rows(
        &mut self,
        schema: &str,
        table: &str,
        key: Option<usize>,
        rows: Vec<Vec<Option<String>>>,
    ) -> Result<ReplaceOutcome, StateError> {
        if !self.budgets.enabled {
            return Err(StateError::Disabled);
        }
        if key.is_none() {
            // No unique constraint modelled: a plain, still atomic, insert.
            let inserted = self.insert_rows(schema, table, rows)?;
            return Ok(ReplaceOutcome {
                removed: 0,
                inserted,
            });
        }
        let key = key.expect("checked just above");
        let (schema_position, table_position) = self.locate(schema, table)?;
        let budgets = self.budgets;
        let overlay = self.overlay.as_ref().expect("locate found it");
        let target = &overlay.schemas[schema_position].tables[table_position];

        let mut incoming_cost = 0usize;
        for row in &rows {
            incoming_cost = incoming_cost.saturating_add(self.validate_row(target, row)?);
        }

        // Resolve which existing rows this batch evicts, without touching them.
        let mut claimed = vec![false; target.rows.len()];
        let mut released_rows = 0usize;
        let mut released_bytes = 0usize;
        for row in &rows {
            let Some(value) = row.get(key).and_then(|cell| cell.as_deref()) else {
                continue;
            };
            let mut conflict = None;
            for (position, existing) in target.rows.iter().enumerate() {
                if claimed[position] {
                    continue;
                }
                if existing.get(key).and_then(|cell| cell.as_deref()) == Some(value) {
                    conflict = Some(position);
                    break;
                }
            }
            if let Some(position) = conflict {
                claimed[position] = true;
                released_rows += 1;
                released_bytes = released_bytes.saturating_add(measure_row(&target.rows[position]));
            }
        }

        let final_rows = target.rows.len() - released_rows + rows.len();
        if final_rows > budgets.max_rows_per_table {
            return Err(StateError::TableFull(target.name.clone()));
        }
        if overlay
            .total_rows
            .saturating_sub(released_rows)
            .saturating_add(rows.len())
            > budgets.max_total_rows
        {
            return Err(StateError::TableFull(target.name.clone()));
        }
        let final_bytes = overlay
            .total_bytes
            .saturating_sub(released_bytes)
            .saturating_add(incoming_cost);
        if final_bytes > budgets.max_total_bytes {
            return Err(StateError::BudgetExhausted);
        }

        let inserted = rows.len();
        let overlay = self.overlay.as_mut().expect("locate found it");
        let target = &mut overlay.schemas[schema_position].tables[table_position];
        if released_rows > 0 {
            let mut index = 0usize;
            target.rows.retain(|_| {
                let drop = claimed.get(index).copied().unwrap_or(false);
                index += 1;
                !drop
            });
        }
        target.rows.extend(rows);
        overlay.total_rows = overlay
            .total_rows
            .saturating_sub(released_rows)
            .saturating_add(inserted);
        overlay.total_bytes = final_bytes;
        Ok(ReplaceOutcome {
            removed: released_rows,
            inserted,
        })
    }

    /// Rewrite cells of existing rows.
    ///
    /// `updates` carries `(row index, [(column index, new value)])`. Values are
    /// validated against the string and byte budgets before the first cell is
    /// written, so a rejected `UPDATE` leaves the table exactly as it was.
    pub fn update_rows(
        &mut self,
        schema: &str,
        table: &str,
        updates: &[PendingRowUpdate],
    ) -> Result<UpdateOutcome, StateError> {
        if !self.budgets.enabled {
            return Err(StateError::Disabled);
        }
        let (schema_position, table_position) = self.locate(schema, table)?;
        let budgets = self.budgets;
        let overlay = self.overlay.as_ref().expect("locate found it");
        let target = &overlay.schemas[schema_position].tables[table_position];

        // Pass 1: validate and account. Nothing is written yet.
        let mut seen = vec![false; target.rows.len()];
        let mut matched = 0usize;
        let mut delta: i128 = 0;
        for (index, changes) in updates {
            let Some(row) = target.rows.get(*index) else {
                continue;
            };
            if seen[*index] {
                continue;
            }
            seen[*index] = true;
            matched += 1;
            for (position, value) in changes {
                if let Some(text) = value
                    && text.len() > budgets.max_string_bytes
                {
                    return Err(StateError::ValueTooLong(
                        Self::column_label(target, *position),
                        budgets.max_string_bytes,
                    ));
                }
                let old = row.get(*position).and_then(|cell| cell.as_deref());
                let new = value.as_deref();
                let old_cost = i128::try_from(old.map_or(0usize, str::len)).unwrap_or(i128::MAX);
                let new_cost = i128::try_from(new.map_or(0usize, str::len)).unwrap_or(i128::MAX);
                delta += new_cost - old_cost;
            }
        }
        let final_bytes = i128::try_from(overlay.total_bytes).unwrap_or(i128::MAX) + delta;
        if final_bytes > i128::try_from(budgets.max_total_bytes).unwrap_or(i128::MAX) {
            return Err(StateError::BudgetExhausted);
        }
        if final_bytes < 0 {
            // Cannot happen with consistent counters; refuse rather than go
            // negative if it ever did.
            return Err(StateError::BudgetExhausted);
        }

        // Pass 2: apply. No fallible operation remains, so this cannot stop
        // halfway.
        let overlay = self.overlay.as_mut().expect("locate found it");
        let target = &mut overlay.schemas[schema_position].tables[table_position];
        let mut changed = 0usize;
        for (index, changes) in updates {
            let Some(row) = target.rows.get_mut(*index) else {
                continue;
            };
            let mut touched = false;
            for (position, value) in changes {
                if *position >= row.len() {
                    continue;
                }
                if row[*position] != *value {
                    touched = true;
                    row[*position] = value.clone();
                }
            }
            if touched {
                changed += 1;
            }
        }
        overlay.total_bytes = usize::try_from(final_bytes).unwrap_or(usize::MAX);
        Ok(UpdateOutcome { matched, changed })
    }

    /// Remove rows by index, releasing every byte and row they held.
    pub fn delete_rows(
        &mut self,
        schema: &str,
        table: &str,
        indices: &[usize],
    ) -> Result<usize, StateError> {
        if !self.budgets.enabled {
            return Err(StateError::Disabled);
        }
        let (schema_position, table_position) = self.locate(schema, table)?;
        let overlay = self.overlay.as_ref().expect("locate found it");
        let target = &overlay.schemas[schema_position].tables[table_position];
        let mut drop = vec![false; target.rows.len()];
        let mut removed = 0usize;
        let mut released = 0usize;
        for index in indices {
            let Some(flag) = drop.get_mut(*index) else {
                continue;
            };
            if *flag {
                continue;
            }
            *flag = true;
            removed += 1;
            released = released.saturating_add(measure_row(&target.rows[*index]));
        }
        if removed == 0 {
            return Ok(0);
        }
        let overlay = self.overlay.as_mut().expect("locate found it");
        let target = &mut overlay.schemas[schema_position].tables[table_position];
        let mut index = 0usize;
        target.rows.retain(|_| {
            let drop = drop.get(index).copied().unwrap_or(false);
            index += 1;
            !drop
        });
        overlay.total_rows = overlay.total_rows.saturating_sub(removed);
        overlay.total_bytes = overlay.total_bytes.saturating_sub(released);
        Ok(removed)
    }

    /// Empty a table, releasing the bytes and rows of everything it held.
    pub fn truncate_table(&mut self, schema: &str, table: &str) -> Result<usize, StateError> {
        if !self.budgets.enabled {
            return Err(StateError::Disabled);
        }
        let (schema_position, table_position) = self.locate(schema, table)?;
        let overlay = self.overlay.as_mut().expect("locate found it");
        let target = &mut overlay.schemas[schema_position].tables[table_position];
        let removed = target.rows.len();
        let released = target
            .rows
            .iter()
            .map(|row| measure_row(row))
            .sum::<usize>();
        target.rows.clear();
        target.rows.shrink_to_fit();
        overlay.total_rows = overlay.total_rows.saturating_sub(removed);
        overlay.total_bytes = overlay.total_bytes.saturating_sub(released);
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakedb::FakeColumn;

    fn sample_table(name: &str) -> FakeTable {
        FakeTable {
            name: name.to_string(),
            engine: "InnoDB".to_string(),
            comment: String::new(),
            columns: vec![
                FakeColumn::primary("id", "bigint unsigned", 8),
                FakeColumn::new("username", "varchar(64)", 253),
            ],
            rows: vec![vec![Some("1".to_string()), Some("admin".to_string())]],
        }
    }

    /// Assert the incremental counters equal a from-scratch recount.
    fn assert_consistent(state: &SessionState) {
        let (rows, bytes) = state.recount();
        assert_eq!(state.rows(), rows, "row counter drifted");
        assert_eq!(state.bytes(), bytes, "byte counter drifted");
    }

    #[test]
    fn pristine_sessions_allocate_nothing() {
        let state = SessionState::default();
        assert!(!state.is_dirty());
        assert_eq!(state.bytes(), 0);
        assert_eq!(state.rows(), 0);
        assert_eq!(state.recount(), (0, 0));
    }

    #[test]
    fn attach_clones_once_and_is_idempotent() {
        let mut state = SessionState::default();
        let table = sample_table("users");
        state.attach("app_prod", &table).expect("attach");
        let after_first = state.bytes();
        assert_consistent(&state);
        state.attach("app_prod", &table).expect("attach again");
        assert_eq!(state.owned_tables("app_prod").len(), 1);
        assert_eq!(
            state.bytes(),
            after_first,
            "a repeated attach must not charge the budget twice"
        );
        assert_consistent(&state);
    }

    #[test]
    fn attach_never_double_charges_over_many_calls() {
        let mut state = SessionState::default();
        let table = sample_table("users");
        for _ in 0..100 {
            state.attach("app_prod", &table).expect("attach");
        }
        assert_consistent(&state);
        assert_eq!(state.rows(), 1);
    }

    #[test]
    fn drop_is_remembered_even_for_base_tables() {
        let mut state = SessionState::default();
        state.drop_table("app_prod", "users", true).expect("drop");
        assert!(state.is_dropped("app_prod", "users"));
        assert!(!state.is_dropped("app_prod", "orders"));
        assert_eq!(state.tombstones(), 1);
        assert_consistent(&state);
    }

    #[test]
    fn dropping_a_session_table_leaves_no_tombstone() {
        let mut state = SessionState::default();
        state
            .create_table("app_prod", sample_table("made_up"))
            .expect("create");
        let with_table = state.bytes();
        state
            .drop_table("app_prod", "made_up", false)
            .expect("drop");
        assert!(!state.is_dropped("app_prod", "made_up"));
        assert_eq!(state.tombstones(), 0);
        assert_eq!(state.owned_tables("app_prod").len(), 0);
        assert!(
            state.bytes() < with_table,
            "dropping must release the table's bytes"
        );
        assert_consistent(&state);
    }

    #[test]
    fn create_drop_cycles_do_not_grow_memory() {
        let mut state = SessionState::default();
        // Thousands of distinct names: the overlay must not accumulate markers.
        for round in 0..2_000u32 {
            let name = format!("t{round}");
            state
                .create_table("app_prod", sample_table(&name))
                .expect("create");
            state.drop_table("app_prod", &name, false).expect("drop");
        }
        assert_eq!(state.tombstones(), 0, "session tables need no tombstones");
        assert_eq!(state.rows(), 0);
        assert_consistent(&state);
        assert!(
            state.bytes() < 4_096,
            "overlay grew to {} bytes over 2000 create/drop cycles",
            state.bytes()
        );
    }

    #[test]
    fn repeated_drops_of_one_base_table_are_deduplicated() {
        let mut state = SessionState::default();
        for _ in 0..500 {
            state.drop_table("app_prod", "users", true).expect("drop");
        }
        assert_eq!(state.tombstones(), 1);
        assert_consistent(&state);
    }

    #[test]
    fn tombstone_budget_is_enforced_and_deduplicated() {
        let mut state = SessionState::new(StateBudgets {
            max_tombstones: 4,
            ..StateBudgets::default()
        });
        for round in 0..4 {
            state
                .drop_table("app_prod", &format!("t{round}"), true)
                .expect("drop");
        }
        assert_eq!(state.tombstones(), 4);
        match state.drop_table("app_prod", "overflow", true) {
            Err(StateError::BudgetExhausted) => {}
            other => panic!("unexpected {other:?}"),
        }
        // The table that was already dropped is still deduplicated, not refused.
        state.drop_table("app_prod", "t0", true).expect("dedupe");
        assert_eq!(state.tombstones(), 4);
        assert_consistent(&state);
    }

    #[test]
    fn row_budget_is_enforced() {
        let mut state = SessionState::new(StateBudgets {
            max_rows_per_table: 2,
            ..StateBudgets::default()
        });
        state
            .create_table("app_prod", sample_table("t"))
            .expect("create");
        state
            .insert_rows(
                "app_prod",
                "t",
                vec![vec![Some("2".to_string()), Some("bob".to_string())]],
            )
            .expect("first insert");
        match state.insert_rows(
            "app_prod",
            "t",
            vec![vec![Some("3".to_string()), Some("eve".to_string())]],
        ) {
            Err(StateError::TableFull(_)) => {}
            other => panic!("unexpected {other:?}"),
        }
        assert_consistent(&state);
    }

    #[test]
    fn string_budget_is_enforced() {
        let mut state = SessionState::new(StateBudgets {
            max_string_bytes: 8,
            ..StateBudgets::default()
        });
        state
            .create_table("app_prod", sample_table("t"))
            .expect("create");
        match state.insert_rows(
            "app_prod",
            "t",
            vec![vec![Some("1".to_string()), Some("x".repeat(64))]],
        ) {
            Err(StateError::ValueTooLong(column, 8)) => assert_eq!(column, "username"),
            other => panic!("unexpected {other:?}"),
        }
        assert_consistent(&state);
    }

    #[test]
    fn byte_budget_is_enforced() {
        let mut state = SessionState::new(StateBudgets {
            max_total_bytes: 1,
            ..StateBudgets::default()
        });
        match state.attach("app_prod", &sample_table("users")) {
            Err(StateError::BudgetExhausted) => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn disabled_budgets_refuse_without_panicking() {
        let mut state = SessionState::new(StateBudgets {
            enabled: false,
            ..StateBudgets::default()
        });
        assert!(matches!(
            state.attach("app_prod", &sample_table("users")),
            Err(StateError::Disabled)
        ));
        assert!(matches!(
            state.drop_table("app_prod", "users", true),
            Err(StateError::Disabled)
        ));
        assert!(!state.is_dirty());
    }

    #[test]
    fn reset_clears_everything() {
        let mut state = SessionState::default();
        state
            .attach("app_prod", &sample_table("users"))
            .expect("attach");
        state.set_user_variable("a", "1".to_string()).expect("var");
        state.set_last_insert_id(9);
        assert_consistent(&state);
        state.reset();
        assert!(!state.is_dirty());
        assert!(state.user_variable("a").is_none());
        assert_eq!(state.last_insert_id(), 0);
        assert_eq!(state.recount(), (0, 0));
    }

    // -- mutation accounting ------------------------------------------------

    fn seeded() -> SessionState {
        let mut state = SessionState::default();
        state
            .create_table("app_prod", sample_table("t"))
            .expect("create");
        let batch = (2..=5)
            .map(|id| vec![Some(id.to_string()), Some(format!("user{id}"))])
            .collect();
        state.insert_rows("app_prod", "t", batch).expect("insert");
        state
    }

    #[test]
    fn delete_releases_rows_and_bytes() {
        let mut state = seeded();
        let before_bytes = state.bytes();
        let before_rows = state.rows();
        let removed = state.delete_rows("app_prod", "t", &[1, 2]).expect("delete");
        assert_eq!(removed, 2);
        assert_eq!(state.rows(), before_rows - 2);
        assert!(
            state.bytes() < before_bytes,
            "delete must give the bytes back"
        );
        assert_consistent(&state);
    }

    #[test]
    fn truncate_releases_every_row_and_byte() {
        let mut state = seeded();
        let shell = {
            // Bytes the empty table shell alone occupies, measured the same way.
            let mut empty = SessionState::default();
            empty
                .create_table("app_prod", sample_table("t"))
                .expect("create");
            empty.truncate_table("app_prod", "t").expect("truncate");
            empty.bytes()
        };
        let removed = state.truncate_table("app_prod", "t").expect("truncate");
        assert_eq!(removed, 5);
        assert_eq!(state.rows(), 0);
        assert_eq!(
            state.bytes(),
            shell,
            "truncate must leave only the table shell"
        );
        assert_consistent(&state);
    }

    #[test]
    fn update_accounts_for_the_new_cell_sizes() {
        let mut state = seeded();
        let before = state.bytes();
        let outcome = state
            .update_rows(
                "app_prod",
                "t",
                &[(0, vec![(1, Some("a-much-longer-username".to_string()))])],
            )
            .expect("update");
        assert_eq!(outcome.matched, 1);
        assert_eq!(outcome.changed, 1);
        assert!(state.bytes() > before, "a longer value must cost more");
        assert_consistent(&state);

        // Shrinking it gives the bytes back again.
        let grown = state.bytes();
        state
            .update_rows("app_prod", "t", &[(0, vec![(1, Some("a".to_string()))])])
            .expect("shrink");
        assert!(state.bytes() < grown);
        assert_consistent(&state);
    }

    #[test]
    fn update_over_the_string_budget_is_refused_atomically() {
        let mut state = SessionState::new(StateBudgets {
            max_string_bytes: 8,
            ..StateBudgets::default()
        });
        state
            .create_table("app_prod", sample_table("t"))
            .expect("create");
        state
            .insert_rows(
                "app_prod",
                "t",
                vec![vec![Some("2".to_string()), Some("bob".to_string())]],
            )
            .expect("insert");
        let snapshot = state
            .owned_table("app_prod", "t")
            .expect("owned")
            .rows
            .clone();
        let bytes = state.bytes();
        match state.update_rows(
            "app_prod",
            "t",
            &[
                (0, vec![(1, Some("ok".to_string()))]),
                // The second row is what breaks the budget.
                (1, vec![(1, Some("x".repeat(64)))]),
            ],
        ) {
            Err(StateError::ValueTooLong(_, 8)) => {}
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            state.owned_table("app_prod", "t").expect("owned").rows,
            snapshot,
            "a refused update must not leave row 0 modified"
        );
        assert_eq!(state.bytes(), bytes);
        assert_consistent(&state);
    }

    #[test]
    fn update_over_the_byte_budget_is_refused_atomically() {
        let mut state = SessionState::new(StateBudgets {
            max_total_bytes: 400,
            max_string_bytes: 512,
            ..StateBudgets::default()
        });
        state
            .create_table("app_prod", sample_table("t"))
            .expect("create");
        let snapshot = state
            .owned_table("app_prod", "t")
            .expect("owned")
            .rows
            .clone();
        match state.update_rows(
            "app_prod",
            "t",
            &[(
                0,
                vec![(1, Some("y".repeat(400))), (0, Some("9".to_string()))],
            )],
        ) {
            Err(StateError::BudgetExhausted) => {}
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            state.owned_table("app_prod", "t").expect("owned").rows,
            snapshot
        );
        assert_consistent(&state);
    }

    #[test]
    fn multi_row_insert_is_all_or_nothing() {
        let mut state = SessionState::new(StateBudgets {
            max_rows_per_table: 3,
            ..StateBudgets::default()
        });
        state
            .create_table("app_prod", sample_table("t"))
            .expect("create");
        let snapshot = state
            .owned_table("app_prod", "t")
            .expect("owned")
            .rows
            .clone();
        let rows = (2..=6)
            .map(|id| vec![Some(id.to_string()), Some(format!("u{id}"))])
            .collect();
        match state.insert_rows("app_prod", "t", rows) {
            Err(StateError::TableFull(_)) => {}
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            state.owned_table("app_prod", "t").expect("owned").rows,
            snapshot,
            "a rejected batch must not insert a prefix of its rows"
        );
        assert_consistent(&state);
    }

    #[test]
    fn multi_row_insert_over_the_byte_budget_is_atomic() {
        let mut state = SessionState::new(StateBudgets {
            max_total_bytes: 500,
            max_string_bytes: 512,
            ..StateBudgets::default()
        });
        state
            .create_table("app_prod", sample_table("t"))
            .expect("create");
        let rows = vec![
            vec![Some("2".to_string()), Some("ok".to_string())],
            vec![Some("3".to_string()), Some("z".repeat(400))],
        ];
        match state.insert_rows("app_prod", "t", rows) {
            Err(StateError::BudgetExhausted) => {}
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            state
                .owned_table("app_prod", "t")
                .expect("owned")
                .rows
                .len(),
            1
        );
        assert_consistent(&state);
    }

    #[test]
    fn replace_keeps_the_counters_in_step() {
        let mut state = seeded();
        let outcome = state
            .replace_rows(
                "app_prod",
                "t",
                Some(0),
                vec![vec![Some("2".to_string()), Some("replaced".to_string())]],
            )
            .expect("replace");
        assert_eq!(outcome.removed, 1);
        assert_eq!(outcome.inserted, 1);
        assert_eq!(state.rows(), 5, "REPLACE must not grow the row count");
        let rows = &state.owned_table("app_prod", "t").expect("owned").rows;
        assert_eq!(
            rows.iter()
                .filter(|row| row[0].as_deref() == Some("2"))
                .count(),
            1,
            "the conflicting key must appear exactly once"
        );
        assert_eq!(
            rows.iter()
                .find(|row| row[0].as_deref() == Some("2"))
                .and_then(|row| row[1].clone())
                .as_deref(),
            Some("replaced")
        );
        assert_consistent(&state);
    }

    #[test]
    fn replace_beyond_the_budget_is_refused_atomically() {
        let mut state = SessionState::new(StateBudgets {
            max_total_bytes: 500,
            max_string_bytes: 512,
            ..StateBudgets::default()
        });
        state
            .create_table("app_prod", sample_table("t"))
            .expect("create");
        state
            .insert_rows(
                "app_prod",
                "t",
                vec![
                    vec![Some("2".to_string()), Some("bob".to_string())],
                    vec![Some("3".to_string()), Some("eve".to_string())],
                ],
            )
            .expect("insert");
        let snapshot = state
            .owned_table("app_prod", "t")
            .expect("owned")
            .rows
            .clone();
        // Evicting row 2 frees little; the incoming row needs far more.
        match state.replace_rows(
            "app_prod",
            "t",
            Some(0),
            vec![vec![Some("2".to_string()), Some("w".repeat(500))]],
        ) {
            Err(StateError::BudgetExhausted) => {}
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            state.owned_table("app_prod", "t").expect("owned").rows,
            snapshot,
            "a refused REPLACE must not delete the conflicting row"
        );
        assert_consistent(&state);
    }

    #[test]
    fn insert_update_delete_insert_keeps_the_budget_stable() {
        let mut state = SessionState::new(StateBudgets {
            max_total_bytes: 2_048,
            max_rows_per_table: 64,
            max_string_bytes: 64,
            ..StateBudgets::default()
        });
        state
            .create_table("app_prod", sample_table("t"))
            .expect("create");
        for (round, next_id) in (0..400u32).zip(2u64..) {
            let id = next_id.to_string();
            state
                .insert_rows(
                    "app_prod",
                    "t",
                    vec![vec![Some(id.clone()), Some(format!("user{id}"))]],
                )
                .unwrap_or_else(|err| panic!("round {round} insert: {err:?}"));
            assert_consistent(&state);
            let index = state
                .owned_table("app_prod", "t")
                .expect("owned")
                .rows
                .len()
                - 1;
            state
                .update_rows(
                    "app_prod",
                    "t",
                    &[(index, vec![(1, Some(format!("renamed{round}")))])],
                )
                .unwrap_or_else(|err| panic!("round {round} update: {err:?}"));
            assert_consistent(&state);
            state
                .delete_rows("app_prod", "t", &[index])
                .unwrap_or_else(|err| panic!("round {round} delete: {err:?}"));
            assert_consistent(&state);
        }
        assert_eq!(state.rows(), 1, "only the catalog row remains");
        assert!(
            state.bytes() < 2_048,
            "the overlay drifted to {} bytes",
            state.bytes()
        );
    }

    #[test]
    fn churn_does_not_produce_a_phantom_exhaustion() {
        // A tight byte budget that a create/drop/insert/delete loop must survive
        // forever: a leak would make it fail on a later round.
        let mut state = SessionState::new(StateBudgets {
            max_total_bytes: 512,
            max_string_bytes: 16,
            max_rows_per_table: 8,
            ..StateBudgets::default()
        });
        state
            .create_table("app_prod", sample_table("t"))
            .expect("create");
        for round in 0..1_000u32 {
            state
                .insert_rows(
                    "app_prod",
                    "t",
                    vec![vec![Some("1".to_string()), Some("u".to_string())]],
                )
                .unwrap_or_else(|err| panic!("round {round}: {err:?}"));
            state.delete_rows("app_prod", "t", &[1]).expect("delete");
            assert_consistent(&state);
        }
        assert_eq!(state.rows(), 1);
    }

    #[test]
    fn drop_schema_releases_tables_and_tombstones() {
        let mut state = SessionState::default();
        state
            .create_table("made_up", sample_table("t"))
            .expect("create");
        state.drop_table("app_prod", "users", true).expect("drop");
        state.drop_table("app_prod", "orders", true).expect("drop");
        assert_eq!(state.tombstones(), 2);
        state.drop_schema("app_prod", true).expect("drop schema");
        assert!(state.is_schema_dropped("app_prod"));
        assert_eq!(
            state.tombstones(),
            1,
            "table tombstones inside a dropped schema are redundant"
        );
        assert_consistent(&state);

        state.revive_schema("app_prod");
        assert!(!state.is_schema_dropped("app_prod"));
        assert_eq!(state.tombstones(), 0);
        assert_consistent(&state);
    }

    #[test]
    fn dropping_a_session_schema_needs_no_tombstone() {
        let mut state = SessionState::default();
        state.create_schema("invented").expect("create");
        state
            .create_table("invented", sample_table("t"))
            .expect("create");
        state.drop_schema("invented", false).expect("drop");
        assert_eq!(state.tombstones(), 0);
        assert!(!state.owns_schema("invented"));
        assert_consistent(&state);
    }

    #[test]
    fn user_variables_are_counted_against_the_byte_budget() {
        let mut state = SessionState::new(StateBudgets {
            max_total_bytes: 128,
            max_string_bytes: 64,
            ..StateBudgets::default()
        });
        let mut stored = 0usize;
        for round in 0..64u32 {
            match state.set_user_variable(&format!("v{round}"), "x".repeat(32)) {
                Ok(()) => stored += 1,
                Err(StateError::BudgetExhausted | StateError::TooManyVariables) => break,
                Err(other) => panic!("unexpected {other:?}"),
            }
        }
        assert!(stored > 0 && stored < 64, "stored {stored} variables");
        assert_consistent(&state);
    }

    #[test]
    fn mutation_of_an_unknown_table_reports_the_mysql_error() {
        let mut state = SessionState::default();
        match state.insert_rows("app_prod", "nope", Vec::new()) {
            Err(err @ StateError::NoTable(_)) => assert_eq!(err.code(), 1146),
            other => panic!("unexpected {other:?}"),
        }
    }
}
