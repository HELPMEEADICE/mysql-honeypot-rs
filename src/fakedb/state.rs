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

use super::FakeTable;

/// Everything the state layer may create for one session.
#[derive(Debug, Clone, Copy)]
pub struct StateBudgets {
    /// Whether writes are simulated at all.
    pub enabled: bool,
    /// Maximum number of tables the session may create.
    pub max_tables: usize,
    /// Maximum rows a single table may reach.
    pub max_rows_per_table: usize,
    /// Maximum rows across the whole overlay.
    pub max_total_rows: usize,
    /// Maximum bytes in one stored string.
    pub max_string_bytes: usize,
    /// Maximum bytes of overlay storage.
    pub max_total_bytes: usize,
    /// Maximum number of `SET @var` values.
    pub max_user_variables: usize,
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
    /// The overlay byte budget is exhausted.
    BudgetExhausted,
    /// `ER_TOO_MANY_USER_LEVEL_VARS`
    TooManyVariables,
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
        }
    }

    /// `SQLSTATE` for the error.
    pub fn sqlstate(&self) -> &'static str {
        match self {
            Self::Disabled => "00000",
            Self::TooManyTables => "HY000",
            Self::TableFull(_) | Self::BudgetExhausted => "HY000",
            Self::ValueTooLong(_, _) => "22001",
            Self::TooManyVariables => "HY000",
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
        }
    }
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
    fn schema(&self, name: &str) -> Option<&OverlaySchema> {
        self.schemas
            .iter()
            .find(|schema| schema.name.eq_ignore_ascii_case(name))
    }

    fn schema_mut(&mut self, name: &str) -> Option<&mut OverlaySchema> {
        self.schemas
            .iter_mut()
            .find(|schema| schema.name.eq_ignore_ascii_case(name))
    }

    fn is_dropped(&self, schema: &str, table: &str) -> bool {
        self.dropped.iter().any(|(dropped_schema, dropped_table)| {
            dropped_schema.eq_ignore_ascii_case(schema) && dropped_table.eq_ignore_ascii_case(table)
        })
    }
}

fn measure_table(table: &FakeTable) -> usize {
    let mut total = table.name.len() + table.comment.len();
    for column in &table.columns {
        total += column.name.len() + column.data_type.len() + column.key.len();
    }
    for row in &table.rows {
        for cell in row {
            total += cell.as_ref().map_or(0, String::len);
        }
    }
    total
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
        self.user_variables
            .push((name.to_ascii_lowercase(), clipped));
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

    /// A mutable table this session created or cloned, if any.
    pub fn owned_table_mut(&mut self, schema: &str, table: &str) -> Option<&mut FakeTable> {
        self.overlay
            .as_mut()?
            .schema_mut(schema)?
            .tables
            .iter_mut()
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
        self.overlay.as_ref().is_some_and(|overlay| {
            overlay
                .dropped_schemas
                .iter()
                .any(|dropped| dropped.eq_ignore_ascii_case(schema))
        })
    }

    /// Create an empty schema in the overlay.
    pub fn create_schema(&mut self, name: &str) -> Result<(), StateError> {
        self.ensure_schema(name).map(|_| ())
    }

    /// Drop a schema and every table it contains.
    pub fn drop_schema(&mut self, name: &str) {
        if !self.budgets.enabled {
            return;
        }
        let overlay = self
            .overlay
            .get_or_insert_with(|| Box::new(Overlay::default()));
        if let Some(found) = overlay
            .schemas
            .iter_mut()
            .find(|candidate| candidate.name.eq_ignore_ascii_case(name))
        {
            for table in &found.tables {
                overlay.total_rows = overlay.total_rows.saturating_sub(table.rows.len());
                overlay.total_bytes = overlay.total_bytes.saturating_sub(measure_table(table));
            }
            found.tables.clear();
        }
        if !overlay
            .dropped_schemas
            .iter()
            .any(|dropped| dropped.eq_ignore_ascii_case(name))
        {
            overlay.dropped_schemas.push(name.to_ascii_lowercase());
        }
    }

    /// Undo a `DROP DATABASE` so it can be created again.
    pub fn revive_schema(&mut self, name: &str) {
        if let Some(overlay) = self.overlay.as_mut() {
            overlay
                .dropped_schemas
                .retain(|dropped| !dropped.eq_ignore_ascii_case(name));
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

    // -- mutation -----------------------------------------------------------

    /// Ensure `schema` exists in the overlay and return a mutable handle to it.
    fn ensure_schema(&mut self, schema: &str) -> Result<&mut OverlaySchema, StateError> {
        if !self.budgets.enabled {
            return Err(StateError::Disabled);
        }
        if self.overlay.is_none() {
            self.overlay = Some(Box::new(Overlay::default()));
        }
        let overlay = self.overlay.as_mut().expect("overlay was just created");
        if let Some(index) = overlay
            .schemas
            .iter()
            .position(|candidate| candidate.name.eq_ignore_ascii_case(schema))
        {
            return Ok(&mut overlay.schemas[index]);
        }
        if overlay.schemas.len() >= self.budgets.max_tables {
            return Err(StateError::TooManyTables);
        }
        overlay.schemas.push(OverlaySchema {
            name: schema.to_string(),
            tables: Vec::new(),
        });
        let last = overlay.schemas.len() - 1;
        Ok(&mut overlay.schemas[last])
    }

    /// Copy `table` into the overlay so it can be mutated.
    pub fn attach(&mut self, schema: &str, table: &FakeTable) -> Result<(), StateError> {
        if !self.budgets.enabled {
            return Err(StateError::Disabled);
        }
        let cost = measure_table(table);
        let row_count = table.rows.len();
        if let Some(existing) = self
            .overlay
            .as_ref()
            .and_then(|overlay| overlay.schema(schema))
            && existing.tables.len() >= self.budgets.max_tables
        {
            return Err(StateError::TooManyTables);
        }
        {
            let overlay = self
                .overlay
                .get_or_insert_with(|| Box::new(Overlay::default()));
            if overlay.total_bytes.saturating_add(cost) > self.budgets.max_total_bytes {
                return Err(StateError::BudgetExhausted);
            }
            if overlay.total_rows.saturating_add(row_count) > self.budgets.max_total_rows {
                return Err(StateError::BudgetExhausted);
            }
            overlay.total_bytes += cost;
            overlay.total_rows += row_count;
        }
        let target = self.ensure_schema(schema)?;
        if target
            .tables
            .iter()
            .any(|existing| existing.name.eq_ignore_ascii_case(&table.name))
        {
            return Ok(());
        }
        target.tables.push(table.clone());
        Ok(())
    }

    /// Register a brand new table created by the client.
    pub fn create_table(&mut self, schema: &str, table: FakeTable) -> Result<(), StateError> {
        self.attach(schema, &table)?;
        // A freshly created table must not carry the "dropped" tombstone.
        if let Some(overlay) = self.overlay.as_mut() {
            overlay.dropped.retain(|(dropped_schema, dropped_table)| {
                !(dropped_schema.eq_ignore_ascii_case(schema)
                    && dropped_table.eq_ignore_ascii_case(&table.name))
            });
        }
        Ok(())
    }

    /// Remove a table from the overlay and remember that it is gone.
    pub fn drop_table(&mut self, schema: &str, table: &str) {
        if !self.budgets.enabled {
            return;
        }
        let overlay = self
            .overlay
            .get_or_insert_with(|| Box::new(Overlay::default()));
        if let Some(found) = overlay
            .schemas
            .iter_mut()
            .find(|candidate| candidate.name.eq_ignore_ascii_case(schema))
            && let Some(index) = found
                .tables
                .iter()
                .position(|candidate| candidate.name.eq_ignore_ascii_case(table))
        {
            let removed = found.tables.remove(index);
            overlay.total_rows = overlay.total_rows.saturating_sub(removed.rows.len());
            overlay.total_bytes = overlay.total_bytes.saturating_sub(measure_table(&removed));
        }
        if !overlay.is_dropped(schema, table) {
            overlay
                .dropped
                .push((schema.to_ascii_lowercase(), table.to_ascii_lowercase()));
        }
    }

    /// Append a row, enforcing the row and byte budgets.
    ///
    /// Returns the row index the row was stored at.
    pub fn push_row(
        &mut self,
        schema: &str,
        table_name: &str,
        row: Vec<Option<String>>,
    ) -> Result<usize, StateError> {
        let max_string = self.budgets.max_string_bytes;
        for (index, cell) in row.iter().enumerate() {
            if let Some(text) = cell
                && text.len() > max_string
            {
                return Err(StateError::ValueTooLong(
                    format!("column {index}"),
                    max_string,
                ));
            }
        }
        let cost: usize = row
            .iter()
            .map(|cell| cell.as_ref().map_or(0, String::len))
            .sum();
        let budgets = self.budgets;
        let Some(overlay) = self.overlay.as_mut() else {
            return Err(StateError::BudgetExhausted);
        };
        let Some(schema_entry) = overlay
            .schemas
            .iter_mut()
            .find(|candidate| candidate.name.eq_ignore_ascii_case(schema))
        else {
            return Err(StateError::BudgetExhausted);
        };
        let Some(table) = schema_entry
            .tables
            .iter_mut()
            .find(|candidate| candidate.name.eq_ignore_ascii_case(table_name))
        else {
            return Err(StateError::BudgetExhausted);
        };
        if table.rows.len() >= budgets.max_rows_per_table {
            return Err(StateError::TableFull(table.name.clone()));
        }
        if overlay.total_rows >= budgets.max_total_rows {
            return Err(StateError::TableFull(table.name.clone()));
        }
        if overlay.total_bytes.saturating_add(cost) > budgets.max_total_bytes {
            return Err(StateError::BudgetExhausted);
        }
        table.rows.push(row);
        let index = table.rows.len() - 1;
        overlay.total_rows += 1;
        overlay.total_bytes += cost;
        Ok(index)
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
            columns: vec![FakeColumn::primary("id", "bigint unsigned", 8)],
            rows: vec![vec![Some("1".to_string())]],
        }
    }

    #[test]
    fn pristine_sessions_allocate_nothing() {
        let state = SessionState::default();
        assert!(!state.is_dirty());
        assert_eq!(state.bytes(), 0);
        assert_eq!(state.rows(), 0);
    }

    #[test]
    fn attach_clones_once_and_is_idempotent() {
        let mut state = SessionState::default();
        let table = sample_table("users");
        state.attach("app_prod", &table).expect("attach");
        state.attach("app_prod", &table).expect("attach again");
        assert_eq!(state.owned_tables("app_prod").len(), 1);
        assert!(state.bytes() > 0);
    }

    #[test]
    fn drop_is_remembered_even_for_base_tables() {
        let mut state = SessionState::default();
        state.drop_table("app_prod", "users");
        assert!(state.is_dropped("app_prod", "users"));
        assert!(!state.is_dropped("app_prod", "orders"));
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
            .push_row("app_prod", "t", vec![Some("2".to_string())])
            .expect("first insert");
        match state.push_row("app_prod", "t", vec![Some("3".to_string())]) {
            Err(StateError::TableFull(_)) => {}
            other => panic!("unexpected {other:?}"),
        }
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
        match state.push_row("app_prod", "t", vec![Some("x".repeat(64))]) {
            Err(StateError::ValueTooLong(_, 8)) => {}
            other => panic!("unexpected {other:?}"),
        }
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
        state.drop_table("app_prod", "users");
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
        state.reset();
        assert!(!state.is_dirty());
        assert!(state.user_variable("a").is_none());
        assert_eq!(state.last_insert_id(), 0);
    }
}
