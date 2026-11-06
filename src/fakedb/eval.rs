// SPDX-License-Identifier: GPL-3.0-only
//! Evaluation of the expressions produced by [`super::sql`].
//!
//! The evaluator is *column aware*: a comparison involving `users.username`
//! only ever looks at that column, so a `WHERE` clause can no longer match a row
//! because some unrelated field happened to contain the same text. Unknown
//! column names raise the same `ER_BAD_FIELD_ERROR` a real server raises.
//!
//! Comparison follows MySQL's coercion rules closely enough to be
//! indistinguishable from the outside:
//!
//! * `NULL` propagates, so a comparison with `NULL` is never true;
//! * number-vs-string compares numerically, with a non numeric string reading
//!   as `0`;
//! * two strings compare case insensitively (the `utf8mb4_0900_ai_ci`
//!   collation the catalog advertises).
//!
//! `WHERE`, `ORDER BY`, `GROUP BY` and the aggregates all share the same
//! ordering rule so they can never contradict each other:
//!
//! * a **numeric** key compares as `f64` with [`f64::total_cmp`], which is a
//!   genuine total order (no `NaN` hole, so a sort can never misbehave);
//! * a **text** key compares by its rendered string under the advertised
//!   case-insensitive collation, which is what makes `ORDER BY username` sort
//!   `admin < alice < bob` instead of collapsing every non numeric string to
//!   `0`;
//! * `NULL` sorts before every non-`NULL` value, matching MySQL's `ASC`
//!   placement (and therefore last under `DESC`).

use std::cell::Cell;
use std::cmp::Ordering;

use super::FakeColumn;
use super::sql::{BinOp, Expr, Value, parse_number, tokenize};
use super::state::SessionState;
use crate::hash;
use crate::util;

/// Character comparisons one statement may spend evaluating `LIKE`.
///
/// The matcher is O(value × pattern); without a shared ceiling a handful of
/// `LIKE` predicates over a full table would pin a core for every connection.
/// Once the budget is gone the predicate answers "no match", which is the
/// conservative direction: a filter may return fewer rows, never more.
const LIKE_WORK_LIMIT: usize = 2_000_000;

/// Longest `LIKE` pattern the matcher will consider.
const LIKE_PATTERN_LIMIT: usize = 1_024;

/// Identity and session facts an expression may read.
#[derive(Debug, Clone)]
pub struct EvalContext {
    /// Schema selected by `USE` / `COM_INIT_DB`.
    pub current_db: String,
    /// Login name the client supplied.
    pub username: String,
    /// Peer address as text.
    pub client_host: String,
    /// Connection id.
    pub connection_id: u32,
    /// Advertised server version.
    pub server_version: String,
    /// Remaining `LIKE` work for this statement.
    pub like_budget: Cell<usize>,
}

impl EvalContext {
    /// A context with a fresh `LIKE` budget.
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
            like_budget: Cell::new(LIKE_WORK_LIMIT),
        }
    }
}

/// Why an expression could not be evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalError {
    /// The name is not a column of the table being read.
    UnknownColumn(String),
    /// An aggregate appeared where a scalar is required.
    GroupFunction,
    /// `FUNCTION <name> does not exist`.
    UnknownFunction(String),
    /// A known function was called with the wrong arity.
    WrongArgCount(String),
}

impl EvalError {
    /// MySQL error code for this failure.
    pub fn code(&self) -> u16 {
        match self {
            Self::UnknownColumn(_) => 1054,
            Self::GroupFunction => 1111,
            Self::UnknownFunction(_) => 1305,
            Self::WrongArgCount(_) => 1582,
        }
    }

    /// `SQLSTATE` for this failure.
    pub fn sqlstate(&self) -> &'static str {
        match self {
            Self::UnknownColumn(_) | Self::WrongArgCount(_) => "42S22",
            Self::GroupFunction | Self::UnknownFunction(_) => "42000",
        }
    }

    /// Render the message MySQL would produce.
    pub fn message(&self, context: &str) -> String {
        match self {
            Self::UnknownColumn(name) => {
                format!("Unknown column '{}' in '{context}'", util::clip(name, 64))
            }
            Self::GroupFunction => "Invalid use of group function".to_string(),
            Self::UnknownFunction(name) => {
                format!("FUNCTION {} does not exist", util::clip(name, 64))
            }
            Self::WrongArgCount(name) => format!(
                "Incorrect parameter count in the call to native function '{}'",
                util::clip(name, 64)
            ),
        }
    }
}

/// One row being evaluated, plus the columns it was read from.
pub struct RowContext<'a> {
    /// Column definitions of the table.
    pub columns: &'a [FakeColumn],
    /// Cell values aligned with `columns`.
    pub row: &'a [Option<String>],
    /// Session identity.
    pub session: &'a EvalContext,
    /// Session state (`@vars`, `LAST_INSERT_ID()`).
    pub state: &'a SessionState,
    /// System variable table backing `@@name`.
    pub variables: &'a [(String, String)],
}

impl RowContext<'_> {
    /// Look up a system variable the way `@@name` does.
    pub fn system_variable(&self, name: &str) -> Option<&str> {
        self.variables
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Whether a declared column type is numeric.
pub fn is_numeric_type(data_type: &str) -> bool {
    let head = data_type
        .split(['(', ' '])
        .next()
        .unwrap_or(data_type)
        .to_ascii_lowercase();
    matches!(
        head.as_str(),
        "int"
            | "integer"
            | "bigint"
            | "smallint"
            | "tinyint"
            | "mediumint"
            | "decimal"
            | "numeric"
            | "double"
            | "float"
            | "real"
            | "bit"
            | "year"
    )
}

fn column_index(columns: &[FakeColumn], name: &str) -> Option<usize> {
    columns
        .iter()
        .position(|column| column.name.eq_ignore_ascii_case(name))
}

fn cell_value(row: &[Option<String>], index: usize) -> Value {
    match row.get(index).and_then(|cell| cell.as_deref()) {
        // The catalog stores the textual `NULL` for cells that are null, which
        // is how `information_schema` renders a missing default.
        None => Value::Null,
        Some(text) => Value::Text(text.to_string()),
    }
}

/// Compare two values with MySQL coercion rules; `None` for an unknown result.
///
/// `numeric` selects the interpretation of the operands. Both branches return a
/// **total** order over everything except `NULL`, so a comparator built on this
/// function is always consistent and transitive.
pub fn compare_values(left: &Value, right: &Value, numeric: bool) -> Option<Ordering> {
    if matches!(left, Value::Null) || matches!(right, Value::Null) {
        return None;
    }
    if numeric {
        // `total_cmp` gives a real total order (NaN included) and `as_f64`
        // already maps an unparsable string to `0.0` the way MySQL coerces it.
        // No type-based tie-break here: `'admin' = 0` has to stay true, which is
        // exactly what MySQL does. `SortKey` is what adds determinism for
        // sorting.
        let a = left.as_f64().unwrap_or(0.0);
        let b = right.as_f64().unwrap_or(0.0);
        return Some(a.total_cmp(&b));
    }
    // Text mode is a pure function of the renderings, which is what makes it
    // transitive. A mixed numeric/text fast path here would break transitivity —
    // and `slice::sort_by` is allowed to panic on a comparator that does not
    // describe a total order.
    Some(collate(left, right))
}

/// Compare two values by their rendered text under the `ai_ci` collation.
fn collate(left: &Value, right: &Value) -> Ordering {
    let left = left.to_wire().unwrap_or_default();
    let right = right.to_wire().unwrap_or_default();
    case_insensitive_cmp(&left, &right)
}

/// A pre-computed ordering key for `ORDER BY` / `GROUP BY`.
///
/// Building the key once per row turns the comparator into a handful of
/// comparisons: no lowercasing, no allocation and — critically — no chance of an
/// inconsistent `sort_by` closure, which `slice::sort_by` may exploit to panic.
#[derive(Debug, Clone)]
pub enum SortKey {
    /// The SQL `NULL`, ordered before every non-`NULL` value.
    Null,
    /// A numeric interpretation.
    Number(f64),
    /// A lowercased rendering for the case-insensitive collation.
    Text(String),
}

impl SortKey {
    /// Build the ordering key for one value.
    pub fn new(value: &Value, numeric: bool) -> Self {
        match value {
            Value::Null => Self::Null,
            other if numeric => Self::Number(other.as_f64().unwrap_or(0.0)),
            other => Self::Text(other.to_wire().unwrap_or_default().to_lowercase()),
        }
    }
}

impl Ord for SortKey {
    /// Total order over keys: `NULL` first, then numbers, then text.
    ///
    /// `f64::total_cmp` is used rather than `partial_cmp`, so the order stays
    /// total even when a hostile query produces a `NaN`.
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Null, Self::Null) => Ordering::Equal,
            (Self::Null, _) => Ordering::Less,
            (_, Self::Null) => Ordering::Greater,
            (Self::Number(a), Self::Number(b)) => a.total_cmp(b),
            (Self::Number(_), Self::Text(_)) => Ordering::Less,
            (Self::Text(_), Self::Number(_)) => Ordering::Greater,
            (Self::Text(a), Self::Text(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for SortKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for SortKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for SortKey {}

/// Whether an `ORDER BY` / `GROUP BY` key should compare numerically.
///
/// The decision follows the declared column type, so `ORDER BY id` is numeric
/// while `ORDER BY username` is a real dictionary comparison. Anything that is
/// not known to produce text is treated as numeric, which keeps numbers and
/// `0`/`1` predicates ordered correctly.
pub fn sort_is_numeric(expression: &Expr, columns: &[FakeColumn]) -> bool {
    fn produces_text(expression: &Expr, columns: &[FakeColumn]) -> bool {
        match expression {
            Expr::Column(name) => column_index(columns, name)
                .is_some_and(|index| !is_numeric_type(&columns[index].data_type)),
            Expr::Literal(value) => matches!(value, Value::Text(_)),
            Expr::UserVar(_) | Expr::SysVar(_) => true,
            Expr::Neg(inner) => produces_text(inner, columns),
            Expr::Not(_) | Expr::IsNull { .. } | Expr::InList { .. } | Expr::Like { .. } => false,
            // Arithmetic and comparisons both produce numbers.
            Expr::Binary(_, _, _) => false,
            Expr::Func { name, args, .. } => match name.to_ascii_uppercase().as_str() {
                "MIN" | "MAX" | "IFNULL" | "COALESCE" | "NULLIF" | "IF" => {
                    args.first().is_some_and(|arg| produces_text(arg, columns))
                }
                "CONCAT" | "CONCAT_WS" | "UPPER" | "UCASE" | "LOWER" | "LCASE" | "TRIM"
                | "LTRIM" | "RTRIM" | "REPLACE" | "SUBSTRING" | "SUBSTR" | "MID" | "LEFT"
                | "RIGHT" | "REVERSE" | "REPEAT" | "MD5" | "SHA" | "SHA1" | "SHA2" | "PASSWORD"
                | "OLD_PASSWORD" | "HEX" | "UNHEX" | "USER" | "SESSION_USER" | "SYSTEM_USER"
                | "CURRENT_USER" | "DATABASE" | "SCHEMA" | "VERSION" | "VERSION_COMMENT"
                | "NOW" | "CURRENT_TIMESTAMP" | "SYSDATE" | "LOCALTIME" | "LOCALTIMESTAMP"
                | "CURDATE" | "CURRENT_DATE" | "CURTIME" | "CURRENT_TIME" | "UUID" | "CAST"
                | "CONVERT" => true,
                _ => false,
            },
        }
    }
    !produces_text(expression, columns)
}

/// `utf8mb4_0900_ai_ci` comparison: case insensitive, accent rules ignored.
///
/// There is deliberately no exact-byte tie-break: under `ai_ci` the strings
/// `Admin` and `admin` *are* equal, in `WHERE`, `GROUP BY` and `ORDER BY` alike.
/// A tie-break here would make `WHERE username = 'ALICE'` miss `alice`, which the
/// advertised collation says is the same value. The relation is still a total
/// preorder (a pure function of the lowercased text), so it is transitive and a
/// comparator built on it is consistent.
fn case_insensitive_cmp(left: &str, right: &str) -> Ordering {
    left.to_lowercase().cmp(&right.to_lowercase())
}

/// Decide whether a comparison should be numeric.
fn numeric_comparison(left_expr: &Expr, right_expr: &Expr, columns: &[FakeColumn]) -> bool {
    fn literal_number(expression: &Expr) -> bool {
        matches!(
            expression,
            Expr::Literal(Value::Int(_)) | Expr::Literal(Value::Float(_))
        )
    }
    fn column_is_numeric(expression: &Expr, columns: &[FakeColumn]) -> bool {
        match expression {
            Expr::Column(name) => column_index(columns, name)
                .is_some_and(|index| is_numeric_type(&columns[index].data_type)),
            Expr::Neg(inner) => column_is_numeric(inner, columns),
            _ => false,
        }
    }
    literal_number(left_expr)
        || literal_number(right_expr)
        || column_is_numeric(left_expr, columns)
        || column_is_numeric(right_expr, columns)
}

/// `LIKE` matching with `%` and `_`, case insensitive, no backtracking blow-up.
///
/// The implementation is the classic single-star backtracking scan: it is
/// O(value × pattern) worst case and can never recurse. This wrapper has no work
/// ceiling — the statement path uses [`like_match_bounded`], which does.
pub fn like_match(pattern: &str, value: &str) -> bool {
    like_match_inner(pattern, value, None).unwrap_or(false)
}

/// `LIKE` matching that charges its work against a per-statement budget.
///
/// Returns `false` once the budget is exhausted: a filter may lose rows under
/// load, but it can never invent them.
pub fn like_match_bounded(pattern: &str, value: &str, budget: &Cell<usize>) -> bool {
    like_match_inner(pattern, value, Some(budget)).unwrap_or(false)
}

/// `Some(matched)`, or `None` when the work budget ran out.
fn like_match_inner(pattern: &str, value: &str, budget: Option<&Cell<usize>>) -> Option<bool> {
    if pattern.len() > LIKE_PATTERN_LIMIT * 4 {
        // A pattern longer than any value we store cannot match usefully, and
        // it is the multiplier that makes the scan expensive.
        return Some(false);
    }
    let pattern: Vec<char> = pattern.to_lowercase().chars().collect();
    if pattern.len() > LIKE_PATTERN_LIMIT {
        return Some(false);
    }
    let value: Vec<char> = value.to_lowercase().chars().collect();
    let mut pattern_index = 0usize;
    let mut value_index = 0usize;
    let mut star_index: Option<usize> = None;
    let mut star_value_index = 0usize;
    while value_index < value.len() {
        if let Some(budget) = budget {
            let remaining = budget.get();
            if remaining == 0 {
                return None;
            }
            budget.set(remaining - 1);
        }
        let mut advanced = false;
        if pattern_index < pattern.len() {
            match pattern[pattern_index] {
                '%' => {
                    star_index = Some(pattern_index);
                    star_value_index = value_index;
                    pattern_index += 1;
                    advanced = true;
                }
                '_' => {
                    pattern_index += 1;
                    value_index += 1;
                    advanced = true;
                }
                '\\' if pattern_index + 1 < pattern.len() => {
                    if pattern[pattern_index + 1] == value[value_index] {
                        pattern_index += 2;
                        value_index += 1;
                        advanced = true;
                    }
                }
                literal => {
                    if literal == value[value_index] {
                        pattern_index += 1;
                        value_index += 1;
                        advanced = true;
                    }
                }
            }
        }
        if !advanced {
            match star_index {
                Some(star) => {
                    // Let the star swallow one more character and retry.
                    star_value_index += 1;
                    value_index = star_value_index;
                    pattern_index = star + 1;
                }
                None => return Some(false),
            }
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == '%' {
        pattern_index += 1;
    }
    Some(pattern_index == pattern.len())
}

/// Evaluate `expression` against one row.
pub fn evaluate(expression: &Expr, context: &RowContext<'_>) -> Result<Value, EvalError> {
    match expression {
        Expr::Literal(value) => Ok(value.clone()),
        Expr::Column(name) => match column_index(context.columns, name) {
            Some(index) => Ok(cell_value(context.row, index)),
            None => Err(EvalError::UnknownColumn(name.clone())),
        },
        Expr::UserVar(name) => Ok(context
            .state
            .user_variable(name)
            .map(|value| Value::Text(value.to_string()))
            .unwrap_or(Value::Null)),
        Expr::SysVar(name) => Ok(context
            .system_variable(name)
            .map(|value| Value::Text(value.to_string()))
            .unwrap_or(Value::Null)),
        Expr::Neg(inner) => {
            let value = evaluate(inner, context)?;
            Ok(match value {
                Value::Null => Value::Null,
                Value::Int(number) => Value::Int(number.wrapping_neg()),
                Value::Float(number) => Value::Float(-number),
                Value::Text(text) => Value::Float(-parse_number(&text).unwrap_or(0.0)),
            })
        }
        Expr::Not(inner) => {
            let value = evaluate(inner, context)?;
            Ok(match value.truthy() {
                None => Value::Null,
                Some(flag) => Value::Int(i64::from(!flag)),
            })
        }
        Expr::IsNull { inner, negated } => {
            let value = evaluate(inner, context)?;
            let is_null = matches!(value, Value::Null);
            Ok(Value::Int(i64::from(is_null != *negated)))
        }
        Expr::InList {
            inner,
            list,
            negated,
        } => {
            let needle = evaluate(inner, context)?;
            if matches!(needle, Value::Null) {
                return Ok(Value::Null);
            }
            let mut matched = false;
            let mut saw_null = false;
            for candidate in list {
                let value = evaluate(candidate, context)?;
                match compare_values(
                    &needle,
                    &value,
                    numeric_comparison(inner, candidate, context.columns),
                ) {
                    Some(Ordering::Equal) => {
                        matched = true;
                        break;
                    }
                    None => saw_null = true,
                    _ => {}
                }
            }
            if matched {
                return Ok(Value::Int(i64::from(!*negated)));
            }
            if saw_null {
                return Ok(Value::Null);
            }
            Ok(Value::Int(i64::from(*negated)))
        }
        Expr::Like {
            inner,
            pattern,
            negated,
        } => {
            let value = evaluate(inner, context)?;
            let pattern = evaluate(pattern, context)?;
            let (Value::Text(value), Value::Text(pattern)) = (value, pattern) else {
                // MySQL: LIKE with a NULL operand is NULL.
                return Ok(Value::Null);
            };
            let matched = like_match_bounded(&pattern, &value, &context.session.like_budget);
            Ok(Value::Int(i64::from(matched != *negated)))
        }
        Expr::Binary(operator, left, right) => match operator {
            BinOp::And => {
                let left = evaluate(left, context)?.truthy();
                if left == Some(false) {
                    return Ok(Value::Int(0));
                }
                let right = evaluate(right, context)?.truthy();
                Ok(match (left, right) {
                    (_, Some(false)) => Value::Int(0),
                    (Some(true), Some(true)) => Value::Int(1),
                    _ => Value::Null,
                })
            }
            BinOp::Or => {
                let left = evaluate(left, context)?.truthy();
                if left == Some(true) {
                    return Ok(Value::Int(1));
                }
                let right = evaluate(right, context)?.truthy();
                Ok(match (left, right) {
                    (_, Some(true)) => Value::Int(1),
                    (Some(false), Some(false)) => Value::Int(0),
                    _ => Value::Null,
                })
            }
            BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod => {
                let left = evaluate(left, context)?;
                let right = evaluate(right, context)?;
                Ok(arithmetic(*operator, left, right))
            }
            comparison => {
                let left_value = evaluate(left, context)?;
                let right_value = evaluate(right, context)?;
                let numeric = numeric_comparison(left, right, context.columns);
                let ordering = compare_values(&left_value, &right_value, numeric);
                let Some(ordering) = ordering else {
                    return Ok(Value::Null);
                };
                let result = match comparison {
                    BinOp::Eq => ordering == Ordering::Equal,
                    BinOp::NotEq => ordering != Ordering::Equal,
                    BinOp::Lt => ordering == Ordering::Less,
                    BinOp::Le => ordering != Ordering::Greater,
                    BinOp::Gt => ordering == Ordering::Greater,
                    BinOp::Ge => ordering != Ordering::Less,
                    _ => unreachable!("only comparisons reach this arm"),
                };
                Ok(Value::Int(i64::from(result)))
            }
        },
        Expr::Func {
            name,
            args,
            distinct,
            star,
        } => {
            let mut values = Vec::with_capacity(args.len());
            for argument in args {
                values.push(evaluate(argument, context)?);
            }
            call_scalar(name, &values, *distinct, *star, context)
        }
    }
}

fn arithmetic(operator: BinOp, left: Value, right: Value) -> Value {
    if matches!(left, Value::Null) || matches!(right, Value::Null) {
        return Value::Null;
    }
    if let (Value::Int(a), Value::Int(b)) = (&left, &right) {
        let (a, b) = (*a, *b);
        return match operator {
            BinOp::Add => Value::Int(a.wrapping_add(b)),
            BinOp::Sub => Value::Int(a.wrapping_sub(b)),
            BinOp::Mul => Value::Int(a.wrapping_mul(b)),
            BinOp::Div if b != 0 => Value::Float(a as f64 / b as f64),
            BinOp::Mod if b != 0 => Value::Int(a % b),
            _ => Value::Null,
        };
    }
    let a = left.as_f64().unwrap_or(0.0);
    let b = right.as_f64().unwrap_or(0.0);
    match operator {
        BinOp::Add => Value::Float(a + b),
        BinOp::Sub => Value::Float(a - b),
        BinOp::Mul => Value::Float(a * b),
        BinOp::Div if b != 0.0 => Value::Float(a / b),
        BinOp::Mod if b != 0.0 => Value::Float(a % b),
        _ => Value::Null,
    }
}

/// Evaluate a `WHERE` clause: `NULL` and errors that mean "no" filter the row out.
pub fn matches_where(expression: &Expr, context: &RowContext<'_>) -> Result<bool, EvalError> {
    Ok(evaluate(expression, context)?.truthy().unwrap_or(false))
}

// ---------------------------------------------------------------------------
// Scalar functions
// ---------------------------------------------------------------------------

fn text_argument(values: &[Value], index: usize) -> Option<String> {
    values.get(index).and_then(|value| match value {
        Value::Null => None,
        other => other.to_wire(),
    })
}

/// Wrap a produced string, clipping it to the per-value budget.
///
/// `CONCAT`, `REPLACE` and `UPPER` can be handed a 16 KiB literal and return
/// more than they were given; without this ceiling one statement could pin far
/// more memory than the virtual database budgets allow a stored value.
fn text_value(text: String) -> Value {
    if text.len() > super::MAX_STRING_VALUE_BYTES {
        Value::Text(util::truncate_to(&text, super::MAX_STRING_VALUE_BYTES).0)
    } else {
        Value::Text(text)
    }
}

fn call_scalar(
    name: &str,
    values: &[Value],
    distinct: bool,
    star: bool,
    context: &RowContext<'_>,
) -> Result<Value, EvalError> {
    if super::sql::is_aggregate(name) {
        // Aggregates are folded by the selector, never here.
        return Err(EvalError::GroupFunction);
    }
    let upper = name.to_ascii_uppercase();
    match upper.as_str() {
        "VERSION" => Ok(Value::Text(context.session.server_version.clone())),
        "DATABASE" | "SCHEMA" => Ok(if context.session.current_db.is_empty() {
            Value::Null
        } else {
            Value::Text(context.session.current_db.clone())
        }),
        "USER" | "SESSION_USER" | "SYSTEM_USER" => Ok(Value::Text(format!(
            "{}@{}",
            context.session.username, context.session.client_host
        ))),
        "CURRENT_USER" => Ok(Value::Text(format!("{}@%", context.session.username))),
        "CONNECTION_ID" => Ok(Value::Int(i64::from(context.session.connection_id))),
        "NOW" | "CURRENT_TIMESTAMP" | "SYSDATE" | "LOCALTIME" | "LOCALTIMESTAMP" => {
            Ok(Value::Text(sql_datetime(&util::utc_now())))
        }
        "CURDATE" | "CURRENT_DATE" => Ok(Value::Text(date_part(&util::utc_now()))),
        "CURTIME" | "CURRENT_TIME" => Ok(Value::Text(time_part(&util::utc_now()))),
        "UNIX_TIMESTAMP" => Ok(Value::Int(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|delta| delta.as_secs() as i64)
                .unwrap_or(0),
        )),
        "MD5" => Ok(match text_argument(values, 0) {
            Some(text) => Value::Text(hash::md5_hex(text.as_bytes())),
            None => Value::Null,
        }),
        "SHA" | "SHA1" => Ok(match text_argument(values, 0) {
            Some(text) => Value::Text(hash::sha1_hex(text.as_bytes())),
            None => Value::Null,
        }),
        "SHA2" => {
            let Some(text) = text_argument(values, 0) else {
                return Ok(Value::Null);
            };
            let bits = values
                .get(1)
                .and_then(Value::as_f64)
                .map(|number| number.max(0.0) as u64)
                .ok_or_else(|| EvalError::WrongArgCount(upper.clone()))?;
            Ok(Value::Text(hash::sha2_hex(
                text.as_bytes(),
                hash::Sha2Bits::from_bits(bits),
            )))
        }
        "PASSWORD" | "OLD_PASSWORD" => Ok(match text_argument(values, 0) {
            Some(text) => Value::Text(hash::password_hash(text.as_bytes())),
            None => Value::Null,
        }),
        "LENGTH" | "OCTET_LENGTH" => Ok(match text_argument(values, 0) {
            Some(text) => Value::Int(text.len() as i64),
            None => Value::Null,
        }),
        "BIT_LENGTH" => Ok(match text_argument(values, 0) {
            Some(text) => Value::Int((text.len() * 8) as i64),
            None => Value::Null,
        }),
        "CHAR_LENGTH" | "CHARACTER_LENGTH" => Ok(match text_argument(values, 0) {
            Some(text) => Value::Int(text.chars().count() as i64),
            None => Value::Null,
        }),
        "UPPER" | "UCASE" => Ok(match text_argument(values, 0) {
            Some(text) => text_value(text.to_uppercase()),
            None => Value::Null,
        }),
        "LOWER" | "LCASE" => Ok(match text_argument(values, 0) {
            Some(text) => text_value(text.to_lowercase()),
            None => Value::Null,
        }),
        "HEX" => Ok(match text_argument(values, 0) {
            Some(text) => Value::Text(hash::hex_upper(text.as_bytes())),
            None => Value::Null,
        }),
        "UNHEX" => Ok(match text_argument(values, 0) {
            Some(text) => {
                let bytes = decode_hex(&text);
                match bytes {
                    Some(bytes) => text_value(String::from_utf8_lossy(&bytes).into_owned()),
                    None => Value::Null,
                }
            }
            None => Value::Null,
        }),
        "ASCII" | "ORD" => Ok(match text_argument(values, 0) {
            Some(text) => Value::Int(i64::from(text.as_bytes().first().copied().unwrap_or(0))),
            None => Value::Null,
        }),
        "CONCAT" => {
            if values.iter().any(|value| matches!(value, Value::Null)) {
                return Ok(Value::Null);
            }
            Ok(text_value(
                values
                    .iter()
                    .map(|value| value.to_wire().unwrap_or_default())
                    .collect::<Vec<_>>()
                    .join(""),
            ))
        }
        "CONCAT_WS" => {
            let Some(separator) = text_argument(values, 0) else {
                return Ok(Value::Null);
            };
            let parts: Vec<String> = values
                .iter()
                .skip(1)
                .filter_map(|value| value.to_wire())
                .collect();
            Ok(text_value(parts.join(&separator)))
        }
        "TRIM" => Ok(match text_argument(values, 0) {
            Some(text) => Value::Text(text.trim().to_string()),
            None => Value::Null,
        }),
        "LTRIM" => Ok(match text_argument(values, 0) {
            Some(text) => Value::Text(text.trim_start().to_string()),
            None => Value::Null,
        }),
        "RTRIM" => Ok(match text_argument(values, 0) {
            Some(text) => Value::Text(text.trim_end().to_string()),
            None => Value::Null,
        }),
        "REPLACE" => Ok(
            match (
                text_argument(values, 0),
                text_argument(values, 1),
                text_argument(values, 2),
            ) {
                (Some(haystack), Some(needle), Some(replacement)) => {
                    text_value(haystack.replace(&needle, &replacement))
                }
                _ => Value::Null,
            },
        ),
        "SUBSTRING" | "SUBSTR" | "MID" => {
            let Some(text) = text_argument(values, 0) else {
                return Ok(Value::Null);
            };
            let start = values.get(1).and_then(Value::as_f64).unwrap_or(1.0) as i64;
            let length = values.get(2).and_then(Value::as_f64);
            let chars: Vec<char> = text.chars().collect();
            let begin = if start > 0 {
                (start - 1) as usize
            } else if start < 0 {
                chars.len().saturating_sub(start.unsigned_abs() as usize)
            } else {
                0
            };
            let begin = begin.min(chars.len());
            let end = match length {
                // `saturating_add`, not `+`: `length as usize` saturates to
                // `usize::MAX` for a hostile `SUBSTRING(x, 1, 1e300)`, and the
                // wrapped sum would make `begin > end`, which panics on slice
                // indexing.
                Some(length) if length > 0.0 => {
                    begin.saturating_add(length as usize).min(chars.len())
                }
                Some(_) => begin,
                None => chars.len(),
            };
            Ok(Value::Text(chars[begin..end].iter().collect()))
        }
        "LEFT" => Ok(
            match (
                text_argument(values, 0),
                values.get(1).and_then(Value::as_f64),
            ) {
                (Some(text), Some(count)) => {
                    let chars: Vec<char> = text.chars().collect();
                    let take = (count.max(0.0) as usize).min(chars.len());
                    Value::Text(chars[..take].iter().collect())
                }
                _ => Value::Null,
            },
        ),
        "RIGHT" => Ok(
            match (
                text_argument(values, 0),
                values.get(1).and_then(Value::as_f64),
            ) {
                (Some(text), Some(count)) => {
                    let chars: Vec<char> = text.chars().collect();
                    let take = (count.max(0.0) as usize).min(chars.len());
                    Value::Text(chars[chars.len() - take..].iter().collect())
                }
                _ => Value::Null,
            },
        ),
        "REVERSE" => Ok(match text_argument(values, 0) {
            Some(text) => text_value(text.chars().rev().collect()),
            None => Value::Null,
        }),
        "REPEAT" => Ok(
            match (
                text_argument(values, 0),
                values.get(1).and_then(Value::as_f64),
            ) {
                (Some(text), Some(count)) => {
                    // Cap the product so a hostile `REPEAT('x', 1e18)` cannot
                    // allocate gigabytes.
                    let count = (count.max(0.0) as usize).min(1024);
                    let total = text.len().saturating_mul(count);
                    if total > super::MAX_STRING_VALUE_BYTES {
                        return Ok(Value::Null);
                    }
                    Value::Text(text.repeat(count))
                }
                _ => Value::Null,
            },
        ),
        "ABS" => Ok(match values.first() {
            Some(Value::Int(number)) => Value::Int(number.wrapping_abs()),
            Some(Value::Float(number)) => Value::Float(number.abs()),
            Some(Value::Text(text)) => Value::Float(parse_number(text).unwrap_or(0.0).abs()),
            _ => Value::Null,
        }),
        "CEIL" | "CEILING" => Ok(match values.first().and_then(Value::as_f64) {
            Some(number) => Value::Int(number.ceil() as i64),
            None => Value::Null,
        }),
        "FLOOR" => Ok(match values.first().and_then(Value::as_f64) {
            Some(number) => Value::Int(number.floor() as i64),
            None => Value::Null,
        }),
        "ROUND" => {
            let Some(number) = values.first().and_then(Value::as_f64) else {
                return Ok(Value::Null);
            };
            let places = values
                .get(1)
                .and_then(Value::as_f64)
                .map(|value| value.clamp(-30.0, 30.0) as i32)
                .unwrap_or(0);
            if places <= 0 {
                let factor = 10f64.powi(-places);
                // `factor as i64` saturates for `places = -30`, and the product
                // of two saturated values overflows: use checked arithmetic so a
                // hostile `ROUND(1e308, -30)` cannot trap the process.
                let scaled = (number / factor).round();
                let scaled = if scaled.is_finite() { scaled as i64 } else { 0 };
                Ok(Value::Int(scaled.saturating_mul(factor as i64)))
            } else {
                let factor = 10f64.powi(places);
                let result = (number * factor).round() / factor;
                Ok(if result.is_finite() {
                    Value::Float(result)
                } else {
                    Value::Null
                })
            }
        }
        "SIGN" => Ok(match values.first().and_then(Value::as_f64) {
            Some(number) if number > 0.0 => Value::Int(1),
            Some(number) if number < 0.0 => Value::Int(-1),
            Some(_) => Value::Int(0),
            None => Value::Null,
        }),
        "SQRT" => Ok(match values.first().and_then(Value::as_f64) {
            Some(number) if number >= 0.0 => Value::Float(number.sqrt()),
            Some(_) => Value::Null,
            None => Value::Null,
        }),
        "POW" | "POWER" => Ok(
            match (
                values.first().and_then(Value::as_f64),
                values.get(1).and_then(Value::as_f64),
            ) {
                (Some(base), Some(exponent)) => Value::Float(base.powf(exponent)),
                _ => Value::Null,
            },
        ),
        "MOD" => Ok(
            match (
                values.first().and_then(Value::as_f64),
                values.get(1).and_then(Value::as_f64),
            ) {
                (Some(_), Some(0.0)) | (Some(_), None) | (None, _) => Value::Null,
                (Some(left), Some(right)) => Value::Float(left % right),
            },
        ),
        "IFNULL" => Ok(match values.first() {
            Some(Value::Null) | None => values.get(1).cloned().unwrap_or(Value::Null),
            Some(value) => value.clone(),
        }),
        "NULLIF" => Ok(match (values.first(), values.get(1)) {
            (Some(left), Some(right)) => {
                if compare_values(left, right, true) == Some(Ordering::Equal) {
                    Value::Null
                } else {
                    left.clone()
                }
            }
            _ => Value::Null,
        }),
        "COALESCE" => Ok(values
            .iter()
            .find(|value| !matches!(value, Value::Null))
            .cloned()
            .unwrap_or(Value::Null)),
        "IF" => Ok(match values.first().map(Value::truthy) {
            Some(Some(true)) => values.get(1).cloned().unwrap_or(Value::Null),
            Some(Some(false)) => values.get(2).cloned().unwrap_or(Value::Null),
            _ => Value::Null,
        }),
        "ISNULL" => Ok(Value::Int(i64::from(matches!(
            values.first(),
            Some(Value::Null) | None
        )))),
        "CAST" | "CONVERT" => Ok(values.first().cloned().unwrap_or(Value::Null)),
        // A honeypot must never actually sleep: the delay would be an
        // amplification lever for anyone opening connections in a loop.
        "SLEEP" => Ok(Value::Int(0)),
        "BENCHMARK" => Ok(Value::Int(0)),
        "LAST_INSERT_ID" => Ok(Value::Int(
            values
                .first()
                .and_then(Value::as_f64)
                .map(|number| number as i64)
                .unwrap_or(context.state.last_insert_id() as i64),
        )),
        "ROW_COUNT" => Ok(Value::Int(context.state.row_count())),
        "FOUND_ROWS" => Ok(Value::Int(context.state.row_count())),
        "EXISTS" => Ok(Value::Int(1)),
        "UUID" => Ok(Value::Text(random_uuid())),
        "VERSION_COMMENT" => Ok(Value::Text("MySQL Community Server - GPL".to_string())),
        _ => {
            let _ = (distinct, star);
            Err(EvalError::UnknownFunction(upper))
        }
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for step in 0..bytes.len() / 2 {
        let high = (bytes[step * 2] as char).to_digit(16)?;
        let low = (bytes[step * 2 + 1] as char).to_digit(16)?;
        out.push(((high << 4) | low) as u8);
    }
    Some(out)
}

fn random_uuid() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    let mut bytes = [0u8; 16];
    for byte in &mut bytes {
        *byte = rng.random_range(0u8..=255);
    }
    // RFC 4122 version 4 layout.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hash::hex_upper(&bytes).to_lowercase();
    // Defensive: the slices below assume 32 hex characters.
    if hex.len() != 32 {
        return "00000000-0000-4000-8000-000000000000".to_string();
    }
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn sql_datetime(timestamp: &str) -> String {
    if timestamp.len() >= 19 {
        format!("{} {}", date_part(timestamp), time_part(timestamp))
    } else {
        timestamp.to_string()
    }
}

/// `YYYY-MM-DD` of a `YYYY-MM-DDTHH:MM:SS…` timestamp.
///
/// Slicing is guarded by `is_char_boundary` so a caller that ever hands over a
/// non-ASCII string gets a truncated answer instead of a panic.
fn date_part(timestamp: &str) -> String {
    let end = timestamp.len().min(10);
    match timestamp.get(..end) {
        Some(text) if text.is_char_boundary(text.len()) => text.to_string(),
        _ => timestamp.to_string(),
    }
}

/// `HH:MM:SS` of a `YYYY-MM-DDTHH:MM:SS…` timestamp.
fn time_part(timestamp: &str) -> String {
    let start = 11.min(timestamp.len());
    let end = 19.min(timestamp.len());
    if start < end
        && timestamp.is_char_boundary(start)
        && timestamp.is_char_boundary(end)
        && let Some(text) = timestamp.get(start..end)
    {
        return text.to_string();
    }
    timestamp.to_string()
}

/// Convenience used by the selector: parse `text` as a standalone expression.
pub fn parse(text: &str) -> Option<Expr> {
    let tokens = tokenize(text)?;
    let mut budget = super::sql::Budget::new(super::sql::MAX_TOKENS);
    super::sql::parse_expression(&tokens, &mut budget)
}

/// Render a value list for `SHOW WARNINGS`-style output.
pub fn join_values(values: &[Value]) -> String {
    values
        .iter()
        .map(|value| value.to_wire().unwrap_or_else(|| "NULL".to_string()))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakedb::FakeColumn;

    fn columns() -> Vec<FakeColumn> {
        vec![
            FakeColumn::primary("id", "bigint unsigned", 8),
            FakeColumn::new("username", "varchar(64)", 253),
            FakeColumn::new("email", "varchar(128)", 253),
        ]
    }

    fn row() -> Vec<Option<String>> {
        vec![
            Some("1".to_string()),
            Some("admin".to_string()),
            Some("admin@example.com".to_string()),
        ]
    }

    fn state() -> SessionState {
        SessionState::default()
    }

    fn session() -> EvalContext {
        EvalContext::new(
            "app_prod".to_string(),
            "root".to_string(),
            "203.0.113.9".to_string(),
            7,
            "8.0.36".to_string(),
        )
    }

    fn run(sql: &str) -> Result<Value, EvalError> {
        let expression = super::parse(sql).expect("parse");
        let columns = columns();
        let row = row();
        let state = state();
        let session = session();
        let variables = crate::fakedb::catalog::variables("8.0.36");
        evaluate(
            &expression,
            &RowContext {
                columns: &columns,
                row: &row,
                session: &session,
                state: &state,
                variables: &variables,
            },
        )
    }

    #[test]
    fn equality_is_column_aware() {
        assert_eq!(run("username = 'admin'").expect("eval"), Value::Int(1));
        assert_eq!(run("email = 'admin'").expect("eval"), Value::Int(0));
        assert_eq!(run("id = 1").expect("eval"), Value::Int(1));
        assert_eq!(run("id = '1'").expect("eval"), Value::Int(1));
        assert_eq!(run("id > 0").expect("eval"), Value::Int(1));
        assert_eq!(run("id < 0").expect("eval"), Value::Int(0));
    }

    #[test]
    fn unknown_columns_are_reported_not_ignored() {
        match run("nope = 'x'") {
            Err(EvalError::UnknownColumn(name)) => assert_eq!(name, "nope"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn boolean_operators_follow_three_valued_logic() {
        assert_eq!(
            run("username = 'admin' AND id = 1").expect("eval"),
            Value::Int(1)
        );
        assert_eq!(
            run("username = 'nope' OR id = 1").expect("eval"),
            Value::Int(1)
        );
        assert_eq!(run("NOT username = 'admin'").expect("eval"), Value::Int(0));
        assert_eq!(run("username != 'admin'").expect("eval"), Value::Int(0));
        assert_eq!(run("username <> 'admin'").expect("eval"), Value::Int(0));
    }

    #[test]
    fn in_like_and_null_predicates() {
        assert_eq!(
            run("username IN ('admin','bob')").expect("eval"),
            Value::Int(1)
        );
        assert_eq!(run("username IN ('bob')").expect("eval"), Value::Int(0));
        assert_eq!(run("username NOT IN ('bob')").expect("eval"), Value::Int(1));
        assert_eq!(run("username LIKE 'adm%'").expect("eval"), Value::Int(1));
        assert_eq!(run("username LIKE '_dmin'").expect("eval"), Value::Int(1));
        assert_eq!(run("username LIKE 'ADM%'").expect("eval"), Value::Int(1));
        assert_eq!(
            run("username NOT LIKE 'adm%'").expect("eval"),
            Value::Int(0)
        );
        assert_eq!(run("email IS NULL").expect("eval"), Value::Int(0));
        assert_eq!(run("email IS NOT NULL").expect("eval"), Value::Int(1));
    }

    #[test]
    fn like_never_backtracks_exponentially() {
        let pattern = "%a".repeat(40) + "%b";
        let value = "a".repeat(4_000);
        let started = std::time::Instant::now();
        assert!(!like_match(&pattern, &value));
        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "LIKE matching took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn string_versus_number_uses_mysql_semantics() {
        // 'admin' coerces to 0, so `username = 0` is true in MySQL.
        assert_eq!(run("username = 0").expect("eval"), Value::Int(1));
        assert_eq!(run("username = 1").expect("eval"), Value::Int(0));
    }

    #[test]
    fn identity_functions_are_self_consistent() {
        assert_eq!(
            run("CURRENT_USER()").expect("eval"),
            Value::Text("root@%".to_string())
        );
        assert_eq!(
            run("USER()").expect("eval"),
            Value::Text("root@203.0.113.9".to_string())
        );
        assert_eq!(
            run("DATABASE()").expect("eval"),
            Value::Text("app_prod".to_string())
        );
        assert_eq!(
            run("VERSION()").expect("eval"),
            Value::Text("8.0.36".to_string())
        );
        assert_eq!(run("CONNECTION_ID()").expect("eval"), Value::Int(7));
        assert_eq!(run("SLEEP(30)").expect("eval"), Value::Int(0));
    }

    #[test]
    fn digest_functions_return_real_digests() {
        assert_eq!(
            run("MD5('abc')").expect("eval"),
            Value::Text("900150983CD24FB0D6963F7D28E17F72".to_string())
        );
        assert_eq!(
            run("SHA1('abc')").expect("eval"),
            Value::Text("A9993E364706816ABA3E25717850C26C9CD0D89D".to_string())
        );
        assert!(
            matches!(run("SHA2('abc', 256)").expect("eval"), Value::Text(text)
            if text.len() == 64 && text.starts_with("BA7816BF"))
        );
        assert!(
            matches!(run("PASSWORD('x')").expect("eval"), Value::Text(text)
            if text.starts_with('*') && text.len() == 41)
        );
    }

    #[test]
    fn unknown_functions_report_the_mysql_error() {
        match run("LOAD_FILE('/etc/passwd')") {
            Err(EvalError::UnknownFunction(name)) => assert_eq!(name, "LOAD_FILE"),
            other => panic!("unexpected {other:?}"),
        }
        match run("COUNT(*)") {
            Err(EvalError::GroupFunction) => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn repeat_cannot_allocate_without_bound() {
        // The count is clamped and the product is checked, so a hostile repeat
        // count can never allocate more than the value budget.
        match run("REPEAT('x', 1000000000)").expect("eval") {
            Value::Text(text) => assert!(text.len() <= super::super::MAX_STRING_VALUE_BYTES),
            other => panic!("unexpected {other:?}"),
        }
        // A long needle times a clamped count still exceeds the budget.
        assert_eq!(
            run("REPEAT('0123456789', 1000)").expect("eval"),
            Value::Null
        );
    }

    #[test]
    fn numeric_helpers_match_mysql_coercion() {
        assert!(is_numeric_type("bigint unsigned"));
        assert!(is_numeric_type("decimal(10,2)"));
        assert!(!is_numeric_type("varchar(64)"));
        assert!(!is_numeric_type("datetime"));
    }

    #[test]
    fn text_sort_keys_are_dictionary_ordered() {
        let mut keys: Vec<SortKey> = ["bob", "alice", "admin", "alice2"]
            .iter()
            .map(|name| SortKey::new(&Value::Text((*name).to_string()), false))
            .collect();
        keys.sort_by(SortKey::cmp);
        let ordered: Vec<String> = keys
            .iter()
            .map(|key| match key {
                SortKey::Text(text) => text.clone(),
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(ordered, vec!["admin", "alice", "alice2", "bob"]);
    }

    #[test]
    fn numeric_sort_keys_are_value_ordered() {
        let mut keys: Vec<SortKey> = ["10", "9", "100", "2"]
            .iter()
            .map(|number| SortKey::new(&Value::Text((*number).to_string()), true))
            .collect();
        keys.sort_by(SortKey::cmp);
        let ordered: Vec<f64> = keys
            .iter()
            .map(|key| match key {
                SortKey::Number(number) => *number,
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(ordered, vec![2.0, 9.0, 10.0, 100.0]);
    }

    #[test]
    fn non_numeric_strings_are_not_all_equal() {
        // The bug this guards: with a forced numeric comparison every string
        // reads as `0`, so `admin`, `alice` and `bob` all compare equal and the
        // sort order collapses to insertion order.
        let values = [
            Value::Text("bob".to_string()),
            Value::Text("admin".to_string()),
            Value::Text("alice".to_string()),
        ];
        assert_eq!(
            compare_values(&values[1], &values[2], false),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare_values(&values[2], &values[0], false),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare_values(&values[1], &values[0], false),
            Some(Ordering::Less)
        );
        // And a forced numeric comparison really does collapse them — this is
        // exactly the regression that a hard-coded `numeric = true` produced for
        // every `ORDER BY` over a `varchar` column.
        for left in &values {
            for right in &values {
                assert_eq!(
                    compare_values(left, right, true),
                    Some(Ordering::Equal),
                    "{left:?} and {right:?} must both coerce to 0"
                );
            }
        }
    }

    #[test]
    fn sort_keys_form_a_total_order() {
        let values = [
            Value::Null,
            Value::Int(0),
            Value::Int(-1),
            Value::Float(2.5),
            Value::Float(f64::NAN),
            Value::Text("abc".to_string()),
            Value::Text("10".to_string()),
            Value::Text(String::new()),
        ];
        for numeric in [true, false] {
            let keys: Vec<SortKey> = values
                .iter()
                .map(|value| SortKey::new(value, numeric))
                .collect();
            // Totality: every pair must compare, and the result must be
            // antisymmetric.
            for left in &keys {
                for right in &keys {
                    let forward = left.cmp(right);
                    let backward = right.cmp(left);
                    assert_eq!(forward, backward.reverse(), "not antisymmetric");
                }
            }
            // Transitivity on the strict part, which is what `sort_by` requires.
            for a in &keys {
                for b in &keys {
                    for c in &keys {
                        if a.cmp(b) == Ordering::Less && b.cmp(c) == Ordering::Less {
                            assert_eq!(a.cmp(c), Ordering::Less, "not transitive");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn null_sorts_before_everything_ascending() {
        let null = SortKey::new(&Value::Null, true);
        let zero = SortKey::new(&Value::Int(0), true);
        let text = SortKey::new(&Value::Text("a".to_string()), false);
        let text_null = SortKey::new(&Value::Null, false);
        assert_eq!(null.cmp(&zero), Ordering::Less);
        assert_eq!(text_null.cmp(&text), Ordering::Less);
    }

    #[test]
    fn sort_is_numeric_follows_the_column_type() {
        let columns = columns();
        let identifier = Expr::Column("id".to_string());
        let username = Expr::Column("username".to_string());
        assert!(sort_is_numeric(&identifier, &columns));
        assert!(!sort_is_numeric(&username, &columns));
        // A string function keeps the text collation.
        let upper = super::parse("UPPER(username)").expect("parse");
        assert!(!sort_is_numeric(&upper, &columns));
        // An aggregate over a text column stays textual.
        let minimum = super::parse("MIN(username)").expect("parse");
        assert!(!sort_is_numeric(&minimum, &columns));
        let count = super::parse("COUNT(username)").expect("parse");
        assert!(sort_is_numeric(&count, &columns));
    }

    #[test]
    fn substring_with_a_hostile_length_does_not_overflow() {
        // `1e300 as usize` saturates; a plain `+` would wrap and produce
        // `begin > end`, which panics while slicing.
        assert!(
            matches!(run("SUBSTRING('abcdef', 2, 1e300)"), Ok(Value::Text(ref text)) if text == "bcdef")
        );
        assert!(matches!(
            run("SUBSTRING('abcdef', -1e300, 3)"),
            Ok(Value::Text(_))
        ));
        assert!(
            matches!(run("SUBSTRING('abcdef', 3, -1e300)"), Ok(Value::Text(ref text)) if text.is_empty())
        );
    }

    #[test]
    fn round_with_a_hostile_scale_does_not_overflow() {
        // `10f64.powi(30) as i64` saturates to `i64::MAX`, so the surrounding
        // multiplication has to be saturating as well.
        assert!(run("ROUND(1e308, -30)").is_ok());
        assert!(run("ROUND(-1e308, -30)").is_ok());
        assert!(run("ROUND(1e308, 30)").is_ok());
    }

    #[test]
    fn like_work_budget_stops_a_hostile_pattern() {
        let budget = Cell::new(64);
        let pattern = "%a".repeat(200) + "%b";
        let value = "a".repeat(4_000);
        assert!(!like_match_bounded(&pattern, &value, &budget));
        assert_eq!(budget.get(), 0, "the budget must be spent, not reset");
        // An exhausted budget answers "no match" rather than looping.
        assert!(!like_match_bounded("a%", "abc", &budget));
    }

    #[test]
    fn like_pattern_length_is_capped() {
        let budget = Cell::new(LIKE_WORK_LIMIT);
        let pattern = "x".repeat(LIKE_PATTERN_LIMIT + 8);
        assert!(!like_match_bounded(&pattern, "xxxx", &budget));
        assert_eq!(
            budget.get(),
            LIKE_WORK_LIMIT,
            "an over-long pattern must be refused before any work"
        );
    }

    #[test]
    fn produced_strings_stay_within_the_value_budget() {
        let long = "x".repeat(8_000);
        match text_value(long.to_uppercase()) {
            Value::Text(text) => assert!(text.len() <= super::super::MAX_STRING_VALUE_BYTES),
            other => panic!("unexpected {other:?}"),
        }
    }
}
