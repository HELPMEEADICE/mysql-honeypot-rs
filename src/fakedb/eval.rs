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

use std::cmp::Ordering;

use super::FakeColumn;
use super::sql::{BinOp, Expr, Value, parse_number, tokenize};
use super::state::SessionState;
use crate::hash;
use crate::util;

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
pub fn compare_values(left: &Value, right: &Value, numeric: bool) -> Option<Ordering> {
    if matches!(left, Value::Null) || matches!(right, Value::Null) {
        return None;
    }
    if numeric {
        return match (left, right) {
            (Value::Int(a), Value::Int(b)) => Some(a.cmp(b)),
            _ => {
                let a = left.as_f64().unwrap_or(0.0);
                let b = right.as_f64().unwrap_or(0.0);
                a.partial_cmp(&b)
            }
        };
    }
    match (left, right) {
        (Value::Int(a), Value::Int(b)) => Some(a.cmp(b)),
        (Value::Text(a), Value::Text(b)) => Some(case_insensitive_cmp(a, b)),
        // A number on either side turns the comparison numeric.
        _ => {
            let a = left.as_f64().unwrap_or(0.0);
            let b = right.as_f64().unwrap_or(0.0);
            a.partial_cmp(&b)
        }
    }
}

/// `utf8mb4_0900_ai_ci` style comparison: case insensitive, then byte order.
fn case_insensitive_cmp(left: &str, right: &str) -> Ordering {
    let lowered_left = left.to_lowercase();
    let lowered_right = right.to_lowercase();
    lowered_left
        .cmp(&lowered_right)
        .then_with(|| left.cmp(right))
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
/// O(value × pattern) worst case and can never recurse.
pub fn like_match(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.to_lowercase().chars().collect();
    let value: Vec<char> = value.to_lowercase().chars().collect();
    let mut pattern_index = 0usize;
    let mut value_index = 0usize;
    let mut star_index: Option<usize> = None;
    let mut star_value_index = 0usize;
    while value_index < value.len() {
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
                None => return false,
            }
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == '%' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
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
            let matched = like_match(&pattern, &value);
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
        "CURDATE" | "CURRENT_DATE" => {
            let now = util::utc_now();
            Ok(Value::Text(now[..10].to_string()))
        }
        "CURTIME" | "CURRENT_TIME" => {
            let now = util::utc_now();
            Ok(Value::Text(now[11..19].to_string()))
        }
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
            Some(text) => Value::Text(text.to_uppercase()),
            None => Value::Null,
        }),
        "LOWER" | "LCASE" => Ok(match text_argument(values, 0) {
            Some(text) => Value::Text(text.to_lowercase()),
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
                    Some(bytes) => Value::Text(String::from_utf8_lossy(&bytes).into_owned()),
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
            Ok(Value::Text(
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
            Ok(Value::Text(parts.join(&separator)))
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
                    Value::Text(haystack.replace(&needle, &replacement))
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
                Some(length) if length > 0.0 => (begin + length as usize).min(chars.len()),
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
            Some(text) => Value::Text(text.chars().rev().collect()),
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
                Ok(Value::Int((number / factor).round() as i64 * factor as i64))
            } else {
                let factor = 10f64.powi(places);
                Ok(Value::Float((number * factor).round() / factor))
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
        format!("{} {}", &timestamp[0..10], &timestamp[11..19])
    } else {
        timestamp.to_string()
    }
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
        EvalContext {
            current_db: "app_prod".to_string(),
            username: "root".to_string(),
            client_host: "203.0.113.9".to_string(),
            connection_id: 7,
            server_version: "8.0.36".to_string(),
        }
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
}
