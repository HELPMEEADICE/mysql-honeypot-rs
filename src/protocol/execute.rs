// SPDX-License-Identifier: GPL-3.0-only
//! Decoding of `COM_STMT_EXECUTE` parameters.
//!
//! The binary protocol sends one *typed* value per `?` placeholder: the client
//! declares a `(type, unsigned)` pair per parameter and then the raw bytes of
//! each value. This module turns that payload into [`Value`]s the expression
//! evaluator can use, which is what makes real parameter binding possible
//! without splicing attacker-controlled text into the statement.
//!
//! Everything here treats the payload as hostile:
//!
//! * every length is checked against the remaining bytes before it is used, so a
//!   truncated packet yields an error instead of a panic;
//! * the parameter count must match the prepared statement exactly;
//! * a parameter larger than [`MAX_PARAMETER_BYTES`] is refused rather than
//!   materialised, which keeps a 1 MiB packet from turning into 1 MiB of
//!   evaluated string;
//! * an unknown wire type is reported as an unsupported command rather than
//!   guessed at.

use crate::fakedb::sql::Value;

/// `ER_WRONG_ARGUMENTS`: the payload does not describe a valid execution.
pub const ER_WRONG_ARGUMENTS: u16 = 1210;

/// `ER_UNSUPPORTED_PS`: the command asked for something not implemented.
pub const ER_UNSUPPORTED_PS: u16 = 1295;

/// Longest single parameter value the decoder will materialise.
pub const MAX_PARAMETER_BYTES: usize = 64 * 1024;

/// Cursor flags in the `COM_STMT_EXECUTE` flags byte.
const CURSOR_FLAGS: u8 = 0x01 | 0x02 | 0x04 | 0x08;

/// `enum_field_types` values the binary protocol uses for parameters.
pub mod field_type {
    pub const DECIMAL: u8 = 0x00;
    pub const TINY: u8 = 0x01;
    pub const SHORT: u8 = 0x02;
    pub const LONG: u8 = 0x03;
    pub const FLOAT: u8 = 0x04;
    pub const DOUBLE: u8 = 0x05;
    pub const NULL: u8 = 0x06;
    pub const TIMESTAMP: u8 = 0x07;
    pub const LONGLONG: u8 = 0x08;
    pub const INT24: u8 = 0x09;
    pub const DATE: u8 = 0x0a;
    pub const TIME: u8 = 0x0b;
    pub const DATETIME: u8 = 0x0c;
    pub const YEAR: u8 = 0x0d;
    pub const NEWDATE: u8 = 0x0e;
    pub const VARCHAR: u8 = 0x0f;
    pub const BIT: u8 = 0x10;
    pub const JSON: u8 = 0xf5;
    pub const NEWDECIMAL: u8 = 0xf6;
    pub const ENUM: u8 = 0xf7;
    pub const SET: u8 = 0xf8;
    pub const TINY_BLOB: u8 = 0xf9;
    pub const MEDIUM_BLOB: u8 = 0xfa;
    pub const LONG_BLOB: u8 = 0xfb;
    pub const BLOB: u8 = 0xfc;
    pub const VAR_STRING: u8 = 0xfd;
    pub const STRING: u8 = 0xfe;
    pub const GEOMETRY: u8 = 0xff;
}

/// One parameter's declared type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParamType {
    /// `enum_field_types` byte.
    pub wire_type: u8,
    /// The unsigned flag byte was non-zero.
    pub unsigned: bool,
}

/// Why an execution payload could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecuteError {
    /// Truncated payload, wrong parameter count, or a bad iteration count.
    Malformed(&'static str),
    /// Cursors or an unknown wire type.
    Unsupported(&'static str),
}

impl ExecuteError {
    /// MySQL error code.
    pub fn code(&self) -> u16 {
        match self {
            Self::Malformed(_) => ER_WRONG_ARGUMENTS,
            Self::Unsupported(_) => ER_UNSUPPORTED_PS,
        }
    }

    /// `SQLSTATE` for the error.
    pub fn sqlstate(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "HY000",
            Self::Unsupported(_) => "HY000",
        }
    }

    /// Message a real server would send.
    pub fn message(&self) -> String {
        match self {
            Self::Malformed(_) => "Incorrect arguments to mysqld_stmt_execute".to_string(),
            Self::Unsupported(reason) => format!(
                "This command is not supported in the prepared statement protocol yet: {reason}"
            ),
        }
    }
}

/// A decoded `COM_STMT_EXECUTE`.
#[derive(Debug, Clone)]
pub struct ExecuteRequest {
    /// Statement the client is executing.
    pub statement_id: u32,
    /// The client asked for a cursor.
    pub cursor: bool,
    /// `iteration_count` from the payload.
    pub iteration_count: u32,
    /// Bound values, aligned with the statement's placeholders.
    pub values: Vec<Value>,
    /// Types to remember for a later execute that reuses them.
    pub param_types: Vec<ParamType>,
}

/// A bounds-checked cursor over the payload.
struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ExecuteError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ExecuteError::Malformed("length overflow"))?;
        let slice = self
            .data
            .get(self.position..end)
            .ok_or(ExecuteError::Malformed("truncated parameter"))?;
        self.position = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, ExecuteError> {
        Ok(self.take(1)?[0])
    }

    fn u16le(&mut self) -> Result<u16, ExecuteError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32le(&mut self) -> Result<u32, ExecuteError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64le(&mut self) -> Result<u64, ExecuteError> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// A length-encoded byte string; `None` is the `0xfb` NULL marker.
    fn lenenc(&mut self) -> Result<Option<&'a [u8]>, ExecuteError> {
        let first = self.u8()?;
        let length = match first {
            0xfb => return Ok(None),
            0xfc => usize::from(self.u16le()?),
            0xfd => {
                let bytes = self.take(3)?;
                usize::from(bytes[0]) | (usize::from(bytes[1]) << 8) | (usize::from(bytes[2]) << 16)
            }
            0xfe => {
                let value = self.u64le()?;
                usize::try_from(value).map_err(|_| ExecuteError::Malformed("length overflow"))?
            }
            0xff => return Err(ExecuteError::Malformed("invalid length prefix")),
            other => usize::from(other),
        };
        if length > MAX_PARAMETER_BYTES {
            return Err(ExecuteError::Malformed("parameter too long"));
        }
        Ok(Some(self.take(length)?))
    }
}

/// Decode the payload of a `COM_STMT_EXECUTE` command.
///
/// `expected_params` is the placeholder count recorded at prepare time and
/// `previous_types` holds the types of the previous execute, which the client may
/// ask to reuse by leaving `new_params_bound_flag` clear.
pub fn decode_execute(
    body: &[u8],
    expected_params: usize,
    previous_types: &[ParamType],
) -> Result<ExecuteRequest, ExecuteError> {
    let mut reader = Reader::new(body);
    let statement_id = reader.u32le()?;
    let flags = reader.u8()?;
    let iteration_count = reader.u32le()?;
    if iteration_count != 1 {
        return Err(ExecuteError::Malformed("iteration count must be 1"));
    }
    let cursor = flags & CURSOR_FLAGS != 0;

    if expected_params == 0 {
        // A statement without placeholders carries no parameter block at all, so
        // any trailing bytes are the client's problem, not ours.
        return Ok(ExecuteRequest {
            statement_id,
            cursor,
            iteration_count,
            values: Vec::new(),
            param_types: Vec::new(),
        });
    }

    // NULL bitmap: one bit per parameter, no offset for this command.
    let bitmap_len = expected_params.div_ceil(8);
    let bitmap = reader.take(bitmap_len)?.to_vec();
    let new_params_bound = reader.u8()?;
    let param_types = if new_params_bound == 1 {
        let mut types = Vec::with_capacity(expected_params);
        for _ in 0..expected_params {
            let wire_type = reader.u8()?;
            let unsigned = reader.u8()? != 0;
            types.push(ParamType {
                wire_type,
                unsigned,
            });
        }
        types
    } else {
        if previous_types.len() != expected_params {
            return Err(ExecuteError::Malformed(
                "parameter types must be sent on first execute",
            ));
        }
        previous_types.to_vec()
    };

    let mut values = Vec::with_capacity(expected_params);
    for (index, declared) in param_types.iter().enumerate() {
        let is_null = bitmap
            .get(index / 8)
            .is_some_and(|byte| byte & (1 << (index % 8)) != 0);
        if is_null {
            values.push(Value::Null);
            continue;
        }
        values.push(decode_value(&mut reader, *declared)?);
    }

    Ok(ExecuteRequest {
        statement_id,
        cursor,
        iteration_count,
        values,
        param_types,
    })
}

/// Decode one parameter value.
fn decode_value(reader: &mut Reader<'_>, declared: ParamType) -> Result<Value, ExecuteError> {
    use field_type as ft;
    match declared.wire_type {
        ft::NULL => Ok(Value::Null),
        ft::TINY => {
            let raw = reader.u8()?;
            Ok(Value::Int(if declared.unsigned {
                i64::from(raw)
            } else {
                i64::from(raw as i8)
            }))
        }
        ft::SHORT | ft::YEAR => {
            let raw = reader.u16le()?;
            Ok(Value::Int(if declared.unsigned {
                i64::from(raw)
            } else {
                i64::from(raw as i16)
            }))
        }
        ft::LONG | ft::INT24 => {
            let raw = reader.u32le()?;
            Ok(Value::Int(if declared.unsigned {
                i64::from(raw)
            } else {
                i64::from(raw as i32)
            }))
        }
        ft::LONGLONG => {
            let raw = reader.u64le()?;
            if declared.unsigned && raw > i64::MAX as u64 {
                // Beyond the signed range: keep the magnitude rather than wrap.
                Ok(Value::Float(raw as f64))
            } else {
                Ok(Value::Int(raw as i64))
            }
        }
        ft::FLOAT => Ok(Value::Float(f64::from(f32::from_bits(reader.u32le()?)))),
        ft::DOUBLE => Ok(Value::Float(f64::from_bits(reader.u64le()?))),
        // Every remaining type travels as a length-encoded byte string: temporal
        // and decimal values are rendered text on the wire, and the string/blob
        // family is literal bytes.
        ft::DECIMAL
        | ft::NEWDECIMAL
        | ft::TIMESTAMP
        | ft::DATE
        | ft::TIME
        | ft::DATETIME
        | ft::NEWDATE
        | ft::VARCHAR
        | ft::BIT
        | ft::JSON
        | ft::ENUM
        | ft::SET
        | ft::TINY_BLOB
        | ft::MEDIUM_BLOB
        | ft::LONG_BLOB
        | ft::BLOB
        | ft::VAR_STRING
        | ft::STRING
        | ft::GEOMETRY => match reader.lenenc()? {
            None => Ok(Value::Null),
            Some(bytes) => Ok(Value::Text(String::from_utf8_lossy(bytes).into_owned())),
        },
        _ => Err(ExecuteError::Unsupported("unknown parameter type")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(statement_id: u32, flags: u8) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&statement_id.to_le_bytes());
        payload.push(flags);
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload
    }

    fn types(entries: &[(u8, bool)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (wire, unsigned) in entries {
            bytes.push(*wire);
            bytes.push(u8::from(*unsigned));
        }
        bytes
    }

    #[test]
    fn a_statement_without_parameters_needs_no_block() {
        let request = decode_execute(&header(7, 0), 0, &[]).expect("decode");
        assert_eq!(request.statement_id, 7);
        assert!(!request.cursor);
        assert!(request.values.is_empty());
    }

    #[test]
    fn integers_decode_with_sign_and_unsignedness() {
        let mut payload = header(1, 0);
        payload.push(0); // null bitmap
        payload.push(1); // new params bound
        payload.extend_from_slice(&types(&[(field_type::LONGLONG, false)]));
        payload.extend_from_slice(&(-5i64).to_le_bytes());
        let request = decode_execute(&payload, 1, &[]).expect("decode");
        assert_eq!(request.values, vec![Value::Int(-5)]);

        let mut payload = header(1, 0);
        payload.push(0);
        payload.push(1);
        payload.extend_from_slice(&types(&[
            (field_type::TINY, true),
            (field_type::LONG, true),
        ]));
        payload.push(200);
        payload.extend_from_slice(&4_000_000_000u32.to_le_bytes());
        let request = decode_execute(&payload, 2, &[]).expect("decode");
        assert_eq!(
            request.values,
            vec![Value::Int(200), Value::Int(4_000_000_000)]
        );
    }

    #[test]
    fn floats_doubles_and_strings_decode() {
        let mut payload = header(1, 0);
        payload.push(0);
        payload.push(1);
        payload.extend_from_slice(&types(&[
            (field_type::DOUBLE, false),
            (field_type::VAR_STRING, false),
        ]));
        payload.extend_from_slice(&2.5f64.to_le_bytes());
        payload.push(5);
        payload.extend_from_slice(b"alice");
        let request = decode_execute(&payload, 2, &[]).expect("decode");
        assert_eq!(
            request.values,
            vec![Value::Float(2.5), Value::Text("alice".to_string())]
        );
    }

    #[test]
    fn the_null_bitmap_wins_over_the_type() {
        let mut payload = header(1, 0);
        payload.push(0b0000_0010); // second parameter is NULL
        payload.push(1);
        payload.extend_from_slice(&types(&[
            (field_type::LONGLONG, false),
            (field_type::LONGLONG, false),
        ]));
        payload.extend_from_slice(&3i64.to_le_bytes());
        // No bytes for the NULL parameter.
        let request = decode_execute(&payload, 2, &[]).expect("decode");
        assert_eq!(request.values, vec![Value::Int(3), Value::Null]);
    }

    #[test]
    fn a_cleared_new_params_flag_reuses_the_previous_types() {
        let previous = [ParamType {
            wire_type: field_type::LONG,
            unsigned: false,
        }];
        let mut payload = header(1, 0);
        payload.push(0);
        payload.push(0); // reuse
        payload.extend_from_slice(&7i32.to_le_bytes());
        let request = decode_execute(&payload, 1, &previous).expect("decode");
        assert_eq!(request.values, vec![Value::Int(7)]);
        assert_eq!(request.param_types, previous.to_vec());
    }

    #[test]
    fn reusing_types_without_a_previous_execute_is_an_error() {
        let mut payload = header(1, 0);
        payload.push(0);
        payload.push(0);
        let error = decode_execute(&payload, 1, &[]).expect_err("must fail");
        assert_eq!(error.code(), ER_WRONG_ARGUMENTS);
    }

    #[test]
    fn a_parameter_count_mismatch_is_rejected() {
        // Two placeholders announced, one type declared: the payload runs dry.
        let mut payload = header(1, 0);
        payload.push(0);
        payload.push(1);
        payload.extend_from_slice(&types(&[(field_type::LONG, false)]));
        payload.extend_from_slice(&1i32.to_le_bytes());
        let error = decode_execute(&payload, 2, &[]).expect_err("must fail");
        assert_eq!(error.code(), ER_WRONG_ARGUMENTS);
    }

    #[test]
    fn truncated_payloads_never_panic() {
        let full = {
            let mut payload = header(1, 0);
            payload.push(0);
            payload.push(1);
            payload.extend_from_slice(&types(&[(field_type::DOUBLE, false)]));
            payload.extend_from_slice(&1.0f64.to_le_bytes());
            payload
        };
        for length in 0..full.len() {
            let slice = &full[..length];
            let result = decode_execute(slice, 1, &[]);
            assert!(result.is_err(), "prefix of {length} bytes must be refused");
        }
        assert!(decode_execute(&full, 1, &[]).is_ok());
    }

    #[test]
    fn a_hostile_length_prefix_cannot_escape_the_buffer() {
        let mut payload = header(1, 0);
        payload.push(0);
        payload.push(1);
        payload.extend_from_slice(&types(&[(field_type::VAR_STRING, false)]));
        payload.push(0xfe); // eight byte length
        payload.extend_from_slice(&u64::MAX.to_le_bytes());
        let error = decode_execute(&payload, 1, &[]).expect_err("must fail");
        assert_eq!(error.code(), ER_WRONG_ARGUMENTS);
    }

    #[test]
    fn an_oversized_parameter_is_refused() {
        let mut payload = header(1, 0);
        payload.push(0);
        payload.push(1);
        payload.extend_from_slice(&types(&[(field_type::BLOB, false)]));
        payload.push(0xfd);
        let length = MAX_PARAMETER_BYTES + 1;
        payload.extend_from_slice(&[
            (length & 0xff) as u8,
            ((length >> 8) & 0xff) as u8,
            ((length >> 16) & 0xff) as u8,
        ]);
        payload.extend(std::iter::repeat_n(b'a', MAX_PARAMETER_BYTES + 1));
        let error = decode_execute(&payload, 1, &[]).expect_err("must fail");
        assert_eq!(error.code(), ER_WRONG_ARGUMENTS);
    }

    #[test]
    fn an_unknown_wire_type_is_reported_as_unsupported() {
        let mut payload = header(1, 0);
        payload.push(0);
        payload.push(1);
        payload.extend_from_slice(&types(&[(0x7f, false)]));
        let error = decode_execute(&payload, 1, &[]).expect_err("must fail");
        assert_eq!(error.code(), ER_UNSUPPORTED_PS);
    }

    #[test]
    fn a_cursor_request_is_flagged_and_an_iteration_count_other_than_one_refused() {
        let request = decode_execute(&header(1, 0x01), 0, &[]).expect("decode");
        assert!(request.cursor);

        let mut payload = header(1, 0);
        payload[5..9].copy_from_slice(&2u32.to_le_bytes());
        let error = decode_execute(&payload, 0, &[]).expect_err("must fail");
        assert_eq!(error.code(), ER_WRONG_ARGUMENTS);
    }

    #[test]
    fn the_null_wire_type_decodes_without_consuming_bytes() {
        let mut payload = header(1, 0);
        payload.push(0);
        payload.push(1);
        payload.extend_from_slice(&types(&[(field_type::NULL, false)]));
        let request = decode_execute(&payload, 1, &[]).expect("decode");
        assert_eq!(request.values, vec![Value::Null]);
    }
}
