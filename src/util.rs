// SPDX-License-Identifier: GPL-3.0-only
//! Small helpers: UTC timestamp formatting without a date-time dependency,
//! byte-bounded string truncation and hex encoding.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Days since 1970-01-01 → (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { y + 1 } else { y }, month, day)
}

/// Format an instant as `YYYY-MM-DDTHH:MM:SS.mmmZ` (UTC, millisecond precision).
pub fn format_system_time(time: SystemTime) -> String {
    let since_epoch = match time.duration_since(UNIX_EPOCH) {
        Ok(delta) => delta,
        // Clock before the epoch: keep the value coherent instead of panicking.
        Err(err) => {
            let back = err.duration();
            return format_negative(back);
        }
    };
    format_offset(since_epoch)
}

fn format_negative(back: Duration) -> String {
    // Only reachable on a badly misconfigured clock; clamp to the epoch.
    let _ = back;
    format_offset(Duration::ZERO)
}

fn format_offset(since_epoch: Duration) -> String {
    let secs = since_epoch.as_secs() as i64;
    let millis = since_epoch.subsec_millis();
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Current UTC timestamp in the canonical log format.
pub fn utc_now() -> String {
    format_system_time(SystemTime::now())
}

/// Truncate to at most `max_bytes` bytes on a UTF-8 character boundary.
///
/// Returns the (possibly shortened) text and whether anything was dropped.
pub fn truncate_to(text: &str, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text.to_string(), false);
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_string(), true)
}

/// Lowercase hex encoding, used for the fake password hashes served in
/// `mysql.user`.
pub fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Milliseconds of a duration, saturating at `u64::MAX`.
pub fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_formatted_as_utc() {
        assert_eq!(format_system_time(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn known_instants_roundtrip() {
        // 2024-02-29T12:34:56.789Z (leap day)
        let sample = UNIX_EPOCH + Duration::from_millis(1_709_210_096_789);
        assert_eq!(format_system_time(sample), "2024-02-29T12:34:56.789Z");
        // 2000-01-01T00:00:00.000Z
        let y2k = UNIX_EPOCH + Duration::from_secs(946_684_800);
        assert_eq!(format_system_time(y2k), "2000-01-01T00:00:00.000Z");
    }

    #[test]
    fn timestamps_are_utc_iso8601() {
        let now = utc_now();
        assert_eq!(now.len(), 24, "unexpected timestamp shape: {now}");
        assert!(now.ends_with('Z'));
        assert_eq!(&now[10..11], "T");
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        let text = "aäb";
        assert_eq!(truncate_to("short", 32), ("short".to_string(), false));
        let (out, truncated) = truncate_to(text, 2);
        assert!(truncated);
        assert_eq!(out, "a", "must not split the two byte character");
        assert!(out.is_char_boundary(out.len()));
    }

    #[test]
    fn hex_encoding() {
        assert_eq!(hex_lower(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex_lower(b""), "");
    }

    #[test]
    fn duration_millis() {
        assert_eq!(millis(Duration::from_millis(1500)), 1500);
        assert_eq!(millis(Duration::ZERO), 0);
    }
}
