//! RFC 3339 timestamps, both directions, without a date-time dependency.
//!
//! Sund speaks Go's `time.RFC3339` on the wire — `2026-07-24T09:00:00Z` — in
//! two places this crate cares about: the signed request timestamp (which the
//! server compares against its own clock, five-minute window) and the
//! `received_at` / `expires` fields of a drained message.
//!
//! A calendar crate would be a reasonable dependency; the reason not to take
//! one is that this core is cross-compiled to Android, iOS and wasm, and every
//! dependency is paid for in three toolchains. Civil-date conversion is a
//! well-known twenty lines (Howard Hinnant's `days_from_civil` /
//! `civil_from_days`), and the tests below pin it against known instants.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Format an instant as `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Sub-second precision is dropped: Go's `time.RFC3339` layout has none, so
/// keeping it would only produce a timestamp that differs from the one the
/// server would have written for the same instant.
pub fn format(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    format_epoch_seconds(seconds)
}

fn format_epoch_seconds(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let time_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60,
    );
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Parse an RFC 3339 timestamp into an instant.
///
/// Accepts what Sund emits and a little more: an optional fractional part
/// (discarded) and a numeric offset as well as `Z`. Returns `None` for anything
/// it cannot read rather than guessing — a timestamp this crate cannot parse is
/// a field it must not pretend to know.
pub fn parse(text: &str) -> Option<SystemTime> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    let year: i64 = text.get(0..4)?.parse().ok()?;
    let month: i64 = text.get(5..7)?.parse().ok()?;
    let day: i64 = text.get(8..10)?.parse().ok()?;
    let hour: i64 = text.get(11..13)?.parse().ok()?;
    let minute: i64 = text.get(14..16)?.parse().ok()?;
    let second: i64 = text.get(17..19)?.parse().ok()?;
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' && bytes[10] != b't' {
        return None;
    }
    if bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let mut rest = text.get(19..)?;
    if let Some(after_dot) = rest.strip_prefix('.') {
        let digits = after_dot.bytes().take_while(u8::is_ascii_digit).count();
        rest = after_dot.get(digits..)?;
    }
    let offset_seconds = match rest.as_bytes().first() {
        Some(b'Z' | b'z') if rest.len() == 1 => 0,
        Some(sign @ (b'+' | b'-')) if rest.len() == 6 => {
            let hours: i64 = rest.get(1..3)?.parse().ok()?;
            let minutes: i64 = rest.get(4..6)?.parse().ok()?;
            let magnitude = hours * 3600 + minutes * 60;
            if *sign == b'-' { -magnitude } else { magnitude }
        }
        _ => return None,
    };

    let epoch = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
        - offset_seconds;
    if epoch >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(epoch as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(epoch.unsigned_abs()))
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn known_instants_format_the_way_go_formats_them() {
        // Cross-checked against `date -u -d @<epoch> +%Y-%m-%dT%H:%M:%SZ`,
        // which is what Sund's Go `time.RFC3339` produces for the same instant.
        let cases = [
            (0u64, "1970-01-01T00:00:00Z"),
            (1_000_000_000, "2001-09-09T01:46:40Z"),
            (1_753_347_600, "2025-07-24T09:00:00Z"),
            (1_784_883_600, "2026-07-24T09:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"), // leap day, century rule
        ];
        for (epoch, want) in cases {
            assert_eq!(format(at(epoch)), want, "epoch {epoch}");
        }
    }

    #[test]
    fn every_formatted_timestamp_parses_back_to_the_same_instant() {
        for epoch in [0u64, 1, 86_399, 86_400, 951_782_400, 1_784_883_600] {
            let text = format(at(epoch));
            assert_eq!(parse(&text), Some(at(epoch)), "{text}");
        }
    }

    #[test]
    fn fractional_seconds_and_offsets_are_understood() {
        let noon = at(1_784_883_600);
        assert_eq!(parse("2026-07-24T09:00:00.123456Z"), Some(noon));
        assert_eq!(parse("2026-07-24T11:00:00+02:00"), Some(noon));
        assert_eq!(parse("2026-07-24T07:00:00-02:00"), Some(noon));
    }

    #[test]
    fn unreadable_timestamps_are_none_rather_than_a_guess() {
        for text in [
            "",
            "2026-07-24",
            "2026-07-24 09:00:00Z",
            "2026-07-24T09:00:00",
            "2026-13-24T09:00:00Z",
            "2026-07-24T25:00:00Z",
            "2026-07-24T09:00:00+2:00",
            "yesterday",
        ] {
            assert_eq!(parse(text), None, "{text} should not parse");
        }
    }
}
