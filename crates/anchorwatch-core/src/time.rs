//! Timestamp handling for the two RFC 3339 forms the OKF spec allows.
//!
//! A value is either a date (`YYYY-MM-DD`) or a date-time with an
//! offset (`YYYY-MM-DDTHH:MM:SSZ` or with a numeric offset). Parsing
//! converts a value to seconds since the Unix epoch so comparisons
//! never depend on string shape. A value that does not parse is
//! malformed, which the freshness rules treat as a defect rather than
//! as fresh. Date-only values resolve to the start of that day in UTC.

/// Parses an OKF timestamp into seconds since the Unix epoch.
/// Returns `None` when the value matches neither allowed form.
pub fn parse_timestamp(value: &str) -> Option<i64> {
    let value = value.trim().trim_matches('"');
    if value.len() == 10 {
        let (y, m, d) = parse_date(value)?;
        return Some(days_from_civil(y, m, d) * 86_400);
    }
    let (date_part, rest) = value.split_once('T')?;
    let (y, m, d) = parse_date(date_part)?;
    let (time_part, offset_secs) = if let Some(t) = rest.strip_suffix('Z') {
        (t, 0i64)
    } else if let Some(idx) = rest.rfind(|c| c == '+' || c == '-') {
        if idx == 0 {
            return None;
        }
        let sign = if rest.as_bytes()[idx] == b'+' { 1i64 } else { -1i64 };
        let off = &rest[idx + 1..];
        let (oh, om) = off.split_once(':')?;
        let oh: i64 = oh.parse().ok()?;
        let om: i64 = om.parse().ok()?;
        (&rest[..idx], sign * (oh * 3600 + om * 60))
    } else {
        return None;
    };
    let mut parts = time_part.split(':');
    let hh: i64 = parts.next()?.parse().ok()?;
    let mm: i64 = parts.next()?.parse().ok()?;
    let ss: i64 = parts.next()?.split('.').next()?.parse().ok()?;
    if parts.next().is_some() || !(0..24).contains(&hh) || !(0..60).contains(&mm) || !(0..61).contains(&ss) {
        return None;
    }
    Some(days_from_civil(y, m, d) * 86_400 + hh * 3600 + mm * 60 + ss - offset_secs)
}

fn parse_date(value: &str) -> Option<(i64, u32, u32)> {
    let mut parts = value.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some((y, m, d))
}

/// Days from civil date, after Howard Hinnant's algorithm.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y_adj = if m <= 2 { y - 1 } else { y };
    let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
    let yoe = y_adj - era * 400;
    let mp = ((m + 9) % 12) as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::parse_timestamp;

    #[test]
    fn epoch_parses_to_zero() {
        assert_eq!(parse_timestamp("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_timestamp("1970-01-01"), Some(0));
    }

    #[test]
    fn offsets_normalise_to_utc() {
        assert_eq!(
            parse_timestamp("2026-11-21T14:05:00+02:00"),
            parse_timestamp("2026-11-21T12:05:00Z")
        );
    }

    #[test]
    fn ordering_survives_mixed_forms() {
        let a = parse_timestamp("2026-11-20").unwrap();
        let b = parse_timestamp("2026-11-21T00:00:01Z").unwrap();
        assert!(a < b);
    }

    #[test]
    fn malformed_values_do_not_parse() {
        assert_eq!(parse_timestamp("next Tuesday"), None);
        assert_eq!(parse_timestamp("2026-13-01"), None);
        assert_eq!(parse_timestamp("2026-11-21 10:00:00"), None);
        assert_eq!(parse_timestamp(""), None);
    }
}
