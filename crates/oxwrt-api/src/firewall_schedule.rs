//! Parser for the `schedule` field on [[firewall.rules]].
//!
//! Lives in oxwrt-api (not oxwrt-linux) so the validator runs on
//! every target — `reload-dry-run` on a dev Mac catches schedule
//! typos without cross-compiling.
//!
//! Output is a small typed struct the daemon's firewall installer
//! consumes: a day bitmask (sun=0 .. sat=6 on Linux's nft
//! convention) and an optional `HH:MM-HH:MM` hour range. Either
//! half may be absent — "just days" or "just hours" are valid
//! shapes.
//!
//! v1 grammar (case-insensitive, whitespace-collapsed):
//!
//!   schedule := days hours | days | hours
//!   days     := "daily"
//!             | "weekdays"
//!             | "weekends"
//!             | day-list
//!   day-list := day-range ("," day-range)*
//!   day-range:= day | day "-" day
//!   day      := "mon" | "tue" | "wed" | "thu" | "fri" | "sat" | "sun"
//!   hours    := HH:MM "-" HH:MM   (each HH ∈ 0..=23, MM ∈ 0..=59)
//!
//! Future extensions (out of scope v1): date ranges, one-off
//! windows, holiday calendars. The structured schema makes those
//! adds additive.

/// Day-of-week bitmask, bit N = day N where Sunday=0 matching
/// nft's `meta day` numeric convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DayMask(pub u8);

impl DayMask {
    pub const SUN: u8 = 1 << 0;
    pub const MON: u8 = 1 << 1;
    pub const TUE: u8 = 1 << 2;
    pub const WED: u8 = 1 << 3;
    pub const THU: u8 = 1 << 4;
    pub const FRI: u8 = 1 << 5;
    pub const SAT: u8 = 1 << 6;

    pub const WEEKDAYS: u8 = Self::MON | Self::TUE | Self::WED | Self::THU | Self::FRI;
    pub const WEEKENDS: u8 = Self::SAT | Self::SUN;
    pub const ALL: u8 = 0b0111_1111;

    /// Iterate set-bit days in 0..=6 order (matches nft numeric).
    pub fn iter(&self) -> impl Iterator<Item = u8> + '_ {
        (0u8..=6).filter(move |d| self.0 & (1 << d) != 0)
    }
}

/// A single HH:MM clock time, 0 ≤ h ≤ 23, 0 ≤ m ≤ 59.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HourMinute {
    pub h: u8,
    pub m: u8,
}

impl std::fmt::Display for HourMinute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02}:{:02}", self.h, self.m)
    }
}

/// Parsed schedule. At least one of `days` or `hours` is set;
/// "empty" schedules reject at parse time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schedule {
    pub days: Option<DayMask>,
    pub hours: Option<(HourMinute, HourMinute)>,
}

pub fn parse_schedule(s: &str) -> Result<Schedule, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("schedule: empty string".to_string());
    }

    // Split on whitespace into at most two tokens: "<days> <hours>",
    // "<days>" alone, or "<hours>" alone. The first char of each
    // token determines which — a digit starts an hour range.
    let mut parts = s.split_whitespace();
    let first = parts.next().unwrap_or("");
    let second = parts.next();
    if parts.next().is_some() {
        return Err(format!(
            "schedule {s:?}: too many tokens (expected `<days> <hours>`, `<days>`, or `<hours>`)"
        ));
    }

    // Is the first token an hour-range or a day-spec? Hour ranges
    // always start with a digit and contain a ':' before the '-'.
    let first_is_hours = first.chars().next().is_some_and(|c| c.is_ascii_digit());

    let (days_tok, hours_tok) = if first_is_hours {
        if second.is_some() {
            return Err(format!(
                "schedule {s:?}: hour range must come AFTER the day spec (got `hours days`)"
            ));
        }
        (None, Some(first))
    } else {
        (Some(first), second)
    };

    let days = days_tok.map(parse_days).transpose()?;
    let hours = hours_tok.map(parse_hour_range).transpose()?;

    if days.is_none() && hours.is_none() {
        return Err(format!("schedule {s:?}: empty after parse"));
    }

    Ok(Schedule { days, hours })
}

fn parse_days(s: &str) -> Result<DayMask, String> {
    match s.to_ascii_lowercase().as_str() {
        "daily" | "everyday" | "all" => return Ok(DayMask(DayMask::ALL)),
        "weekdays" => return Ok(DayMask(DayMask::WEEKDAYS)),
        "weekends" => return Ok(DayMask(DayMask::WEEKENDS)),
        _ => {}
    }
    // day-list := day-range ("," day-range)*
    let mut mask: u8 = 0;
    for range in s.split(',') {
        let range = range.trim();
        if range.is_empty() {
            return Err(format!("days {s:?}: empty range in comma-separated list"));
        }
        mask |= parse_day_range(range)?;
    }
    if mask == 0 {
        return Err(format!("days {s:?}: no valid days"));
    }
    Ok(DayMask(mask))
}

fn parse_day_range(s: &str) -> Result<u8, String> {
    if let Some((a, b)) = s.split_once('-') {
        let a_bit = day_bit(a.trim())?;
        let b_bit = day_bit(b.trim())?;
        let a_idx = bit_to_idx(a_bit);
        let b_idx = bit_to_idx(b_bit);
        // Wrap-around ranges (e.g. fri-tue) — accept them and
        // interpret as "fri, sat, sun, mon, tue".
        let mut mask = 0;
        let mut i = a_idx;
        loop {
            mask |= 1 << i;
            if i == b_idx {
                break;
            }
            i = (i + 1) % 7;
        }
        Ok(mask)
    } else {
        day_bit(s)
    }
}

fn day_bit(s: &str) -> Result<u8, String> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "sun" | "sunday" => DayMask::SUN,
        "mon" | "monday" => DayMask::MON,
        "tue" | "tues" | "tuesday" => DayMask::TUE,
        "wed" | "wednesday" => DayMask::WED,
        "thu" | "thur" | "thurs" | "thursday" => DayMask::THU,
        "fri" | "friday" => DayMask::FRI,
        "sat" | "saturday" => DayMask::SAT,
        other => return Err(format!("unknown day {other:?}")),
    })
}

fn bit_to_idx(bit: u8) -> u8 {
    // Must be exactly one bit set.
    bit.trailing_zeros() as u8
}

fn parse_hour_range(s: &str) -> Result<(HourMinute, HourMinute), String> {
    let (a, b) = s
        .split_once('-')
        .ok_or_else(|| format!("hours {s:?}: expected `HH:MM-HH:MM`"))?;
    let start = parse_hm(a.trim())?;
    let end = parse_hm(b.trim())?;
    // start == end would match zero packets. Reject as likely typo.
    if start == end {
        return Err(format!(
            "hours {s:?}: start equals end — window matches nothing"
        ));
    }
    Ok((start, end))
}

fn parse_hm(s: &str) -> Result<HourMinute, String> {
    let (h_str, m_str) = s
        .split_once(':')
        .ok_or_else(|| format!("time {s:?}: expected HH:MM"))?;
    let h: u8 = h_str
        .parse()
        .map_err(|_| format!("time {s:?}: hour {h_str:?} not a number"))?;
    let m: u8 = m_str
        .parse()
        .map_err(|_| format!("time {s:?}: minute {m_str:?} not a number"))?;
    if h > 23 {
        return Err(format!("time {s:?}: hour {h} > 23"));
    }
    if m > 59 {
        return Err(format!("time {s:?}: minute {m} > 59"));
    }
    Ok(HourMinute { h, m })
}

/// Render the parsed schedule as an nft predicate fragment —
/// what goes BEFORE the action in a rule body, e.g.:
///   `meta day { 1, 2, 3, 4, 5 } meta hour "22:00"-"06:00"`
///
/// Each predicate is elided when its field is None. The caller
/// prepends this to the rest of the rule.
pub fn render_nft_predicate(sched: &Schedule) -> String {
    let mut out = String::new();
    if let Some(mask) = sched.days {
        let names: Vec<String> = mask.iter().map(|d| day_name(d).to_string()).collect();
        out.push_str("meta day { ");
        out.push_str(&names.join(", "));
        out.push_str(" } ");
    }
    if let Some((start, end)) = sched.hours {
        out.push_str(&format!("meta hour \"{start}\"-\"{end}\" "));
    }
    out
}

fn day_name(idx: u8) -> &'static str {
    match idx {
        0 => "\"Sunday\"",
        1 => "\"Monday\"",
        2 => "\"Tuesday\"",
        3 => "\"Wednesday\"",
        4 => "\"Thursday\"",
        5 => "\"Friday\"",
        6 => "\"Saturday\"",
        _ => "\"?\"",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daily_nightly() {
        let s = parse_schedule("daily 22:00-06:00").unwrap();
        assert_eq!(s.days, Some(DayMask(DayMask::ALL)));
        assert_eq!(
            s.hours,
            Some((HourMinute { h: 22, m: 0 }, HourMinute { h: 6, m: 0 }))
        );
    }

    #[test]
    fn weekdays_office_hours() {
        let s = parse_schedule("weekdays 09:00-17:00").unwrap();
        assert_eq!(s.days, Some(DayMask(DayMask::WEEKDAYS)));
    }

    #[test]
    fn weekends_all_day() {
        let s = parse_schedule("weekends").unwrap();
        assert_eq!(s.days, Some(DayMask(DayMask::WEEKENDS)));
        assert_eq!(s.hours, None);
    }

    #[test]
    fn hours_only() {
        let s = parse_schedule("22:00-06:00").unwrap();
        assert_eq!(s.days, None);
        assert!(s.hours.is_some());
    }

    #[test]
    fn day_range() {
        let s = parse_schedule("mon-fri").unwrap();
        assert_eq!(s.days.unwrap().0, DayMask::WEEKDAYS);
    }

    #[test]
    fn day_wrap_around_range() {
        let s = parse_schedule("fri-mon").unwrap();
        // fri + sat + sun + mon
        assert_eq!(
            s.days.unwrap().0,
            DayMask::FRI | DayMask::SAT | DayMask::SUN | DayMask::MON
        );
    }

    #[test]
    fn comma_separated_days() {
        let s = parse_schedule("mon,wed,fri 09:00-12:00").unwrap();
        assert_eq!(
            s.days.unwrap().0,
            DayMask::MON | DayMask::WED | DayMask::FRI
        );
    }

    #[test]
    fn mixed_range_and_list() {
        let s = parse_schedule("mon-wed,sat").unwrap();
        assert_eq!(
            s.days.unwrap().0,
            DayMask::MON | DayMask::TUE | DayMask::WED | DayMask::SAT
        );
    }

    #[test]
    fn full_day_names_accepted() {
        let s = parse_schedule("monday,tuesday 08:00-10:00").unwrap();
        assert_eq!(s.days.unwrap().0, DayMask::MON | DayMask::TUE);
    }

    #[test]
    fn case_insensitive() {
        assert!(parse_schedule("WEEKDAYS 09:00-17:00").is_ok());
        assert!(parse_schedule("Mon-Fri 09:00-17:00").is_ok());
    }

    #[test]
    fn empty_string_rejected() {
        assert!(parse_schedule("").is_err());
        assert!(parse_schedule("   ").is_err());
    }

    #[test]
    fn unknown_day_rejected() {
        let err = parse_schedule("funday 09:00-10:00").unwrap_err();
        assert!(err.contains("unknown day"));
    }

    #[test]
    fn invalid_hour_rejected() {
        assert!(parse_schedule("daily 25:00-26:00").is_err());
        assert!(parse_schedule("daily 09:60-10:00").is_err());
        assert!(parse_schedule("daily 9-10").is_err()); // no colon
    }

    #[test]
    fn zero_length_window_rejected() {
        let err = parse_schedule("daily 10:00-10:00").unwrap_err();
        assert!(err.contains("matches nothing"));
    }

    #[test]
    fn hours_before_days_rejected() {
        let err = parse_schedule("22:00-06:00 weekdays").unwrap_err();
        assert!(err.contains("AFTER"));
    }

    #[test]
    fn too_many_tokens_rejected() {
        let err = parse_schedule("mon tue wed").unwrap_err();
        assert!(err.contains("too many tokens"));
    }

    #[test]
    fn render_predicate_with_both() {
        let s = parse_schedule("weekdays 22:00-06:00").unwrap();
        let out = render_nft_predicate(&s);
        assert!(out.contains("meta day {"));
        assert!(out.contains("\"Monday\""));
        assert!(out.contains("\"Friday\""));
        assert!(out.contains("meta hour \"22:00\"-\"06:00\""));
    }

    #[test]
    fn render_predicate_days_only() {
        let s = parse_schedule("weekends").unwrap();
        let out = render_nft_predicate(&s);
        assert!(out.contains("meta day {"));
        assert!(out.contains("\"Saturday\""));
        assert!(out.contains("\"Sunday\""));
        assert!(!out.contains("meta hour"));
    }

    #[test]
    fn render_predicate_hours_only() {
        let s = parse_schedule("22:00-06:00").unwrap();
        let out = render_nft_predicate(&s);
        assert!(!out.contains("meta day"));
        assert!(out.contains("meta hour \"22:00\"-\"06:00\""));
    }

    #[test]
    fn daymask_iter_sorted() {
        let s = parse_schedule("fri,mon,wed").unwrap();
        let days: Vec<u8> = s.days.unwrap().iter().collect();
        assert_eq!(days, vec![1, 3, 5]); // mon=1, wed=3, fri=5
    }
}
