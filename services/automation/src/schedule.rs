//! UTC daily/weekly occurrences. Every instant is UTC; local time zones are never consulted.
use crate::workflow::{CatchUp, Every, ScheduleSpec, parse_time_of_day, parse_weekday};
use chrono::{DateTime, Datelike, Duration, TimeZone, Utc};

/// How long after an occurrence it may still be started as "on time".
pub const ON_TIME_GRACE: Duration = Duration::minutes(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Due {
    /// Nothing is due yet.
    Wait,
    /// Start the occurrence now (on time, or the most recent missed one under `run_once`).
    Run(DateTime<Utc>),
    /// Occurrences were missed and the policy skips them.
    Skip(DateTime<Utc>),
}

fn occurrence_on(date: chrono::NaiveDate, h: u32, m: u32) -> DateTime<Utc> {
    Utc.from_utc_datetime(&date.and_hms_opt(h, m, 0).expect("validated time of day"))
}
/// First occurrence strictly after `after`.
pub fn next_after(spec: &ScheduleSpec, after: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let (h, m) = parse_time_of_day(&spec.at)?;
    let weekday = match spec.every {
        Every::Daily => None,
        Every::Weekly => Some(parse_weekday(spec.weekday.as_deref()?)?),
    };
    for offset in 0..=8 {
        let date = (after + Duration::days(offset)).date_naive();
        if weekday.is_some_and(|w| date.weekday() != w) {
            continue;
        }
        let candidate = occurrence_on(date, h, m);
        if candidate > after {
            return Some(candidate);
        }
    }
    None
}
/// Latest occurrence at or before `now`.
pub fn latest_at_or_before(spec: &ScheduleSpec, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let (h, m) = parse_time_of_day(&spec.at)?;
    let weekday = match spec.every {
        Every::Daily => None,
        Every::Weekly => Some(parse_weekday(spec.weekday.as_deref()?)?),
    };
    for offset in 0..=8 {
        let date = (now - Duration::days(offset)).date_naive();
        if weekday.is_some_and(|w| date.weekday() != w) {
            continue;
        }
        let candidate = occurrence_on(date, h, m);
        if candidate <= now {
            return Some(candidate);
        }
    }
    None
}
/// Decide what to do for a trigger whose persisted `next_run_at` has passed.
pub fn due(spec: &ScheduleSpec, next_run_at: DateTime<Utc>, now: DateTime<Utc>) -> Due {
    if next_run_at > now {
        return Due::Wait;
    }
    let latest = latest_at_or_before(spec, now).unwrap_or(next_run_at);
    if now - latest <= ON_TIME_GRACE && latest == next_run_at {
        return Due::Run(latest);
    }
    match spec.catch_up {
        CatchUp::RunOnce => Due::Run(latest),
        CatchUp::Skip => {
            if now - latest <= ON_TIME_GRACE {
                Due::Run(latest)
            } else {
                Due::Skip(latest)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn at(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }
    fn daily(t: &str, catch_up: CatchUp) -> ScheduleSpec {
        ScheduleSpec {
            every: Every::Daily,
            at: t.into(),
            weekday: None,
            source_ref: None,
            catch_up,
        }
    }
    fn weekly(t: &str, d: &str) -> ScheduleSpec {
        ScheduleSpec {
            every: Every::Weekly,
            at: t.into(),
            weekday: Some(d.into()),
            source_ref: None,
            catch_up: CatchUp::Skip,
        }
    }
    #[test]
    fn daily_occurrence_is_strictly_after() {
        let s = daily("03:30", CatchUp::Skip);
        assert_eq!(
            next_after(&s, at("2026-01-01T03:00:00Z")),
            Some(at("2026-01-01T03:30:00Z"))
        );
        assert_eq!(
            next_after(&s, at("2026-01-01T03:30:00Z")),
            Some(at("2026-01-02T03:30:00Z"))
        );
        assert_eq!(
            next_after(&s, at("2026-12-31T23:59:59Z")),
            Some(at("2027-01-01T03:30:00Z"))
        );
    }
    #[test]
    fn weekly_occurrence_uses_utc_weekday() {
        let s = weekly("00:00", "mon");
        // 2026-01-05 is a Monday.
        assert_eq!(
            next_after(&s, at("2026-01-05T00:00:00Z")),
            Some(at("2026-01-12T00:00:00Z"))
        );
        assert_eq!(
            next_after(&s, at("2026-01-01T12:00:00Z")),
            Some(at("2026-01-05T00:00:00Z"))
        );
        assert_eq!(
            latest_at_or_before(&s, at("2026-01-11T23:59:59Z")),
            Some(at("2026-01-05T00:00:00Z"))
        );
    }
    #[test]
    fn on_time_runs_once_and_late_follows_policy() {
        let s = daily("03:30", CatchUp::Skip);
        let next = at("2026-01-01T03:30:00Z");
        assert_eq!(due(&s, next, at("2026-01-01T03:29:59Z")), Due::Wait);
        assert_eq!(due(&s, next, at("2026-01-01T03:31:00Z")), Due::Run(next));
        assert_eq!(
            due(&s, next, at("2026-01-03T10:00:00Z")),
            Due::Skip(at("2026-01-03T03:30:00Z"))
        );
        let catch = daily("03:30", CatchUp::RunOnce);
        assert_eq!(
            due(&catch, next, at("2026-01-03T10:00:00Z")),
            Due::Run(at("2026-01-03T03:30:00Z"))
        );
    }
}
