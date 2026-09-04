//! A deliberately narrow iCalendar (RFC 5545) reader and writer covering the
//! `VEVENT` subset ZeroClaw exchanges with a CalDAV server.
//!
//! This is not a general iCalendar implementation and does not try to be. It
//! handles line unfolding, property/parameter splitting, text escaping, and the
//! handful of properties a calendar event needs. Recurrence is expanded
//! server-side (RFC 4791 `<C:expand>`), so there is no RRULE engine here and no
//! timezone database — an `RRULE` that survives to this layer is reported
//! verbatim and blocks writes rather than being interpreted.

use chrono::{DateTime, Duration as ChronoDuration, NaiveDate, NaiveDateTime, TimeZone, Utc};

/// One `VEVENT`, reduced to the fields the tool surfaces.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VEvent {
    pub uid: String,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub location: Option<String>,
    /// Event start. `None` when `DTSTART` is missing or unparseable.
    pub start: Option<EventTime>,
    /// Event end. RFC 5545 lets a component carry either `DTEND` or
    /// `DURATION`; when only the latter is present this is derived from
    /// `DTSTART` as the component closes, so callers see an end time either way.
    pub end: Option<EventTime>,
    /// Raw `RRULE` value when the component is a recurring master. Its presence
    /// is what [`VEvent::is_recurring`] reports, and it blocks writes.
    pub rrule: Option<String>,
    /// Present on an overridden occurrence of a recurring series.
    pub recurrence_id: Option<String>,
    pub status: Option<String>,
    pub organizer: Option<String>,
    pub attendees: Vec<String>,
}

/// A `DTSTART`/`DTEND` value. All-day events carry a date with no time, and
/// conflating the two would silently shift a birthday by a timezone offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventTime {
    /// A `DATE-TIME`. Absolute when the source carried `Z` or a resolvable
    /// offset; see [`EventTime::DateTimeFloating`] for the ambiguous case.
    DateTime(DateTime<Utc>),
    /// A `DATE` value (`VALUE=DATE`) — an all-day event.
    Date(NaiveDate),
    /// A local `DATE-TIME` we cannot anchor to UTC, because it carried a `TZID`
    /// and we intentionally ship no timezone database. Retained verbatim with
    /// its `TZID` so output is honest rather than silently wrong.
    DateTimeFloating {
        local: NaiveDateTime,
        tzid: Option<String>,
    },
}

impl EventTime {
    /// Render for tool output. UTC instants use RFC 3339; the other two forms
    /// are labelled so a reader can tell them apart.
    pub fn to_display(&self) -> String {
        match self {
            Self::DateTime(dt) => dt.to_rfc3339(),
            Self::Date(d) => d.format("%Y-%m-%d").to_string(),
            Self::DateTimeFloating { local, tzid } => match tzid {
                Some(tz) => format!("{} ({})", local.format("%Y-%m-%dT%H:%M:%S"), tz),
                None => local.format("%Y-%m-%dT%H:%M:%S").to_string(),
            },
        }
    }

    /// The absolute instant, when there is one. `None` for all-day and
    /// floating values, which callers must not silently coerce.
    pub fn as_utc(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::DateTime(dt) => Some(*dt),
            _ => None,
        }
    }

    /// Offset this time by `delta`, preserving its kind.
    ///
    /// Used to derive an end time from `DURATION`. Returns `None` on overflow
    /// rather than wrapping to a nonsense date.
    fn checked_add(&self, delta: ChronoDuration) -> Option<Self> {
        match self {
            Self::DateTime(dt) => dt.checked_add_signed(delta).map(Self::DateTime),
            Self::Date(d) => d.checked_add_signed(delta).map(Self::Date),
            Self::DateTimeFloating { local, tzid } => {
                local
                    .checked_add_signed(delta)
                    .map(|local| Self::DateTimeFloating {
                        local,
                        tzid: tzid.clone(),
                    })
            }
        }
    }

    /// Serialize back to an iCalendar property value plus any parameters.
    fn to_property(&self, name: &str) -> String {
        match self {
            Self::DateTime(dt) => {
                format!("{}:{}", name, dt.format("%Y%m%dT%H%M%SZ"))
            }
            Self::Date(d) => format!("{};VALUE=DATE:{}", name, d.format("%Y%m%d")),
            Self::DateTimeFloating { local, tzid } => match tzid {
                Some(tz) => format!("{};TZID={}:{}", name, tz, local.format("%Y%m%dT%H%M%S")),
                None => format!("{}:{}", name, local.format("%Y%m%dT%H%M%S")),
            },
        }
    }
}

impl VEvent {
    /// Whether this component is a recurring master or a series override.
    ///
    /// The tool refuses to update or delete such a component: a `PUT` against a
    /// recurring master rewrites every occurrence, which is never what a
    /// single-event edit intends.
    pub fn is_recurring(&self) -> bool {
        self.rrule.is_some() || self.recurrence_id.is_some()
    }

    /// Render as a complete `VCALENDAR` document suitable for `PUT`.
    pub fn to_ics(&self) -> String {
        let mut lines = vec![
            "BEGIN:VCALENDAR".to_string(),
            "VERSION:2.0".to_string(),
            "PRODID:-//ZeroClaw//CalDAV Tool//EN".to_string(),
            "BEGIN:VEVENT".to_string(),
            format!("UID:{}", escape_text(&self.uid)),
            format!("DTSTAMP:{}", Utc::now().format("%Y%m%dT%H%M%SZ")),
        ];
        if let Some(start) = &self.start {
            lines.push(start.to_property("DTSTART"));
        }
        if let Some(end) = &self.end {
            lines.push(end.to_property("DTEND"));
        }
        if let Some(summary) = &self.summary {
            lines.push(format!("SUMMARY:{}", escape_text(summary)));
        }
        if let Some(description) = &self.description {
            lines.push(format!("DESCRIPTION:{}", escape_text(description)));
        }
        if let Some(location) = &self.location {
            lines.push(format!("LOCATION:{}", escape_text(location)));
        }
        if let Some(status) = &self.status {
            lines.push(format!("STATUS:{}", escape_text(status)));
        }
        for attendee in &self.attendees {
            lines.push(format!("ATTENDEE:{}", escape_text(attendee)));
        }
        lines.push("END:VEVENT".to_string());
        lines.push("END:VCALENDAR".to_string());

        let folded: Vec<String> = lines.iter().map(|l| fold_line(l)).collect();
        // RFC 5545 mandates CRLF line endings.
        format!("{}\r\n", folded.join("\r\n"))
    }
}

/// Parse every `VEVENT` in an iCalendar document.
///
/// A `VCALENDAR` from an expanded `calendar-query` holds one component per
/// occurrence, so this returns a vector rather than a single event. `VTIMEZONE`
/// and other components are skipped.
pub fn parse_events(ics: &str) -> Vec<VEvent> {
    let lines = unfold(ics);
    let mut events = Vec::new();
    let mut current: Option<VEvent> = None;
    // Depth of any non-VEVENT component we are inside (e.g. VTIMEZONE, or a
    // VALARM nested in a VEVENT). Properties there must not leak into the event.
    let mut skip_depth = 0usize;
    // `DURATION` for the component being read. Resolved into `end` when the
    // component closes, because DURATION may precede or follow DTSTART.
    let mut duration: Option<ChronoDuration> = None;

    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let upper = trimmed.to_ascii_uppercase();

        // VCALENDAR is a transparent container, not a component to skip:
        // counting it would put every VEVENT inside it out of reach.
        if upper == "BEGIN:VCALENDAR" || upper == "END:VCALENDAR" {
            continue;
        }
        if upper == "BEGIN:VEVENT" && skip_depth == 0 {
            current = Some(VEvent::default());
            duration = None;
            continue;
        }
        if upper == "END:VEVENT" && skip_depth == 0 {
            if let Some(mut event) = current.take() {
                // DTEND wins when both are present; RFC 5545 forbids that
                // combination, but a server that sends both should not lose the
                // explicit end.
                if event.end.is_none()
                    && let (Some(start), Some(d)) = (event.start.as_ref(), duration)
                {
                    event.end = start.checked_add(d);
                }
                events.push(event);
            }
            duration = None;
            continue;
        }
        if upper.starts_with("BEGIN:") {
            skip_depth += 1;
            continue;
        }
        if upper.starts_with("END:") {
            skip_depth = skip_depth.saturating_sub(1);
            continue;
        }
        if skip_depth > 0 {
            continue;
        }
        let Some(event) = current.as_mut() else {
            continue;
        };
        if let Some(parsed) = parse_duration_property(trimmed) {
            duration = Some(parsed);
            continue;
        }
        apply_property(event, trimmed);
    }

    events
}

/// Parse a `DURATION:` line into a [`ChronoDuration`], or `None` when the line
/// is a different property.
fn parse_duration_property(line: &str) -> Option<ChronoDuration> {
    let (name, _, value) = split_property(line)?;
    if name != "DURATION" {
        return None;
    }
    parse_duration(value)
}

/// Parse an RFC 5545 duration (`PnWnDTnHnMnS`, optionally signed).
///
/// Returns `None` for anything malformed, so a bad value leaves the end time
/// absent rather than inventing one.
fn parse_duration(value: &str) -> Option<ChronoDuration> {
    let raw = value.trim();
    let (negative, rest) = match raw.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, raw.strip_prefix('+').unwrap_or(raw)),
    };
    let mut chars = rest.strip_prefix(['P', 'p'])?.chars().peekable();

    let mut total = ChronoDuration::zero();
    let mut in_time = false;
    let mut digits = String::new();
    let mut saw_unit = false;

    while let Some(ch) = chars.next() {
        if ch == 'T' || ch == 't' {
            // A `T` with pending digits is malformed (`P1T`).
            if !digits.is_empty() {
                return None;
            }
            in_time = true;
            continue;
        }
        if ch.is_ascii_digit() {
            digits.push(ch);
            continue;
        }
        let n: i64 = digits.parse().ok()?;
        digits.clear();
        let unit = match (ch.to_ascii_uppercase(), in_time) {
            ('W', false) => ChronoDuration::weeks(n),
            ('D', false) => ChronoDuration::days(n),
            ('H', true) => ChronoDuration::hours(n),
            ('M', true) => ChronoDuration::minutes(n),
            ('S', true) => ChronoDuration::seconds(n),
            // e.g. `PT1D` or `P1H`: the unit is in the wrong section.
            _ => return None,
        };
        total = total.checked_add(&unit)?;
        saw_unit = true;
        let _ = chars.peek();
    }

    // Trailing digits with no unit, or a bare `P`, are malformed.
    if !digits.is_empty() || !saw_unit {
        return None;
    }
    Some(if negative { -total } else { total })
}

fn apply_property(event: &mut VEvent, line: &str) {
    let Some((name, params, value)) = split_property(line) else {
        return;
    };
    match name.as_str() {
        "UID" => event.uid = unescape_text(value),
        "SUMMARY" => event.summary = Some(unescape_text(value)),
        "DESCRIPTION" => event.description = Some(unescape_text(value)),
        "LOCATION" => event.location = Some(unescape_text(value)),
        "STATUS" => event.status = Some(unescape_text(value)),
        "ORGANIZER" => event.organizer = Some(unescape_text(value)),
        "ATTENDEE" => event.attendees.push(unescape_text(value)),
        "RRULE" => event.rrule = Some(value.to_string()),
        "RECURRENCE-ID" => event.recurrence_id = Some(value.to_string()),
        "DTSTART" => event.start = parse_time(value, &params),
        "DTEND" => event.end = parse_time(value, &params),
        _ => {}
    }
}

/// One property's parameters, as `(NAME, value)` pairs.
type Params = Vec<(String, String)>;

/// Split `NAME;PARAM=v:value` into its three parts.
///
/// The name/value colon is found outside of any double-quoted parameter value,
/// so a quoted `TZID` or `CN` containing `:` does not truncate the property.
fn split_property(line: &str) -> Option<(String, Params, &str)> {
    let mut in_quotes = false;
    let mut colon = None;
    for (idx, ch) in line.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ':' if !in_quotes => {
                colon = Some(idx);
                break;
            }
            _ => {}
        }
    }
    let colon = colon?;
    let (head, rest) = line.split_at(colon);
    let value = &rest[1..];

    let mut parts = split_unquoted(head, ';');
    if parts.is_empty() {
        return None;
    }
    let name = parts.remove(0).trim().to_ascii_uppercase();
    let params = parts
        .into_iter()
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((
                k.trim().to_ascii_uppercase(),
                v.trim().trim_matches('"').to_string(),
            ))
        })
        .collect();
    Some((name, params, value))
}

fn split_unquoted(input: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_quotes = false;
    for ch in input.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                buf.push(ch);
            }
            c if c == sep && !in_quotes => {
                out.push(std::mem::take(&mut buf));
            }
            c => buf.push(c),
        }
    }
    out.push(buf);
    out
}

fn param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Parse a `DTSTART`/`DTEND` value into an [`EventTime`].
///
/// A trailing `Z` yields a UTC instant. `VALUE=DATE` yields an all-day date. A
/// `TZID`-qualified or bare local time is kept floating: resolving it would
/// need a timezone database, and guessing would silently misreport the time.
fn parse_time(value: &str, params: &[(String, String)]) -> Option<EventTime> {
    let value = value.trim();
    if param(params, "VALUE") == Some("DATE") || (value.len() == 8 && !value.contains('T')) {
        return NaiveDate::parse_from_str(value, "%Y%m%d")
            .ok()
            .map(EventTime::Date);
    }
    if let Some(stripped) = value.strip_suffix('Z') {
        return NaiveDateTime::parse_from_str(stripped, "%Y%m%dT%H%M%S")
            .ok()
            .map(|naive| EventTime::DateTime(Utc.from_utc_datetime(&naive)));
    }
    NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%S")
        .ok()
        .map(|local| EventTime::DateTimeFloating {
            local,
            tzid: param(params, "TZID").map(str::to_string),
        })
}

/// Undo RFC 5545 line folding: a CRLF (or LF) followed by a single space or tab
/// is a continuation of the previous line, not a new one.
fn unfold(input: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in input.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(rest) = line.strip_prefix([' ', '\t'])
            && let Some(last) = out.last_mut()
        {
            last.push_str(rest);
            continue;
        }
        out.push(line.to_string());
    }
    out
}

/// Fold a content line to the 75-octet limit, breaking on character boundaries
/// so multibyte text is never split mid-codepoint.
fn fold_line(line: &str) -> String {
    const LIMIT: usize = 75;
    if line.len() <= LIMIT {
        return line.to_string();
    }
    let mut out = String::with_capacity(line.len() + line.len() / LIMIT * 3);
    let mut width = 0usize;
    for ch in line.chars() {
        let ch_len = ch.len_utf8();
        // Continuation lines carry a leading space that counts toward the limit.
        let limit = if out.is_empty() { LIMIT } else { LIMIT - 1 };
        if width + ch_len > limit {
            out.push_str("\r\n ");
            width = 1;
        }
        out.push(ch);
        width += ch_len;
    }
    out
}

/// Escape the RFC 5545 TEXT specials: backslash, newline, comma, semicolon.
fn escape_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            ',' => out.push_str("\\,"),
            ';' => out.push_str("\\;"),
            c => out.push(c),
        }
    }
    out
}

fn unescape_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') | Some('N') => out.push('\n'),
            Some('\\') => out.push('\\'),
            Some(',') => out.push(','),
            Some(';') => out.push(';'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unfold_joins_continuation_lines() {
        let input = "SUMMARY:Hello\r\n  World\r\nUID:1";
        let lines = unfold(input);
        assert_eq!(lines, vec!["SUMMARY:Hello World", "UID:1"]);
    }

    #[test]
    fn unfold_accepts_bare_lf_and_tab_continuation() {
        let lines = unfold("SUMMARY:a\n\tb");
        assert_eq!(lines, vec!["SUMMARY:ab"]);
    }

    #[test]
    fn fold_line_respects_75_octets_and_char_boundaries() {
        let long = format!("SUMMARY:{}", "é".repeat(100));
        let folded = fold_line(&long);
        for segment in folded.split("\r\n") {
            assert!(segment.len() <= 75, "segment too long: {}", segment.len());
        }
        // Folding must be reversible.
        let round = unfold(&folded).join("");
        assert_eq!(round, long);
    }

    #[test]
    fn escape_and_unescape_roundtrip_specials() {
        let raw = "a,b;c\\d\ne";
        let escaped = escape_text(raw);
        assert_eq!(escaped, "a\\,b\\;c\\\\d\\ne");
        assert_eq!(unescape_text(&escaped), raw);
    }

    #[test]
    fn parse_utc_datetime() {
        let t = parse_time("20260904T150000Z", &[]).expect("parses");
        assert_eq!(
            t.as_utc().map(|d| d.to_rfc3339()),
            Some("2026-09-04T15:00:00+00:00".to_string())
        );
    }

    #[test]
    fn parse_all_day_date_is_not_a_datetime() {
        let params = vec![("VALUE".to_string(), "DATE".to_string())];
        let t = parse_time("20260904", &params).expect("parses");
        assert_eq!(
            t,
            EventTime::Date(NaiveDate::from_ymd_opt(2026, 9, 4).unwrap())
        );
        // An all-day event has no absolute instant; coercing one would shift it.
        assert!(t.as_utc().is_none());
    }

    #[test]
    fn parse_date_without_value_param_is_still_all_day() {
        let t = parse_time("20260904", &[]).expect("parses");
        assert!(matches!(t, EventTime::Date(_)));
    }

    #[test]
    fn tzid_datetime_stays_floating_and_reports_its_zone() {
        let params = vec![("TZID".to_string(), "Europe/Paris".to_string())];
        let t = parse_time("20260904T150000", &params).expect("parses");
        assert!(t.as_utc().is_none(), "must not invent a UTC instant");
        assert_eq!(t.to_display(), "2026-09-04T15:00:00 (Europe/Paris)");
    }

    #[test]
    fn parse_events_extracts_fields() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:abc-123\r\n\
                   SUMMARY:Standup\\, daily\r\nDTSTART:20260904T150000Z\r\n\
                   DTEND:20260904T153000Z\r\nLOCATION:Room 1\r\n\
                   END:VEVENT\r\nEND:VCALENDAR\r\n";
        let events = parse_events(ics);
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.uid, "abc-123");
        assert_eq!(e.summary.as_deref(), Some("Standup, daily"));
        assert_eq!(e.location.as_deref(), Some("Room 1"));
        assert!(!e.is_recurring());
    }

    #[test]
    fn parse_events_returns_one_event_per_expanded_occurrence() {
        let ics = "BEGIN:VCALENDAR\r\n\
                   BEGIN:VEVENT\r\nUID:x\r\nDTSTART:20260901T090000Z\r\nEND:VEVENT\r\n\
                   BEGIN:VEVENT\r\nUID:x\r\nDTSTART:20260908T090000Z\r\nEND:VEVENT\r\n\
                   END:VCALENDAR\r\n";
        assert_eq!(parse_events(ics).len(), 2);
    }

    #[test]
    fn parse_duration_covers_the_rfc5545_grammar() {
        assert_eq!(parse_duration("PT1H"), Some(ChronoDuration::hours(1)));
        assert_eq!(parse_duration("PT30M"), Some(ChronoDuration::minutes(30)));
        assert_eq!(parse_duration("PT45S"), Some(ChronoDuration::seconds(45)));
        assert_eq!(parse_duration("P1D"), Some(ChronoDuration::days(1)));
        assert_eq!(parse_duration("P2W"), Some(ChronoDuration::weeks(2)));
        assert_eq!(
            parse_duration("P1DT2H30M"),
            Some(ChronoDuration::days(1) + ChronoDuration::hours(2) + ChronoDuration::minutes(30))
        );
        assert_eq!(parse_duration("-PT1H"), Some(ChronoDuration::hours(-1)));
        assert_eq!(parse_duration("+PT1H"), Some(ChronoDuration::hours(1)));
    }

    #[test]
    fn parse_duration_rejects_malformed_values() {
        // A bad duration must not silently become a zero-length event.
        for bad in ["", "P", "1H", "PT", "PT1", "P1H", "PT1D", "PTX", "P1T"] {
            assert_eq!(parse_duration(bad), None, "should reject {bad:?}");
        }
    }

    #[test]
    fn duration_supplies_the_end_when_dtend_is_absent() {
        // Regression: Fastmail stores a timed event as DTSTART + DURATION with
        // no DTEND, so reading only DTEND reported every such event as having
        // no end time.
        let ics = "BEGIN:VEVENT\r\nUID:k\r\nDTSTART:20260905T140000Z\r\n\
                   DURATION:PT1H\r\nEND:VEVENT";
        let events = parse_events(ics);
        assert_eq!(
            events[0].end,
            Some(EventTime::DateTime(
                Utc.with_ymd_and_hms(2026, 9, 5, 15, 0, 0).unwrap()
            ))
        );
    }

    #[test]
    fn duration_before_dtstart_still_resolves() {
        // Property order is not guaranteed.
        let ics = "BEGIN:VEVENT\r\nUID:k\r\nDURATION:PT90M\r\n\
                   DTSTART:20260905T140000Z\r\nEND:VEVENT";
        assert_eq!(
            parse_events(ics)[0].end,
            Some(EventTime::DateTime(
                Utc.with_ymd_and_hms(2026, 9, 5, 15, 30, 0).unwrap()
            ))
        );
    }

    #[test]
    fn explicit_dtend_wins_over_duration() {
        let ics = "BEGIN:VEVENT\r\nUID:k\r\nDTSTART:20260905T140000Z\r\n\
                   DTEND:20260905T160000Z\r\nDURATION:PT1H\r\nEND:VEVENT";
        assert_eq!(
            parse_events(ics)[0].end,
            Some(EventTime::DateTime(
                Utc.with_ymd_and_hms(2026, 9, 5, 16, 0, 0).unwrap()
            ))
        );
    }

    #[test]
    fn duration_applies_to_floating_and_all_day_starts() {
        let ics = "BEGIN:VEVENT\r\nUID:f\r\nDTSTART;TZID=America/Chicago:20260905T090000\r\n\
                   DURATION:PT1H\r\nEND:VEVENT";
        let end = parse_events(ics)[0].end.clone().expect("end derived");
        assert_eq!(end.to_display(), "2026-09-05T10:00:00 (America/Chicago)");

        let ics = "BEGIN:VEVENT\r\nUID:d\r\nDTSTART;VALUE=DATE:20260905\r\n\
                   DURATION:P1D\r\nEND:VEVENT";
        assert_eq!(
            parse_events(ics)[0].end,
            Some(EventTime::Date(
                NaiveDate::from_ymd_opt(2026, 9, 6).unwrap()
            ))
        );
    }

    #[test]
    fn duration_inside_a_valarm_does_not_reach_the_event() {
        // VALARM carries its own DURATION; using it as the event's end would
        // be wrong.
        let ics = "BEGIN:VEVENT\r\nUID:a\r\nDTSTART:20260905T140000Z\r\n\
                   BEGIN:VALARM\r\nDURATION:PT15M\r\nEND:VALARM\r\nEND:VEVENT";
        assert_eq!(
            parse_events(ics)[0].end,
            None,
            "an alarm's duration must not become the event's end"
        );
    }

    #[test]
    fn vcalendar_wrapper_does_not_hide_the_events_inside_it() {
        // Regression: treating BEGIN:VCALENDAR as a skippable component put
        // every VEVENT out of reach, so a well-formed response parsed as zero
        // events — a silent empty calendar rather than an error.
        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n\
                   BEGIN:VEVENT\r\nUID:inside\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let events = parse_events(ics);
        assert_eq!(events.len(), 1, "VEVENT inside VCALENDAR must be found");
        assert_eq!(events[0].uid, "inside");
    }

    #[test]
    fn vtimezone_properties_do_not_leak_into_the_event() {
        let ics = "BEGIN:VCALENDAR\r\n\
                   BEGIN:VTIMEZONE\r\nBEGIN:STANDARD\r\nDTSTART:19701025T030000\r\n\
                   END:STANDARD\r\nEND:VTIMEZONE\r\n\
                   BEGIN:VEVENT\r\nUID:real\r\nDTSTART:20260904T150000Z\r\nEND:VEVENT\r\n\
                   END:VCALENDAR\r\n";
        let events = parse_events(ics);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].uid, "real");
        assert_eq!(
            events[0]
                .start
                .as_ref()
                .and_then(|s| s.as_utc())
                .map(|d| d.to_rfc3339()),
            Some("2026-09-04T15:00:00+00:00".to_string())
        );
    }

    #[test]
    fn valarm_nested_in_event_does_not_overwrite_event_fields() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:real\r\n\
                   SUMMARY:Real\r\nBEGIN:VALARM\r\nDESCRIPTION:Reminder\r\n\
                   END:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let events = parse_events(ics);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].summary.as_deref(), Some("Real"));
        assert_eq!(
            events[0].description, None,
            "VALARM description must not leak"
        );
    }

    #[test]
    fn rrule_and_recurrence_id_mark_the_event_recurring() {
        let ics = "BEGIN:VEVENT\r\nUID:r\r\nRRULE:FREQ=WEEKLY;BYDAY=MO\r\nEND:VEVENT";
        let events = parse_events(ics);
        assert!(events[0].is_recurring());
        assert_eq!(events[0].rrule.as_deref(), Some("FREQ=WEEKLY;BYDAY=MO"));

        let ics = "BEGIN:VEVENT\r\nUID:r\r\nRECURRENCE-ID:20260904T150000Z\r\nEND:VEVENT";
        assert!(parse_events(ics)[0].is_recurring());
    }

    #[test]
    fn quoted_parameter_containing_colon_does_not_truncate_value() {
        let (name, params, value) =
            split_property("DTSTART;TZID=\"weird:zone\":20260904T150000").expect("splits");
        assert_eq!(name, "DTSTART");
        assert_eq!(param(&params, "TZID"), Some("weird:zone"));
        assert_eq!(value, "20260904T150000");
    }

    #[test]
    fn to_ics_roundtrips_through_the_parser() {
        let event = VEvent {
            uid: "uid-1".into(),
            summary: Some("Lunch; with, Ana".into()),
            description: Some("Line one\nLine two".into()),
            location: Some("Café".into()),
            start: Some(EventTime::DateTime(
                Utc.with_ymd_and_hms(2026, 9, 4, 12, 0, 0).unwrap(),
            )),
            end: Some(EventTime::DateTime(
                Utc.with_ymd_and_hms(2026, 9, 4, 13, 0, 0).unwrap(),
            )),
            ..Default::default()
        };
        let parsed = parse_events(&event.to_ics());
        assert_eq!(parsed.len(), 1);
        let back = &parsed[0];
        assert_eq!(back.uid, event.uid);
        assert_eq!(back.summary, event.summary);
        assert_eq!(back.description, event.description);
        assert_eq!(back.location, event.location);
        assert_eq!(back.start, event.start);
        assert_eq!(back.end, event.end);
    }

    #[test]
    fn to_ics_emits_crlf_and_all_day_value_param() {
        let event = VEvent {
            uid: "d".into(),
            start: Some(EventTime::Date(
                NaiveDate::from_ymd_opt(2026, 9, 4).unwrap(),
            )),
            ..Default::default()
        };
        let ics = event.to_ics();
        assert!(ics.contains("DTSTART;VALUE=DATE:20260904"));
        assert!(ics.ends_with("END:VCALENDAR\r\n"));
        assert!(!ics.contains("\n\n"));
    }

    #[test]
    fn to_ics_preserves_tzid_for_floating_times() {
        let event = VEvent {
            uid: "f".into(),
            start: Some(EventTime::DateTimeFloating {
                local: NaiveDate::from_ymd_opt(2026, 9, 4)
                    .unwrap()
                    .and_hms_opt(15, 0, 0)
                    .unwrap(),
                tzid: Some("Europe/Paris".into()),
            }),
            ..Default::default()
        };
        assert!(
            event
                .to_ics()
                .contains("DTSTART;TZID=Europe/Paris:20260904T150000")
        );
    }
}
