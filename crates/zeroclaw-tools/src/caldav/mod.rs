//! CalDAV calendar tool: read and write events on any RFC 4791 server.
//!
//! Structured like the other multi-action integration tools (`jira`, `notion`):
//! one tool, an `action` parameter, an operator allowlist, and a
//! [`ToolOperation`] classification so read and write obey the runtime's
//! autonomy policy separately.
//!
//! Recurring events are expanded server-side on read and are refused for
//! writes; see [`ical`] for why no RRULE engine lives here.

pub mod client;
pub mod discovery;
pub mod ical;
pub mod xml;

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use serde_json::json;

use zeroclaw_api::tool::{Tool, ToolOutput, ToolResult};
use zeroclaw_config::policy::{SecurityPolicy, ToolOperation};

use client::{CalDavClient, WriteOutcome};
use discovery::{Calendar, select_calendar};
use ical::{CalendarObject, EventTime, PropertyChange, VEvent};

/// Every action this tool understands.
const VALID_ACTIONS: &[&str] = &[
    "list_calendars",
    "list_events",
    "get_event",
    "create_event",
    "update_event",
    "delete_event",
];

/// Upper bound on events returned in one call, so a wide date range cannot
/// flood the model's context.
const MAX_EVENTS: usize = 250;

/// Widest date range accepted for `list_events`, in days.
const MAX_RANGE_DAYS: i64 = 366;

pub struct CalDavTool {
    client: CalDavClient,
    security: Arc<SecurityPolicy>,
    allowed_actions: Vec<String>,
    default_calendar: Option<String>,
}

impl CalDavTool {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base_url: String,
        username: String,
        password: String,
        default_calendar: Option<String>,
        allowed_actions: Vec<String>,
        allow_private_hosts: bool,
        nat64_prefixes: Vec<String>,
        timeout_secs: u64,
        security: Arc<SecurityPolicy>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            client: CalDavClient::new(
                base_url,
                username,
                password,
                timeout_secs,
                allow_private_hosts,
                nat64_prefixes,
            )?,
            security,
            allowed_actions: allowed_actions
                .into_iter()
                .map(|a| a.trim().to_string())
                .collect(),
            default_calendar: default_calendar
                .map(|c| c.trim().to_string())
                .filter(|c| !c.is_empty()),
        })
    }

    fn is_action_allowed(&self, action: &str) -> bool {
        self.allowed_actions.iter().any(|a| a == action)
    }

    /// `Read` for the three read actions, `Act` for the three that mutate.
    fn operation_for(action: &str) -> ToolOperation {
        match action {
            "list_calendars" | "list_events" | "get_event" => ToolOperation::Read,
            _ => ToolOperation::Act,
        }
    }

    async fn calendars(&self) -> anyhow::Result<Vec<Calendar>> {
        discovery::discover_calendars(&self.client).await
    }

    /// Discover calendars and pick the one this call targets.
    async fn target_calendar(&self, args: &serde_json::Value) -> anyhow::Result<Calendar> {
        let requested = args.get("calendar").and_then(|v| v.as_str());
        let calendars = self.calendars().await?;
        let selected = select_calendar(&calendars, requested, self.default_calendar.as_deref())?;
        Ok(selected.clone())
    }

    async fn list_calendars(&self) -> anyhow::Result<serde_json::Value> {
        let calendars = self.calendars().await?;
        let items: Vec<serde_json::Value> = calendars
            .iter()
            .map(|c| {
                json!({
                    "name": c.display_name,
                    "href": c.href,
                    "url": c.url,
                    "color": c.color,
                    "supported_components": c.supported_components,
                })
            })
            .collect();
        Ok(json!({ "calendars": items, "count": items.len() }))
    }

    async fn list_events(&self, args: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let (start, end) = parse_range(args)?;
        let calendar = self.target_calendar(args).await?;

        let start_ical = to_ical_utc(start);
        let end_ical = to_ical_utc(end);

        // Ask the server to expand recurrences. A server that cannot do it
        // rejects the report body; retry unexpanded and say so in the output
        // rather than silently reporting a weekly meeting as a single event.
        let body = xml::calendar_query_body(&start_ical, &end_ical, true);
        let (responses, expanded) = match self.client.report(&calendar.url, body).await? {
            Some(responses) => (responses, true),
            None => {
                let fallback = xml::calendar_query_body(&start_ical, &end_ical, false);
                let responses = self
                    .client
                    .report(&calendar.url, fallback)
                    .await?
                    .ok_or_else(|| {
                        anyhow::Error::msg(
                            "the CalDAV server rejected the calendar-query report; \
                             it may not support RFC 4791 time-range filtering",
                        )
                    })?;
                (responses, false)
            }
        };

        let mut events = Vec::new();
        let mut truncated = false;
        for r in &responses {
            let Some(data) = r.calendar_data.as_deref() else {
                continue;
            };
            for event in ical::parse_events(data) {
                if events.len() >= MAX_EVENTS {
                    truncated = true;
                    break;
                }
                events.push(event_json(&event, Some(&r.href), r.etag.as_deref()));
            }
            if truncated {
                break;
            }
        }

        let mut out = json!({
            "calendar": calendar.label(),
            "start": start.to_rfc3339_opts(SecondsFormat::Secs, true),
            "end": end.to_rfc3339_opts(SecondsFormat::Secs, true),
            "count": events.len(),
            "events": events,
            "recurrence_expanded": expanded,
        });
        if !expanded {
            out["note"] = json!(
                "This server does not support server-side recurrence expansion, so a \
                 recurring event is listed once with its raw RRULE rather than as \
                 individual occurrences."
            );
        }
        if truncated {
            out["truncated"] = json!(true);
            out["note_truncated"] = json!(format!(
                "Only the first {MAX_EVENTS} events are shown. Narrow the date range to see the rest."
            ));
        }
        Ok(out)
    }

    /// Locate an event by UID, returning the whole calendar object plus the
    /// href and ETag needed to write to it.
    ///
    /// The full object is carried, not just the parsed [`VEvent`], so an update
    /// can patch the original document instead of regenerating it and losing
    /// everything the parser does not model.
    async fn find_event(
        &self,
        calendar: &Calendar,
        uid: &str,
    ) -> anyhow::Result<Option<(CalendarObject, String, Option<String>)>> {
        let body = xml::calendar_query_by_uid_body(uid);
        let responses = self
            .client
            .report(&calendar.url, body)
            .await?
            .unwrap_or_default();

        for r in responses {
            let Some(data) = r.calendar_data.as_deref() else {
                continue;
            };
            let Some(object) = CalendarObject::parse(data) else {
                continue;
            };
            if object.event.uid == uid {
                let url = self.client.resolve_href(&r.href)?;
                return Ok(Some((object, url, r.etag)));
            }
        }
        Ok(None)
    }

    async fn get_event(&self, args: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let uid = require_str(args, "uid")?;
        let calendar = self.target_calendar(args).await?;
        match self.find_event(&calendar, uid).await? {
            Some((object, url, etag)) => {
                let mut value = event_json(&object.event, Some(&url), etag.as_deref());
                value["calendar"] = json!(calendar.label());
                Ok(value)
            }
            None => anyhow::bail!(
                "no event with uid '{uid}' in calendar '{}'",
                calendar.label()
            ),
        }
    }

    async fn create_event(&self, args: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let summary = require_str(args, "summary")?;
        let start = require_time(args, "start")?;
        let end = resolve_end(args, &start)?;
        let calendar = self.target_calendar(args).await?;

        let uid = format!("{}@zeroclaw", uuid::Uuid::new_v4());
        let event = VEvent {
            uid: uid.clone(),
            summary: Some(summary.to_string()),
            description: optional_string(args, "description"),
            location: optional_string(args, "location"),
            start: Some(start),
            end: Some(end),
            attendees: string_list(args, "attendees"),
            ..Default::default()
        };

        let url = format!("{}/{}.ics", calendar.url.trim_end_matches('/'), uid);
        // `If-None-Match: *` makes this a create, never an overwrite.
        match self
            .client
            .put_object(&url, event.to_ics(), None, Some("*"))
            .await?
        {
            WriteOutcome::Ok { etag } => {
                let mut value = event_json(&event, Some(&url), etag.as_deref());
                value["calendar"] = json!(calendar.label());
                value["created"] = json!(true);
                Ok(value)
            }
            WriteOutcome::PreconditionFailed => {
                anyhow::bail!("an event already exists at {url}; retry to get a fresh UID")
            }
            WriteOutcome::NotFound => anyhow::bail!(
                "calendar '{}' rejected the new event (404). Check that it accepts VEVENT items",
                calendar.label()
            ),
        }
    }

    async fn update_event(&self, args: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let uid = require_str(args, "uid")?;
        let calendar = self.target_calendar(args).await?;

        let Some((object, url, etag)) = self.find_event(&calendar, uid).await? else {
            anyhow::bail!(
                "no event with uid '{uid}' in calendar '{}'",
                calendar.label()
            );
        };
        reject_recurring(&object.event, "update")?;

        let etag = etag.ok_or_else(|| {
            anyhow::Error::msg(format!(
                "the server did not supply an ETag for event '{uid}', so it cannot be updated \
                 safely without risking overwriting a concurrent change"
            ))
        })?;

        // Build the change set from the arguments actually supplied. Anything
        // not named here keeps whatever the server holds, including properties
        // and sub-components this tool does not model.
        let mut changes = Vec::new();
        let mut updated = object.event.clone();

        if let Some(v) = optional_string(args, "summary") {
            changes.push(PropertyChange::set(
                "SUMMARY",
                format!("SUMMARY:{}", ical::escape_text(&v)),
            ));
            updated.summary = Some(v);
        }
        if let Some(v) = optional_string(args, "description") {
            changes.push(PropertyChange::set(
                "DESCRIPTION",
                format!("DESCRIPTION:{}", ical::escape_text(&v)),
            ));
            updated.description = Some(v);
        }
        if let Some(v) = optional_string(args, "location") {
            changes.push(PropertyChange::set(
                "LOCATION",
                format!("LOCATION:{}", ical::escape_text(&v)),
            ));
            updated.location = Some(v);
        }
        if args.get("start").is_some() {
            let start = require_time(args, "start")?;
            changes.push(PropertyChange::set("DTSTART", start.to_property("DTSTART")));
            updated.start = Some(start);
        }
        if args.get("end").is_some() {
            let end = require_time(args, "end")?;
            changes.push(PropertyChange::set("DTEND", end.to_property("DTEND")));
            // DTEND and DURATION are mutually exclusive under RFC 5545, and
            // Fastmail stores timed events with DURATION. Writing DTEND without
            // dropping DURATION would produce an invalid component.
            changes.push(PropertyChange::remove("DURATION"));
            updated.end = Some(end);
        }
        let attendees = string_list(args, "attendees");
        if !attendees.is_empty() {
            changes.push(PropertyChange::replace(
                "ATTENDEE",
                attendees
                    .iter()
                    .map(|a| format!("ATTENDEE:{}", ical::escape_text(a)))
                    .collect(),
            ));
            updated.attendees = attendees;
        }

        if changes.is_empty() {
            anyhow::bail!(
                "no changes supplied for event '{uid}'; pass at least one of \
                 summary, description, location, start, end, attendees"
            );
        }

        // Stamp the revision so other clients see the edit.
        changes.push(PropertyChange::set(
            "LAST-MODIFIED",
            format!("LAST-MODIFIED:{}", Utc::now().format("%Y%m%dT%H%M%SZ")),
        ));
        changes.push(PropertyChange::set(
            "DTSTAMP",
            format!("DTSTAMP:{}", Utc::now().format("%Y%m%dT%H%M%SZ")),
        ));
        changes.push(PropertyChange::set(
            "SEQUENCE",
            format!("SEQUENCE:{}", object.event.sequence.unwrap_or(0) + 1),
        ));

        match self
            .client
            .put_object(&url, object.patched(&changes), Some(&etag), None)
            .await?
        {
            WriteOutcome::Ok { etag } => {
                let mut value = event_json(&updated, Some(&url), etag.as_deref());
                value["calendar"] = json!(calendar.label());
                value["updated"] = json!(true);
                Ok(value)
            }
            WriteOutcome::PreconditionFailed => anyhow::bail!(
                "event '{uid}' changed on the server since it was read, so the update was \
                 refused rather than overwriting that change. Read the event again and retry"
            ),
            WriteOutcome::NotFound => {
                anyhow::bail!("event '{uid}' no longer exists on the server")
            }
        }
    }

    async fn delete_event(&self, args: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let uid = require_str(args, "uid")?;
        let calendar = self.target_calendar(args).await?;

        let Some((existing, url, etag)) = self.find_event(&calendar, uid).await? else {
            anyhow::bail!(
                "no event with uid '{uid}' in calendar '{}'",
                calendar.label()
            );
        };
        reject_recurring(&existing.event, "delete")?;

        match self.client.delete_object(&url, etag.as_deref()).await? {
            WriteOutcome::Ok { .. } => Ok(json!({
                "deleted": true,
                "uid": uid,
                "summary": existing.event.summary,
                "calendar": calendar.label(),
            })),
            WriteOutcome::PreconditionFailed => anyhow::bail!(
                "event '{uid}' changed on the server since it was read, so the delete was \
                 refused. Read the event again and retry"
            ),
            WriteOutcome::NotFound => {
                anyhow::bail!("event '{uid}' no longer exists on the server")
            }
        }
    }
}

/// Refuse to mutate a recurring master or a series override.
///
/// A `PUT` against a recurring master rewrites the whole series, and a `DELETE`
/// removes every occurrence. Neither is what a single-event edit means, and the
/// damage is silent, so this is a hard stop rather than a warning.
fn reject_recurring(event: &VEvent, verb: &str) -> anyhow::Result<()> {
    if !event.is_recurring() {
        return Ok(());
    }
    let detail = match (&event.rrule, &event.recurrence_id) {
        (Some(rule), _) => format!("it repeats ({rule})"),
        (_, Some(_)) => "it is one occurrence of a repeating series".to_string(),
        _ => "it is part of a repeating series".to_string(),
    };
    anyhow::bail!(
        "refusing to {verb} event '{}' because {detail}. Editing a repeating event here \
         would change every occurrence. Use your calendar app for recurring events.",
        event.uid
    )
}

fn event_json(event: &VEvent, href: Option<&str>, etag: Option<&str>) -> serde_json::Value {
    json!({
        "uid": event.uid,
        "summary": event.summary,
        "description": event.description,
        "location": event.location,
        "start": event.start.as_ref().map(EventTime::to_display),
        "end": event.end.as_ref().map(EventTime::to_display),
        "all_day": matches!(event.start, Some(EventTime::Date(_))),
        "status": event.status,
        "organizer": event.organizer,
        "attendees": event.attendees,
        "recurring": event.is_recurring(),
        "rrule": event.rrule,
        "reminder_count": event.alarm_count,
        "href": href,
        "etag": etag,
    })
}

fn require_str<'a>(args: &'a serde_json::Value, key: &str) -> anyhow::Result<&'a str> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::Error::msg(format!("'{key}' is required")))
}

fn optional_string(args: &serde_json::Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
}

fn string_list(args: &serde_json::Value, key: &str) -> Vec<String> {
    args.get(key)
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Parse an RFC 3339 timestamp into an [`EventTime`], or a bare `YYYY-MM-DD`
/// into an all-day date.
fn parse_event_time(raw: &str) -> anyhow::Result<EventTime> {
    let raw = raw.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Ok(EventTime::DateTime(dt.with_timezone(&Utc)));
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(raw, "%Y-%m-%d") {
        return Ok(EventTime::Date(date));
    }
    anyhow::bail!(
        "could not parse '{raw}' as a time. Use RFC 3339 \
         (e.g. 2026-09-04T15:00:00Z) or YYYY-MM-DD for an all-day event"
    )
}

fn require_time(args: &serde_json::Value, key: &str) -> anyhow::Result<EventTime> {
    parse_event_time(require_str(args, key)?)
}

/// Resolve the end of a new event: explicit `end`, or `start` plus
/// `duration_minutes`, defaulting to one hour.
fn resolve_end(args: &serde_json::Value, start: &EventTime) -> anyhow::Result<EventTime> {
    if args.get("end").is_some() {
        return require_time(args, "end");
    }
    let minutes = args
        .get("duration_minutes")
        .and_then(|v| v.as_i64())
        .unwrap_or(60);
    if minutes <= 0 {
        anyhow::bail!("duration_minutes must be positive");
    }
    match start {
        EventTime::DateTime(dt) => Ok(EventTime::DateTime(*dt + ChronoDuration::minutes(minutes))),
        // An all-day event ends the next day (DTEND is exclusive).
        EventTime::Date(d) => Ok(EventTime::Date(*d + ChronoDuration::days(1))),
        EventTime::DateTimeFloating { local, tzid } => Ok(EventTime::DateTimeFloating {
            local: *local + ChronoDuration::minutes(minutes),
            tzid: tzid.clone(),
        }),
    }
}

/// Parse and validate the `start`/`end` range for `list_events`.
fn parse_range(args: &serde_json::Value) -> anyhow::Result<(DateTime<Utc>, DateTime<Utc>)> {
    let start = match args.get("start").and_then(|v| v.as_str()) {
        Some(raw) => to_utc_bound(raw)?,
        None => Utc::now(),
    };
    let end = match args.get("end").and_then(|v| v.as_str()) {
        Some(raw) => to_utc_bound(raw)?,
        None => start + ChronoDuration::days(7),
    };
    if end <= start {
        anyhow::bail!("'end' must be after 'start'");
    }
    if (end - start).num_days() > MAX_RANGE_DAYS {
        anyhow::bail!("date range must not exceed {MAX_RANGE_DAYS} days");
    }
    Ok((start, end))
}

/// Coerce a range bound to an absolute instant. A bare date is taken as
/// midnight UTC, which is the only defensible reading without a user timezone.
fn to_utc_bound(raw: &str) -> anyhow::Result<DateTime<Utc>> {
    match parse_event_time(raw)? {
        EventTime::DateTime(dt) => Ok(dt),
        EventTime::Date(d) => Ok(DateTime::from_naive_utc_and_offset(
            d.and_hms_opt(0, 0, 0)
                .ok_or_else(|| anyhow::Error::msg("invalid date"))?,
            Utc,
        )),
        EventTime::DateTimeFloating { local, .. } => {
            Ok(DateTime::from_naive_utc_and_offset(local, Utc))
        }
    }
}

fn to_ical_utc(dt: DateTime<Utc>) -> String {
    dt.format("%Y%m%dT%H%M%SZ").to_string()
}

#[async_trait]
impl Tool for CalDavTool {
    fn name(&self) -> &str {
        "caldav"
    }

    fn description(&self) -> &str {
        "Read and manage calendar events on a CalDAV server (Fastmail, iCloud, Nextcloud, \
         Radicale, and other RFC 4791 servers). List calendars, list events in a date range, \
         read one event, and — when the operator has allow-listed the action — create, update, \
         or delete events. Repeating events are listed as individual occurrences but cannot be \
         edited or deleted through this tool."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "required": ["action"],
            "properties": {
                "action": {
                    "type": "string",
                    "enum": VALID_ACTIONS,
                    "description": "Operation to perform."
                },
                "calendar": {
                    "type": "string",
                    "description": "Calendar display name or href. Defaults to the configured default calendar, or the first calendar found."
                },
                "uid": {
                    "type": "string",
                    "description": "Event UID. Required for get_event, update_event, and delete_event."
                },
                "start": {
                    "type": "string",
                    "description": "RFC 3339 timestamp (2026-09-04T15:00:00Z) or YYYY-MM-DD for an all-day event. For list_events this is the range start and defaults to now."
                },
                "end": {
                    "type": "string",
                    "description": "RFC 3339 timestamp or YYYY-MM-DD. For list_events this is the range end and defaults to 7 days after start."
                },
                "duration_minutes": {
                    "type": "integer",
                    "description": "For create_event, length of the event when 'end' is omitted. Default 60."
                },
                "summary": {
                    "type": "string",
                    "description": "Event title. Required for create_event."
                },
                "description": { "type": "string", "description": "Event body text." },
                "location": { "type": "string", "description": "Event location." },
                "attendees": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Attendee email addresses. Note that this records attendees on the event; it does not send invitation emails."
                }
            }
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let Some(action) = args.get("action").and_then(|v| v.as_str()) else {
            return Ok(ToolResult::err(format!(
                "'action' is required. Valid actions: {}",
                VALID_ACTIONS.join(", ")
            )));
        };
        let action = action.trim();

        if !VALID_ACTIONS.contains(&action) {
            return Ok(ToolResult::err(format!(
                "Unknown action: '{action}'. Valid actions: {}",
                VALID_ACTIONS.join(", ")
            )));
        }

        if !self.is_action_allowed(action) {
            return Ok(ToolResult::err(format!(
                "Action '{action}' is not enabled. Add it to caldav.allowed_actions in \
                 config.toml. Currently allowed: {}",
                if self.allowed_actions.is_empty() {
                    "(none)".to_string()
                } else {
                    self.allowed_actions.join(", ")
                }
            )));
        }

        if let Err(error) = self
            .security
            .enforce_tool_operation(Self::operation_for(action), "caldav")
        {
            return Ok(ToolResult::err(error));
        }

        let result = match action {
            "list_calendars" => self.list_calendars().await,
            "list_events" => self.list_events(&args).await,
            "get_event" => self.get_event(&args).await,
            "create_event" => self.create_event(&args).await,
            "update_event" => self.update_event(&args).await,
            "delete_event" => self.delete_event(&args).await,
            _ => unreachable!("action validated above"),
        };

        match result {
            Ok(value) => Ok(ToolResult::ok(ToolOutput::json(value))),
            // Domain failures are reported through ToolResult so the model can
            // read and act on them; `Err` is reserved for host-level faults.
            Err(e) => Ok(ToolResult::err(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests;
