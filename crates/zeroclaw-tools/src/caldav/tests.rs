//! Tests for the `caldav` tool.
//!
//! The wiremock cases drive the real client against a loopback server, so the
//! discovery chain, the `<C:expand>` fallback, and the ETag preconditions are
//! exercised end to end rather than stubbed.

use super::*;
use serde_json::json;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ALL_ACTIONS: &[&str] = &[
    "list_calendars",
    "list_events",
    "get_event",
    "create_event",
    "update_event",
    "delete_event",
];

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

/// A tool pointed at `base_url`, with `allowed_actions` and a default policy.
/// Private hosts are permitted so the loopback mock server is reachable.
fn tool_with(base_url: &str, allowed: &[&str]) -> CalDavTool {
    CalDavTool::new(
        base_url.to_string(),
        "user@example.com".into(),
        "app-password".into(),
        None,
        strings(allowed),
        true,
        Vec::new(),
        5,
        Arc::new(SecurityPolicy::default()),
    )
    .expect("tool builds")
}

fn tool(base_url: &str) -> CalDavTool {
    tool_with(base_url, ALL_ACTIONS)
}

// ── discovery + REPORT fixtures ───────────────────────────────────

const PRINCIPAL_XML: &str = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/</d:href>
<d:propstat><d:prop><d:current-user-principal>
<d:href>/dav/principals/user/me/</d:href>
</d:current-user-principal></d:prop></d:propstat></d:response></d:multistatus>"#;

const HOME_XML: &str = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
<d:response><d:href>/dav/principals/user/me/</d:href><d:propstat><d:prop>
<c:calendar-home-set><d:href>/dav/calendars/user/me/</d:href></c:calendar-home-set>
</d:prop></d:propstat></d:response></d:multistatus>"#;

const CALENDAR_LIST_XML: &str = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
<d:response><d:href>/dav/calendars/user/me/</d:href><d:propstat><d:prop>
<d:resourcetype><d:collection/></d:resourcetype>
<d:displayname>Home</d:displayname></d:prop></d:propstat></d:response>
<d:response><d:href>/dav/calendars/user/me/work/</d:href><d:propstat><d:prop>
<d:resourcetype><d:collection/><c:calendar/></d:resourcetype>
<d:displayname>Work</d:displayname>
<c:supported-calendar-component-set><c:comp name="VEVENT"/></c:supported-calendar-component-set>
</d:prop></d:propstat></d:response>
<d:response><d:href>/dav/calendars/user/me/tasks/</d:href><d:propstat><d:prop>
<d:resourcetype><d:collection/><c:calendar/></d:resourcetype>
<d:displayname>Tasks</d:displayname>
<c:supported-calendar-component-set><c:comp name="VTODO"/></c:supported-calendar-component-set>
</d:prop></d:propstat></d:response>
</d:multistatus>"#;

/// Mount the three discovery PROPFINDs. The first is the "calendar-home at
/// root" probe, which this fake server answers with a 404 so the full
/// principal chain runs.
async fn mount_discovery(server: &MockServer) {
    Mock::given(method("PROPFIND"))
        .and(path("/dav/"))
        .and(body_string_contains("calendar-home-set"))
        .respond_with(ResponseTemplate::new(404))
        .mount(server)
        .await;
    Mock::given(method("PROPFIND"))
        .and(path("/dav/"))
        .and(body_string_contains("current-user-principal"))
        .respond_with(ResponseTemplate::new(207).set_body_string(PRINCIPAL_XML))
        .mount(server)
        .await;
    Mock::given(method("PROPFIND"))
        .and(path("/dav/principals/user/me/"))
        .respond_with(ResponseTemplate::new(207).set_body_string(HOME_XML))
        .mount(server)
        .await;
    Mock::given(method("PROPFIND"))
        .and(path("/dav/calendars/user/me/"))
        .respond_with(ResponseTemplate::new(207).set_body_string(CALENDAR_LIST_XML))
        .mount(server)
        .await;
}

fn event_report_xml(events: &str) -> String {
    format!(
        r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
<d:response><d:href>/dav/calendars/user/me/work/e1.ics</d:href><d:propstat><d:prop>
<d:getetag>"etag-1"</d:getetag>
<c:calendar-data>{events}</c:calendar-data>
</d:prop></d:propstat></d:response></d:multistatus>"#
    )
}

// ── schema and dispatch ───────────────────────────────────────────

#[test]
fn tool_name_is_caldav() {
    assert_eq!(tool("https://example.com/dav").name(), "caldav");
}

#[test]
fn schema_lists_every_action_and_requires_action() {
    let schema = tool("https://example.com/dav").parameters_schema();
    assert_eq!(schema["required"], json!(["action"]));
    let listed = schema["properties"]["action"]["enum"]
        .as_array()
        .expect("enum present")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(listed, ALL_ACTIONS);
}

#[test]
fn read_actions_are_read_and_write_actions_are_act() {
    for action in ["list_calendars", "list_events", "get_event"] {
        assert_eq!(
            CalDavTool::operation_for(action),
            ToolOperation::Read,
            "{action} must be Read"
        );
    }
    for action in ["create_event", "update_event", "delete_event"] {
        assert_eq!(
            CalDavTool::operation_for(action),
            ToolOperation::Act,
            "{action} must be Act"
        );
    }
}

#[tokio::test]
async fn missing_action_is_an_error() {
    let result = tool("https://example.com/dav")
        .execute(json!({}))
        .await
        .expect("no host error");
    assert!(!result.success);
    assert!(result.error.unwrap().contains("'action' is required"));
}

#[tokio::test]
async fn unknown_action_is_an_error_listing_valid_ones() {
    let result = tool("https://example.com/dav")
        .execute(json!({"action": "drop_calendar"}))
        .await
        .expect("no host error");
    assert!(!result.success);
    let err = result.error.unwrap();
    assert!(err.contains("Unknown action"));
    assert!(err.contains("list_events"));
}

#[tokio::test]
async fn write_actions_are_refused_under_the_default_read_only_allowlist() {
    // Mirrors the shipped default: the three read actions only.
    let t = tool_with(
        "https://example.com/dav",
        &["list_calendars", "list_events", "get_event"],
    );
    for action in ["create_event", "update_event", "delete_event"] {
        let result = t
            .execute(json!({"action": action, "uid": "x", "summary": "s", "start": "2026-09-04T10:00:00Z"}))
            .await
            .expect("no host error");
        assert!(!result.success, "{action} must be refused");
        let err = result.error.unwrap();
        assert!(
            err.contains("caldav.allowed_actions"),
            "error should name the config key: {err}"
        );
    }
}

#[tokio::test]
async fn allowlist_rejection_happens_before_any_network_call() {
    // An unreachable base URL proves no request was attempted: the allowlist
    // check must short-circuit first.
    let t = tool_with("https://127.0.0.1:1/dav", &["list_calendars"]);
    let result = t
        .execute(json!({"action": "delete_event", "uid": "x"}))
        .await
        .expect("no host error");
    assert!(!result.success);
    assert!(result.error.unwrap().contains("not enabled"));
}

#[tokio::test]
async fn empty_allowlist_reports_none_allowed() {
    let t = tool_with("https://example.com/dav", &[]);
    let result = t
        .execute(json!({"action": "list_events"}))
        .await
        .expect("no host error");
    assert!(result.error.unwrap().contains("(none)"));
}

// ── argument validation ───────────────────────────────────────────

#[test]
fn parse_event_time_accepts_rfc3339_and_bare_dates() {
    assert!(matches!(
        parse_event_time("2026-09-04T15:00:00Z").unwrap(),
        EventTime::DateTime(_)
    ));
    // A non-UTC offset is normalized to UTC.
    let EventTime::DateTime(dt) = parse_event_time("2026-09-04T17:00:00+02:00").unwrap() else {
        panic!("expected an absolute instant");
    };
    assert_eq!(dt.to_rfc3339(), "2026-09-04T15:00:00+00:00");
    assert!(matches!(
        parse_event_time("2026-09-04").unwrap(),
        EventTime::Date(_)
    ));
}

#[test]
fn parse_event_time_rejects_garbage_with_a_usable_hint() {
    let err = parse_event_time("next tuesday").unwrap_err().to_string();
    assert!(err.contains("RFC 3339"), "{err}");
}

#[test]
fn range_defaults_to_the_next_seven_days() {
    let (start, end) = parse_range(&json!({})).expect("defaults");
    assert_eq!((end - start).num_days(), 7);
}

#[test]
fn range_rejects_inverted_and_oversized_windows() {
    let err = parse_range(&json!({"start": "2026-09-10", "end": "2026-09-01"})).unwrap_err();
    assert!(err.to_string().contains("must be after"));

    let err = parse_range(&json!({"start": "2020-01-01", "end": "2026-01-01"})).unwrap_err();
    assert!(err.to_string().contains("must not exceed"));
}

#[test]
fn resolve_end_defaults_to_one_hour_after_start() {
    let start = parse_event_time("2026-09-04T15:00:00Z").unwrap();
    let EventTime::DateTime(end) = resolve_end(&json!({}), &start).unwrap() else {
        panic!("expected a datetime");
    };
    assert_eq!(end.to_rfc3339(), "2026-09-04T16:00:00+00:00");
}

#[test]
fn resolve_end_honours_duration_minutes_and_rejects_non_positive() {
    let start = parse_event_time("2026-09-04T15:00:00Z").unwrap();
    let EventTime::DateTime(end) = resolve_end(&json!({"duration_minutes": 30}), &start).unwrap()
    else {
        panic!("expected a datetime");
    };
    assert_eq!(end.to_rfc3339(), "2026-09-04T15:30:00+00:00");

    assert!(resolve_end(&json!({"duration_minutes": 0}), &start).is_err());
    assert!(resolve_end(&json!({"duration_minutes": -5}), &start).is_err());
}

#[test]
fn all_day_event_ends_the_following_day() {
    let start = parse_event_time("2026-09-04").unwrap();
    let EventTime::Date(end) = resolve_end(&json!({}), &start).unwrap() else {
        panic!("expected a date");
    };
    assert_eq!(end.to_string(), "2026-09-05");
}

// ── the recurrence guard ──────────────────────────────────────────

#[test]
fn reject_recurring_blocks_a_master_and_names_the_rule() {
    let event = VEvent {
        uid: "weekly-standup".into(),
        rrule: Some("FREQ=WEEKLY;BYDAY=MO".into()),
        ..Default::default()
    };
    let err = reject_recurring(&event, "update").unwrap_err().to_string();
    assert!(err.contains("weekly-standup"), "{err}");
    assert!(err.contains("FREQ=WEEKLY"), "{err}");
    assert!(err.contains("every occurrence"), "{err}");
}

#[test]
fn reject_recurring_blocks_a_series_override() {
    let event = VEvent {
        uid: "x".into(),
        recurrence_id: Some("20260904T150000Z".into()),
        ..Default::default()
    };
    assert!(reject_recurring(&event, "delete").is_err());
}

#[test]
fn reject_recurring_allows_a_plain_event() {
    let event = VEvent {
        uid: "one-off".into(),
        ..Default::default()
    };
    assert!(reject_recurring(&event, "update").is_ok());
}

// ── wiremock: discovery ───────────────────────────────────────────

#[tokio::test]
async fn list_calendars_walks_the_discovery_chain_and_filters_non_event_collections() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    let result = tool(&format!("{}/dav", server.uri()))
        .execute(json!({"action": "list_calendars"}))
        .await
        .expect("no host error");
    assert!(result.success, "unexpected error: {:?}", result.error);

    let data = result.output.data().expect("structured output");
    // "Home" is a plain collection and "Tasks" only holds VTODO, so only
    // "Work" survives.
    assert_eq!(data["count"], 1);
    assert_eq!(data["calendars"][0]["name"], "Work");
}

#[tokio::test]
async fn discovery_sends_basic_auth() {
    let server = MockServer::start().await;
    let expected = format!(
        "Basic {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "user@example.com:app-password"
        )
    );
    // Scoped to the DAV root: without the path constraint this would also
    // swallow the calendar-home PROPFIND aimed at the principal URL.
    Mock::given(method("PROPFIND"))
        .and(path("/dav/"))
        .and(header("authorization", expected.as_str()))
        .and(body_string_contains("calendar-home-set"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1..)
        .mount(&server)
        .await;
    Mock::given(method("PROPFIND"))
        .and(path("/dav/"))
        .and(header("authorization", expected.as_str()))
        .and(body_string_contains("current-user-principal"))
        .respond_with(ResponseTemplate::new(207).set_body_string(PRINCIPAL_XML))
        .mount(&server)
        .await;
    Mock::given(method("PROPFIND"))
        .and(path("/dav/principals/user/me/"))
        .respond_with(ResponseTemplate::new(207).set_body_string(HOME_XML))
        .mount(&server)
        .await;
    Mock::given(method("PROPFIND"))
        .and(path("/dav/calendars/user/me/"))
        .respond_with(ResponseTemplate::new(207).set_body_string(CALENDAR_LIST_XML))
        .mount(&server)
        .await;

    let result = tool(&format!("{}/dav", server.uri()))
        .execute(json!({"action": "list_calendars"}))
        .await
        .expect("no host error");
    assert!(result.success, "unexpected error: {:?}", result.error);
    server.verify().await;
}

#[tokio::test]
async fn unauthorized_discovery_reports_the_app_password_hint() {
    let server = MockServer::start().await;
    Mock::given(method("PROPFIND"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let result = tool(&format!("{}/dav", server.uri()))
        .execute(json!({"action": "list_calendars"}))
        .await
        .expect("no host error");
    assert!(!result.success);
    assert!(
        result.error.unwrap().contains("app-specific password"),
        "401 should tell the operator what to check"
    );
}

// ── wiremock: reads ───────────────────────────────────────────────

#[tokio::test]
async fn list_events_requests_server_side_expansion_and_returns_each_occurrence() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    // Two expanded occurrences of a weekly meeting.
    let expanded = "BEGIN:VCALENDAR\r\n\
        BEGIN:VEVENT\r\nUID:weekly\r\nSUMMARY:Standup\r\nDTSTART:20260901T090000Z\r\n\
        DTEND:20260901T091500Z\r\nEND:VEVENT\r\n\
        BEGIN:VEVENT\r\nUID:weekly\r\nSUMMARY:Standup\r\nDTSTART:20260908T090000Z\r\n\
        DTEND:20260908T091500Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    Mock::given(method("REPORT"))
        .and(path("/dav/calendars/user/me/work/"))
        .and(body_string_contains("<c:expand"))
        .respond_with(ResponseTemplate::new(207).set_body_string(event_report_xml(expanded)))
        .expect(1)
        .mount(&server)
        .await;

    let result = tool(&format!("{}/dav", server.uri()))
        .execute(json!({
            "action": "list_events",
            "start": "2026-09-01",
            "end": "2026-09-14"
        }))
        .await
        .expect("no host error");
    assert!(result.success, "unexpected error: {:?}", result.error);

    let data = result.output.data().expect("structured output");
    assert_eq!(data["count"], 2, "each occurrence should be listed");
    assert_eq!(data["recurrence_expanded"], true);
    assert_eq!(data["events"][0]["start"], "2026-09-01T09:00:00+00:00");
    assert_eq!(data["events"][1]["start"], "2026-09-08T09:00:00+00:00");
    server.verify().await;
}

#[tokio::test]
async fn list_events_falls_back_when_the_server_rejects_expand_and_says_so() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    // The expand report is refused; the plain one succeeds.
    Mock::given(method("REPORT"))
        .and(body_string_contains("<c:expand"))
        .respond_with(ResponseTemplate::new(400))
        .expect(1)
        .mount(&server)
        .await;
    let raw = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:weekly\r\nSUMMARY:Standup\r\n\
        DTSTART:20260901T090000Z\r\nRRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    Mock::given(method("REPORT"))
        .and(path("/dav/calendars/user/me/work/"))
        .respond_with(ResponseTemplate::new(207).set_body_string(event_report_xml(raw)))
        .mount(&server)
        .await;

    let result = tool(&format!("{}/dav", server.uri()))
        .execute(json!({"action": "list_events", "start": "2026-09-01", "end": "2026-09-14"}))
        .await
        .expect("no host error");
    assert!(result.success, "unexpected error: {:?}", result.error);

    let data = result.output.data().expect("structured output");
    assert_eq!(data["recurrence_expanded"], false);
    assert_eq!(data["count"], 1);
    assert_eq!(data["events"][0]["recurring"], true);
    assert_eq!(data["events"][0]["rrule"], "FREQ=WEEKLY");
    // The output must admit that occurrences were not expanded.
    assert!(
        data["note"].as_str().unwrap().contains("recurring"),
        "fallback must be disclosed, not silent"
    );
    server.verify().await;
}

#[tokio::test]
async fn list_events_rejects_an_unknown_calendar_instead_of_using_the_default() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    let result = tool(&format!("{}/dav", server.uri()))
        .execute(json!({"action": "list_events", "calendar": "Holidays"}))
        .await
        .expect("no host error");
    assert!(!result.success);
    let err = result.error.unwrap();
    assert!(err.contains("Holidays"), "{err}");
    assert!(err.contains("Work"), "should list what is available: {err}");
}

#[tokio::test]
async fn get_event_returns_the_etag_needed_for_a_later_write() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:abc\r\nSUMMARY:Lunch\r\n\
        DTSTART:20260904T120000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    Mock::given(method("REPORT"))
        .and(body_string_contains("<c:text-match"))
        .respond_with(ResponseTemplate::new(207).set_body_string(event_report_xml(ics)))
        .mount(&server)
        .await;

    let result = tool(&format!("{}/dav", server.uri()))
        .execute(json!({"action": "get_event", "uid": "abc"}))
        .await
        .expect("no host error");
    assert!(result.success, "unexpected error: {:?}", result.error);

    let data = result.output.data().expect("structured output");
    assert_eq!(data["uid"], "abc");
    assert_eq!(data["summary"], "Lunch");
    assert_eq!(data["etag"], "\"etag-1\"");
}

#[tokio::test]
async fn get_event_reports_a_missing_uid() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    Mock::given(method("REPORT"))
        .respond_with(
            ResponseTemplate::new(207)
                .set_body_string(r#"<d:multistatus xmlns:d="DAV:"></d:multistatus>"#),
        )
        .mount(&server)
        .await;

    let result = tool(&format!("{}/dav", server.uri()))
        .execute(json!({"action": "get_event", "uid": "nope"}))
        .await
        .expect("no host error");
    assert!(!result.success);
    assert!(result.error.unwrap().contains("no event with uid 'nope'"));
}

// ── wiremock: writes ──────────────────────────────────────────────

#[tokio::test]
async fn create_event_puts_with_if_none_match_so_it_cannot_overwrite() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    Mock::given(method("PUT"))
        .and(header("if-none-match", "*"))
        .and(header("content-type", "text/calendar; charset=utf-8"))
        .and(body_string_contains("SUMMARY:Dentist"))
        .and(body_string_contains("DTSTART:20260904T150000Z"))
        .respond_with(ResponseTemplate::new(201).insert_header("etag", "\"new-etag\""))
        .expect(1)
        .mount(&server)
        .await;

    let result = tool(&format!("{}/dav", server.uri()))
        .execute(json!({
            "action": "create_event",
            "summary": "Dentist",
            "start": "2026-09-04T15:00:00Z",
            "duration_minutes": 30
        }))
        .await
        .expect("no host error");
    assert!(result.success, "unexpected error: {:?}", result.error);

    let data = result.output.data().expect("structured output");
    assert_eq!(data["created"], true);
    assert_eq!(data["summary"], "Dentist");
    assert_eq!(data["end"], "2026-09-04T15:30:00+00:00");
    server.verify().await;
}

#[tokio::test]
async fn create_event_requires_a_summary_and_a_start() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    let t = tool(&format!("{}/dav", server.uri()));

    let result = t
        .execute(json!({"action": "create_event", "start": "2026-09-04T15:00:00Z"}))
        .await
        .expect("no host error");
    assert!(result.error.unwrap().contains("'summary' is required"));

    let result = t
        .execute(json!({"action": "create_event", "summary": "x"}))
        .await
        .expect("no host error");
    assert!(result.error.unwrap().contains("'start' is required"));
}

#[tokio::test]
async fn update_event_sends_if_match_and_preserves_unspecified_fields() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:abc\r\nSUMMARY:Lunch\r\n\
        LOCATION:Cafe\r\nDTSTART:20260904T120000Z\r\nDTEND:20260904T130000Z\r\n\
        END:VEVENT\r\nEND:VCALENDAR\r\n";
    Mock::given(method("REPORT"))
        .respond_with(ResponseTemplate::new(207).set_body_string(event_report_xml(ics)))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(header("if-match", "\"etag-1\""))
        .and(body_string_contains("SUMMARY:Brunch"))
        // The untouched location must survive the round trip.
        .and(body_string_contains("LOCATION:Cafe"))
        .respond_with(ResponseTemplate::new(204).insert_header("etag", "\"etag-2\""))
        .expect(1)
        .mount(&server)
        .await;

    let result = tool(&format!("{}/dav", server.uri()))
        .execute(json!({"action": "update_event", "uid": "abc", "summary": "Brunch"}))
        .await
        .expect("no host error");
    assert!(result.success, "unexpected error: {:?}", result.error);
    assert_eq!(result.output.data().unwrap()["updated"], true);
    server.verify().await;
}

#[tokio::test]
async fn update_event_preserves_reminders_and_unmodelled_properties() {
    // Regression: regenerating the .ics from the parsed struct silently
    // deleted the user's reminder, the organizer, and the timezone block.
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n\
        BEGIN:VTIMEZONE\r\nTZID:America/Chicago\r\nEND:VTIMEZONE\r\n\
        BEGIN:VEVENT\r\nUID:abc\r\nSUMMARY:Lunch\r\nDTSTART:20260904T120000Z\r\n\
        DURATION:PT1H\r\nSEQUENCE:2\r\nTRANSP:OPAQUE\r\n\
        ORGANIZER;CN=Ana:mailto:ana@example.com\r\n\
        X-JMAP-USEDEFAULTALERTS;VALUE=BOOLEAN:TRUE\r\n\
        BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nEND:VALARM\r\n\
        END:VEVENT\r\nEND:VCALENDAR\r\n";
    Mock::given(method("REPORT"))
        .respond_with(ResponseTemplate::new(207).set_body_string(event_report_xml(ics)))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(header("if-match", "\"etag-1\""))
        .and(body_string_contains("SUMMARY:Brunch"))
        .and(body_string_contains("BEGIN:VALARM"))
        .and(body_string_contains("TRIGGER:-PT15M"))
        .and(body_string_contains("ORGANIZER;CN=Ana:mailto:ana@example.com"))
        .and(body_string_contains("BEGIN:VTIMEZONE"))
        .and(body_string_contains("TRANSP:OPAQUE"))
        .and(body_string_contains("X-JMAP-USEDEFAULTALERTS"))
        // SEQUENCE must advance so other clients treat the edit as newer.
        .and(body_string_contains("SEQUENCE:3"))
        .respond_with(ResponseTemplate::new(204).insert_header("etag", "\"etag-2\""))
        .expect(1)
        .mount(&server)
        .await;

    let result = tool(&format!("{}/dav", server.uri()))
        .execute(json!({"action": "update_event", "uid": "abc", "summary": "Brunch"}))
        .await
        .expect("no host error");
    assert!(result.success, "unexpected error: {:?}", result.error);
    server.verify().await;
}

#[tokio::test]
async fn changing_the_end_drops_duration_so_the_component_stays_valid() {
    // DTEND and DURATION are mutually exclusive under RFC 5545.
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:abc\r\nSUMMARY:Lunch\r\n\
        DTSTART:20260904T120000Z\r\nDURATION:PT1H\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    Mock::given(method("REPORT"))
        .respond_with(ResponseTemplate::new(207).set_body_string(event_report_xml(ics)))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(body_string_contains("DTEND:20260904T140000Z"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let result = tool(&format!("{}/dav", server.uri()))
        .execute(json!({
            "action": "update_event", "uid": "abc", "end": "2026-09-04T14:00:00Z"
        }))
        .await
        .expect("no host error");
    assert!(result.success, "unexpected error: {:?}", result.error);

    // Assert the negative directly: the received body must not carry both.
    let requests = server.received_requests().await.expect("requests recorded");
    let put = requests
        .iter()
        .find(|r| r.method.as_str() == "PUT")
        .expect("a PUT was made");
    let body = String::from_utf8_lossy(&put.body);
    assert!(
        !body.contains("DURATION:"),
        "DTEND and DURATION must not coexist:\n{body}"
    );
}

#[tokio::test]
async fn create_event_writes_requested_reminders() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    Mock::given(method("PUT"))
        .and(body_string_contains("TRIGGER:-PT15M"))
        .and(body_string_contains("TRIGGER:-PT1440M"))
        .and(body_string_contains("ACTION:DISPLAY"))
        // Without this, Fastmail ignores the alarms we just set.
        .and(body_string_contains("X-JMAP-USEDEFAULTALERTS;VALUE=BOOLEAN:FALSE"))
        .respond_with(ResponseTemplate::new(201))
        .expect(1)
        .mount(&server)
        .await;

    let result = tool(&format!("{}/dav", server.uri()))
        .execute(json!({
            "action": "create_event",
            "summary": "Dentist",
            "start": "2026-09-04T15:00:00Z",
            "reminders": [15, 1440],
        }))
        .await
        .expect("no host error");
    assert!(result.success, "unexpected error: {:?}", result.error);
    assert_eq!(
        result.output.data().unwrap()["reminders_minutes_before"],
        json!([15, 1440])
    );
    server.verify().await;
}

#[tokio::test]
async fn update_event_can_replace_and_clear_reminders() {
    for (reminders, expect_alarm) in [(json!([30]), true), (json!([]), false)] {
        let server = MockServer::start().await;
        mount_discovery(&server).await;

        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:abc\r\nSUMMARY:Lunch\r\n\
            DTSTART:20260904T120000Z\r\n\
            BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT5M\r\nEND:VALARM\r\n\
            END:VEVENT\r\nEND:VCALENDAR\r\n";
        Mock::given(method("REPORT"))
            .respond_with(ResponseTemplate::new(207).set_body_string(event_report_xml(ics)))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let result = tool(&format!("{}/dav", server.uri()))
            .execute(json!({
                "action": "update_event", "uid": "abc", "reminders": reminders
            }))
            .await
            .expect("no host error");
        assert!(result.success, "unexpected error: {:?}", result.error);

        let requests = server.received_requests().await.expect("recorded");
        let put = requests
            .iter()
            .find(|r| r.method.as_str() == "PUT")
            .expect("a PUT was made");
        let body = String::from_utf8_lossy(&put.body);
        // The pre-existing 5-minute alarm is replaced either way.
        assert!(!body.contains("-PT5M"), "old reminder survived:\n{body}");
        if expect_alarm {
            assert!(
                body.contains("TRIGGER:-PT30M"),
                "new reminder missing:\n{body}"
            );
        } else {
            assert!(
                !body.contains("VALARM"),
                "reminders should be cleared:\n{body}"
            );
        }
    }
}

#[tokio::test]
async fn omitting_reminders_on_update_leaves_them_alone() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:abc\r\nSUMMARY:Lunch\r\n\
        DTSTART:20260904T120000Z\r\n\
        BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT5M\r\nEND:VALARM\r\n\
        END:VEVENT\r\nEND:VCALENDAR\r\n";
    Mock::given(method("REPORT"))
        .respond_with(ResponseTemplate::new(207).set_body_string(event_report_xml(ics)))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(body_string_contains("TRIGGER:-PT5M"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let result = tool(&format!("{}/dav", server.uri()))
        .execute(json!({"action": "update_event", "uid": "abc", "summary": "Brunch"}))
        .await
        .expect("no host error");
    assert!(result.success, "unexpected error: {:?}", result.error);
    server.verify().await;
}

#[tokio::test]
async fn get_event_reports_reminders_separating_odd_triggers() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:abc\r\nSUMMARY:Lunch\r\n\
        DTSTART:20260904T120000Z\r\n\
        BEGIN:VALARM\r\nTRIGGER:-PT15M\r\nEND:VALARM\r\n\
        BEGIN:VALARM\r\nTRIGGER;RELATED=END:-PT5M\r\nEND:VALARM\r\n\
        END:VEVENT\r\nEND:VCALENDAR\r\n";
    Mock::given(method("REPORT"))
        .respond_with(ResponseTemplate::new(207).set_body_string(event_report_xml(ics)))
        .mount(&server)
        .await;

    let result = tool(&format!("{}/dav", server.uri()))
        .execute(json!({"action": "get_event", "uid": "abc"}))
        .await
        .expect("no host error");
    assert!(result.success, "unexpected error: {:?}", result.error);

    let data = result.output.data().expect("structured output");
    assert_eq!(data["reminders_minutes_before"], json!([15]));
    assert_eq!(data["reminders_other"][0]["related_to_end"], true);
}

#[tokio::test]
async fn invalid_reminders_are_rejected_with_a_usable_message() {
    // Port 1 is closed, so any error mentioning the connection would mean
    // validation ran after the network call instead of before it.
    let t = tool("http://127.0.0.1:1/dav");
    for (bad, expect) in [
        (json!("15"), "must be an array"),
        (json!([-5]), "cannot be negative"),
        (json!([1.5]), "whole numbers"),
        (json!([999_999]), "more than a year"),
    ] {
        let result = t
            .execute(json!({
                "action": "create_event",
                "summary": "s",
                "start": "2026-09-04T15:00:00Z",
                "reminders": bad,
            }))
            .await
            .expect("no host error");
        assert!(!result.success, "should reject {bad}");
        let err = result.error.unwrap();
        assert!(err.contains(expect), "for {bad}, got: {err}");
    }
}

#[tokio::test]
async fn update_event_surfaces_a_412_as_a_conflict_rather_than_retrying() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:abc\r\nSUMMARY:Lunch\r\n\
        DTSTART:20260904T120000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    Mock::given(method("REPORT"))
        .respond_with(ResponseTemplate::new(207).set_body_string(event_report_xml(ics)))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(412))
        .expect(1)
        .mount(&server)
        .await;

    let result = tool(&format!("{}/dav", server.uri()))
        .execute(json!({"action": "update_event", "uid": "abc", "summary": "Brunch"}))
        .await
        .expect("no host error");
    assert!(!result.success);
    let err = result.error.unwrap();
    assert!(err.contains("changed on the server"), "{err}");
    server.verify().await;
}

#[tokio::test]
async fn update_event_refuses_a_recurring_event_without_writing() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:weekly\r\nSUMMARY:Standup\r\n\
        DTSTART:20260901T090000Z\r\nRRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    Mock::given(method("REPORT"))
        .respond_with(ResponseTemplate::new(207).set_body_string(event_report_xml(ics)))
        .mount(&server)
        .await;
    // No PUT is mounted: any write attempt fails the test.

    let result = tool(&format!("{}/dav", server.uri()))
        .execute(json!({"action": "update_event", "uid": "weekly", "summary": "Renamed"}))
        .await
        .expect("no host error");
    assert!(!result.success);
    assert!(result.error.unwrap().contains("every occurrence"));
}

#[tokio::test]
async fn update_event_with_no_changes_is_refused() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:abc\r\nSUMMARY:Lunch\r\n\
        DTSTART:20260904T120000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    Mock::given(method("REPORT"))
        .respond_with(ResponseTemplate::new(207).set_body_string(event_report_xml(ics)))
        .mount(&server)
        .await;

    let result = tool(&format!("{}/dav", server.uri()))
        .execute(json!({"action": "update_event", "uid": "abc"}))
        .await
        .expect("no host error");
    assert!(!result.success);
    assert!(result.error.unwrap().contains("no changes supplied"));
}

#[tokio::test]
async fn delete_event_sends_if_match() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:abc\r\nSUMMARY:Lunch\r\n\
        DTSTART:20260904T120000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    Mock::given(method("REPORT"))
        .respond_with(ResponseTemplate::new(207).set_body_string(event_report_xml(ics)))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(header("if-match", "\"etag-1\""))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let result = tool(&format!("{}/dav", server.uri()))
        .execute(json!({"action": "delete_event", "uid": "abc"}))
        .await
        .expect("no host error");
    assert!(result.success, "unexpected error: {:?}", result.error);
    let data = result.output.data().expect("structured output");
    assert_eq!(data["deleted"], true);
    assert_eq!(data["summary"], "Lunch");
    server.verify().await;
}

#[tokio::test]
async fn delete_event_refuses_a_recurring_series() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:weekly\r\n\
        DTSTART:20260901T090000Z\r\nRRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    Mock::given(method("REPORT"))
        .respond_with(ResponseTemplate::new(207).set_body_string(event_report_xml(ics)))
        .mount(&server)
        .await;

    let result = tool(&format!("{}/dav", server.uri()))
        .execute(json!({"action": "delete_event", "uid": "weekly"}))
        .await
        .expect("no host error");
    assert!(!result.success);
    assert!(result.error.unwrap().contains("every occurrence"));
}
