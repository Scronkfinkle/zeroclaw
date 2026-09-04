//! Live CalDAV tests against a real server.
//!
//! These require real credentials and are marked `#[ignore]`. Run with:
//!
//! ```bash
//! ZEROCLAW_TEST_CALDAV_BASE_URL="https://caldav.fastmail.com/dav/" \
//! ZEROCLAW_TEST_CALDAV_USERNAME="you@fastmail.com" \
//! ZEROCLAW_TEST_CALDAV_PASSWORD="app-password" \
//!   cargo test --test live caldav -- --ignored --nocapture
//! ```
//!
//! The read tests are safe to run against a real account. The write test
//! creates an event, updates it, and deletes it again, so point it at a
//! calendar you do not mind being touched.

use std::sync::Arc;

use serde_json::json;
use zeroclaw::tools::CalDavTool;
use zeroclaw_api::tool::Tool;
use zeroclaw_config::policy::SecurityPolicy;

const ALL_ACTIONS: &[&str] = &[
    "list_calendars",
    "list_events",
    "get_event",
    "create_event",
    "update_event",
    "delete_event",
];

/// Build a tool from `ZEROCLAW_TEST_CALDAV_*`, or return `None` when the
/// credentials are absent so the test can skip rather than fail.
fn live_tool() -> Option<CalDavTool> {
    let base_url = std::env::var("ZEROCLAW_TEST_CALDAV_BASE_URL").ok()?;
    let username = std::env::var("ZEROCLAW_TEST_CALDAV_USERNAME").ok()?;
    let password = std::env::var("ZEROCLAW_TEST_CALDAV_PASSWORD").ok()?;
    Some(
        CalDavTool::new(
            base_url,
            username,
            password,
            None,
            ALL_ACTIONS.iter().map(|s| (*s).to_string()).collect(),
            false,
            Vec::new(),
            30,
            Arc::new(SecurityPolicy::default()),
        )
        .expect("tool builds"),
    )
}

#[tokio::test]
#[ignore = "requires live CalDAV credentials"]
async fn live_caldav_lists_calendars() {
    let Some(tool) = live_tool() else {
        eprintln!("skipping: ZEROCLAW_TEST_CALDAV_* not set");
        return;
    };

    let result = tool
        .execute(json!({"action": "list_calendars"}))
        .await
        .expect("no host error");
    assert!(result.success, "list_calendars failed: {:?}", result.error);

    let data = result.output.data().expect("structured output");
    eprintln!("calendars: {}", serde_json::to_string_pretty(data).unwrap());
    assert!(
        data["count"].as_u64().unwrap_or(0) > 0,
        "expected at least one calendar"
    );
    // Scheduling collections (schedule-inbox / schedule-outbox) are not
    // calendars and must not be offered as write targets.
    let names: Vec<String> = data["calendars"]
        .as_array()
        .expect("array")
        .iter()
        .map(|c| c["name"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        !names.iter().any(|n| n == "Inbox" || n == "Outbox"),
        "scheduling collections leaked into the calendar list: {names:?}"
    );
}

#[tokio::test]
#[ignore = "requires live CalDAV credentials"]
async fn live_caldav_lists_events() {
    let Some(tool) = live_tool() else {
        eprintln!("skipping: ZEROCLAW_TEST_CALDAV_* not set");
        return;
    };

    // Override to inspect a window known to contain repeating events.
    let mut args = json!({"action": "list_events"});
    if let Ok(start) = std::env::var("ZEROCLAW_TEST_CALDAV_START") {
        args["start"] = json!(start);
    }
    if let Ok(end) = std::env::var("ZEROCLAW_TEST_CALDAV_END") {
        args["end"] = json!(end);
    }

    let result = tool.execute(args).await.expect("no host error");
    assert!(result.success, "list_events failed: {:?}", result.error);

    let data = result.output.data().expect("structured output");
    eprintln!("events: {}", serde_json::to_string_pretty(data).unwrap());
    assert_eq!(
        data["recurrence_expanded"], true,
        "Fastmail supports <C:expand>; falling back would misreport repeating events"
    );
    // Every returned instance must carry a resolved start. An event stored with
    // DURATION instead of DTEND must still report an end.
    for event in data["events"].as_array().expect("array") {
        let summary = event["summary"].as_str().unwrap_or("(none)");
        assert!(
            event["start"].as_str().is_some(),
            "event {summary:?} has no start"
        );
        assert!(
            event["end"].as_str().is_some(),
            "event {summary:?} has no end; DTEND and DURATION both unhandled?"
        );
    }
}

#[tokio::test]
#[ignore = "requires live CalDAV credentials; creates and deletes a real event"]
async fn live_caldav_create_update_delete_roundtrip() {
    let Some(tool) = live_tool() else {
        eprintln!("skipping: ZEROCLAW_TEST_CALDAV_* not set");
        return;
    };

    let created = tool
        .execute(json!({
            "action": "create_event",
            "summary": "ZeroClaw live test (safe to delete)",
            "description": "Created by the CalDAV live test.",
            "location": "Nowhere",
            "start": "2026-12-01T15:00:00Z",
            "duration_minutes": 30,
        }))
        .await
        .expect("no host error");
    assert!(created.success, "create_event failed: {:?}", created.error);
    let uid = created.output.data().expect("data")["uid"]
        .as_str()
        .expect("uid")
        .to_string();
    eprintln!("created uid={uid}");

    // Read it back to prove the write landed and is discoverable by UID.
    let fetched = tool
        .execute(json!({"action": "get_event", "uid": uid}))
        .await
        .expect("no host error");
    assert!(fetched.success, "get_event failed: {:?}", fetched.error);
    let fetched_data = fetched.output.data().expect("data");
    assert_eq!(
        fetched_data["summary"], "ZeroClaw live test (safe to delete)",
        "round-tripped summary should match"
    );
    assert_eq!(fetched_data["location"], "Nowhere");
    assert!(
        fetched_data["etag"].as_str().is_some(),
        "an ETag is required for the conditional update below"
    );

    let updated = tool
        .execute(json!({
            "action": "update_event",
            "uid": uid,
            "summary": "ZeroClaw live test (renamed)",
        }))
        .await
        .expect("no host error");
    assert!(updated.success, "update_event failed: {:?}", updated.error);

    // The untouched location must survive a partial update.
    let after = tool
        .execute(json!({"action": "get_event", "uid": uid}))
        .await
        .expect("no host error");
    let after_data = after.output.data().expect("data");
    assert_eq!(after_data["summary"], "ZeroClaw live test (renamed)");
    assert_eq!(
        after_data["location"], "Nowhere",
        "a partial update must not blank unspecified fields"
    );

    let deleted = tool
        .execute(json!({"action": "delete_event", "uid": uid}))
        .await
        .expect("no host error");
    assert!(deleted.success, "delete_event failed: {:?}", deleted.error);

    // And it should be gone.
    let gone = tool
        .execute(json!({"action": "get_event", "uid": uid}))
        .await
        .expect("no host error");
    assert!(!gone.success, "event should no longer exist after delete");
}
