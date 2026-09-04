//! CalDAV calendar discovery (RFC 4791 §6, RFC 5397).
//!
//! The chain is: `PROPFIND` the base URL for `current-user-principal`,
//! `PROPFIND` that principal for `calendar-home-set`, then `PROPFIND Depth: 1`
//! the home for the calendar collections it contains. Each step is skippable
//! when the server answers early, because some servers report the calendar home
//! directly from the base URL.

use super::client::CalDavClient;
use super::xml;

/// A calendar collection the account can reach.
#[derive(Debug, Clone, PartialEq)]
pub struct Calendar {
    /// Absolute URL of the collection.
    pub url: String,
    /// Server-reported href, as returned (usually a path).
    pub href: String,
    pub display_name: Option<String>,
    pub color: Option<String>,
    pub supported_components: Vec<String>,
}

impl Calendar {
    /// Name used when matching a user-supplied `calendar` argument.
    pub fn label(&self) -> &str {
        self.display_name.as_deref().unwrap_or(&self.href)
    }

    /// Whether this collection can hold events. A contacts or tasks collection
    /// advertises a component set without `VEVENT`; writing an event there
    /// would be rejected by the server, so it is filtered out up front.
    fn holds_events(&self) -> bool {
        self.supported_components.is_empty()
            || self
                .supported_components
                .iter()
                .any(|c| c.eq_ignore_ascii_case("VEVENT"))
    }
}

/// Discover every event-capable calendar collection for the account.
pub async fn discover_calendars(client: &CalDavClient) -> anyhow::Result<Vec<Calendar>> {
    let home = discover_calendar_home(client).await?;
    let responses = client
        .propfind(&home, "1", xml::PROPFIND_CALENDAR_LIST)
        .await?;

    let mut calendars: Vec<Calendar> = Vec::new();
    for r in responses {
        if !r.is_calendar || r.href.is_empty() {
            continue;
        }
        let url = client.resolve_href(&r.href)?;
        let calendar = Calendar {
            url,
            href: r.href,
            display_name: r.displayname,
            color: r.color,
            supported_components: r.supported_components,
        };
        if calendar.holds_events() {
            calendars.push(calendar);
        }
    }

    if calendars.is_empty() {
        anyhow::bail!(
            "no event calendars found under {home}. \
             Check caldav.base_url and that the account has at least one calendar"
        );
    }
    Ok(calendars)
}

/// Resolve the calendar home collection URL.
async fn discover_calendar_home(client: &CalDavClient) -> anyhow::Result<String> {
    let base = client.base_url().to_string();

    // Some servers answer calendar-home-set directly at the DAV root, which
    // saves a round trip.
    if let Ok(responses) = client
        .propfind(&base, "0", xml::PROPFIND_CALENDAR_HOME)
        .await
        && let Some(home) = responses.iter().find_map(|r| r.calendar_home.as_deref())
    {
        return client.resolve_href(home);
    }

    let responses = client
        .propfind(&base, "0", xml::PROPFIND_CURRENT_USER_PRINCIPAL)
        .await?;
    let principal = responses
        .iter()
        .find_map(|r| r.principal_href.as_deref())
        .ok_or_else(|| {
            anyhow::Error::msg(format!(
                "CalDAV server at {base} did not report a current-user-principal. \
                 Check that caldav.base_url points at the server's DAV root"
            ))
        })?;
    let principal_url = client.resolve_href(principal)?;

    let responses = client
        .propfind(&principal_url, "0", xml::PROPFIND_CALENDAR_HOME)
        .await?;
    let home = responses
        .iter()
        .find_map(|r| r.calendar_home.as_deref())
        .ok_or_else(|| {
            anyhow::Error::msg(format!(
                "CalDAV principal {principal_url} did not report a calendar-home-set"
            ))
        })?;
    client.resolve_href(home)
}

/// Select the calendar a tool call targets.
///
/// `requested` matches a display name (case-insensitive) or an href/URL
/// substring. With no request, `default_calendar` from config applies; failing
/// that, the first discovered calendar. An unmatched request is an error that
/// lists what is available rather than silently falling back — writing to the
/// wrong calendar is worse than refusing.
pub fn select_calendar<'a>(
    calendars: &'a [Calendar],
    requested: Option<&str>,
    default_calendar: Option<&str>,
) -> anyhow::Result<&'a Calendar> {
    let wanted = requested
        .or(default_calendar)
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let Some(wanted) = wanted else {
        return calendars
            .first()
            .ok_or_else(|| anyhow::Error::msg("no calendars available"));
    };

    if let Some(hit) = calendars.iter().find(|c| {
        c.display_name
            .as_deref()
            .is_some_and(|n| n.eq_ignore_ascii_case(wanted))
            || c.href.eq_ignore_ascii_case(wanted)
            || c.url.eq_ignore_ascii_case(wanted)
    }) {
        return Ok(hit);
    }
    if let Some(hit) = calendars
        .iter()
        .find(|c| c.href.contains(wanted) || c.url.contains(wanted))
    {
        return Ok(hit);
    }

    let available: Vec<&str> = calendars.iter().map(Calendar::label).collect();
    // A requested-but-missing calendar must fail loudly; falling back to the
    // default would write to a calendar the caller did not name.
    anyhow::bail!(
        "no calendar matching '{}'. Available: {}",
        wanted,
        available.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cal(href: &str, name: Option<&str>, comps: &[&str]) -> Calendar {
        Calendar {
            url: format!("https://example.com{href}"),
            href: href.to_string(),
            display_name: name.map(str::to_string),
            color: None,
            supported_components: comps.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn holds_events_filters_non_event_collections() {
        assert!(cal("/a/", None, &["VEVENT"]).holds_events());
        assert!(cal("/a/", None, &["VEVENT", "VTODO"]).holds_events());
        // No advertised set means "unknown"; do not exclude it.
        assert!(cal("/a/", None, &[]).holds_events());
        assert!(!cal("/a/", None, &["VTODO"]).holds_events());
        assert!(!cal("/a/", None, &["VJOURNAL"]).holds_events());
    }

    #[test]
    fn label_prefers_display_name() {
        assert_eq!(cal("/a/", Some("Work"), &[]).label(), "Work");
        assert_eq!(cal("/a/", None, &[]).label(), "/a/");
    }

    #[test]
    fn select_defaults_to_first_when_nothing_requested() {
        let cals = vec![
            cal("/a/", Some("Personal"), &[]),
            cal("/b/", Some("Work"), &[]),
        ];
        assert_eq!(select_calendar(&cals, None, None).unwrap().href, "/a/");
    }

    #[test]
    fn select_uses_config_default_when_no_argument() {
        let cals = vec![
            cal("/a/", Some("Personal"), &[]),
            cal("/b/", Some("Work"), &[]),
        ];
        assert_eq!(
            select_calendar(&cals, None, Some("Work")).unwrap().href,
            "/b/"
        );
    }

    #[test]
    fn explicit_argument_overrides_config_default() {
        let cals = vec![
            cal("/a/", Some("Personal"), &[]),
            cal("/b/", Some("Work"), &[]),
        ];
        assert_eq!(
            select_calendar(&cals, Some("Personal"), Some("Work"))
                .unwrap()
                .href,
            "/a/"
        );
    }

    #[test]
    fn select_matches_display_name_case_insensitively() {
        let cals = vec![cal("/b/", Some("Work"), &[])];
        assert_eq!(
            select_calendar(&cals, Some("wOrK"), None).unwrap().href,
            "/b/"
        );
    }

    #[test]
    fn select_matches_href_and_url() {
        let cals = vec![cal("/calendars/me/work/", Some("Work"), &[])];
        assert!(select_calendar(&cals, Some("/calendars/me/work/"), None).is_ok());
        assert!(
            select_calendar(&cals, Some("https://example.com/calendars/me/work/"), None).is_ok()
        );
        // Substring fallback.
        assert!(select_calendar(&cals, Some("me/work"), None).is_ok());
    }

    #[test]
    fn unmatched_request_errors_and_lists_options_rather_than_falling_back() {
        let cals = vec![
            cal("/a/", Some("Personal"), &[]),
            cal("/b/", Some("Work"), &[]),
        ];
        let err = select_calendar(&cals, Some("Holidays"), Some("Work")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Holidays"), "{msg}");
        assert!(msg.contains("Personal") && msg.contains("Work"), "{msg}");
    }

    #[test]
    fn blank_request_is_treated_as_absent() {
        let cals = vec![cal("/a/", Some("Personal"), &[])];
        assert!(select_calendar(&cals, Some("   "), None).is_ok());
    }
}
