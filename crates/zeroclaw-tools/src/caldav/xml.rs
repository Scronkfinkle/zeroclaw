//! WebDAV `multistatus` parsing, and the request bodies CalDAV needs.
//!
//! Servers vary in how they spell namespaces (`d:`, `D:`, `dav:`, default-ns),
//! so matching is done on the local name after stripping any prefix rather than
//! on the literal qualified name. Namespace *values* are not validated; the
//! element set here is unambiguous by local name in a DAV response.

use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};

/// One `<response>` from a `multistatus` document.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DavResponse {
    pub href: String,
    pub etag: Option<String>,
    pub displayname: Option<String>,
    /// `calendar-data`, when the request asked for it.
    pub calendar_data: Option<String>,
    /// `current-user-principal`/`calendar-home-set` inner `href`, when present.
    pub principal_href: Option<String>,
    pub calendar_home: Option<String>,
    /// `calendar-color`, when the server reports one.
    pub color: Option<String>,
    /// True when `resourcetype` contains `calendar`.
    pub is_calendar: bool,
    /// Component names from `supported-calendar-component-set`.
    pub supported_components: Vec<String>,
    /// The `status` line, e.g. `HTTP/1.1 404 Not Found`.
    pub status: Option<String>,
}

/// Strip any namespace prefix, lowercase the local name.
fn local_name(raw: &[u8]) -> String {
    let name = String::from_utf8_lossy(raw);
    let local = name.rsplit(':').next().unwrap_or(&name);
    local.to_ascii_lowercase()
}

/// Parse a WebDAV `multistatus` document.
///
/// Returns an error only when the XML itself is malformed. An empty document
/// yields an empty vector, which callers treat as "nothing matched" rather than
/// as a failure.
pub fn parse_multistatus(body: &str) -> anyhow::Result<Vec<DavResponse>> {
    let mut reader = Reader::from_str(body);
    let config = reader.config_mut();
    // A truncated or unbalanced document must be an error, not a silently
    // empty result: an empty vector means "nothing matched", and conflating
    // the two would report a parse failure as "no calendars".
    config.check_end_names = true;

    let mut responses = Vec::new();
    let mut current: Option<DavResponse> = None;
    // Element path by local name, so a nested <href> can be attributed to the
    // property that contains it rather than to the response itself.
    let mut path: Vec<String> = Vec::new();
    // Character data for the element currently open. quick-xml reports an
    // entity reference as its own event, so `Ana &amp; Bob` arrives as three
    // events; accumulating (rather than assigning per event) is what keeps the
    // value whole.
    let mut text_acc = String::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = local_name(e.name().as_ref());
                if name == "response" {
                    current = Some(DavResponse::default());
                    path.clear();
                }
                if name == "calendar"
                    && path.iter().any(|p| p == "resourcetype")
                    && let Some(r) = current.as_mut()
                {
                    r.is_calendar = true;
                }
                path.push(name);
                text_acc.clear();
            }
            Ok(Event::Empty(e)) => {
                let name = local_name(e.name().as_ref());
                // Self-closing elements carry meaning by presence alone:
                // <C:calendar/> inside <resourcetype>, <C:comp name="VEVENT"/>.
                if let Some(r) = current.as_mut() {
                    if name == "calendar" && path.iter().any(|p| p == "resourcetype") {
                        r.is_calendar = true;
                    }
                    if name == "comp"
                        && let Some(attr) = e
                            .attributes()
                            .flatten()
                            .find(|a| local_name(a.key.as_ref()) == "name")
                        && let Ok(v) = attr.normalized_value(XmlVersion::Implicit1_0)
                    {
                        r.supported_components.push(v.to_string());
                    }
                }
            }
            Ok(Event::Text(e)) => {
                // Decode the transport encoding, then resolve any entities the
                // reader left inline. Undecodable bytes are skipped rather than
                // surfaced half-parsed.
                if let Ok(decoded) = e.decode() {
                    match quick_xml::escape::unescape(&decoded) {
                        Ok(text) => text_acc.push_str(&text),
                        Err(_) => text_acc.push_str(&decoded),
                    }
                }
            }
            Ok(Event::CData(e)) => {
                // CDATA is literal: no entity resolution.
                if let Ok(decoded) = e.decode() {
                    text_acc.push_str(&decoded);
                }
            }
            Ok(Event::GeneralRef(e)) => {
                // A standalone entity reference between text runs.
                if let Ok(decoded) = e.decode()
                    && let Ok(resolved) = quick_xml::escape::unescape(&format!("&{decoded};"))
                {
                    text_acc.push_str(&resolved);
                }
            }
            Ok(Event::End(e)) => {
                let name = local_name(e.name().as_ref());
                let text = std::mem::take(&mut text_acc);
                let trimmed = text.trim();
                if !trimmed.is_empty()
                    && let Some(r) = current.as_mut()
                {
                    assign_text(r, &path, trimmed.to_string());
                }
                if name == "response"
                    && let Some(r) = current.take()
                {
                    responses.push(r);
                }
                if path.last().map(String::as_str) == Some(name.as_str()) {
                    path.pop();
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                anyhow::bail!("malformed WebDAV XML response: {e}");
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(responses)
}

fn assign_text(r: &mut DavResponse, path: &[String], text: String) {
    let Some(leaf) = path.last().map(String::as_str) else {
        return;
    };
    let in_ = |p: &str| path.iter().any(|x| x == p);

    match leaf {
        // An <href> means different things depending on its parent property.
        "href" => {
            if in_("current-user-principal") {
                r.principal_href = Some(text);
            } else if in_("calendar-home-set") {
                r.calendar_home = Some(text);
            } else if in_("owner") {
                // Ignore: not a resource locator we act on.
            } else if r.href.is_empty() {
                r.href = text;
            }
        }
        "getetag" => r.etag = Some(text),
        "displayname" => r.displayname = Some(text),
        "calendar-data" => r.calendar_data = Some(text),
        "calendar-color" => r.color = Some(text),
        "status" => r.status = Some(text),
        _ => {}
    }
}

/// `PROPFIND` body discovering the principal URL for the authenticated user.
pub const PROPFIND_CURRENT_USER_PRINCIPAL: &str = concat!(
    r#"<?xml version="1.0" encoding="utf-8"?>"#,
    r#"<d:propfind xmlns:d="DAV:"><d:prop>"#,
    r#"<d:current-user-principal/>"#,
    r#"</d:prop></d:propfind>"#
);

/// `PROPFIND` body discovering the calendar home collection for a principal.
pub const PROPFIND_CALENDAR_HOME: &str = concat!(
    r#"<?xml version="1.0" encoding="utf-8"?>"#,
    r#"<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop>"#,
    r#"<c:calendar-home-set/>"#,
    r#"</d:prop></d:propfind>"#
);

/// `PROPFIND` body listing calendar collections and their metadata.
pub const PROPFIND_CALENDAR_LIST: &str = concat!(
    r#"<?xml version="1.0" encoding="utf-8"?>"#,
    r#"<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav" "#,
    r#"xmlns:i="http://apple.com/ns/ical/"><d:prop>"#,
    r#"<d:resourcetype/><d:displayname/><i:calendar-color/>"#,
    r#"<c:supported-calendar-component-set/>"#,
    r#"</d:prop></d:propfind>"#
);

/// `calendar-query` REPORT body for a time range.
///
/// When `expand` is set, the server is asked to expand recurring events into
/// concrete occurrences (RFC 4791 §9.6.5) so no RRULE engine or timezone
/// database is needed on this side. Servers that do not implement `expand`
/// reject the report, and the caller retries with `expand = false`.
///
/// `start` and `end` must already be in iCalendar UTC form (`YYYYMMDDTHHMMSSZ`).
pub fn calendar_query_body(start: &str, end: &str, expand: bool) -> String {
    let calendar_data = if expand {
        format!(r#"<c:calendar-data><c:expand start="{start}" end="{end}"/></c:calendar-data>"#)
    } else {
        "<c:calendar-data/>".to_string()
    };
    format!(
        concat!(
            r#"<?xml version="1.0" encoding="utf-8"?>"#,
            r#"<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">"#,
            r#"<d:prop><d:getetag/>{}</d:prop>"#,
            r#"<c:filter><c:comp-filter name="VCALENDAR">"#,
            r#"<c:comp-filter name="VEVENT">"#,
            r#"<c:time-range start="{}" end="{}"/>"#,
            r#"</c:comp-filter></c:comp-filter></c:filter>"#,
            r#"</c:calendar-query>"#
        ),
        calendar_data, start, end
    )
}

/// `calendar-multiget`-style REPORT body fetching one event by UID.
pub fn calendar_query_by_uid_body(uid: &str) -> String {
    format!(
        concat!(
            r#"<?xml version="1.0" encoding="utf-8"?>"#,
            r#"<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">"#,
            r#"<d:prop><d:getetag/><c:calendar-data/></d:prop>"#,
            r#"<c:filter><c:comp-filter name="VCALENDAR">"#,
            r#"<c:comp-filter name="VEVENT">"#,
            r#"<c:prop-filter name="UID">"#,
            r#"<c:text-match collation="i;octet">{}</c:text-match>"#,
            r#"</c:prop-filter>"#,
            r#"</c:comp-filter></c:comp-filter></c:filter>"#,
            r#"</c:calendar-query>"#
        ),
        escape_xml(uid)
    )
}

/// Escape the five XML predefined entities.
pub fn escape_xml(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_current_user_principal() {
        let body = r#"<?xml version="1.0"?>
        <d:multistatus xmlns:d="DAV:">
          <d:response>
            <d:href>/dav/</d:href>
            <d:propstat><d:prop>
              <d:current-user-principal><d:href>/dav/principals/user/me/</d:href></d:current-user-principal>
            </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
          </d:response>
        </d:multistatus>"#;
        let responses = parse_multistatus(body).expect("parses");
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].href, "/dav/");
        assert_eq!(
            responses[0].principal_href.as_deref(),
            Some("/dav/principals/user/me/")
        );
    }

    #[test]
    fn nested_href_is_not_mistaken_for_the_response_href() {
        let body = r#"<d:multistatus xmlns:d="DAV:"><d:response>
            <d:href>/dav/</d:href>
            <d:propstat><d:prop><d:current-user-principal>
              <d:href>/principals/me/</d:href>
            </d:current-user-principal></d:prop></d:propstat>
        </d:response></d:multistatus>"#;
        let r = &parse_multistatus(body).expect("parses")[0];
        assert_eq!(r.href, "/dav/", "response href must win");
        assert_eq!(r.principal_href.as_deref(), Some("/principals/me/"));
    }

    #[test]
    fn parses_calendar_home_set() {
        let body = r#"<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
          <d:response><d:href>/principals/me/</d:href><d:propstat><d:prop>
            <c:calendar-home-set><d:href>/dav/calendars/user/me/</d:href></c:calendar-home-set>
          </d:prop></d:propstat></d:response></d:multistatus>"#;
        let r = &parse_multistatus(body).expect("parses")[0];
        assert_eq!(r.calendar_home.as_deref(), Some("/dav/calendars/user/me/"));
    }

    #[test]
    fn detects_calendar_collections_and_skips_plain_ones() {
        let body = r#"<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
          <d:response><d:href>/cal/home/</d:href><d:propstat><d:prop>
            <d:resourcetype><d:collection/></d:resourcetype>
            <d:displayname>Home collection</d:displayname>
          </d:prop></d:propstat></d:response>
          <d:response><d:href>/cal/home/work/</d:href><d:propstat><d:prop>
            <d:resourcetype><d:collection/><c:calendar/></d:resourcetype>
            <d:displayname>Work</d:displayname>
          </d:prop></d:propstat></d:response>
        </d:multistatus>"#;
        let responses = parse_multistatus(body).expect("parses");
        assert_eq!(responses.len(), 2);
        assert!(!responses[0].is_calendar);
        assert!(responses[1].is_calendar);
        assert_eq!(responses[1].displayname.as_deref(), Some("Work"));
    }

    #[test]
    fn reads_supported_component_set() {
        let body = r#"<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
          <d:response><d:href>/c/</d:href><d:propstat><d:prop>
            <c:supported-calendar-component-set>
              <c:comp name="VEVENT"/><c:comp name="VTODO"/>
            </c:supported-calendar-component-set>
          </d:prop></d:propstat></d:response></d:multistatus>"#;
        let r = &parse_multistatus(body).expect("parses")[0];
        assert_eq!(r.supported_components, vec!["VEVENT", "VTODO"]);
    }

    #[test]
    fn parses_etag_and_calendar_data() {
        let body = r#"<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
          <d:response><d:href>/cal/e1.ics</d:href><d:propstat><d:prop>
            <d:getetag>"abc123"</d:getetag>
            <c:calendar-data>BEGIN:VCALENDAR
END:VCALENDAR</c:calendar-data>
          </d:prop></d:propstat></d:response></d:multistatus>"#;
        let r = &parse_multistatus(body).expect("parses")[0];
        assert_eq!(r.etag.as_deref(), Some("\"abc123\""));
        assert!(
            r.calendar_data
                .as_deref()
                .unwrap()
                .contains("BEGIN:VCALENDAR")
        );
    }

    #[test]
    fn namespace_prefix_spelling_does_not_matter() {
        // Uppercase prefix, and a default-namespace document. Both must parse.
        let upper = r#"<D:multistatus xmlns:D="DAV:"><D:response>
            <D:href>/a/</D:href></D:response></D:multistatus>"#;
        assert_eq!(parse_multistatus(upper).expect("parses")[0].href, "/a/");

        let default_ns = r#"<multistatus xmlns="DAV:"><response>
            <href>/b/</href></response></multistatus>"#;
        assert_eq!(
            parse_multistatus(default_ns).expect("parses")[0].href,
            "/b/"
        );
    }

    #[test]
    fn malformed_xml_is_an_error_not_a_silent_empty_result() {
        // A mismatched end tag: the response is corrupt, and reporting it as
        // "no calendars" would be indistinguishable from an empty account.
        let err = parse_multistatus("<d:multistatus><a></b></d:multistatus>").unwrap_err();
        assert!(err.to_string().contains("malformed WebDAV XML"), "{err}");
    }

    #[test]
    fn empty_document_yields_no_responses() {
        assert!(parse_multistatus("").expect("parses").is_empty());
    }

    #[test]
    fn escaped_entities_are_decoded() {
        let body = r#"<d:multistatus xmlns:d="DAV:"><d:response>
            <d:href>/a/</d:href><d:propstat><d:prop>
            <d:displayname>Ana &amp; Bob &lt;work&gt;</d:displayname>
            </d:prop></d:propstat></d:response></d:multistatus>"#;
        let r = &parse_multistatus(body).expect("parses")[0];
        assert_eq!(r.displayname.as_deref(), Some("Ana & Bob <work>"));
    }

    #[test]
    fn calendar_query_body_includes_expand_only_when_requested() {
        let with = calendar_query_body("20260901T000000Z", "20260908T000000Z", true);
        assert!(with.contains(r#"<c:expand start="20260901T000000Z" end="20260908T000000Z"/>"#));
        assert!(with.contains(r#"<c:time-range start="20260901T000000Z""#));

        let without = calendar_query_body("20260901T000000Z", "20260908T000000Z", false);
        assert!(!without.contains("expand"));
        assert!(without.contains("<c:calendar-data/>"));
    }

    #[test]
    fn uid_query_escapes_xml_specials() {
        let body = calendar_query_by_uid_body("a&b<c>");
        assert!(body.contains("a&amp;b&lt;c&gt;"));
        assert!(!body.contains("a&b<c>"));
    }

    #[test]
    fn escape_xml_covers_all_five_entities() {
        assert_eq!(escape_xml(r#"&<>"'"#), "&amp;&lt;&gt;&quot;&apos;");
    }
}
