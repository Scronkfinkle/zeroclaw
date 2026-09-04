//! HTTP transport for CalDAV: the WebDAV verbs, auth, and the SSRF guard.
//!
//! `base_url` is operator-supplied, so every request is validated and its DNS
//! answer pinned before the connection is made — the same discipline the
//! `http_request` and `web_fetch` tools apply. Private and loopback addresses
//! are refused unless `caldav.allow_private_hosts` is set, which is what makes
//! a self-hosted server on the local network reachable without opening the
//! default configuration to SSRF.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use reqwest::{Method, StatusCode};

use crate::helpers::domain_guard::{self, Nat64Prefix};
use zeroclaw_infra::net_guard::{PrivateNetworkAccess, ResolvedDestination, normalize_host};

use super::xml::{self, DavResponse};

/// Cap on a single response body. CalDAV responses are text; a server that
/// returns more than this is either misbehaving or hostile.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Outcome of a conditional write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteOutcome {
    Ok {
        etag: Option<String>,
    },
    /// The `If-Match`/`If-None-Match` precondition failed: the resource changed
    /// (or already exists) since the ETag was read.
    PreconditionFailed,
    /// The resource does not exist.
    NotFound,
}

pub struct CalDavClient {
    base_url: String,
    username: String,
    password: String,
    timeout: Duration,
    allow_private_hosts: bool,
    nat64_prefixes: Vec<Nat64Prefix>,
}

impl CalDavClient {
    pub fn new(
        base_url: String,
        username: String,
        password: String,
        timeout_secs: u64,
        allow_private_hosts: bool,
        nat64_prefixes: Vec<String>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            // Normalize *to* a trailing slash, never away from it. `base_url`
            // names a WebDAV collection, and Cyrus (Fastmail) answers PROPFIND
            // on `/dav/` but returns 405 for `/dav`. The slash also makes
            // `Url::join` resolve a relative href inside the collection rather
            // than against its parent.
            base_url: format!("{}/", base_url.trim().trim_end_matches('/')),
            username,
            password,
            // A zero timeout would mean "no timeout" in reqwest, turning a
            // misconfiguration into a hung agent turn.
            timeout: Duration::from_secs(timeout_secs.max(1)),
            allow_private_hosts,
            nat64_prefixes: domain_guard::parse_nat64_prefixes(
                &nat64_prefixes,
                "security.nat64_prefixes",
            )?,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Resolve a possibly-relative href against the configured base URL.
    ///
    /// CalDAV servers return absolute *paths* (`/dav/calendars/…`) far more
    /// often than absolute URLs, and some return full URLs. Both must work.
    pub fn resolve_href(&self, href: &str) -> anyhow::Result<String> {
        let href = href.trim();
        if href.starts_with("http://") || href.starts_with("https://") {
            return Ok(href.to_string());
        }
        let base = reqwest::Url::parse(&self.base_url)
            .map_err(|_| anyhow::Error::msg("caldav.base_url is not a valid URL"))?;
        let joined = base
            .join(href)
            .map_err(|_| anyhow::Error::msg(format!("could not resolve href '{href}'")))?;
        Ok(joined.to_string())
    }

    /// Validate a URL and pin its resolved addresses, then build a client for it.
    ///
    /// Redirects are disabled: following one would let a server bounce the
    /// request to an address the guard already rejected.
    async fn prepare(&self, raw_url: &str) -> anyhow::Result<(reqwest::Client, reqwest::Url)> {
        let mut url = reqwest::Url::parse(raw_url)
            .map_err(|_| anyhow::Error::msg("CalDAV URL is invalid"))?;
        if !url.username().is_empty() || url.password().is_some() {
            anyhow::bail!("CalDAV URL must not embed credentials; use caldav.username/password");
        }
        if !matches!(url.scheme(), "http" | "https") {
            anyhow::bail!("CalDAV URL must use http:// or https://");
        }
        let request_host = url
            .host_str()
            .ok_or_else(|| anyhow::Error::msg("CalDAV URL must include a host"))?;
        let host = normalize_host(request_host)
            .map_err(|_| anyhow::Error::msg("CalDAV URL host is invalid"))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| anyhow::Error::msg("CalDAV URL must include a valid port"))?;

        let addresses = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, port)]
        } else {
            tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|_| anyhow::Error::msg(format!("could not resolve CalDAV host '{host}'")))?
                .collect::<Vec<_>>()
        };

        let access = if self.allow_private_hosts {
            PrivateNetworkAccess::Allow
        } else {
            PrivateNetworkAccess::Deny
        };
        let destination =
            ResolvedDestination::new(&host, port, addresses, access, &self.nat64_prefixes)
                .map_err(|_| {
                    anyhow::Error::msg(format!(
                        "CalDAV host '{host}' was rejected by network policy. \
                         For a server on your own network, set caldav.allow_private_hosts = true"
                    ))
                })?;

        if host.parse::<IpAddr>().is_err() {
            url.set_host(Some(destination.host()))
                .map_err(|_| anyhow::Error::msg("CalDAV URL host is invalid"))?;
        }

        let builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(self.timeout);
        let builder = if destination.host().parse::<IpAddr>().is_ok() {
            builder
        } else {
            builder.resolve_to_addrs(destination.host(), destination.addresses())
        };
        let client = builder
            .build()
            .map_err(|_| anyhow::Error::msg("failed to build CalDAV HTTP client"))?;
        Ok((client, url))
    }

    fn auth_header(&self) -> String {
        format!(
            "Basic {}",
            BASE64.encode(format!("{}:{}", self.username, self.password))
        )
    }

    /// Issue a raw DAV request. Returns status, body, and ETag.
    async fn request(
        &self,
        method: &str,
        url: &str,
        depth: Option<&str>,
        content_type: Option<&str>,
        body: Option<String>,
        if_match: Option<&str>,
        if_none_match: Option<&str>,
    ) -> anyhow::Result<(StatusCode, String, Option<String>)> {
        let (client, parsed) = self.prepare(url).await?;
        let method = Method::from_bytes(method.as_bytes())
            .map_err(|_| anyhow::Error::msg("invalid HTTP method"))?;
        let mut req = client
            .request(method, parsed)
            .header(reqwest::header::AUTHORIZATION, self.auth_header());
        if let Some(depth) = depth {
            req = req.header("Depth", depth);
        }
        if let Some(ct) = content_type {
            req = req.header(reqwest::header::CONTENT_TYPE, ct);
        }
        if let Some(etag) = if_match {
            req = req.header(reqwest::header::IF_MATCH, etag);
        }
        if let Some(etag) = if_none_match {
            req = req.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        if let Some(body) = body {
            req = req.body(body);
        }

        let response = req
            .send()
            .await
            .map_err(|e| anyhow::Error::msg(format!("CalDAV request failed: {e}")))?;
        let status = response.status();
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        let bytes = response
            .bytes()
            .await
            .map_err(|e| anyhow::Error::msg(format!("failed to read CalDAV response: {e}")))?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            anyhow::bail!(
                "CalDAV response exceeded {} bytes; narrow the date range",
                MAX_RESPONSE_BYTES
            );
        }
        let text = String::from_utf8_lossy(&bytes).to_string();
        Ok((status, text, etag))
    }

    /// Map an unsuccessful status to an actionable error.
    fn status_error(status: StatusCode, body: &str, context: &str) -> anyhow::Error {
        let hint = match status {
            StatusCode::UNAUTHORIZED => {
                " — check caldav.username and caldav.password (most providers require an \
                 app-specific password, not your account password)"
            }
            StatusCode::FORBIDDEN => " — the account lacks permission for this calendar",
            StatusCode::NOT_FOUND => " — the calendar or event does not exist",
            _ => "",
        };
        let snippet = crate::util_helpers::truncate_with_ellipsis(body.trim(), 300);
        anyhow::Error::msg(format!("{context}: HTTP {status}{hint}. {snippet}"))
    }

    /// `PROPFIND` returning parsed `multistatus` responses.
    pub async fn propfind(
        &self,
        url: &str,
        depth: &str,
        body: &str,
    ) -> anyhow::Result<Vec<DavResponse>> {
        let (status, text, _) = self
            .request(
                "PROPFIND",
                url,
                Some(depth),
                Some("application/xml; charset=utf-8"),
                Some(body.to_string()),
                None,
                None,
            )
            .await?;
        if !(status.is_success() || status == StatusCode::MULTI_STATUS) {
            return Err(Self::status_error(status, &text, "PROPFIND failed"));
        }
        xml::parse_multistatus(&text)
    }

    /// `REPORT` returning parsed `multistatus` responses.
    ///
    /// `Ok(None)` signals the server rejected the report body itself (as
    /// opposed to failing outright), which is how a missing `<C:expand>`
    /// implementation surfaces. The caller retries unexpanded.
    pub async fn report(
        &self,
        url: &str,
        body: String,
    ) -> anyhow::Result<Option<Vec<DavResponse>>> {
        let (status, text, _) = self
            .request(
                "REPORT",
                url,
                Some("1"),
                Some("application/xml; charset=utf-8"),
                Some(body),
                None,
                None,
            )
            .await?;
        // 400/403/409/501 from a REPORT generally means "I don't support this
        // report body", which for us means `expand` is unavailable.
        if matches!(
            status,
            StatusCode::BAD_REQUEST
                | StatusCode::FORBIDDEN
                | StatusCode::CONFLICT
                | StatusCode::NOT_IMPLEMENTED
        ) {
            return Ok(None);
        }
        if !(status.is_success() || status == StatusCode::MULTI_STATUS) {
            return Err(Self::status_error(status, &text, "calendar REPORT failed"));
        }
        xml::parse_multistatus(&text).map(Some)
    }

    /// `GET` a single calendar object, returning its body and ETag.
    pub async fn get_object(&self, url: &str) -> anyhow::Result<Option<(String, Option<String>)>> {
        let (status, text, etag) = self
            .request("GET", url, None, None, None, None, None)
            .await?;
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(Self::status_error(status, &text, "GET failed"));
        }
        Ok(Some((text, etag)))
    }

    /// `PUT` a calendar object under a conditional header.
    ///
    /// `if_match` guards an update against a concurrent edit; `if_none_match`
    /// of `*` guards a create against clobbering an existing resource. Passing
    /// neither would make a write unconditional, which this tool never does.
    pub async fn put_object(
        &self,
        url: &str,
        ics: String,
        if_match: Option<&str>,
        if_none_match: Option<&str>,
    ) -> anyhow::Result<WriteOutcome> {
        let (status, text, etag) = self
            .request(
                "PUT",
                url,
                None,
                Some("text/calendar; charset=utf-8"),
                Some(ics),
                if_match,
                if_none_match,
            )
            .await?;
        match status {
            StatusCode::PRECONDITION_FAILED => Ok(WriteOutcome::PreconditionFailed),
            StatusCode::NOT_FOUND => Ok(WriteOutcome::NotFound),
            s if s.is_success() => Ok(WriteOutcome::Ok { etag }),
            s => Err(Self::status_error(s, &text, "PUT failed")),
        }
    }

    /// `DELETE` a calendar object under an `If-Match` precondition.
    pub async fn delete_object(
        &self,
        url: &str,
        if_match: Option<&str>,
    ) -> anyhow::Result<WriteOutcome> {
        let (status, text, _) = self
            .request("DELETE", url, None, None, None, if_match, None)
            .await?;
        match status {
            StatusCode::PRECONDITION_FAILED => Ok(WriteOutcome::PreconditionFailed),
            StatusCode::NOT_FOUND => Ok(WriteOutcome::NotFound),
            s if s.is_success() => Ok(WriteOutcome::Ok { etag: None }),
            s => Err(Self::status_error(s, &text, "DELETE failed")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(base: &str) -> CalDavClient {
        // Tests dial a loopback mock server, so private access is allowed here.
        CalDavClient::new(
            base.to_string(),
            "user@example.com".into(),
            "app-password".into(),
            5,
            true,
            Vec::new(),
        )
        .expect("client builds")
    }

    #[test]
    fn auth_header_is_basic_base64() {
        let c = client("https://example.com/dav/");
        // "user@example.com:app-password"
        assert_eq!(
            c.auth_header(),
            format!("Basic {}", BASE64.encode("user@example.com:app-password"))
        );
    }

    #[test]
    fn base_url_always_keeps_a_trailing_slash() {
        // Regression: stripping the slash made Cyrus (Fastmail) answer PROPFIND
        // on the DAV root with 405 Method Not Allowed, so discovery never
        // started. Both spellings must normalize to the collection form.
        assert_eq!(
            client("https://e.com/dav/").base_url(),
            "https://e.com/dav/"
        );
        assert_eq!(client("https://e.com/dav").base_url(), "https://e.com/dav/");
        assert_eq!(
            client("https://e.com/dav///").base_url(),
            "https://e.com/dav/"
        );
    }

    #[test]
    fn relative_href_resolves_inside_the_collection_not_its_parent() {
        // This is the second reason the trailing slash matters: without it,
        // `Url::join` would resolve "work/" against `/dav`'s parent.
        let c = client("https://e.com/dav");
        assert_eq!(
            c.resolve_href("work/").expect("resolves"),
            "https://e.com/dav/work/"
        );
    }

    #[test]
    fn resolve_href_handles_absolute_paths_and_urls() {
        let c = client("https://caldav.example.com/dav/");
        assert_eq!(
            c.resolve_href("/dav/calendars/me/work/").expect("resolves"),
            "https://caldav.example.com/dav/calendars/me/work/"
        );
        assert_eq!(
            c.resolve_href("https://other.example.com/x/")
                .expect("resolves"),
            "https://other.example.com/x/"
        );
    }

    #[tokio::test]
    async fn private_host_is_rejected_when_not_allowed() {
        let c = CalDavClient::new(
            "http://127.0.0.1:8080/dav/".into(),
            "u".into(),
            "p".into(),
            5,
            false,
            Vec::new(),
        )
        .expect("client builds");
        let err = c.prepare("http://127.0.0.1:8080/dav/").await.unwrap_err();
        assert!(
            err.to_string().contains("allow_private_hosts"),
            "error should name the escape hatch: {err}"
        );
    }

    #[tokio::test]
    async fn private_host_is_accepted_when_allowed() {
        let c = client("http://127.0.0.1:8080/dav/");
        assert!(c.prepare("http://127.0.0.1:8080/dav/").await.is_ok());
    }

    #[tokio::test]
    async fn credentials_embedded_in_url_are_refused() {
        let c = client("https://example.com/dav/");
        let err = c
            .prepare("https://user:pass@example.com/dav/")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("must not embed credentials"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn non_http_scheme_is_refused() {
        let c = client("https://example.com/dav/");
        let err = c.prepare("file:///etc/passwd").await.unwrap_err();
        assert!(err.to_string().contains("http://"), "{err}");
    }

    #[test]
    fn zero_timeout_is_clamped_so_requests_cannot_hang_forever() {
        let c = CalDavClient::new(
            "https://e.com".into(),
            "u".into(),
            "p".into(),
            0,
            false,
            vec![],
        )
        .expect("builds");
        assert_eq!(c.timeout, Duration::from_secs(1));
    }

    #[test]
    fn unauthorized_error_points_at_app_passwords() {
        let err = CalDavClient::status_error(StatusCode::UNAUTHORIZED, "nope", "PROPFIND failed");
        assert!(err.to_string().contains("app-specific password"), "{err}");
    }
}
