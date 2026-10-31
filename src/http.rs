use crate::{network::NetworkPolicy, tls_observation::TlsObservation, waf::WafEvidence};
use anyhow::{Context, Result, bail};
use reqwest::{Url, blocking::Client, header::LOCATION};
use serde::Serialize;
use std::{
    io::Read,
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct Limits {
    pub timeout: Duration,
    pub max_requests: usize,
    pub max_body: usize,
    pub delay: Duration,
}

#[derive(Debug, Serialize)]
pub struct Observation {
    pub url: String,
    pub status: u16,
    pub truncated: bool,
    pub redirect_blocked: bool,
    pub cached: bool,
    pub redirect_limited: bool,
    pub scope_blocked: bool,
}

pub struct PublicMetadata {
    pub technology_cookies: Vec<String>,
    pub url: Url,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// Selected security fields, retained in memory only; never export raw values.
    pub security_headers: Vec<(String, String)>,
    pub cookies: Vec<CookieShape>,
    pub cached: bool,
}

pub struct CookieShape {
    pub name: String,
    pub length: usize,
    pub alphabet: &'static str,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: &'static str,
}

pub struct Page {
    pub url: Url,
    pub status: u16,
    pub server: String,
    pub powered_by: String,
    pub body: String,
    pub metadata: PublicMetadata,
}

pub struct Transport {
    fingerprints: Option<std::sync::Arc<crate::fingerprints::Catalog>>,
    client: Client,
    limits: Limits,
    pub requests: usize,
    pub observations: Vec<Observation>,
    pub redirect_metadata: Vec<PublicMetadata>,
    pub tls: Vec<TlsObservation>,
    pub waf: Vec<WafEvidence>,
    policy: NetworkPolicy,
    started: Instant,
}

pub fn validate_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("Use an absolute http:// or https:// URL")?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        bail!("Only HTTP(S) targets with a host are supported");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("Credentials in URLs are not accepted");
    }
    if url.fragment().is_some() {
        bail!("Remove the URL fragment before scanning");
    }
    Ok(url)
}

/// Keep query values out of reports; request URLs are retained only in memory.
pub fn display_url(url: &Url) -> String {
    let mut clean = url.clone();
    clean.set_query(None);
    clean.set_fragment(None);
    clean.to_string()
}

pub fn allowed_redirect(from: &Url, to: &Url) -> bool {
    from.origin() == to.origin() && to.username().is_empty() && to.password().is_none()
}

impl Transport {
    pub fn set_fingerprints(&mut self, catalog: std::sync::Arc<crate::fingerprints::Catalog>) {
        self.fingerprints = Some(catalog);
    }
    pub fn new(limits: Limits) -> Result<Self> {
        Self::with_policy(limits, NetworkPolicy::default())
    }

    pub fn with_policy(limits: Limits, policy: NetworkPolicy) -> Result<Self> {
        let builder = Client::builder()
            .timeout(limits.timeout)
            .connect_timeout(
                policy
                    .connect_timeout
                    .unwrap_or(limits.timeout)
                    .min(limits.timeout),
            )
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .tls_info(true)
            .user_agent(concat!(
                "Anatoly/",
                env!("CARGO_PKG_VERSION"),
                " (PHP security assessment)"
            ));
        let client = policy
            .configure(builder)?
            .build()
            .context("Building HTTP client")?;
        Ok(Self {
            fingerprints: None,
            client,
            limits,
            requests: 0,
            observations: vec![],
            redirect_metadata: vec![],
            tls: vec![],
            waf: vec![],
            policy,
            started: Instant::now(),
        })
    }

    pub fn remaining(&self) -> bool {
        self.requests < self.limits.max_requests && self.time_left().is_ok()
    }

    fn time_left(&self) -> Result<Duration> {
        match self.policy.target_timeout {
            Some(limit) => limit
                .checked_sub(self.started.elapsed())
                .filter(|d| !d.is_zero())
                .context("Target time budget exhausted"),
            None => Ok(Duration::MAX),
        }
    }

    /// All hops share one request budget; body reading is bounded before decoding.
    pub fn get(&mut self, start: &Url) -> Result<Page> {
        let mut url = start.clone();
        let mut redirects = 0;
        loop {
            if !self.policy.permits(&url) {
                bail!("URL is outside the configured scan scope");
            }
            let left = self.time_left()?;
            if !self.remaining() {
                bail!("Request or target time budget exhausted");
            }
            if self.requests > 0 {
                if self.limits.delay >= left {
                    bail!("Target time budget cannot accommodate the next request delay");
                }
                std::thread::sleep(self.limits.delay);
            }
            let request_timeout = self.limits.timeout.min(self.time_left()?);
            self.requests += 1;
            let response = self.client.get(url.clone()).timeout(request_timeout).send()
                .map_err(|_| anyhow::anyhow!("HTTP request failed (DNS, TLS, connection or timeout); verify the target and certificate"))?;
            let status = response.status();
            self.capture_edge(&url, &response);
            let next = if status.is_redirection() {
                response
                    .headers()
                    .get(LOCATION)
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| url.join(s).ok())
            } else {
                None
            };
            let blocked = next.as_ref().is_some_and(|to| !allowed_redirect(&url, to));
            let scope_blocked = next.as_ref().is_some_and(|to| !self.policy.permits(to));
            let redirect_limited = next.is_some() && redirects >= self.policy.max_redirects;
            let server = response
                .headers()
                .get_all("server")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect::<Vec<_>>()
                .join(", ");
            let powered_by = response
                .headers()
                .get_all("x-powered-by")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect::<Vec<_>>()
                .join(", ");
            let metadata = crate::http_metadata::public_metadata(
                &url,
                status.as_u16(),
                response.headers(),
                self.fingerprints.as_deref(),
            );
            let cached = metadata.cached;
            let mut bytes = Vec::new();
            response
                .take((self.limits.max_body + 1) as u64)
                .read_to_end(&mut bytes)
                .context("Reading bounded HTTP response")?;
            let truncated = bytes.len() > self.limits.max_body;
            bytes.truncate(self.limits.max_body);
            self.observations.push(Observation {
                url: display_url(&url),
                status: status.as_u16(),
                truncated,
                redirect_blocked: blocked,
                cached,
                redirect_limited,
                scope_blocked,
            });
            if let Some(next) = next.filter(|_| !blocked && !scope_blocked && !redirect_limited) {
                self.redirect_metadata.push(metadata);
                redirects += 1;
                url = next;
                continue;
            }
            return Ok(Page {
                url,
                status: status.as_u16(),
                server,
                powered_by,
                body: String::from_utf8_lossy(&bytes).into_owned(),
                metadata,
            });
        }
    }

    fn capture_edge(&mut self, url: &Url, response: &reqwest::blocking::Response) {
        if url.scheme() == "https" {
            let tls = crate::tls_observation::inspect(
                url,
                response.extensions().get::<reqwest::tls::TlsInfo>(),
            );
            if !self.tls.contains(&tls) {
                self.tls.push(tls);
            }
        }
        for evidence in crate::waf::inspect(url, response.status().as_u16(), response.headers()) {
            if !self.waf.contains(&evidence) {
                self.waf.push(evidence);
            }
        }
    }
}
