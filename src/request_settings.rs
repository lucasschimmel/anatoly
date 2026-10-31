use anyhow::{Result, bail};
use reqwest::{
    Url,
    blocking::ClientBuilder,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

/// Sensitive values stay in memory and are deliberately excluded from Debug/reports.
#[derive(Clone, Default)]
pub struct RequestSettings {
    pub headers: HeaderMap,
    pub origin: Option<Url>,
    pub resolves: Vec<(String, IpAddr)>,
}

impl fmt::Debug for RequestSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestSettings")
            .field("header_count", &self.headers.len())
            .field("origin_pinned", &self.origin.is_some())
            .field("resolve_count", &self.resolves.len())
            .finish()
    }
}

impl RequestSettings {
    pub fn insert(&mut self, value: &str) -> Result<()> {
        let (name, value) = value
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("Header must use Name: value syntax; input omitted"))?;
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|_| anyhow::anyhow!("Invalid header name; input omitted"))?;
        if reserved(name.as_str()) {
            bail!(
                "Reserved transport header cannot be overridden; use --resolve for virtual hosts"
            );
        }
        let mut value = HeaderValue::from_str(value.trim())
            .map_err(|_| anyhow::anyhow!("Invalid header value; input omitted"))?;
        value.set_sensitive(true);
        if self.headers.contains_key(&name) {
            bail!("Duplicate request header; input omitted");
        }
        self.headers.insert(name, value);
        self.validate_size()
    }

    pub fn resolve(&mut self, value: &str) -> Result<()> {
        let (host, address) = if value.starts_with('[') {
            let end = value
                .find(']')
                .ok_or_else(|| anyhow::anyhow!("Invalid --resolve host; use HOST:IP"))?;
            (
                &value[..=end],
                value[end + 1..]
                    .strip_prefix(':')
                    .ok_or_else(|| anyhow::anyhow!("Use --resolve HOST:IP"))?,
            )
        } else {
            value
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("Use --resolve HOST:IP; bracket IPv6 addresses"))?
        };
        let host = crate::network::normalize_host(host)?;
        if host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
            bail!("--resolve requires a DNS hostname; IP-literal URL hosts cannot be remapped");
        }
        let address = address
            .strip_prefix('[')
            .and_then(|v| v.strip_suffix(']'))
            .unwrap_or(address);
        let address: IpAddr = address.parse().map_err(|_| {
            anyhow::anyhow!(
                "Invalid --resolve IP address; DNS names and port overrides are not accepted"
            )
        })?;
        if self.resolves.iter().any(|(name, _)| name == &host) || self.resolves.len() >= 32 {
            bail!("Duplicate resolution host or more than 32 overrides");
        }
        self.resolves.push((host, address));
        Ok(())
    }

    fn validate_size(&self) -> Result<()> {
        if self.headers.len() > 32
            || self
                .headers
                .iter()
                .map(|(n, v)| n.as_str().len() + v.as_bytes().len())
                .sum::<usize>()
                > 16_384
        {
            bail!("Request headers exceed 32 fields or 16 KiB");
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<()> {
        self.validate_size()?;
        for name in self.headers.keys() {
            if reserved(name.as_str()) {
                bail!("Reserved transport header cannot be overridden");
            }
            if self.headers.get_all(name).iter().count() != 1 {
                bail!("Duplicate custom request header");
            }
        }
        let mut seen = std::collections::HashSet::new();
        for (host, _) in &self.resolves {
            if host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
                bail!("Resolution override host must be a DNS hostname");
            }
            if crate::network::normalize_host(host)? != *host
                || !seen.insert(host)
                || self.resolves.len() > 32
            {
                bail!("Invalid or duplicate resolution override");
            }
        }
        if !self.headers.is_empty() && self.origin.is_none() {
            bail!("Custom request headers require one pinned target origin");
        }
        if let Some(origin) = &self.origin {
            crate::http::validate_url(origin.as_str())
                .map_err(|_| anyhow::anyhow!("Invalid pinned request origin"))?;
        }
        Ok(())
    }
    pub fn permits(&self, url: &Url) -> bool {
        self.origin
            .as_ref()
            .is_none_or(|origin| origin.origin() == url.origin())
    }
    pub fn configure(&self, mut builder: ClientBuilder) -> Result<ClientBuilder> {
        self.validate()?;
        builder = builder.default_headers(self.headers.clone());
        for (host, ip) in &self.resolves {
            builder = builder.resolve(host, SocketAddr::new(*ip, 0));
        }
        Ok(builder)
    }
}

fn reserved(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "proxy-authorization"
            | "proxy-connection"
            | "trailer"
            | "te"
            | "upgrade"
            | "accept-encoding"
    )
}
