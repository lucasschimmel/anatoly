use anyhow::{Context, Result, bail};
use reqwest::{Certificate, Proxy, Url, blocking::ClientBuilder};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct NetworkPolicy {
    pub connect_timeout: Option<Duration>,
    pub target_timeout: Option<Duration>,
    pub max_redirects: usize,
    pub https_only: bool,
    pub allow_hosts: Vec<String>,
    pub exclude_paths: Vec<String>,
    pub proxy: Option<String>,
    pub no_proxy: bool,
    pub ca_pem: Option<Vec<u8>>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            connect_timeout: None,
            target_timeout: None,
            max_redirects: 5,
            https_only: false,
            allow_hosts: vec![],
            exclude_paths: vec![],
            proxy: None,
            no_proxy: false,
            ca_pem: None,
        }
    }
}

impl NetworkPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.max_redirects > 10 {
            bail!("Maximum redirects must be between 0 and 10");
        }
        if self.proxy.is_some() && self.no_proxy {
            bail!("--proxy and --no-proxy cannot be combined");
        }
        if let Some(value) = &self.proxy {
            let proxy = crate::http::validate_url(value).context("Invalid HTTP(S) proxy")?;
            if proxy.query().is_some() || proxy.path() != "/" {
                bail!("Proxy URLs cannot contain query values or paths");
            }
            Proxy::all(proxy.as_str()).context("Invalid proxy configuration")?;
        }
        for host in &self.allow_hosts {
            if normalize_host(host)? != *host {
                bail!("Allowed hosts must be normalized hostnames");
            }
        }
        for path in &self.exclude_paths {
            if !path.starts_with('/') || path.contains(['?', '#', '\\']) {
                bail!(
                    "Excluded paths must start with / and contain no query, fragment or backslash"
                );
            }
        }
        if let Some(pem) = &self.ca_pem {
            if pem.len() > 1_048_576 || String::from_utf8_lossy(pem).contains("PRIVATE KEY") {
                bail!("CA input must contain public certificates only, at most 1 MiB");
            }
            Certificate::from_pem(pem).context("Invalid public PEM CA certificate")?;
        }
        Ok(())
    }

    pub fn configure(&self, mut builder: ClientBuilder) -> Result<ClientBuilder> {
        self.validate()?;
        builder = builder.https_only(self.https_only);
        if self.no_proxy {
            builder = builder.no_proxy();
        }
        if let Some(proxy) = &self.proxy {
            builder = builder.proxy(Proxy::all(proxy).context("Invalid proxy configuration")?);
        }
        if let Some(pem) = &self.ca_pem {
            builder = builder.add_root_certificate(
                Certificate::from_pem(pem).context("Invalid public PEM CA certificate")?,
            );
        }
        Ok(builder)
    }

    pub fn permits(&self, url: &Url) -> bool {
        (!self.https_only || url.scheme() == "https")
            && (self.allow_hosts.is_empty()
                || url
                    .host_str()
                    .is_some_and(|h| self.allow_hosts.iter().any(|a| a == h)))
            && !self.excluded(url)
    }

    pub fn excluded(&self, url: &Url) -> bool {
        let canonical = canonical_path(url.path()).to_ascii_lowercase();
        if !self.exclude_paths.is_empty() && canonical.contains('%') {
            return true;
        }
        self.exclude_paths
            .iter()
            .any(|prefix| canonical.starts_with(&canonical_path(prefix).to_ascii_lowercase()))
    }
}

pub fn normalize_host(value: &str) -> Result<String> {
    if value.contains(':') && !(value.starts_with('[') && value.ends_with(']')) {
        bail!("--allow-host does not accept port numbers; bracket IPv6 literals");
    }
    let url = crate::http::validate_url(&format!("https://{value}/"))
        .context("Invalid allowed hostname")?;
    if url.port().is_some() || url.path() != "/" || url.query().is_some() {
        bail!("--allow-host accepts an exact hostname, without port, path or query");
    }
    url.host_str()
        .map(str::to_owned)
        .context("Missing allowed hostname")
}

/// Decode common encoded separators and normalize dot segments before scope comparison.
pub fn canonical_path(value: &str) -> String {
    let mut path = value.to_owned();
    for _ in 0..3 {
        let bytes = path.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%'
                && i + 2 < bytes.len()
                && let (Some(a), Some(b)) = (
                    (bytes[i + 1] as char).to_digit(16),
                    (bytes[i + 2] as char).to_digit(16),
                )
            {
                decoded.push((a * 16 + b) as u8);
                i += 3;
                continue;
            }
            decoded.push(bytes[i]);
            i += 1;
        }
        let next = String::from_utf8_lossy(&decoded).replace('\\', "/");
        if next == path {
            break;
        }
        path = next;
    }
    let mut segments = vec![];
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            _ => segments.push(segment),
        }
    }
    format!("/{}", segments.join("/"))
}
