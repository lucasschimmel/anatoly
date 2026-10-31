use crate::discovery::is_diagnostic_name;
use crate::{
    fingerprint::{Evidence, EvidenceKind, Patterns},
    html::Facts,
    http::{Page, PublicMetadata, allowed_redirect, display_url},
    technology::{self, Catalog, Technology},
};
use anyhow::Result;
use regex::Regex;
use reqwest::Url;
use serde::Serialize;

pub const DEEP_PATHS: &[&str] = &[
    "php_info.php",
    "php-info.php",
    "phpversion.php",
    "php-version.php",
    "version.php",
    "status.php",
    "diagnostics.php",
    "info",
    "version",
    "status",
    "composer.json",
    "composer.lock",
    "robots.txt",
    "__anatoly_missing__.php",
];

#[derive(Clone, Debug, Serialize)]
pub struct Signal {
    pub category: String,
    pub source: String,
    pub observation: String,
    pub hypothesis: String,
    pub version_hint: Option<String>,
    pub reference: &'static str,
}

pub struct Detector {
    address: Regex,
    catalog: std::sync::Arc<Catalog>,
    php_hint: Regex,
    dynamic_property: Regex,
    null_parameter: Regex,
    robot: Regex,
    json_version: Regex,
}

#[derive(Default)]
pub struct Findings {
    pub html_limited: bool,
    pub evidence: Vec<Evidence>,
    pub signals: Vec<Signal>,
    pub links: Vec<String>,
    pub technologies: Vec<Technology>,
}

impl Detector {
    pub fn new() -> Result<Self> {
        Ok(Self {
            address: Regex::new(r"(?is)<address\b[^>]*>(.*?)</address>")?,
            catalog: Catalog::shared_builtin()?,
            php_hint: Regex::new(r"(?i)\bPHP\s*[/ ]?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)")?,
            dynamic_property: Regex::new(
                r"(?is)deprecated\s*:?.{0,80}creation of dynamic property.{0,180}is deprecated",
            )?,
            null_parameter: Regex::new(
                r"(?is)deprecated\s*:?.{0,160}passing null to parameter.{0,180}is deprecated",
            )?,
            robot: Regex::new(r"(?im)^\s*(?:allow|disallow)\s*:\s*(/[^\s#]{1,512})")?,
            json_version: Regex::new(r"(?i)^\d+\.\d+\.\d+(?:[-+~]?[a-z0-9][a-z0-9.+~_-]*)?$")?,
        })
    }

    pub fn metadata(
        &self,
        data: &PublicMetadata,
        patterns: &Patterns,
    ) -> (Vec<Evidence>, Vec<Signal>) {
        self.metadata_with_catalog(data, patterns, None)
    }

    pub fn catalog(&self) -> std::sync::Arc<Catalog> {
        std::sync::Arc::clone(&self.catalog)
    }

    pub fn metadata_with_catalog(
        &self,
        data: &PublicMetadata,
        patterns: &Patterns,
        catalog: Option<&Catalog>,
    ) -> (Vec<Evidence>, Vec<Signal>) {
        let catalog = catalog.unwrap_or(&self.catalog);
        let url = display_url(&data.url);
        let mut proofs = vec![];
        let mut signals = vec![];
        for (name, value) in &data.headers {
            if !matches!(
                name.as_str(),
                "server"
                    | "x-powered-by"
                    | "x-php-version"
                    | "php-version"
                    | "x-runtime"
                    | "x-runtime-version"
                    | "x-generator"
            ) {
                continue;
            }
            let label = match name.as_str() {
                "x-powered-by" => "X-Powered-By",
                "server" => "Server",
                other => other,
            };
            let source = format!("{url} [{label}]");
            let exact = if matches!(name.as_str(), "x-php-version" | "php-version") {
                patterns.named_version(value, &source, EvidenceKind::Header)
            } else {
                patterns.header_evidence(value, &source)
            };
            let hint_text = if matches!(name.as_str(), "x-php-version" | "php-version") {
                format!("PHP/{value}")
            } else {
                value.clone()
            };
            if exact.is_empty()
                && let Some(c) = self.php_hint.captures(&hint_text)
            {
                signals.push(signal(
                    "partial_version",
                    &source,
                    "PHP branch mentioned in a header",
                    "Partial declaration; patch level is not known.",
                    Some(if c[1].matches('.').count() == 1 {
                        format!("{}.x", &c[1])
                    } else {
                        format!("{} (unverified mention)", &c[1])
                    }),
                    "https://www.php.net/manual/en/ini.core.php",
                ));
            }
            proofs.extend(exact);
        }
        for cookie in &data.cookies {
            signals.push(signal("cookie", &url, &format!("Set-Cookie {}: {} bytes, {}, Secure={}, HttpOnly={}, SameSite={} (value discarded)", cookie.name, cookie.length, cookie.alphabet, cookie.secure, cookie.http_only, cookie.same_site),
                "PHP or a PHP application is plausible. Cookie names, lengths and alphabets do not identify a PHP release.", None,
                "https://www.php.net/manual/en/session.configuration.php"));
        }
        if data.cached {
            signals.push(signal("cache", &url, "Cache HIT or positive Age header", "Repeated responses may be cached and do not prove independent workers were sampled.", None,
                "https://www.rfc-editor.org/rfc/rfc9111.html"));
        }
        for proof in &mut proofs {
            proof.http_status = Some(data.status);
        }
        signals.extend(technology::application_signals(
            &catalog.metadata(data, false),
        ));
        (proofs, signals)
    }

    pub fn technologies(
        &self,
        data: &PublicMetadata,
        cookies: bool,
        catalog: Option<&Catalog>,
    ) -> Vec<Technology> {
        catalog.unwrap_or(&self.catalog).metadata(data, cookies)
    }

    pub fn body(&self, page: &Page, patterns: &Patterns, catalog: Option<&Catalog>) -> Findings {
        let catalog = catalog.unwrap_or(&self.catalog);
        let url = display_url(&page.url);
        let mut proofs = vec![];
        let mut signals = vec![];
        let facts = Facts::parse(&page.body);
        let mut technologies = vec![];
        technology::merge(&mut technologies, catalog.resources(&facts, page));
        let (html_technologies, fingerprint_limited) = catalog.html(&facts, page);
        technology::merge(&mut technologies, html_technologies);
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&page.body) {
            self.json_runtime(&json, &url, patterns, &mut proofs, 0);
            self.composer(&json, &page.url, &mut signals);
            technology::merge(&mut technologies, catalog.composer(&json, page));
        }
        let name = page.url.path().rsplit('/').next().unwrap_or("");
        if ["phpversion.php", "php-version.php"].contains(&name)
            && self.json_version.is_match(page.body.trim())
        {
            proofs.extend(patterns.named_version(
                page.body.trim(),
                &format!("{url} [PHP version endpoint]"),
                EvidenceKind::StructuredMetadata,
            ));
        }
        if page.status >= 400 {
            for address in self.address.captures_iter(&page.body) {
                let mut found =
                    patterns.header_evidence(&address[1], &format!("{url} [error footer]"));
                for proof in &mut found {
                    proof.kind = EvidenceKind::ErrorDisclosure;
                }
                proofs.extend(found);
            }
        }
        for (values, method) in [
            (&facts.generators, "generator"),
            (&facts.attributions, "attribution"),
        ] {
            for value in values {
                technology::merge(
                    &mut technologies,
                    catalog.declarations(value, &format!("{url} [{method}]"), method, page.status),
                );
            }
        }
        signals.extend(technology::application_signals(&technologies));
        if let Some(c) = self.php_hint.captures(&page.body) {
            signals.push(signal("body_mention", &url, &format!("Page text mentions PHP {}", &c[1]), "This may be documentation, an application requirement or static content; it does not identify the running PHP release.", Some(format!("{} (text hypothesis)", &c[1])), "https://www.php.net/manual/en/security.hiding.php"));
        }
        if self.dynamic_property.is_match(&page.body) {
            signals.push(signal("error_behavior", &url, "Dynamic-property deprecation wording", "If this is a genuine runtime diagnostic, PHP >=8.2 and <9 is plausible. Static text or custom messages can imitate it.", Some(">=8.2,<9 (hypothesis)".into()), "https://wiki.php.net/rfc/deprecate_dynamic_properties"));
        }
        if self.null_parameter.is_match(&page.body) {
            signals.push(signal("error_behavior", &url, "Null-to-non-nullable parameter deprecation wording", "If emitted by the runtime, PHP >=8.1 is plausible. This is not an exact version or a patch check.", Some(">=8.1 (hypothesis)".into()), "https://www.php.net/releases/8.1/en.php"));
        }
        if facts.links.iter().any(|link| {
            link.split('?')
                .next()
                .is_some_and(|s| s.to_ascii_lowercase().ends_with(".php"))
        }) {
            signals.push(signal("extension", &url, "HTML links or form actions use .php paths", "PHP routing is plausible; extensions can be rewritten or served statically. No version can be inferred.", None, "https://www.php.net/manual/en/security.hiding.php"));
        }
        for proof in &mut proofs {
            proof.http_status = Some(page.status);
        }
        Findings {
            html_limited: facts.limited || fingerprint_limited,
            evidence: proofs,
            signals,
            links: self.links_from(&page.url, &facts.links, &page.body),
            technologies,
        }
    }

    fn json_runtime(
        &self,
        json: &serde_json::Value,
        url: &str,
        patterns: &Patterns,
        out: &mut Vec<Evidence>,
        depth: usize,
    ) {
        if depth > 4 {
            return;
        }
        let Some(object) = json.as_object() else {
            return;
        };
        for (key, value) in object {
            let normalized = key.to_ascii_lowercase();
            let source = format!("{url} [JSON:{key}]");
            if matches!(normalized.as_str(), "php_version" | "phpversion") {
                if let Some(text) = value
                    .as_str()
                    .filter(|s| s.len() <= 80 && self.json_version.is_match(s))
                {
                    out.extend(patterns.named_version(
                        text,
                        &source,
                        EvidenceKind::StructuredMetadata,
                    ));
                }
            } else if normalized == "php_version_id" {
                if let Some(id) = value.as_u64().filter(|id| (50000..=999999).contains(id)) {
                    out.extend(patterns.named_version(
                        &format!("{}.{}.{}", id / 10000, id / 100 % 100, id % 100),
                        &source,
                        EvidenceKind::StructuredMetadata,
                    ));
                }
            } else if normalized == "php"
                && let Some(text) = value
                    .get("version")
                    .and_then(|v| v.as_str())
                    .filter(|s| s.len() <= 80 && self.json_version.is_match(s))
            {
                out.extend(patterns.named_version(text, &source, EvidenceKind::StructuredMetadata));
            }
            if matches!(
                normalized.as_str(),
                "runtime" | "environment" | "system" | "php" | "info"
            ) {
                self.json_runtime(value, url, patterns, out, depth + 1);
            }
        }
    }

    fn composer(&self, json: &serde_json::Value, url: &Url, output: &mut Vec<Signal>) {
        let path = url.path();
        if !path.ends_with("/composer.json") && !path.ends_with("/composer.lock") {
            return;
        }
        for pointer in [
            "/require/php",
            "/platform/php",
            "/config/platform/php",
            "/platform-overrides/php",
        ] {
            if let Some(text) = json.pointer(pointer).and_then(|v| v.as_str())
                && text.len() <= 80
                && text
                    .chars()
                    .all(|c| c.is_ascii_digit() || "<>=^~|.* ,!+-".contains(c))
            {
                output.push(signal("composer_constraint", &display_url(url), &format!("Composer {pointer}: {text}"), "Dependency or simulated build-platform constraint; not the current web PHP version.", Some(text.to_owned()),
                        "https://getcomposer.org/doc/articles/composer-platform-dependencies.md"));
            }
        }
    }

    pub fn links(&self, base: &Url, body: &str) -> Vec<String> {
        self.links_from(base, &Facts::parse(body).links, body)
    }

    fn links_from(&self, base: &Url, attributes: &[String], body: &str) -> Vec<String> {
        let mut links = vec![];
        let mut seen = std::collections::HashSet::new();
        let values = attributes.iter().cloned().chain(
            self.robot
                .captures_iter(
                    if base.path().ends_with("/robots.txt") && !body.contains('<') {
                        body
                    } else {
                        ""
                    },
                )
                .map(|c| c[1].to_owned()),
        );
        for value in values {
            let Ok(mut next) = base.join(&value.replace("&amp;", "&")) else {
                continue;
            };
            next.set_query(None);
            next.set_fragment(None);
            let name = next
                .path()
                .rsplit('/')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            if allowed_redirect(base, &next) && is_diagnostic_name(&name) {
                let display = display_url(&next);
                if seen.insert(display.clone()) {
                    links.push(display);
                }
            }
        }
        links
    }
}

pub(crate) fn signal(
    category: &str,
    source: &str,
    observation: &str,
    hypothesis: &str,
    version_hint: Option<String>,
    reference: &'static str,
) -> Signal {
    Signal {
        category: category.into(),
        source: source.into(),
        observation: observation.into(),
        hypothesis: hypothesis.into(),
        version_hint,
        reference,
    }
}

pub fn merge_signals(output: &mut Vec<Signal>, signals: Vec<Signal>) {
    for signal in signals {
        if output.len() == 64 {
            break;
        }
        if !output.iter().any(|s| {
            s.category == signal.category
                && s.source == signal.source
                && s.observation == signal.observation
        }) {
            output.push(signal);
        }
    }
}
