use crate::{
    html::{Facts, element_text, visible},
    policy::{PhpVersion, VersionStatus, classify},
};
use anyhow::Result;
use regex::Regex;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    pub source: String,
    pub version: PhpVersion,
    pub kind: EvidenceKind,
    pub excerpt: String,
    pub http_status: Option<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Header,
    Diagnostic,
    StructuredMetadata,
    ErrorDisclosure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionLevel {
    Declared,
    Corroborated,
    Contradictory,
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct VersionCandidate {
    pub version: PhpVersion,
    pub level: DetectionLevel,
    pub proofs: Vec<Evidence>,
}

pub fn candidates(evidence: &[Evidence]) -> Vec<VersionCandidate> {
    let mut groups: Vec<VersionCandidate> = vec![];
    for proof in evidence {
        if let Some(group) = groups.iter_mut().find(|g| g.version == proof.version) {
            group.proofs.push(proof.clone());
        } else {
            groups.push(VersionCandidate {
                version: proof.version.clone(),
                level: DetectionLevel::Declared,
                proofs: vec![proof.clone()],
            });
        }
    }
    for group in &mut groups {
        let channels: std::collections::HashSet<_> = group.proofs.iter().map(|p| p.kind).collect();
        if channels.len() > 1 {
            group.level = DetectionLevel::Corroborated;
        }
    }
    groups
}

#[derive(Clone, Debug, Serialize)]
pub struct Directive {
    pub source: String,
    pub name: String,
    pub local_value: String,
    pub master_value: Option<String>,
}

/// Only these diagnostic settings are retained; phpinfo can also contain credentials.
pub const DIAGNOSTIC_DIRECTIVES: &[&str] = &[
    "session.upload_progress.enabled",
    "memory_limit",
    "post_max_size",
    "upload_max_filesize",
    "display_errors",
    "server api",
    "fatal_error_backtraces",
    "opcache.enable",
    "opcache.enable_cli",
    "file_uploads",
    "max_file_uploads",
    "max_input_vars",
    "max_input_nesting_level",
    "max_multipart_body_parts",
    "enable_post_data_reading",
    "session.serialize_handler",
];

pub struct Patterns {
    header: Regex,
    info_version: Regex,
    diagnostic_nodes: scraper::Selector,
    rows: scraper::Selector,
    info_heading: Regex,
}

impl Patterns {
    pub fn new() -> Result<Self> {
        Ok(Self {
            header: Regex::new(
                r"(?i)\bPHP\s*[/ ]\s*(\d+)\.(\d+)\.(\d+)(?:[-~]?([a-zA-Z][a-zA-Z0-9]*))?",
            )?,
            info_version: Regex::new(
                r"(?i)^PHP Version\s*(?:=>\s*)?(\d+)\.(\d+)\.(\d+)(?:[-~]?([a-zA-Z][a-zA-Z0-9]*))?",
            )?,
            diagnostic_nodes: scraper::Selector::parse("h1, title, h2, a, p, td, th")
                .map_err(|_| anyhow::anyhow!("Invalid diagnostic selector"))?,
            rows: scraper::Selector::parse("tr")
                .map_err(|_| anyhow::anyhow!("Invalid diagnostic row selector"))?,
            info_heading: Regex::new(r"(?i)^PHP\s+(?:Version\s+)?[0-9]+\.[0-9]+\.[0-9]+")?,
        })
    }

    fn versions(&self, re: &Regex, text: &str, source: &str) -> Vec<Evidence> {
        re.captures_iter(text)
            .filter_map(|c| {
                let version = PhpVersion {
                    major: c[1].parse().ok()?,
                    minor: c[2].parse().ok()?,
                    patch: c[3].parse().ok()?,
                    prerelease: c.get(4).is_some_and(|m| {
                        let suffix = m.as_str().to_ascii_lowercase();
                        suffix.starts_with("rc")
                            || suffix.starts_with("alpha")
                            || suffix.starts_with("beta")
                            || suffix.starts_with("dev")
                    }),
                };
                Some(Evidence {
                    source: source.to_owned(),
                    excerpt: format!("PHP/{version}"),
                    version,
                    kind: if source.ends_with("[phpinfo]") {
                        EvidenceKind::Diagnostic
                    } else {
                        EvidenceKind::Header
                    },
                    http_status: None,
                })
            })
            .collect()
    }

    pub fn header_evidence(&self, value: &str, source: &str) -> Vec<Evidence> {
        self.versions(&self.header, value, source)
    }

    pub fn named_version(&self, value: &str, source: &str, kind: EvidenceKind) -> Vec<Evidence> {
        let mut proofs: Vec<_> = value
            .split(',')
            .flat_map(|value| self.header_evidence(&format!("PHP/{}", value.trim()), source))
            .collect();
        for proof in &mut proofs {
            proof.kind = kind;
        }
        proofs
    }

    /// Plain diagnostics are line-based; HTML evidence comes only from active DOM nodes.
    pub fn phpinfo(&self, body: &str, source: &str) -> (Vec<Evidence>, Vec<Directive>) {
        let lower = body.trim_start().to_ascii_lowercase();
        let plain = lower.starts_with("phpinfo()")
            || (!lower.contains('<') && lower.starts_with("php version"));
        let (mut versions, directives) = if plain {
            self.plain_info(body, source)
        } else {
            self.html_info(body, source)
        };
        for proof in &mut versions {
            proof.kind = EvidenceKind::Diagnostic;
        }
        (versions, directives)
    }

    fn plain_info(&self, body: &str, source: &str) -> (Vec<Evidence>, Vec<Directive>) {
        if diagnostic_marker_count(&body.to_ascii_lowercase()) < 2 {
            return (vec![], vec![]);
        }
        let mut versions = vec![];
        let mut directives = vec![];
        for line in body.lines() {
            let line = line.trim();
            versions.extend(self.versions(&self.info_version, line, source));
            let cells: Vec<_> = line
                .split("=>")
                .map(|cell| cell.trim().to_owned())
                .collect();
            retain_directive(&cells, source, &mut directives);
        }
        if versions.is_empty() {
            return (vec![], vec![]);
        }
        (versions, directives)
    }

    // Keep headings, contextual markers and rows in one DOM-backed recognition pass.
    fn html_info(&self, body: &str, source: &str) -> (Vec<Evidence>, Vec<Directive>) {
        let facts = Facts::parse(body);
        let Some(document) = facts.document else {
            return (vec![], vec![]);
        };
        let mut versions = vec![];
        let mut markers = String::new();
        let mut heading_found = false;
        for node in document
            .select(&self.diagnostic_nodes)
            .filter(|node| visible(*node))
            .take(1024)
        {
            let (text, clipped) = element_text(node);
            if clipped {
                continue;
            }
            if matches!(node.value().name(), "h1" | "title") && self.info_heading.is_match(&text) {
                heading_found = true;
                versions.extend(self.versions(&self.info_version, &text, source));
                if !text.to_ascii_lowercase().starts_with("php version") {
                    versions.extend(self.header_evidence(&text, source));
                }
            }
            markers.push_str(&text.to_ascii_lowercase());
            markers.push('\n');
        }
        if !heading_found || diagnostic_marker_count(&markers) < 2 {
            return (vec![], vec![]);
        }
        let mut directives = vec![];
        for row in document
            .select(&self.rows)
            .filter(|node| visible(*node))
            .take(1024)
        {
            let nodes: Vec<_> = row
                .children()
                .filter_map(scraper::ElementRef::wrap)
                .filter(|node| matches!(node.value().name(), "td" | "th"))
                .take(4)
                .collect();
            if nodes.iter().any(|node| !visible(*node)) {
                continue;
            }
            let cells: Vec<_> = nodes.into_iter().map(|node| element_text(node).0).collect();
            if cells.len() >= 2 && cells[0].eq_ignore_ascii_case("php version") {
                versions.extend(self.versions(
                    &self.info_version,
                    &format!("PHP Version {}", cells[1]),
                    source,
                ));
            }
            retain_directive(&cells, source, &mut directives);
        }
        (versions, directives)
    }
}

fn diagnostic_marker_count(text: &str) -> usize {
    [
        "php credits",
        "configuration",
        "server api",
        "php api",
        "zend extension",
        "php extension",
    ]
    .iter()
    .filter(|marker| text.contains(**marker))
    .count()
}

fn retain_directive(cells: &[String], source: &str, output: &mut Vec<Directive>) {
    let Some(name) = cells.first().map(|value| value.to_ascii_lowercase()) else {
        return;
    };
    if cells.len() >= 2 && DIAGNOSTIC_DIRECTIVES.contains(&name.as_str()) {
        output.push(Directive {
            source: source.to_owned(),
            name,
            local_value: cells[1].chars().take(120).collect(),
            master_value: cells.get(2).map(|value| value.chars().take(120).collect()),
        });
    }
}
pub fn resolve(evidence: &[Evidence]) -> (Option<PhpVersion>, VersionStatus) {
    let Some(first) = evidence.first() else {
        return (None, VersionStatus::Unknown);
    };
    if evidence.iter().any(|e| e.version != first.version) {
        return (None, VersionStatus::Conflicting);
    }
    (Some(first.version.clone()), classify(&first.version))
}
