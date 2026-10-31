use crate::policy::{PhpVersion, VersionStatus, classify};
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

pub struct Patterns {
    header: Regex,
    info_version: Regex,
    rows: Regex,
    cells: Regex,
    tags: Regex,
    info_heading: Regex,
}

impl Patterns {
    pub fn new() -> Result<Self> {
        Ok(Self {
            header: Regex::new(
                r"(?i)\bPHP\s*[/ ]\s*(\d+)\.(\d+)\.(\d+)(?:[-~]?([a-zA-Z][a-zA-Z0-9]*))?",
            )?,
            info_version: Regex::new(
                r"(?i)\bPHP Version\s*(?:=>\s*)?(\d+)\.(\d+)\.(\d+)(?:[-~]?([a-zA-Z][a-zA-Z0-9]*))?",
            )?,
            rows: Regex::new(r"(?is)<tr\b[^>]*>(.*?)</tr>")?,
            cells: Regex::new(r"(?is)<t[dh]\b[^>]*>(.*?)</t[dh]>")?,
            tags: Regex::new(r"(?s)<[^>]*>")?,
            info_heading: Regex::new(
                r"(?is)<(?:h1|title)\b[^>]*>\s*PHP\s+(?:Version\s+)?[0-9]+\.[0-9]+\.[0-9]+",
            )?,
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

    fn text(&self, html: &str) -> String {
        self.tags
            .replace_all(html, " ")
            .replace("&nbsp;", " ")
            .replace("&#039;", "'")
            .replace("&quot;", "\"")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Only interpret a body as phpinfo when its characteristic diagnostic markers coexist.
    pub fn phpinfo(&self, body: &str, source: &str) -> (Vec<Evidence>, Vec<Directive>) {
        let lower = body.to_ascii_lowercase();
        let markers = [
            "php credits",
            "configuration",
            "server api",
            "php api",
            "zend extension",
            "php extension",
        ];
        let plain_info = lower.trim_start().starts_with("phpinfo()")
            || (!lower.contains('<') && lower.trim_start().starts_with("php version"));
        if (!self.info_heading.is_match(body) && !plain_info)
            || !lower.contains("php version")
            || markers.iter().filter(|m| lower.contains(**m)).count() < 2
        {
            return (vec![], vec![]);
        }
        let versions = self.versions(&self.info_version, &self.text(body), source);
        let names = [
            "session.upload_progress.enabled",
            "memory_limit",
            "post_max_size",
            "upload_max_filesize",
            "display_errors",
            "server api",
        ];
        let mut directives = vec![];
        for row in self.rows.captures_iter(body) {
            let cells: Vec<_> = self
                .cells
                .captures_iter(&row[1])
                .map(|c| self.text(&c[1]))
                .collect();
            if cells.len() >= 2 && names.contains(&cells[0].to_ascii_lowercase().as_str()) {
                directives.push(Directive {
                    source: source.to_owned(),
                    name: cells[0].to_ascii_lowercase(),
                    local_value: cells[1].chars().take(120).collect(),
                    master_value: cells.get(2).map(|s| s.chars().take(120).collect()),
                });
            }
        }
        (versions, directives)
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
