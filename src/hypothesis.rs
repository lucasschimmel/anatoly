//! Bounded, explainable version proposals. Never inputs to exact evidence or CVE policy.
use crate::{fingerprint::Evidence, recon::Signal, technology::Technology};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

const MAX_HYPOTHESES: usize = 64;
const MAX_SOURCES: usize = 8;
const LIMITATION: &str = "Unverified hypothesis, not installed-version evidence. Markers can be configured, copied, cached or backported. No CVE or patch verdict is derived from it.";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionHint {
    pub range: String,
    pub confidence: Confidence,
    pub reason: String,
    pub reference: String,
}

#[derive(Debug, Serialize)]
pub struct VersionHypothesis {
    pub technology: String,
    pub range: String,
    pub confidence: Confidence,
    pub basis: String,
    pub reasons: Vec<String>,
    pub sources: Vec<String>,
    pub references: Vec<String>,
    pub limitations: Vec<String>,
}

pub fn validate_hint(hint: &VersionHint) -> Result<()> {
    ensure!(valid_range(&hint.range), "Invalid hypothesis version range");
    ensure!(
        !hint.reason.trim().is_empty()
            && hint.reason.len() <= 240
            && !hint.reason.chars().any(char::is_control),
        "Invalid hypothesis reason"
    );
    ensure!(
        hint.reference.len() <= 512 && !hint.reference.chars().any(char::is_control),
        "Hypothesis reference is too long"
    );
    let url = reqwest::Url::parse(&hint.reference)
        .map_err(|_| anyhow::anyhow!("Invalid hypothesis reference"))?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none(),
        "Hypothesis reference must be HTTPS without credentials or query values"
    );
    Ok(())
}

fn valid_range(range: &str) -> bool {
    if range.trim().is_empty()
        || range.len() > 96
        || !range.is_ascii()
        || range.chars().any(char::is_control)
    {
        return false;
    }
    range.replace("||", "|").split('|').all(|alternative| {
        !alternative.trim().is_empty() && alternative.split(',').all(valid_clause)
    })
}

fn valid_clause(clause: &str) -> bool {
    let tokens: Vec<_> = clause.split_whitespace().collect();
    if tokens.is_empty() {
        return false;
    }
    let mut index = 0;
    while index < tokens.len() {
        if tokens.get(index + 1) == Some(&"-") {
            if !plain_release(tokens[index])
                || !tokens.get(index + 2).is_some_and(|v| plain_release(v))
            {
                return false;
            }
            index += 3;
        } else if [">=", "<=", ">", "<", "=", "!=", "^", "~"].contains(&tokens[index]) {
            let Some(next) = tokens.get(index + 1) else {
                return false;
            };
            if !valid_bound(&format!("{}{next}", tokens[index])) {
                return false;
            }
            index += 2;
        } else {
            if !valid_bound(tokens[index]) {
                return false;
            }
            index += 1;
        }
    }
    true
}

fn plain_release(version: &str) -> bool {
    valid_bound(version) && version.bytes().all(|c| c.is_ascii_digit() || c == b'.')
}

fn valid_bound(bound: &str) -> bool {
    let core = bound.trim_start_matches(['<', '>', '=', '!', '^', '~']);
    let op = &bound[..bound.len() - core.len()];
    if !["", ">=", "<=", ">", "<", "=", "!=", "^", "~"].contains(&op) {
        return false;
    }
    let parts: Vec<_> = core.split('.').collect();
    (1..=4).contains(&parts.len())
        && parts.iter().enumerate().all(|(index, part)| {
            if matches!(*part, "x" | "*") {
                index == parts.len() - 1
            } else {
                !part.is_empty() && part.len() <= 6 && part.bytes().all(|c| c.is_ascii_digit())
            }
        })
}

pub(crate) fn infer(
    technologies: &[Technology],
    signals: &[Signal],
    evidence: &[Evidence],
) -> (Vec<VersionHypothesis>, bool) {
    let mut output = Proposals {
        entries: vec![],
        limited: false,
    };
    for technology in technologies {
        if exact_version(technology, evidence) {
            continue;
        }
        for observation in &technology.observations {
            if let Some(hint) = &observation.hypothesis {
                let basis = match observation.method.as_str() {
                    "laravel_template" | "laravel_renderer" => observation.method.as_str(),
                    _ => "pattern",
                };
                output.add(&technology.name, hint, basis, &observation.source);
                if technology.name == "Laravel" && hint.range == ">=12" {
                    output.php_requirement(">=8.2", &observation.source,
                        "If the modern Laravel skeleton hypothesis matches the actual framework, Laravel 12 requires PHP >=8.2. This does not identify the running PHP release.",
                        "https://github.com/laravel/framework/blob/v12.70.2/composer.json", evidence);
                }
            }
            if observation.method == "asset_version_hint" {
                asset_proposal(&mut output, technology, observation);
            }
        }
        for version in &technology.versions {
            if version.split('.').count() == 2 && valid_range(version) {
                let hint = VersionHint {
                    range: format!("{version}.x"),
                    confidence: Confidence::Medium,
                    reason: "Only the major/minor declaration is available; the patch is unknown."
                        .into(),
                    reference: "https://www.php.net/manual/en/security.hiding.php".into(),
                };
                for observation in technology
                    .observations
                    .iter()
                    .filter(|o| o.version.as_ref() == Some(version))
                {
                    output.add(
                        &technology.name,
                        &hint,
                        "partial_declaration",
                        &observation.source,
                    );
                }
            }
        }
    }
    framework_requirements(&mut output, technologies, evidence);
    if evidence.is_empty() {
        for signal in signals {
            let confidence = match signal.category.as_str() {
                "partial_version" => Confidence::Medium,
                "error_behavior" | "composer_constraint" => Confidence::Low,
                _ => continue,
            };
            let Some(raw) = &signal.version_hint else {
                continue;
            };
            let range = raw.trim_end_matches(" (hypothesis)").trim();
            if !valid_range(range) {
                continue;
            }
            let hint = VersionHint {
                range: range.into(),
                confidence,
                reason: signal.hypothesis.clone(),
                reference: signal.reference.into(),
            };
            output.add("PHP", &hint, &signal.category, &signal.source);
        }
    }
    (output.entries, output.limited)
}

fn exact_version(technology: &Technology, evidence: &[Evidence]) -> bool {
    (technology.name == "PHP" && !evidence.is_empty())
        || technology.observations.iter().any(|o| {
            o.version.is_some() && matches!(o.method.as_str(), "composer_package" | "npm_package")
        })
        || technology.versions.iter().any(|v| {
            v.split(['-', '+'])
                .next()
                .is_some_and(|v| v.split('.').count() >= 3)
        })
}

fn asset_proposal(
    output: &mut Proposals,
    technology: &Technology,
    observation: &crate::technology::TechnologyObservation,
) {
    let Some(version) = observation
        .detail
        .strip_prefix("Asset version hint ")
        .and_then(|text| text.split(';').next())
    else {
        return;
    };
    if !valid_range(version) {
        return;
    }
    let hint = VersionHint { range: format!("={version}"), confidence: Confidence::Low,
        reason: "Numeric version query on this component's asset; may be a cache key or copied resource, not its installed version.".into(),
        reference: "https://developer.wordpress.org/reference/functions/wp_enqueue_script/".into() };
    output.add(&technology.name, &hint, "asset_query", &observation.source);
}

fn framework_requirements(
    output: &mut Proposals,
    technologies: &[Technology],
    evidence: &[Evidence],
) {
    if !evidence.is_empty() {
        return;
    }
    for technology in technologies {
        for version in &technology.versions {
            let major = version.split('.').next().unwrap_or("");
            let (range, reference) = match (technology.name.as_str(), major) {
                ("Laravel", "12") => (
                    ">=8.2",
                    "https://github.com/laravel/framework/blob/v12.70.2/composer.json",
                ),
                ("Laravel", "13") => (
                    ">=8.3",
                    "https://github.com/laravel/framework/blob/v13.0.0/composer.json",
                ),
                ("Symfony", "7") => (
                    ">=8.2",
                    "https://github.com/symfony/symfony/blob/v7.0.0/composer.json",
                ),
                ("Symfony", "8") => (
                    ">=8.4",
                    "https://github.com/symfony/symfony/blob/v8.0.0/composer.json",
                ),
                _ => continue,
            };
            for observation in technology
                .observations
                .iter()
                .filter(|o| o.version.as_ref() == Some(version))
            {
                output.php_requirement(range, &observation.source,
                    "Conditional on the observed framework matching the deployed application: its upstream PHP requirement constrains compatibility, not the actual web runtime or patch level.", reference, evidence);
            }
        }
    }
}

struct Proposals {
    entries: Vec<VersionHypothesis>,
    limited: bool,
}

impl Proposals {
    fn add(&mut self, technology: &str, hint: &VersionHint, basis: &str, source: &str) {
        if let Some(existing) = self.entries.iter_mut().find(|h| {
            h.technology == technology
                && h.range == hint.range
                && h.basis == basis
                && h.confidence == hint.confidence
        }) {
            retain(&mut existing.sources, source);
            retain(&mut existing.references, &hint.reference);
            retain(&mut existing.reasons, &hint.reason);
            return;
        }
        if self.entries.len() >= MAX_HYPOTHESES {
            self.limited = true;
            return;
        }
        self.entries.push(VersionHypothesis { technology: technology.into(), range: hint.range.clone(),
            confidence: hint.confidence, basis: basis.into(), reasons: vec![hint.reason.clone()],
            sources: vec![source.into()], references: vec![hint.reference.clone()],
            limitations: vec![LIMITATION.into(), "Confidence is qualitative and uncalibrated; repeated responses do not increase it. Alternatives are retained separately, not intersected as facts.".into()] });
    }

    fn php_requirement(
        &mut self,
        range: &str,
        source: &str,
        reason: &str,
        reference: &str,
        evidence: &[Evidence],
    ) {
        if evidence.is_empty() {
            self.add(
                "PHP",
                &VersionHint {
                    range: range.into(),
                    confidence: Confidence::Low,
                    reason: reason.into(),
                    reference: reference.into(),
                },
                "framework_requirement",
                source,
            );
        }
    }
}

fn retain(values: &mut Vec<String>, value: &str) {
    if values.len() < MAX_SOURCES && !values.iter().any(|v| v == value) {
        values.push(value.into());
    }
}
