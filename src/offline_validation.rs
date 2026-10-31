//! Validate imported evidence relationships before evaluating stored conclusions.
use super::text;
use anatoly::{
    fingerprint::{Evidence, EvidenceKind, candidates, resolve},
    policy::PhpVersion,
};
use anyhow::{Context, Result, bail};
use serde_json::Value;

pub(super) fn validate_target(target: &Value) -> Result<()> {
    anatoly::http::validate_url(text(target, "target"))
        .context("Report contains an invalid target URL")?;
    if !matches!(
        text(target, "verdict"),
        "potentially_affected" | "fix_floor_observed" | "inconclusive" | "error"
    ) {
        bail!("Report contains an invalid verdict");
    }
    for field in [
        "evidence",
        "version_candidates",
        "limitations",
        "recommendations",
        "directives",
        "observations",
        "signals",
    ] {
        if !target[field].is_array() {
            bail!("Report is missing a required target collection");
        }
    }
    validate_analysis(target)?;
    validate_evidence(target)?;
    validate_verdict(target)
}

fn validate_analysis(target: &Value) -> Result<()> {
    let analysis = &target["analysis"];
    for field in ["coverage_complete", "http_verified", "secure", "certified"] {
        if !analysis[field].is_boolean() {
            bail!("Report contains invalid analysis flags");
        }
    }
    if analysis["secure"] != false || analysis["certified"] != false {
        bail!("Public HTTP evidence cannot certify security");
    }
    for field in ["gaps", "skipped_checks"] {
        if !analysis[field]
            .as_array()
            .is_some_and(|a| a.iter().all(Value::is_string))
        {
            bail!("Report contains invalid coverage details");
        }
    }
    let completed = count(analysis, "samples_completed")?;
    let requested = count(analysis, "samples_requested")?;
    let diagnostics = count(analysis, "diagnostics_completed")?;
    let planned = count(analysis, "diagnostics_requested")?;
    if count(analysis, "samples_with_version")? > completed
        || completed > requested
        || diagnostics > planned
    {
        bail!("Report contains inconsistent sample counts");
    }
    let complete = analysis["http_verified"] == true
        && completed == requested
        && diagnostics == planned
        && analysis["gaps"].as_array().is_some_and(Vec::is_empty);
    if analysis["coverage_complete"] != complete {
        bail!("Recorded coverage does not match its sample counts and gaps");
    }
    if let Some(final_url) = target["final_url"].as_str() {
        anatoly::http::validate_url(final_url).context("Invalid recorded final URL")?;
    } else if !target["final_url"].is_null() || analysis["http_verified"] == true {
        bail!("Verified HTTP requires a recorded final URL");
    }
    Ok(())
}

fn count(value: &Value, key: &str) -> Result<u64> {
    value[key].as_u64().context("Invalid report sample count")
}

fn parsed_version(value: &Value) -> Result<PhpVersion> {
    let component = |key: &str| {
        value[key]
            .as_u64()
            .and_then(|v| u16::try_from(v).ok())
            .context("Invalid PHP version component")
    };
    Ok(PhpVersion {
        major: component("major")?,
        minor: component("minor")?,
        patch: component("patch")?,
        prerelease: value["prerelease"]
            .as_bool()
            .context("Missing release qualifier")?,
    })
}

fn proof(value: &Value) -> Result<Evidence> {
    let kind = match text(value, "kind") {
        "header" => EvidenceKind::Header,
        "diagnostic" => EvidenceKind::Diagnostic,
        "structured_metadata" => EvidenceKind::StructuredMetadata,
        "error_disclosure" => EvidenceKind::ErrorDisclosure,
        _ => bail!("Invalid version evidence method"),
    };
    if text(value, "source").is_empty() || text(value, "excerpt").is_empty() {
        bail!("Version evidence must retain its source and excerpt");
    }
    let status = match value["http_status"].as_u64() {
        Some(status) if (100..=599).contains(&status) => Some(status as u16),
        None if value["http_status"].is_null() => None,
        _ => bail!("Invalid evidence HTTP status"),
    };
    Ok(Evidence {
        source: text(value, "source").into(),
        version: parsed_version(&value["version"])?,
        kind,
        excerpt: text(value, "excerpt").into(),
        http_status: status,
    })
}

fn validate_evidence(target: &Value) -> Result<()> {
    let evidence = target["evidence"]
        .as_array()
        .context("Missing version evidence")?
        .iter()
        .map(proof)
        .collect::<Result<Vec<_>>>()?;
    let (version, status) = resolve(&evidence);
    let selected = if target["version"].is_null() {
        None
    } else {
        Some(parsed_version(&target["version"])?)
    };
    if version != selected || serde_json::to_value(status)? != target["version_status"] {
        bail!("Selected PHP release is inconsistent with recorded evidence");
    }
    validate_candidates(&evidence, &target["version_candidates"])?;
    let mut expected = anatoly::analysis::Analysis::new(1, 0);
    expected.samples_completed = count(&target["analysis"], "samples_completed")? as usize;
    expected.samples_with_version = count(&target["analysis"], "samples_with_version")? as usize;
    expected.finalize(status, &evidence);
    if serde_json::to_value(expected.detection_level)? != target["analysis"]["detection_level"]
        || serde_json::to_value(expected.version_confidence)?
            != target["analysis"]["version_confidence"]
    {
        bail!("Claimed version confidence does not match evidence methods");
    }
    Ok(())
}

fn validate_candidates(evidence: &[Evidence], value: &Value) -> Result<()> {
    let expected = candidates(evidence);
    let actual = value.as_array().context("Missing candidate groups")?;
    if actual.len() != expected.len() {
        bail!("Version candidates do not match their supporting proofs");
    }
    let mut seen = std::collections::BTreeSet::new();
    for group in actual {
        let version = parsed_version(&group["version"])?;
        if !seen.insert(version.to_string()) {
            bail!("Duplicate candidate groups");
        }
        let expected = expected
            .iter()
            .find(|g| g.version == version)
            .context("Candidate version has no supporting evidence")?;
        if serde_json::to_value(expected.level)? != group["level"] {
            bail!("Candidate confidence does not match its evidence methods");
        }
        let proofs = group["proofs"]
            .as_array()
            .context("Missing candidate proofs")?
            .iter()
            .map(proof)
            .collect::<Result<Vec<_>>>()?;
        let unique = |proofs: &[Evidence]| -> Result<std::collections::BTreeSet<String>> {
            proofs
                .iter()
                .map(serde_json::to_string)
                .collect::<std::result::Result<_, _>>()
                .context("Encoding candidate evidence")
        };
        if unique(&proofs)? != unique(&expected.proofs)? {
            bail!("Candidate proofs do not match recorded evidence");
        }
    }
    Ok(())
}

fn validate_verdict(target: &Value) -> Result<()> {
    use anatoly::{
        assessment::{self, Verdict},
        policy::VersionStatus,
    };
    let status = if target["version"].is_null() {
        if target["evidence"].as_array().is_some_and(Vec::is_empty) {
            VersionStatus::Unknown
        } else {
            VersionStatus::Conflicting
        }
    } else {
        anatoly::policy::classify(&parsed_version(&target["version"])?)
    };
    if text(target, "verdict") == "error" {
        if target["analysis"]["http_verified"] == true {
            bail!("Transport failure cannot claim verified HTTP");
        }
        return Ok(());
    }
    let mut expected = assessment::assess(status, target["analysis"]["http_verified"] == true);
    if expected == Verdict::FixFloorObserved && target["analysis"]["coverage_complete"] != true {
        expected = Verdict::Inconclusive;
    }
    if serde_json::to_value(expected)? != target["verdict"] {
        bail!("Verdict is inconsistent with recorded release and coverage");
    }
    Ok(())
}
