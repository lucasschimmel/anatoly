use crate::{
    fingerprint::Directive,
    policy::{CVES, VersionStatus},
};
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    PotentiallyAffected,
    FixFloorObserved,
    Inconclusive,
    Error,
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub name: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct CveAssessment {
    pub cve: &'static str,
    pub status: &'static str,
    pub exploitation: &'static str,
    pub detail: &'static str,
}

pub fn assess(status: VersionStatus, usable_http: bool) -> Verdict {
    if !usable_http {
        return Verdict::Inconclusive;
    }
    match status {
        VersionStatus::AffectedRange | VersionStatus::UnsupportedBranch => {
            Verdict::PotentiallyAffected
        }
        VersionStatus::FixFloorMet => Verdict::FixFloorObserved,
        _ => Verdict::Inconclusive,
    }
}

pub fn cve_assessments(verdict: &Verdict) -> Vec<CveAssessment> {
    CVES.iter().map(|cve| CveAssessment {
        cve, exploitation: "not_attempted",
        status: match verdict {
            Verdict::PotentiallyAffected => "potentially_affected",
            Verdict::FixFloorObserved => "fix_floor_observed",
            _ => "inconclusive",
        },
        detail: match verdict {
            Verdict::PotentiallyAffected => "Version evidence requires package-patch verification. Configuration signals do not exclude all paths.",
            Verdict::FixFloorObserved => "Advertised version meets the upstream floor. Complete vendor patch and running worker build remain unverified.",
            _ => "Insufficient trusted evidence to assess the running PHP package.",
        },
    }).collect()
}

pub fn configuration_checks(directives: &[Directive]) -> Vec<Check> {
    let mut checks = vec![];
    for name in [
        "session.upload_progress.enabled",
        "memory_limit",
        "post_max_size",
        "server api",
        "display_errors",
    ] {
        let values: Vec<_> = directives.iter().filter(|d| d.name == name).collect();
        let status = if values.is_empty() {
            "unknown"
        } else if values
            .iter()
            .any(|d| d.local_value != values[0].local_value)
        {
            "conflicting"
        } else {
            "observed"
        };
        let detail = if values.is_empty() {
            "Not disclosed; absence of evidence is not a configuration value.".into()
        } else {
            values
                .iter()
                .map(|d| format!("{}: {}", d.source, d.local_value))
                .collect::<Vec<_>>()
                .join("; ")
        };
        checks.push(Check {
            name: name.into(),
            status: status.into(),
            detail,
        });
    }
    checks.push(Check { name: "exploit_validation".into(), status: "not_attempted".into(),
        detail: "HTTP observations cannot certify absence of memory corruption. Validate complete vendor patches and restart all PHP workers.".into() });
    checks
}

pub fn recommendations() -> Vec<String> {
    ["Verify the web runtime package revision and complete vendor patches for both CVEs; CLI PHP may be a different installation.",
     "Upgrade affected or unsupported runtimes and restart every PHP worker after updating.",
     "Disable session.upload_progress administratively if unused; this only reduces some lifecycle paths, not all PHP2Shell paths.",
     "Keep decoded request sizes and multipart complexity bounded at the frontend; this supplements patching.",
     "Review application fatal-error and extension/shutdown paths, including FPM. A WAF or FPM alone is not proof of protection.",
     "Restrict exposed phpinfo diagnostics and disable version disclosure after verifying patches."].map(str::to_owned).to_vec()
}
