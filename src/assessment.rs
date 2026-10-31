use crate::{
    fingerprint::{DIAGNOSTIC_DIRECTIVES, Directive},
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
    for &name in DIAGNOSTIC_DIRECTIVES {
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
        let mut detail: String = if values.is_empty() {
            "Not disclosed; absence of evidence is not a configuration value.".into()
        } else {
            values
                .iter()
                .map(|d| format!("{}: {}", d.source, d.local_value))
                .collect::<Vec<_>>()
                .join("; ")
        };
        detail.push(' ');
        detail.push_str(configuration_context(name));
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

fn configuration_context(name: &str) -> &'static str {
    match name {
        "session.upload_progress.enabled" => {
            "Off reduces the early session path only; other stale-state paths remain. No session_start() call is required for the early path."
        }
        "memory_limit" => {
            "A finite limit enables predictable PHP OOM. -1 does not exclude allocation failures and is not proof of protection."
        }
        "server api" => {
            "FPM may terminate a child on startup failure, but application-stage stale-state paths remain possible. SAPI alone does not establish safety."
        }
        "display_errors" => {
            "Off hides diagnostics; stale-state consumers can run before PHP decides to display or log them."
        }
        "fatal_error_backtraces" => {
            "PHP 8.5: disabling this removes one backtrace producer, not all stale-state paths. An absent directive does not imply Off."
        }
        "opcache.enable" | "opcache.enable_cli" => {
            "OPcache observations describe one context only; disabling it does not exclude the other PHP2Shell paths."
        }
        "session.serialize_handler" => {
            "Session decoder choice affects individual chains; this is not evidence that all lifecycle paths are patched."
        }
        _ => {
            "Input controls constrain specific paths only; their disclosed values cannot verify complete patches or all application routes."
        }
    }
}

pub fn recommendations() -> Vec<String> {
    ["Verify the web runtime package revision and complete vendor patches for both CVEs; CLI PHP may be a different installation.",
     "Upgrade affected or unsupported runtimes and restart every PHP worker after updating.",
     "Disable session.upload_progress administratively if unused; this only reduces some lifecycle paths, not all PHP2Shell paths.",
     "Keep decoded request sizes and multipart complexity bounded at the frontend; this supplements patching.",
     "Review application fatal-error and extension/shutdown paths, including FPM. A WAF or FPM alone is not proof of protection.",
     "Restrict exposed phpinfo diagnostics and disable version disclosure after verifying patches."].map(str::to_owned).to_vec()
}
