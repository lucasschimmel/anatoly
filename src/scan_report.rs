use crate::recon::Signal;
use crate::{
    analysis::{Analysis, Summary},
    assessment::{Check, CveAssessment, Verdict},
    fingerprint::{Directive, Evidence, VersionCandidate},
    http::Observation,
    policy::{self, PhpVersion, VersionStatus},
    tls_observation::TlsObservation,
    waf::WafEvidence,
};
use serde::Serialize;
#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub tls: Vec<TlsObservation>,
    pub waf: Vec<WafEvidence>,
    pub version_candidates: Vec<VersionCandidate>,
    pub signals: Vec<Signal>,
    pub discovered_paths: Vec<String>,
    pub analysis: Analysis,
    pub target: String,
    pub final_url: Option<String>,
    pub verdict: Verdict,
    pub version: Option<PhpVersion>,
    pub version_status: VersionStatus,
    pub evidence: Vec<Evidence>,
    pub directives: Vec<Directive>,
    pub checks: Vec<Check>,
    pub cves: Vec<CveAssessment>,
    pub observations: Vec<Observation>,
    pub requests_sent: usize,
    pub limitations: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_configuration: Option<serde_json::Value>,
    pub summary: Summary,
    pub tool: &'static str,
    pub version: &'static str,
    pub policy_date: &'static str,
    pub advisories: [&'static str; 2],
    pub targets: Vec<ScanReport>,
}

impl Report {
    pub fn new(targets: Vec<ScanReport>) -> Self {
        Self {
            run_configuration: None,
            summary: Summary::from_targets(&targets),
            tool: "anatoly",
            version: env!("CARGO_PKG_VERSION"),
            policy_date: policy::POLICY_DATE,
            advisories: policy::ADVISORIES,
            targets,
        }
    }
    pub fn exit_code(&self) -> u8 {
        if self.targets.iter().any(|s| s.verdict == Verdict::Error) {
            3
        } else if self
            .targets
            .iter()
            .any(|s| s.verdict == Verdict::PotentiallyAffected)
        {
            1
        } else if self
            .targets
            .iter()
            .any(|s| s.verdict == Verdict::Inconclusive)
        {
            2
        } else {
            0
        }
    }
}
