use crate::{
    assessment::Verdict,
    fingerprint::{DetectionLevel, Evidence},
    policy::VersionStatus,
};
use serde::Serialize;
use std::collections::HashSet;

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionConfidence {
    Unknown,
    SingleSource,
    ConsistentSamples,
    Corroborated,
    Conflicting,
}

#[derive(Debug, Serialize)]
pub struct Analysis {
    pub skipped_checks: Vec<String>,
    pub detection_level: DetectionLevel,
    pub http_verified: bool,
    pub samples_requested: usize,
    pub samples_completed: usize,
    pub samples_with_version: usize,
    pub diagnostics_requested: usize,
    pub diagnostics_completed: usize,
    pub version_confidence: VersionConfidence,
    pub coverage_complete: bool,
    pub coverage_scope: &'static str,
    pub discovery_limited: bool,
    pub gaps: Vec<String>,
    pub certified: bool,
    pub secure: bool,
}

impl Analysis {
    pub fn new(samples: usize, diagnostics: usize) -> Self {
        Self {
            skipped_checks: vec![],
            detection_level: DetectionLevel::Unknown,
            http_verified: false,
            samples_requested: samples,
            samples_completed: 0,
            samples_with_version: 0,
            diagnostics_requested: diagnostics,
            diagnostics_completed: 0,
            version_confidence: VersionConfidence::Unknown,
            coverage_complete: false,
            coverage_scope: "Selected request plan only; technology recognition and route discovery are not exhaustive.",
            discovery_limited: false,
            gaps: vec![],
            certified: false,
            secure: false,
        }
    }

    /// Corroboration describes remote observations, never the actual package patch state.
    pub fn finalize(&mut self, status: VersionStatus, evidence: &[Evidence]) {
        if self.samples_with_version > 0 && self.samples_with_version < self.samples_completed {
            self.gaps.push(
                "PHP version disclosure was inconsistent between application samples.".into(),
            );
        }
        self.coverage_complete = self.http_verified
            && self.samples_completed == self.samples_requested
            && self.diagnostics_completed == self.diagnostics_requested
            && self.gaps.is_empty();
        let channels: HashSet<_> = evidence.iter().map(|e| e.kind).collect();
        self.detection_level = if status == VersionStatus::Conflicting {
            DetectionLevel::Contradictory
        } else if evidence.is_empty() {
            DetectionLevel::Unknown
        } else if channels.len() > 1 {
            DetectionLevel::Corroborated
        } else {
            DetectionLevel::Declared
        };
        self.version_confidence = if status == VersionStatus::Conflicting {
            VersionConfidence::Conflicting
        } else if evidence.is_empty() {
            VersionConfidence::Unknown
        } else if channels.len() > 1 {
            VersionConfidence::Corroborated
        } else if self.samples_with_version > 1
            && self.samples_with_version == self.samples_completed
        {
            VersionConfidence::ConsistentSamples
        } else {
            VersionConfidence::SingleSource
        };
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Summary {
    pub php_declared: usize,
    pub php_contradictory: usize,
    pub php_unknown: usize,
    pub urls_analyzed: usize,
    pub http_verified: usize,
    pub php_corroborated: usize,
    pub potentially_affected: usize,
    pub fix_floor_observed: usize,
    pub unknown: usize,
    pub errors: usize,
    pub limited_coverage: usize,
    pub certified: usize,
    pub secure: usize,
    pub assurance_scope: &'static str,
}

impl Summary {
    pub fn from_targets(targets: &[crate::scan::ScanReport]) -> Self {
        let mut summary = Self {
            urls_analyzed: targets.len(),
            assurance_scope: "HTTP observations only; package patch state and absence of exploitability are not certified.",
            ..Self::default()
        };
        for target in targets {
            match target.analysis.detection_level {
                DetectionLevel::Declared => summary.php_declared += 1,
                DetectionLevel::Contradictory => summary.php_contradictory += 1,
                DetectionLevel::Unknown => summary.php_unknown += 1,
                DetectionLevel::Corroborated => {}
            }
            summary.http_verified += usize::from(target.analysis.http_verified);
            summary.php_corroborated +=
                usize::from(target.analysis.version_confidence == VersionConfidence::Corroborated);
            summary.limited_coverage += usize::from(!target.analysis.coverage_complete);
            match target.verdict {
                Verdict::PotentiallyAffected => summary.potentially_affected += 1,
                Verdict::FixFloorObserved => summary.fix_floor_observed += 1,
                Verdict::Inconclusive => summary.unknown += 1,
                Verdict::Error => summary.errors += 1,
            }
        }
        // There is deliberately no trust path from HTTP responses to security certification.
        summary
    }
}
