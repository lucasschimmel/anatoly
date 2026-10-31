use crate::{
    fingerprint::{DetectionLevel, EvidenceKind},
    scan::ScanReport,
    scan_view::{field, line, paragraph},
    ui::Ui,
};

const DIM: &str = "38;5;245";
const TEXT: &str = "38;5;252";

pub(crate) fn render(ui: &Ui, report: &ScanReport) {
    if let Some(final_url) = &report.final_url
        && final_url != &report.target
    {
        field(ui, "Resolved URL", final_url, DIM);
    }
    for candidate in &report.version_candidates {
        line(ui, "", TEXT);
        let level = if candidate.level == DetectionLevel::Corroborated {
            "corroborated"
        } else {
            "declared"
        };
        field(
            ui,
            "Candidate PHP",
            &format!(
                "{} · {level} · {} observations",
                candidate.version,
                candidate.proofs.len()
            ),
            "38;5;81",
        );
        let mut seen = vec![];
        for proof in &candidate.proofs {
            let key = (&proof.source, &proof.excerpt, proof.http_status);
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);
            let method = match proof.kind {
                EvidenceKind::Header => "HTTP header",
                EvidenceKind::Diagnostic => "phpinfo diagnostic",
                EvidenceKind::StructuredMetadata => "runtime metadata",
                EvidenceKind::ErrorDisclosure => "error-page footer",
            };
            field(
                ui,
                "Proof",
                &format!(
                    "{method} · HTTP {} · {}",
                    proof.http_status.map_or("?".into(), |s| s.to_string()),
                    proof.excerpt
                ),
                TEXT,
            );
            field(ui, "Source URL", &proof.source, DIM);
        }
    }
    if !report.signals.is_empty() {
        line(ui, "", TEXT);
        field(
            ui,
            "PUBLIC HYPOTHESES",
            &format!("{} signals · not version proof", report.signals.len()),
            "38;5;221",
        );
        for signal in report.signals.iter().take(6) {
            field(ui, &signal.category, &signal.observation, TEXT);
            if let Some(hint) = &signal.version_hint {
                field(ui, "Possible range", hint, "38;5;221");
            }
            field(ui, "Source URL", &signal.source, DIM);
            paragraph(ui, &signal.hypothesis, DIM);
        }
        if report.signals.len() > 6 {
            field(
                ui,
                "More hypotheses",
                "Use --json or --output to inspect every signal.",
                DIM,
            );
        }
    }
}
