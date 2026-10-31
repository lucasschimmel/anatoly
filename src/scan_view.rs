use crate::{
    analysis::{Summary, VersionConfidence},
    assessment::Verdict,
    fingerprint::DetectionLevel,
    policy::VersionStatus,
    scan::ScanReport,
    ui::{Ui, safe_text},
};

const WIDTH: usize = 72;
const DIM: &str = "38;5;245";
const TEXT: &str = "38;5;252";
const CYAN: &str = "1;38;5;81";
const AMBER: &str = "38;5;221";

pub(crate) fn render(ui: &Ui, index: usize, total: usize, report: &ScanReport) {
    let (badge, tone) = match report.verdict {
        Verdict::PotentiallyAffected => ("!  POTENTIALLY AFFECTED", "1;38;5;203"),
        Verdict::FixFloorObserved => ("◈  FIX FLOOR OBSERVED", CYAN),
        Verdict::Inconclusive => ("?  INCONCLUSIVE", "1;38;5;221"),
        Verdict::Error => ("×  CONNECTION ERROR", "1;38;5;203"),
    };
    let title = format!("─ TARGET {index:02} / {total:02} ");
    println!(
        "  {}",
        ui.paint(
            &format!("╭{title}{}╮", "─".repeat(WIDTH + 2 - title.chars().count())),
            "38;5;24"
        )
    );
    line(ui, badge, tone);
    paragraph(ui, &report.target, TEXT);
    section(ui, "01", "RUNTIME");
    field(
        ui,
        "PHP version",
        &report
            .version
            .as_ref()
            .map_or("not disclosed".into(), ToString::to_string),
        TEXT,
    );
    field(
        ui,
        "Version evidence",
        version_label(report.version_status),
        DIM,
    );
    let statuses = report
        .observations
        .iter()
        .map(|o| o.status.to_string())
        .collect::<Vec<_>>()
        .join(" → ");
    field(
        ui,
        "HTTP requests",
        &format!(
            "{} GET{}",
            report.requests_sent,
            if statuses.is_empty() {
                String::new()
            } else {
                format!("  /  {statuses}")
            }
        ),
        DIM,
    );
    field(
        ui,
        "Detection level",
        match report.analysis.detection_level {
            DetectionLevel::Declared => "DECLARED · one evidence method",
            DetectionLevel::Corroborated => "CORROBORATED · matching evidence methods",
            DetectionLevel::Contradictory => "CONTRADICTORY · multiple versions",
            DetectionLevel::Unknown => "UNKNOWN · no explicit runtime version",
        },
        CYAN,
    );
    field(
        ui,
        "Evidence level",
        match report.analysis.version_confidence {
            VersionConfidence::Unknown => "unknown · no usable PHP version",
            VersionConfidence::SingleSource => "single source · uncorroborated",
            VersionConfidence::ConsistentSamples => "consistent application samples",
            VersionConfidence::Corroborated => "corroborated public declarations",
            VersionConfidence::Conflicting => "conflicting · manual verification required",
        },
        DIM,
    );
    crate::evidence_view::render(ui, report);
    field(
        ui,
        "Response sampling",
        &format!(
            "{} / {} successful · {} disclose PHP",
            report.analysis.samples_completed,
            report.analysis.samples_requested,
            report.analysis.samples_with_version
        ),
        DIM,
    );
    field(
        ui,
        "Planned checks",
        if report.analysis.coverage_complete {
            "completed · not a security certification"
        } else {
            "incomplete · evidence gaps remain"
        },
        if report.analysis.coverage_complete {
            DIM
        } else {
            AMBER
        },
    );
    section(ui, "02", "CVE ASSESSMENT");
    for cve in &report.cves {
        field(ui, cve.cve, cve_label(cve.status), tone);
    }
    field(
        ui,
        "Exploit validation",
        "not attempted · HTTP evidence only",
        DIM,
    );
    configuration(ui, report);
    section(ui, "04", "ACTION");
    paragraph(ui, action(&report.verdict), TEXT);
    section(ui, "05", "ASSESSMENT LIMITS");
    for note in &report.limitations {
        paragraph(ui, &format!("· {note}"), DIM);
    }
    line(ui, "", TEXT);
    println!(
        "  {}\n",
        ui.paint(&format!("╰{}╯", "─".repeat(WIDTH + 2)), "38;5;24")
    );
}

pub(crate) fn summary(ui: &Ui, summary: &Summary) {
    let title = "─ SCAN SUMMARY ";
    println!(
        "  {}",
        ui.paint(
            &format!("╭{title}{}╮", "─".repeat(WIDTH + 2 - title.chars().count())),
            "38;5;24"
        )
    );
    line(ui, "◆  SCAN FINISHED", CYAN);
    field(
        ui,
        "URLs analyzed",
        &summary.urls_analyzed.to_string(),
        TEXT,
    );
    field(
        ui,
        "HTTP verified",
        &format!(
            "{} / {} · initial response usable",
            summary.http_verified, summary.urls_analyzed
        ),
        TEXT,
    );
    field(
        ui,
        "PHP corroborated",
        &format!(
            "{} · matching public evidence methods",
            summary.php_corroborated
        ),
        DIM,
    );
    field(ui, "PHP declared", &summary.php_declared.to_string(), DIM);
    field(
        ui,
        "PHP contradictory",
        &summary.php_contradictory.to_string(),
        AMBER,
    );
    field(ui, "PHP unknown", &summary.php_unknown.to_string(), DIM);
    line(ui, "", TEXT);
    field(
        ui,
        "Potentially affected",
        &summary.potentially_affected.to_string(),
        "38;5;203",
    );
    field(
        ui,
        "Fix floor observed",
        &format!(
            "{} · package patches unverified",
            summary.fix_floor_observed
        ),
        CYAN,
    );
    field(ui, "Unknown", &summary.unknown.to_string(), AMBER);
    field(
        ui,
        "Errors",
        &summary.errors.to_string(),
        if summary.errors > 0 { "38;5;203" } else { DIM },
    );
    field(
        ui,
        "Limited coverage",
        &summary.limited_coverage.to_string(),
        DIM,
    );
    line(ui, "", TEXT);
    field(
        ui,
        "Certified / secure",
        &format!(
            "{} / {} · not attested by HTTP",
            summary.certified, summary.secure
        ),
        DIM,
    );
    paragraph(
        ui,
        "HTTP verified and PHP corroborated are evidence counters. The four outcome counts partition the analyzed URLs. Security requires verification of complete vendor patches on the running web runtime.",
        DIM,
    );
    line(ui, "", TEXT);
    println!(
        "  {}\n",
        ui.paint(&format!("╰{}╯", "─".repeat(WIDTH + 2)), "38;5;24")
    );
}

fn configuration(ui: &Ui, report: &ScanReport) {
    section(ui, "03", "CONFIGURATION");
    let mut missing = vec![];
    for (name, label) in [
        ("session.upload_progress.enabled", "Upload progress"),
        ("memory_limit", "Memory limit"),
        ("post_max_size", "POST limit"),
        ("server api", "PHP SAPI"),
        ("display_errors", "Display errors"),
    ] {
        let values: Vec<_> = report
            .directives
            .iter()
            .filter(|d| d.name == name)
            .collect();
        if values.is_empty() {
            missing.push(label.to_ascii_lowercase());
            continue;
        }
        let conflicting = values
            .iter()
            .any(|d| d.local_value != values[0].local_value);
        let mut unique = vec![];
        for value in values {
            if !unique.contains(&value.local_value) {
                unique.push(value.local_value.clone());
            }
        }
        field(
            ui,
            label,
            &format!(
                "{}  · {}",
                unique.join(" / "),
                if conflicting {
                    "conflicting"
                } else {
                    "observed"
                }
            ),
            if conflicting { AMBER } else { TEXT },
        );
    }
    if !missing.is_empty() {
        field(ui, "Not disclosed", &missing.join(", "), DIM);
    }
}

fn action(verdict: &Verdict) -> &'static str {
    match verdict {
        Verdict::PotentiallyAffected => {
            "Verify vendor patches for the web PHP runtime. Upgrade affected packages and restart every PHP worker."
        }
        Verdict::FixFloorObserved => {
            "Confirm the complete vendor patch set and the build running in every worker. An advertised version does not attest protection."
        }
        Verdict::Inconclusive => {
            "Verify the web PHP version and vendor package revision on the server. Use the canonical app URL if access or redirects blocked this scan."
        }
        Verdict::Error => {
            "Check the URL, DNS, certificate and network access, then retry. The runtime could not be assessed."
        }
    }
}

fn version_label(status: VersionStatus) -> &'static str {
    match status {
        VersionStatus::AffectedRange => "below the upstream fix floor",
        VersionStatus::FixFloorMet => "upstream floor met · package patches unverified",
        VersionStatus::UnsupportedBranch => "unsupported PHP branch · migration required",
        VersionStatus::UnreviewedBranch => "branch outside the reviewed policy",
        VersionStatus::Prerelease => "prerelease · stable fix not established",
        VersionStatus::Conflicting => "conflicting sources · no version selected",
        VersionStatus::Unknown => "insufficient version evidence",
    }
}

fn cve_label(status: &str) -> &str {
    match status {
        "potentially_affected" => "potentially affected",
        "fix_floor_observed" => "fix floor observed · patches unverified",
        "inconclusive" => "inconclusive",
        other => other,
    }
}

fn section(ui: &Ui, number: &str, title: &str) {
    line(ui, "", TEXT);
    line(ui, &format!("{number} / {title}"), CYAN);
}

pub(crate) fn field(ui: &Ui, label: &str, value: &str, tone: &str) {
    for (i, part) in wrap(value, WIDTH - 21).iter().enumerate() {
        line(
            ui,
            &format!("{:<21}{part}", if i == 0 { label } else { "" }),
            tone,
        );
    }
}

pub(crate) fn paragraph(ui: &Ui, text: &str, tone: &str) {
    for part in wrap(text, WIDTH) {
        line(ui, &part, tone);
    }
}

pub(crate) fn line(ui: &Ui, text: &str, tone: &str) {
    let text = safe_text(text);
    let padding = WIDTH.saturating_sub(text.chars().count());
    println!(
        "  {} {}{} {}",
        ui.paint("│", "38;5;24"),
        ui.paint(&text, tone),
        " ".repeat(padding),
        ui.paint("│", "38;5;24")
    );
}

/// Break long URLs and words too, so remote values cannot stretch the result card.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let clean = safe_text(text);
    let mut lines = vec![];
    let mut current = String::new();
    for word in clean.split_whitespace() {
        let count = current.chars().count();
        if count > 0 && count + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut current));
        } else if count > 0 {
            current.push(' ');
        }
        for c in word.chars() {
            if current.chars().count() == width {
                lines.push(std::mem::take(&mut current));
            }
            current.push(c);
        }
    }
    if !current.is_empty() || lines.is_empty() {
        lines.push(current);
    }
    lines
}
