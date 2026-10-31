pub use crate::scan_report::{Report, ScanReport};
use crate::{
    analysis::Analysis,
    assessment::{self, Verdict},
    fingerprint::{Patterns, candidates, resolve},
    http::{Limits, Transport, allowed_redirect, display_url, validate_url},
    policy::VersionStatus,
    recon::{DEEP_PATHS, Detector, Signal, merge_signals},
    scan_options::ScanOptions,
};
use std::collections::HashSet;

/// One target, one isolated request budget. Diagnostics remain on the exact same origin.
pub fn scan(
    target: &str,
    limits: Limits,
    discover: bool,
    paths: &[String],
) -> anyhow::Result<ScanReport> {
    scan_with_samples(target, limits, discover, paths, 1)
}

/// Repeat the application request within the same bounded budget to expose mixed versions.
pub fn scan_with_samples(
    target: &str,
    limits: Limits,
    discover: bool,
    paths: &[String],
    samples: usize,
) -> anyhow::Result<ScanReport> {
    scan_public(target, limits, discover, paths, samples, false)
}

/// Public-only reconnaissance: exact declarations stay separate from weak hypotheses.
pub fn scan_public(
    target: &str,
    limits: Limits,
    discover: bool,
    paths: &[String],
    samples: usize,
    deep: bool,
) -> anyhow::Result<ScanReport> {
    let options = ScanOptions {
        samples,
        discover,
        deep,
        paths: paths.to_vec(),
        ..ScanOptions::default()
    };
    scan_configured(target, limits, &options)
}

pub fn scan_configured(
    target: &str,
    limits: Limits,
    options: &ScanOptions,
) -> anyhow::Result<ScanReport> {
    let (samples, discover, paths, deep) = (
        options.samples,
        options.discover,
        &options.paths,
        options.deep,
    );
    if !(1..=5).contains(&samples) {
        anyhow::bail!("Samples must be between 1 and 5");
    }
    let url = validate_url(target)?;
    options.network.validate()?;
    if !options.network.permits(&url) {
        anyhow::bail!("Target is outside the configured scan scope");
    }
    for path in paths {
        let next = validate_url(url.join(path)?.as_str())?;
        if !allowed_redirect(&url, &next) {
            anyhow::bail!("Diagnostic paths must remain on the target origin");
        }
    }
    let mut transport = Transport::with_policy(limits, options.network.clone())?;
    let patterns = Patterns::new()?;
    let detector = Detector::new()?;
    let mut report = ScanReport {
        tls: vec![], waf: vec![],
        version_candidates: vec![], signals: vec![], discovered_paths: vec![],
        analysis: Analysis::new(samples, if discover { paths.len() } else { 0 }),
        target: display_url(&url), final_url: None, verdict: Verdict::Inconclusive, version: None,
        version_status: VersionStatus::Unknown, evidence: vec![], directives: vec![], checks: vec![],
        cves: vec![], observations: vec![], requests_sent: 0,
        limitations: vec!["Remote headers and diagnostic pages are untrusted; reverse proxies, caches, backports and mixed worker pools can hide the running build.".into(),
            "No OOM, memory-corruption or command-execution payload was sent. Non-vulnerability is not certified.".into()],
        recommendations: assessment::recommendations(),
    };
    for (disabled, note) in [
        (!discover, "Additional path discovery disabled by operator."),
        (
            options.no_cookie_hints,
            "Cookie hypotheses disabled by operator.",
        ),
        (
            options.no_hypotheses,
            "All public hypotheses disabled by operator.",
        ),
        (
            options.no_linked_discovery,
            "Linked diagnostic discovery disabled by operator.",
        ),
    ] {
        if disabled {
            report.analysis.skipped_checks.push(note.into());
        }
    }
    let first = match transport.get(&url) {
        Ok(page) => page,
        Err(error) => {
            report.verdict = Verdict::Error;
            report.limitations.push(error.to_string());
            return Ok(finish(report, transport, &patterns, &detector, options));
        }
    };
    report.final_url = Some(display_url(&first.url));
    let usable_http = (200..300).contains(&first.status);
    report.analysis.http_verified = usable_http;
    report.analysis.samples_completed = usize::from(usable_http);
    if !usable_http {
        report.limitations.push(format!("Initial HTTP {} is not a usable application response; access errors and redirects cannot establish a protected runtime.", first.status));
    }
    collect(&patterns, &detector, &first, &mut report, options);
    report.analysis.samples_with_version = usize::from(usable_http && !report.evidence.is_empty());
    if usable_http {
        for _ in 1..samples {
            if !transport.remaining() {
                report.analysis.gaps.push(
                    "Request or target time budget prevented remaining application samples.".into(),
                );
                break;
            }
            match transport.get(&first.url) {
                Ok(page) if (200..300).contains(&page.status) => {
                    report.analysis.samples_completed += 1;
                    let before = report.evidence.len();
                    collect(&patterns, &detector, &page, &mut report, options);
                    report.analysis.samples_with_version +=
                        usize::from(report.evidence.len() > before);
                }
                Ok(page) => {
                    report
                        .analysis
                        .gaps
                        .push(format!("Application sample returned HTTP {}.", page.status));
                    collect(&patterns, &detector, &page, &mut report, options);
                }
                Err(error) => report
                    .analysis
                    .gaps
                    .push(format!("Application sample failed: {error}")),
            }
        }
    }
    if options.waf_probe && usable_http {
        if transport.remaining() {
            let mut probe = first.url.clone();
            probe.query_pairs_mut().append_pair("anatoly_probe", "1");
            match transport.get(&probe) {
                Ok(page) => collect(&patterns, &detector, &page, &mut report, options),
                Err(_) => report
                    .analysis
                    .gaps
                    .push("The optional benign WAF-marker request could not complete.".into()),
            }
        } else {
            report.analysis.gaps.push(
                "Request/time budget prevented the optional benign WAF-marker request.".into(),
            );
        }
        report.limitations.push("The optional WAF probe uses a benign query marker. No detected marker or unchanged response proves that a WAF is absent or blocks PHP2Shell.".into());
    }
    if discover && usable_http {
        let mut seen = HashSet::from([first.url.as_str().to_owned(), url.as_str().to_owned()]);
        let mut planned = std::collections::VecDeque::new();
        let extra = if deep { DEEP_PATHS } else { &[] };
        let all_paths = report
            .discovered_paths
            .iter()
            .chain(paths.iter())
            .map(String::as_str)
            .chain(extra.iter().copied());
        for path in all_paths {
            let next = first.url.join(path)?;
            if !options.network.permits(&next) {
                report.analysis.skipped_checks.push(format!(
                    "Diagnostic excluded by scope: {}",
                    display_url(&next)
                ));
                continue;
            }
            if seen.insert(next.as_str().to_owned()) {
                planned.push_back(next);
            }
        }
        report.analysis.diagnostics_requested = planned.len();
        while let Some(next) = planned.pop_front() {
            if !transport.remaining() {
                report.limitations.push(
                    "Request or target time budget reached; remaining diagnostic paths skipped."
                        .into(),
                );
                report.analysis.gaps.push(
                    "Request or target time budget prevented remaining diagnostic checks.".into(),
                );
                break;
            }
            match transport.get(&next) {
                Ok(page) => {
                    report.analysis.diagnostics_completed += 1;
                    if !(200..300).contains(&page.status) && !matches!(page.status, 404 | 410) {
                        report.analysis.gaps.push(format!(
                            "Diagnostic route could not be assessed (HTTP {}).",
                            page.status
                        ));
                    }
                    collect(&patterns, &detector, &page, &mut report, options);
                    for path in &report.discovered_paths {
                        let next = first.url.join(path)?;
                        if options.network.permits(&next) && seen.insert(next.as_str().to_owned()) {
                            planned.push_back(next);
                            report.analysis.diagnostics_requested += 1;
                        }
                    }
                }
                Err(error) => report
                    .analysis
                    .gaps
                    .push(format!("Diagnostic probe incomplete: {error}")),
            }
        }
    }
    (report.version, report.version_status) = resolve(&report.evidence);
    report.verdict = assessment::assess(report.version_status, usable_http);
    report.checks = assessment::configuration_checks(&report.directives);
    Ok(finish(report, transport, &patterns, &detector, options))
}

fn collect(
    patterns: &Patterns,
    detector: &Detector,
    page: &crate::http::Page,
    report: &mut ScanReport,
    options: &ScanOptions,
) {
    let source = display_url(&page.url);
    let (proofs, signals) = detector.metadata(&page.metadata, patterns);
    report.evidence.extend(proofs);
    selected_signals(report, signals, options);
    let (proofs, signals, links) = detector.body(page, patterns);
    report.evidence.extend(proofs);
    selected_signals(report, signals, options);
    for link in links {
        if options.discover
            && !options.no_linked_discovery
            && report.discovered_paths.len() < 3
            && !report.discovered_paths.contains(&link)
        {
            report.discovered_paths.push(link);
        }
    }
    let (mut versions, directives) = patterns.phpinfo(&page.body, &format!("{source} [phpinfo]"));
    for proof in &mut versions {
        proof.http_status = Some(page.status);
    }
    report.evidence.extend(versions);
    report.directives.extend(directives);
}

fn finish(
    mut report: ScanReport,
    transport: Transport,
    patterns: &Patterns,
    detector: &Detector,
    options: &ScanOptions,
) -> ScanReport {
    for metadata in &transport.redirect_metadata {
        let (proofs, signals) = detector.metadata(metadata, patterns);
        report.evidence.extend(proofs);
        selected_signals(&mut report, signals, options);
    }
    (report.version, report.version_status) = resolve(&report.evidence);
    if report.verdict != Verdict::Error {
        report.verdict = assessment::assess(report.version_status, report.analysis.http_verified);
    }
    report.version_candidates = candidates(&report.evidence);
    if transport.observations.iter().any(|o| o.truncated) {
        report
            .analysis
            .gaps
            .push("Truncated HTTP response; evidence may be incomplete.".into());
        report
            .limitations
            .push("Response body limit reached; diagnostic evidence may be incomplete.".into());
    }
    if transport.observations.iter().any(|o| o.redirect_blocked) {
        report
            .analysis
            .gaps
            .push("A redirect left the permitted origin.".into());
        report.limitations.push(
            "A cross-origin redirect was blocked; scan the intended canonical origin explicitly."
                .into(),
        );
    }
    if transport.observations.iter().any(|o| o.redirect_limited) {
        report
            .analysis
            .gaps
            .push("Configured redirect limit prevented following a response.".into());
    }
    if transport.observations.iter().any(|o| o.scope_blocked) {
        report
            .analysis
            .gaps
            .push("A redirect was blocked by the configured scope.".into());
    }
    report
        .analysis
        .finalize(report.version_status, &report.evidence);
    if report.verdict == Verdict::FixFloorObserved && !report.analysis.coverage_complete {
        report.verdict = Verdict::Inconclusive;
        report.limitations.push("The fix floor was observed, but planned verification was incomplete; result remains inconclusive.".into());
    }
    report
        .limitations
        .extend(report.analysis.gaps.iter().cloned());
    report
        .limitations
        .extend(report.analysis.skipped_checks.iter().cloned());
    report.cves = assessment::cve_assessments(&report.verdict);
    report.observations = transport.observations;
    report.requests_sent = transport.requests;
    report.tls = transport.tls;
    report.waf = transport.waf;
    report
}

fn selected_signals(report: &mut ScanReport, signals: Vec<Signal>, options: &ScanOptions) {
    if !options.no_hypotheses {
        merge_signals(
            &mut report.signals,
            signals
                .into_iter()
                .filter(|s| !options.no_cookie_hints || s.category != "cookie")
                .collect(),
        );
    }
}
