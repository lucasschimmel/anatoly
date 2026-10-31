//! Budgeted discovery; disclosed routes are scheduled ahead of fallback guesses.
use crate::{
    http::{Page, Transport, display_url},
    recon::DEEP_PATHS,
    scan::ScanReport,
    scan_options::ScanOptions,
};
use reqwest::Url;
use std::collections::HashSet;

// Keep queue construction and execution together so budgets and counts share one plan.
pub(crate) fn run(
    first: &Page,
    url: &Url,
    transport: &mut Transport,
    report: &mut ScanReport,
    options: &ScanOptions,
    collect: impl Fn(&Page, &mut ScanReport),
) -> anyhow::Result<()> {
    let deep = options.deep;
    let paths = &options.paths;

    let mut seen = HashSet::from([first.url.as_str().to_owned(), url.as_str().to_owned()]);
    let mut planned = std::collections::VecDeque::new();
    let extra = if deep { DEEP_PATHS } else { &[] };
    let all_paths = report
        .discovered_paths
        .iter()
        .map(String::as_str)
        .chain(
            if deep {
                &["robots.txt", "composer.json", "composer.lock"][..]
            } else {
                &[]
            }
            .iter()
            .copied(),
        )
        .chain(paths.iter().map(String::as_str))
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
                "Request or target time budget reached; remaining diagnostic paths skipped.".into(),
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
                collect(&page, report);
                for path in report.discovered_paths.iter().rev() {
                    let next = first.url.join(path)?;
                    if options.network.permits(&next) && seen.insert(next.as_str().to_owned()) {
                        planned.push_front(next);
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

    Ok(())
}

pub(crate) fn is_diagnostic_name(name: &str) -> bool {
    [
        "phpinfo.php",
        "php_info.php",
        "php-info.php",
        "phpversion.php",
        "php-version.php",
        "info.php",
        "version.php",
        "diagnostics.php",
        "status.php",
        "phpinfo",
        "php-info",
        "info",
        "version",
        "diagnostics",
        "composer.json",
        "composer.lock",
        "package.json",
        "package-lock.json",
    ]
    .contains(&name)
}
