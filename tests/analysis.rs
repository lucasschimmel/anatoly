mod common;

use anatoly::{
    analysis::VersionConfidence,
    assessment::Verdict,
    policy::VersionStatus,
    scan::{Report, scan, scan_with_samples},
};
use common::{Server, limits, response};
use std::{
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

fn phpinfo(version: &str) -> String {
    format!("<html><h1>PHP Version {version}</h1><h2>Configuration</h2><a>PHP Credits</a></html>")
}

#[test]
fn repeated_application_samples_reveal_mixed_worker_versions() {
    let requests = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&requests);
    let server = Server::new(move |_| {
        let version = if calls.fetch_add(1, Ordering::Relaxed) == 0 {
            "8.4.27"
        } else {
            "8.4.26"
        };
        response("200 OK", &format!("X-Powered-By: PHP/{version}\r\n"), "OK")
    });
    let result = scan_with_samples(&server.url, limits(), false, &[], 3).unwrap();
    assert_eq!(result.analysis.samples_completed, 3);
    assert_eq!(server.paths.lock().unwrap().len(), 3);
    assert_eq!(result.analysis.samples_with_version, 3);
    assert_eq!(
        result.analysis.version_confidence,
        VersionConfidence::Conflicting
    );
    assert_eq!(result.version_status, VersionStatus::Conflicting);
    assert_eq!(result.verdict, Verdict::Inconclusive);
    assert!(result.version.is_none());
}

#[test]
fn a_fixed_header_cannot_override_an_affected_diagnostic_version() {
    let server = Server::new(|path| {
        if path == "/phpinfo.php" {
            response("200 OK", "", &phpinfo("8.4.26"))
        } else {
            response("200 OK", "X-Powered-By: PHP/8.4.27\r\n", "OK")
        }
    });
    let result = scan(&server.url, limits(), true, &["phpinfo.php".into()]).unwrap();
    assert_eq!(result.requests_sent, 2);
    assert_eq!(result.analysis.diagnostics_completed, 1);
    assert_eq!(
        result.analysis.version_confidence,
        VersionConfidence::Conflicting
    );
    assert_eq!(result.verdict, Verdict::Inconclusive);
}

#[test]
fn budget_exhaustion_downgrades_a_fixed_floor_to_inconclusive() {
    let server = Server::new(|_| response("200 OK", "X-Powered-By: PHP/8.4.27\r\n", "OK"));
    let mut bounds = limits();
    bounds.max_requests = 1;
    let result = scan_with_samples(&server.url, bounds, false, &[], 3).unwrap();
    assert_eq!(result.version_status, VersionStatus::FixFloorMet);
    assert_eq!(result.analysis.samples_completed, 1);
    assert!(!result.analysis.coverage_complete);
    assert!(!result.analysis.gaps.is_empty());
    assert_eq!(result.verdict, Verdict::Inconclusive);
}

#[test]
fn failed_application_samples_are_reported_as_a_verification_gap() {
    let count = AtomicUsize::new(0);
    let server = Server::new(move |_| {
        if count.fetch_add(1, Ordering::Relaxed) == 0 {
            response("200 OK", "X-Powered-By: PHP/8.4.27\r\n", "OK")
        } else {
            response("503 Service Unavailable", "", "busy")
        }
    });
    let result = scan_with_samples(&server.url, limits(), false, &[], 3).unwrap();
    assert_eq!(result.analysis.samples_completed, 1);
    assert_eq!(result.requests_sent, 3);
    assert!(!result.analysis.coverage_complete);
    assert!(result.analysis.gaps.iter().any(|s| s.contains("503")));
    assert_eq!(result.verdict, Verdict::Inconclusive);
}

#[test]
fn diagnostic_access_failures_limit_coverage_but_absent_pages_complete_the_check() {
    for (status, completed) in [
        ("403 Forbidden", false),
        ("503 Service Unavailable", false),
        ("429 Too Many Requests", false),
        ("404 Not Found", true),
        ("410 Gone", true),
    ] {
        let server = Server::new(move |path| {
            if path == "/phpinfo.php" {
                response(status, "", "unavailable")
            } else {
                response("200 OK", "X-Powered-By: PHP/8.4.27\r\n", "OK")
            }
        });
        let result = scan(&server.url, limits(), true, &["phpinfo.php".into()]).unwrap();
        assert_eq!(result.requests_sent, 2);
        assert_eq!(result.analysis.coverage_complete, completed, "{status}");
        assert_eq!(result.analysis.gaps.is_empty(), completed, "{status}");
        assert_eq!(
            result.verdict,
            if completed {
                Verdict::FixFloorObserved
            } else {
                Verdict::Inconclusive
            },
            "{status}"
        );
        let summary = Report::new(vec![result]).summary;
        assert_eq!(summary.limited_coverage, usize::from(!completed));
    }
}

#[test]
fn consistent_samples_raise_observation_confidence_without_certifying_security() {
    let server = Server::new(|_| response("200 OK", "X-Powered-By: PHP/8.4.27\r\n", "OK"));
    let result = scan_with_samples(&server.url, limits(), false, &[], 3).unwrap();
    assert_eq!(
        result.analysis.version_confidence,
        VersionConfidence::ConsistentSamples
    );
    assert_eq!(result.analysis.samples_completed, 3);
    assert!(result.analysis.coverage_complete);
    assert_eq!(result.verdict, Verdict::FixFloorObserved);
    assert!(!result.analysis.certified && !result.analysis.secure);
}

#[test]
fn a_matching_diagnostic_corroborates_the_header_without_certifying_security() {
    let server = Server::new(|path| {
        if path == "/phpinfo.php" {
            response("200 OK", "", &phpinfo("8.4.27"))
        } else {
            response("200 OK", "X-Powered-By: PHP/8.4.27\r\n", "OK")
        }
    });
    let result = scan(&server.url, limits(), true, &["phpinfo.php".into()]).unwrap();
    assert_eq!(
        result.analysis.version_confidence,
        VersionConfidence::Corroborated
    );
    assert!(result.analysis.coverage_complete);
    assert!(!result.analysis.certified && !result.analysis.secure);
    let report = Report::new(vec![result]);
    assert_eq!(report.summary.php_corroborated, 1);
    assert_eq!(report.summary.certified, 0);
    assert_eq!(report.summary.secure, 0);
}

#[test]
fn summary_outcomes_partition_targets_and_never_attest_security() {
    let affected = Server::new(|_| response("200 OK", "X-Powered-By: PHP/8.4.26\r\n", "OK"));
    let fixed = Server::new(|_| response("200 OK", "X-Powered-By: PHP/8.4.27\r\n", "OK"));
    let unknown = Server::new(|_| response("200 OK", "", "OK"));
    let mut no_budget = limits();
    no_budget.max_requests = 0;
    let report = Report::new(vec![
        scan(&affected.url, limits(), false, &[]).unwrap(),
        scan(&fixed.url, limits(), false, &[]).unwrap(),
        scan(&unknown.url, limits(), false, &[]).unwrap(),
        scan(&fixed.url, no_budget, false, &[]).unwrap(),
    ]);
    let summary = report.summary;
    assert_eq!(summary.urls_analyzed, 4);
    assert_eq!(summary.http_verified, 3);
    assert_eq!(summary.potentially_affected, 1);
    assert_eq!(summary.fix_floor_observed, 1);
    assert_eq!(summary.unknown, 1);
    assert_eq!(summary.errors, 1);
    assert_eq!(
        summary.potentially_affected
            + summary.fix_floor_observed
            + summary.unknown
            + summary.errors,
        summary.urls_analyzed
    );
    assert_eq!(summary.certified, 0);
    assert_eq!(summary.secure, 0);
}

#[test]
fn human_summary_and_json_summary_are_separate_output_modes() {
    let server = Server::new(|_| response("200 OK", "X-Powered-By: PHP/8.4.27\r\n", "OK"));
    let human = Command::new(env!("CARGO_BIN_EXE_anatoly"))
        .args([
            "scan",
            &server.url,
            "--no-discover",
            "--no-banner",
            "--color",
            "never",
            "--delay-ms",
            "0",
        ])
        .output()
        .unwrap();
    assert!(human.status.success());
    let text = String::from_utf8(human.stdout).unwrap();
    assert!(text.contains("SCAN SUMMARY"));
    assert!(text.contains("URLs analyzed"));
    assert!(text.contains("Certified / secure"));
    assert!(serde_json::from_str::<serde_json::Value>(&text).is_err());
    let machine = Command::new(env!("CARGO_BIN_EXE_anatoly"))
        .args([
            "scan",
            &server.url,
            "--no-discover",
            "--json",
            "--delay-ms",
            "0",
        ])
        .output()
        .unwrap();
    assert!(machine.status.success());
    let value: serde_json::Value = serde_json::from_slice(&machine.stdout).unwrap();
    assert_eq!(value["summary"]["urls_analyzed"], 1);
    assert_eq!(value["summary"]["secure"], 0);
    assert_eq!(value["summary"]["certified"], 0);
    assert_eq!(value["targets"][0]["analysis"]["samples_requested"], 3);
    assert_eq!(value["targets"][0]["analysis"]["samples_completed"], 3);
}
