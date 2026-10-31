mod common;
use common::{Server, limits, response};
use std::process::Command;

use anatoly::{
    assessment::{Verdict, assess},
    fingerprint::{Patterns, resolve},
    http::{Transport, allowed_redirect, display_url, validate_url},
    policy::{PhpVersion, VersionStatus, classify},
    scan::{Report, scan},
    ui::safe_text,
};

fn version(minor: u16, patch: u16) -> PhpVersion {
    PhpVersion {
        major: 8,
        minor,
        patch,
        prerelease: false,
    }
}

#[test]
fn each_upstream_floor_switches_from_affected_to_fix_floor_observed() {
    for (minor, floor) in [(2, 35), (3, 36), (4, 27), (5, 12)] {
        assert_eq!(
            classify(&version(minor, floor - 1)),
            VersionStatus::AffectedRange
        );
        assert_eq!(classify(&version(minor, floor)), VersionStatus::FixFloorMet);
        assert_eq!(
            classify(&version(minor, floor + 1)),
            VersionStatus::FixFloorMet
        );
    }
}

#[test]
fn unsupported_future_and_prerelease_versions_are_never_reported_as_fixed() {
    assert_eq!(classify(&version(1, 34)), VersionStatus::UnsupportedBranch);
    assert_eq!(classify(&version(6, 0)), VersionStatus::UnreviewedBranch);
    let mut rc = version(4, 27);
    rc.prerelease = true;
    assert_eq!(classify(&rc), VersionStatus::Prerelease);
    assert_eq!(
        assess(VersionStatus::FixFloorMet, false),
        Verdict::Inconclusive
    );
}

#[test]
fn conflicting_version_sources_remove_the_selected_version() {
    let patterns = Patterns::new().unwrap();
    let mut evidence = patterns.header_evidence("PHP/8.4.26", "header");
    evidence.extend(patterns.header_evidence("Apache PHP/8.4.27", "server"));
    assert_eq!(resolve(&evidence), (None, VersionStatus::Conflicting));
    assert_eq!(resolve(&[]), (None, VersionStatus::Unknown));
}

#[test]
fn prerelease_header_is_not_promoted_to_a_stable_patch() {
    let patterns = Patterns::new().unwrap();
    for header in [
        "PHP/8.4.27RC1",
        "PHP/8.4.27-RC1",
        "PHP/8.4.27-dev",
        "PHP/8.4.27~beta1",
    ] {
        let evidence = patterns.header_evidence(header, "header");
        assert_eq!(resolve(&evidence).1, VersionStatus::Prerelease, "{header}");
    }
}

const PHPINFO: &str = r#"<html><h1>PHP Version 8.4.26</h1>
<h2>Configuration</h2><a>PHP Credits</a><table>
<tr><td class="e">session.upload_progress.enabled</td><td class="v">Off</td><td class="v">On</td></tr>
<tr><td class="e">memory_limit</td><td class="v">128M</td><td class="v">128M</td></tr>
<tr><td class="e">Server API</td><td class="v">FPM/FastCGI</td></tr>
</table></html>"#;

#[test]
fn phpinfo_keeps_local_master_and_sapi_evidence_separate() {
    let patterns = Patterns::new().unwrap();
    let (evidence, directives) = patterns.phpinfo(PHPINFO, "diagnostic");
    assert_eq!(resolve(&evidence).1, VersionStatus::AffectedRange);
    let progress = directives
        .iter()
        .find(|d| d.name == "session.upload_progress.enabled")
        .unwrap();
    assert_eq!(progress.local_value, "Off");
    assert_eq!(progress.master_value.as_deref(), Some("On"));
    assert!(
        directives
            .iter()
            .any(|d| d.name == "server api" && d.local_value == "FPM/FastCGI")
    );
}

#[test]
fn ordinary_pages_mentioning_php_are_not_treated_as_runtime_evidence() {
    let patterns = Patterns::new().unwrap();
    let (evidence, directives) =
        patterns.phpinfo("<h1>Our guide to PHP Version 8.4.27</h1>", "article");
    assert!(evidence.is_empty() && directives.is_empty());
}

#[test]
fn url_validation_blocks_credentials_fragments_and_non_http_targets() {
    for value in [
        "ftp://example.test",
        "example.test",
        "https://user:example@example.test/",
        "https://example.test/#fragment",
    ] {
        assert!(validate_url(value).is_err(), "accepted {value}");
    }
    let base = validate_url("https://example.test/a?private=value").unwrap();
    assert_eq!(display_url(&base), "https://example.test/a");
    assert!(allowed_redirect(&base, &base.join("/b").unwrap()));
    assert!(!allowed_redirect(
        &base,
        &validate_url("http://example.test/").unwrap()
    ));
    assert!(!allowed_redirect(
        &base,
        &validate_url("https://other.test/").unwrap()
    ));
}

#[test]
fn untrusted_terminal_controls_are_neutralized() {
    let text = safe_text("hello\x1b[31m\r\n\u{202e}world");
    assert!(
        !text.contains('\x1b')
            && !text.contains('\r')
            && !text.contains('\n')
            && !text.contains('\u{202e}')
    );
    assert!(text.contains("hello") && text.contains("world"));
}

#[test]
fn affected_version_gets_configuration_checks_without_turning_off_progress_into_safety() {
    let server = Server::new(|path| {
        if path == "/phpinfo.php" {
            response("200 OK", "", PHPINFO)
        } else {
            response("200 OK", "X-Powered-By: PHP/8.4.26\r\n", "OK")
        }
    });
    let result = scan(&server.url, limits(), true, &["phpinfo.php".into()]).unwrap();
    assert_eq!(result.verdict, Verdict::PotentiallyAffected);
    assert_eq!(result.requests_sent, 2);
    assert!(result.directives.iter().any(|d| d.local_value == "Off"));
    assert!(
        result
            .cves
            .iter()
            .all(|c| c.exploitation == "not_attempted")
    );
    assert_eq!(Report::new(vec![result]).exit_code(), 1);
}

#[test]
fn fixed_advertised_version_checks_diagnostics_without_claiming_verified_patches() {
    let server = Server::new(|_| response("200 OK", "X-Powered-By: PHP/8.4.27\r\n", "OK"));
    let result = scan(&server.url, limits(), true, &["phpinfo.php".into()]).unwrap();
    assert_eq!(result.verdict, Verdict::FixFloorObserved);
    assert_eq!(result.requests_sent, 2);
    assert!(result.cves.iter().all(|c| c.detail.contains("unverified")));
    assert_eq!(Report::new(vec![result]).exit_code(), 0);
}

#[test]
fn hidden_version_and_access_denials_stay_inconclusive() {
    for (status, headers) in [
        ("200 OK", ""),
        ("403 Forbidden", "X-Powered-By: PHP/8.4.27\r\n"),
    ] {
        let server = Server::new(move |_| response(status, headers, "unavailable"));
        let result = scan(&server.url, limits(), false, &[]).unwrap();
        assert_eq!(result.verdict, Verdict::Inconclusive);
        assert_eq!(Report::new(vec![result]).exit_code(), 2);
    }
}

#[test]
fn redirect_loop_obeys_one_shared_request_budget() {
    let server = Server::new(|_| response("302 Found", "Location: /again\r\n", ""));
    let mut bounds = limits();
    bounds.max_requests = 2;
    let result = scan(&server.url, bounds, true, &["phpinfo.php".into()]).unwrap();
    assert_eq!(result.requests_sent, 2);
    assert_eq!(server.paths.lock().unwrap().len(), 2);
    assert!(result.limitations.iter().any(|s| s.contains("budget")));
}

#[test]
fn cross_origin_redirect_is_recorded_without_following_it() {
    let destination = Server::new(|_| response("200 OK", "", "must not be requested"));
    let destination_url = destination.url.clone();
    let server = Server::new(move |_| {
        response("302 Found", &format!("Location: {destination_url}\r\n"), "")
    });
    let result = scan(&server.url, limits(), false, &[]).unwrap();
    assert_eq!(result.requests_sent, 1);
    assert!(result.observations[0].redirect_blocked);
    assert!(destination.paths.lock().unwrap().is_empty());
}

#[test]
fn body_limit_is_enforced_before_retaining_response_data() {
    let server = Server::new(|_| response("200 OK", "", &"x".repeat(2048)));
    let mut bounds = limits();
    bounds.max_body = 128;
    let mut transport = Transport::new(bounds).unwrap();
    let page = transport.get(&validate_url(&server.url).unwrap()).unwrap();
    assert_eq!(page.body.len(), 128);
    assert!(transport.observations[0].truncated);
}

fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_anatoly"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn metadata_commands_emit_parseable_json_without_a_banner() {
    for mode in ["version", "builds", "credits"] {
        let output = cli(&[mode, "--json"]);
        assert!(output.status.success());
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(value.is_object());
        assert!(!output.stdout.contains(&0x1b));
    }
}

#[test]
fn cli_scan_preserves_machine_readable_verdict_and_exit_code() {
    let server = Server::new(|_| response("200 OK", "X-Powered-By: PHP/8.4.26\r\n", "OK"));
    let output = cli(&[
        "scan",
        &server.url,
        "--no-discover",
        "--json",
        "--delay-ms",
        "0",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["targets"][0]["verdict"], "potentially_affected");
    assert_eq!(value["targets"][0]["requests_sent"], 3);
}

#[test]
fn cli_validates_all_diagnostic_origins_before_any_network_request() {
    let server = Server::new(|_| response("200 OK", "", "OK"));
    let output = cli(&[
        "scan",
        &server.url,
        "--diagnostic-path",
        "https://outside.invalid/phpinfo.php",
        "--json",
    ]);
    assert!(!output.status.success());
    assert!(server.paths.lock().unwrap().is_empty());
}

#[test]
fn library_rejects_cross_origin_diagnostic_paths_before_network() {
    let server = Server::new(|_| response("200 OK", "", "OK"));
    let result = scan(
        &server.url,
        limits(),
        true,
        &["https://outside.invalid/phpinfo.php".into()],
    );
    assert!(result.is_err());
    assert!(server.paths.lock().unwrap().is_empty());
}

#[test]
fn an_existing_report_is_preserved_without_scanning() {
    let server = Server::new(|_| response("200 OK", "", "OK"));
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "anatoly-report-test-{}-{unique}.json",
        std::process::id()
    ));
    std::fs::write(&path, "original report").unwrap();
    let output = cli(&[
        "scan",
        &server.url,
        "--output",
        path.to_str().unwrap(),
        "--json",
    ]);
    let contents = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(!output.status.success());
    assert_eq!(contents, "original report");
    assert!(server.paths.lock().unwrap().is_empty());
}
