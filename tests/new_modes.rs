#[allow(dead_code)]
mod common;

use anatoly::scan::{Report, scan};
use common::{Server, limits, response};
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

struct FixtureFiles(Vec<PathBuf>);

impl FixtureFiles {
    fn new() -> Self {
        Self(vec![])
    }
    fn path(&mut self, extension: &str) -> PathBuf {
        let unique = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "anatoly-modes-{}-{unique}.{extension}",
            std::process::id()
        ));
        assert!(!path.exists(), "fixture filename must be new");
        self.0.push(path.clone());
        path
    }
    fn json(&mut self, value: &Value) -> PathBuf {
        let path = self.path("json");
        fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        path
    }
}

impl Drop for FixtureFiles {
    fn drop(&mut self) {
        for path in &self.0 {
            if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
    }
}

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_anatoly"))
        .args(args)
        .output()
        .unwrap()
}

fn snapshot(header: &str) -> Value {
    let header = header.to_owned();
    let server = Server::new(move |_| response("200 OK", &header, "OK"));
    let report = scan(&server.url, limits(), false, &[]).unwrap();
    serde_json::to_value(Report::new(vec![report])).unwrap()
}

#[test]
fn offline_modes_reject_unrelated_json_instead_of_treating_it_as_a_scan() {
    let mut files = FixtureFiles::new();
    let input = files.json(&json!({"tool":"other", "targets":[]}));
    for command in ["explain", "policy"] {
        let result = cli(&[command, input.to_str().unwrap(), "--json"]);
        assert!(
            !result.status.success(),
            "{command} accepted unrelated JSON"
        );
    }
}

#[test]
fn report_escapes_untrusted_text_and_refuses_to_overwrite_existing_html() {
    let mut files = FixtureFiles::new();
    let mut report = snapshot("X-PHP-Version: 8.4.27\r\n");
    report["targets"][0]["limitations"] = json!(["<script>alert('fixture')</script>"]);
    let input = files.json(&report);
    let output = files.path("html");
    let args = [
        "report",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--json",
    ];

    let first = cli(&args);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let html = fs::read_to_string(&output).unwrap();
    assert!(html.contains("Content-Security-Policy"));
    assert!(!html.contains("<script>"));
    assert!(html.contains("&lt;script&gt;"));
    let second = cli(&args);
    assert!(!second.status.success());
    assert_eq!(fs::read_to_string(&output).unwrap(), html);
}

#[test]
fn explain_preserves_per_version_proofs_and_their_confidence_limits() {
    let mut files = FixtureFiles::new();
    let input = files.json(&snapshot("X-PHP-Version: 8.4.26\r\n"));
    let result = cli(&["explain", input.to_str().unwrap(), "--json"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    let text = value.to_string();
    assert!(text.contains("8.4.26"));
    assert!(text.contains("declared"));
    assert!(text.to_ascii_lowercase().contains("x-php-version"));
    assert!(!text.contains("\"certified\":true"));
}

#[test]
fn headers_audit_keeps_cookie_values_and_target_queries_out_of_reports() {
    const PRIVATE: &str = "ANATOLY_COOKIE_FIXTURE_VALUE";
    let server = Server::new(|_| {
        response(
            "200 OK",
            &format!(
                "Set-Cookie: PHPSESSID={PRIVATE}; HttpOnly; SameSite=Lax\r\nX-Content-Type-Options: nosniff\r\n"
            ),
            "OK",
        )
    });
    let target = format!("{}?fixture={PRIVATE}", server.url);
    let result = cli(&[
        "headers",
        &target,
        "--json",
        "--delay-ms",
        "0",
        "--no-proxy",
    ]);
    assert!(result.status.code().is_some());
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    let text = value.to_string();
    assert!(text.contains("PHPSESSID"));
    assert!(!text.contains(PRIVATE));
    assert!(!text.contains("?fixture"));
    assert_eq!(server.paths.lock().unwrap().len(), 1);
}

#[test]
fn doctor_validates_scope_without_sending_network_requests() {
    let server = Server::new(|_| response("200 OK", "", "not requested"));
    let valid = cli(&["doctor", &server.url, "--json", "--no-proxy"]);
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stderr)
    );
    serde_json::from_slice::<Value>(&valid.stdout).unwrap();
    let invalid = cli(&["doctor", &server.url, "--https-only", "--json"]);
    assert!(!invalid.status.success());
    assert!(server.paths.lock().unwrap().is_empty());
}

#[test]
fn compare_ignores_duplicate_proofs_but_detects_changed_coverage() {
    let mut files = FixtureFiles::new();
    let before = snapshot("X-PHP-Version: 8.4.27\r\n");
    let baseline = files.json(&before);
    let mut duplicated = before.clone();
    let proof = duplicated["targets"][0]["evidence"][0].clone();
    duplicated["targets"][0]["evidence"]
        .as_array_mut()
        .unwrap()
        .push(proof);
    let current = files.json(&duplicated);
    let unchanged = cli(&[
        "compare",
        baseline.to_str().unwrap(),
        current.to_str().unwrap(),
        "--json",
    ]);
    assert!(unchanged.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&unchanged.stdout).unwrap()["changed"],
        false
    );

    duplicated["targets"][0]["analysis"]["coverage_complete"] = json!(false);
    duplicated["targets"][0]["analysis"]["gaps"] = json!(["Target budget exhausted"]);
    duplicated["targets"][0]["verdict"] = json!("inconclusive");
    fs::write(&current, serde_json::to_vec(&duplicated).unwrap()).unwrap();
    let changed = cli(&[
        "compare",
        baseline.to_str().unwrap(),
        current.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(changed.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&changed.stdout).unwrap();
    assert_eq!(value["changes"][0]["change"], "changed");
}

#[test]
fn policy_keeps_missing_version_and_unproven_diagnostic_absence_unknown() {
    let mut files = FixtureFiles::new();
    let input = files.json(&snapshot(""));
    let rules = files.json(&json!({"require_https":false}));
    let result = cli(&[
        "policy",
        input.to_str().unwrap(),
        "--rules",
        rules.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(
        result.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["status"], "unknown");
    assert!(
        value["targets"][0]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|check| check["status"] == "unknown")
    );
}

#[test]
fn policy_rejects_a_fixed_verdict_without_supporting_version_evidence() {
    let mut files = FixtureFiles::new();
    let mut report = snapshot("X-PHP-Version: 8.4.27\r\n");
    report["targets"][0]["evidence"] = json!([]);
    report["targets"][0]["version_candidates"] = json!([]);
    let input = files.json(&report);
    let result = cli(&["policy", input.to_str().unwrap(), "--json"]);
    assert_eq!(result.status.code(), Some(3));
    assert!(!String::from_utf8_lossy(&result.stdout).contains("\"status\": \"pass\""));
}

#[test]
fn exposure_dry_run_selects_extended_discovery_without_requests() {
    let server = Server::new(|_| response("200 OK", "", "not requested"));
    let result = cli(&["exposure", &server.url, "--dry-run", "--json"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let plan: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(plan["configuration"]["deep"], true);
    assert_eq!(plan["configuration"]["max_requests"], 32);
    let incompatible = cli(&[
        "exposure",
        &server.url,
        "--profile",
        "quick",
        "--dry-run",
        "--json",
    ]);
    assert!(!incompatible.status.success());
    assert!(server.paths.lock().unwrap().is_empty());
}

#[test]
fn watch_completes_finite_rounds_and_emits_no_change_event_for_identical_results() {
    let server = Server::new(|_| response("200 OK", "X-PHP-Version: 8.4.27\r\n", "OK"));
    let result = cli(&[
        "watch",
        &server.url,
        "--profile",
        "quick",
        "--iterations",
        "2",
        "--interval",
        "1",
        "--delay-ms",
        "0",
        "--no-proxy",
        "--json",
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["rounds_completed"], 2);
    let events = value["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["type"], "baseline");
    assert_eq!(server.paths.lock().unwrap().len(), 2);
}

#[test]
fn watch_reports_a_version_change_after_the_baseline() {
    let count = AtomicU64::new(0);
    let server = Server::new(move |_| {
        let version = if count.fetch_add(1, Ordering::Relaxed) == 0 {
            "8.4.26"
        } else {
            "8.4.27"
        };
        response("200 OK", &format!("X-PHP-Version: {version}\r\n"), "OK")
    });
    let result = cli(&[
        "watch",
        &server.url,
        "--profile",
        "quick",
        "--iterations",
        "2",
        "--interval",
        "1",
        "--delay-ms",
        "0",
        "--no-proxy",
        "--json",
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    let events = value["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1]["type"], "change");
    assert_eq!(events[1]["round"], 2);
    assert_eq!(value["final_report"]["targets"][0]["version"]["patch"], 27);
}
