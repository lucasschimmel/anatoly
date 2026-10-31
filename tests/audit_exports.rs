#[allow(dead_code)]
mod audit_support;

use anatoly::scan::{Report, scan};
use audit_support::{Files, Server, cli, combined, command, response};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::fs;

fn snapshot(header: &str) -> Value {
    let header = header.to_owned();
    let server = Server::new(move |_| response("200 OK", &header, "OK"));
    let limits = anatoly::http::Limits {
        timeout: std::time::Duration::from_secs(3),
        max_requests: 4,
        max_body: 4096,
        delay: std::time::Duration::ZERO,
    };
    serde_json::to_value(Report::new(vec![
        scan(&server.url, limits, false, &[]).unwrap(),
    ]))
    .unwrap()
}

#[test]
fn simultaneous_json_csv_and_sarif_exports_preserve_privacy_and_ci_semantics() {
    let mut files = Files::new();
    let full = files.path("json");
    let csv = files.path("csv");
    let sarif = files.path("sarif");
    let server = Server::new(|_| {
        response(
            "200 OK",
            "X-PHP-Version: 8.4.26\r\ncf-ray: ANATOLY_RAY_EXPORT_FIXTURE\r\n",
            "OK",
        )
    });
    let target = format!("{}?context=ANATOLY_QUERY_EXPORT_FIXTURE", server.url);
    let output = command(&[
        "scan",
        &target,
        "--profile",
        "quick",
        "--no-proxy",
        "--json",
        "--basic-auth-env",
        "ANATOLY_TEST_BASIC",
        "-H",
        "X-Audit: ANATOLY_HEADER_EXPORT_FIXTURE",
        "-o",
        full.to_str().unwrap(),
        "--csv",
        csv.to_str().unwrap(),
        "--sarif",
        sarif.to_str().unwrap(),
    ])
    .env("ANATOLY_TEST_BASIC", "fixture:ANATOLY_AUTH_EXPORT_FIXTURE")
    .output()
    .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stdout: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout["targets"][0]["verdict"], "potentially_affected");
    let report: Value = serde_json::from_slice(&fs::read(&full).unwrap()).unwrap();
    assert_eq!(report["summary"]["secure"], 0);
    let csv_text = fs::read_to_string(&csv).unwrap();
    assert!(csv_text.contains("detection_level"));
    assert!(csv_text.contains("potentially_affected"));
    let sarif_json: Value = serde_json::from_slice(&fs::read(&sarif).unwrap()).unwrap();
    assert_eq!(sarif_json["version"], "2.1.0");
    let results = sarif_json["runs"][0]["results"].as_array().unwrap();
    assert!(
        results
            .iter()
            .any(|r| r["ruleId"] == "ANATOLY-PHP2SHELL-VERSION" && r["level"] == "warning")
    );
    let all = format!("{}{}{}{}", combined(&output), report, csv_text, sarif_json);
    for private in [
        "ANATOLY_QUERY_EXPORT_FIXTURE",
        "ANATOLY_RAY_EXPORT_FIXTURE",
        "ANATOLY_HEADER_EXPORT_FIXTURE",
        "ANATOLY_AUTH_EXPORT_FIXTURE",
    ] {
        assert!(!all.contains(private));
    }
    assert!(!all.contains(&STANDARD.encode("fixture:ANATOLY_AUTH_EXPORT_FIXTURE")));
}

#[test]
fn existing_export_destination_is_refused_before_any_network_request() {
    let mut files = Files::new();
    let existing = files.write("csv", "keep this report");
    let server = Server::new(|_| response("200 OK", "", "not requested"));
    let output = cli(&[
        "scan",
        &server.url,
        "--json",
        "--csv",
        existing.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(existing).unwrap(), "keep this report");
    assert!(server.requests.lock().unwrap().is_empty());
}

#[test]
fn aliased_output_paths_are_rejected_before_http_or_creating_reports() {
    let mut files = Files::new();
    let output = files.path("json");
    let alias = format!(
        "{}/./{}",
        output.parent().unwrap().display(),
        output.file_name().unwrap().to_string_lossy()
    );
    let server = Server::new(|_| response("200 OK", "", "not requested"));
    let result = cli(&[
        "scan",
        &server.url,
        "--json",
        "-o",
        output.to_str().unwrap(),
        "--csv",
        &alias,
    ]);
    assert!(!result.status.success());
    assert!(server.requests.lock().unwrap().is_empty());
    assert!(!output.exists());
}

#[test]
fn offline_csv_neutralizes_spreadsheet_formulas_and_preserves_quoted_structure() {
    let mut files = Files::new();
    let mut report = snapshot("X-PHP-Version: 8.4.27\r\n");
    report["targets"][0]["limitations"] = json!([
        "=HYPERLINK(\"https://example.invalid\",\"fixture\")",
        "comma, quote \" and line\nsecond"
    ]);
    let input = files.write("json", serde_json::to_vec(&report).unwrap());
    let output = files.path("csv");
    let result = cli(&[
        "report",
        input.to_str().unwrap(),
        "-o",
        output.to_str().unwrap(),
        "--format",
        "csv",
        "--json",
    ]);
    assert!(result.status.success(), "{}", combined(&result));
    let csv = fs::read_to_string(output).unwrap();
    assert!(csv.contains("'=HYPERLINK("));
    assert!(csv.contains("\"\"https://example.invalid\"\""));
    assert!(csv.contains("security_certified"));
    assert_eq!(csv.lines().count(), 2);
}

#[test]
fn offline_sarif_marks_unknown_as_note_instead_of_confirmed_vulnerability() {
    let mut files = Files::new();
    let input = files.write("json", serde_json::to_vec(&snapshot("")).unwrap());
    let output = files.path("sarif");
    let result = cli(&[
        "report",
        input.to_str().unwrap(),
        "-o",
        output.to_str().unwrap(),
        "--format",
        "sarif",
        "--json",
    ]);
    assert!(result.status.success(), "{}", combined(&result));
    let sarif: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    let findings = sarif["runs"][0]["results"].as_array().unwrap();
    assert!(!findings.is_empty());
    assert!(
        findings
            .iter()
            .all(|r| r["ruleId"] == "ANATOLY-ASSESSMENT-INCOMPLETE" && r["level"] == "note")
    );
}

#[test]
fn clean_fixed_floor_report_has_no_sarif_vulnerability_finding() {
    let mut files = Files::new();
    let input = files.write(
        "json",
        serde_json::to_vec(&snapshot("X-PHP-Version: 8.4.27\r\n")).unwrap(),
    );
    let output = files.path("sarif");
    let result = cli(&[
        "report",
        input.to_str().unwrap(),
        "-o",
        output.to_str().unwrap(),
        "--format",
        "sarif",
        "--json",
    ]);
    assert!(result.status.success(), "{}", combined(&result));
    let sarif: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
    assert!(sarif["runs"][0]["results"].as_array().unwrap().is_empty());
}

#[test]
fn authenticated_diagnostic_sarif_describes_request_access_without_claiming_public_exposure() {
    let mut files = Files::new();
    let sarif = files.path("sarif");
    let server = Server::new(|request| {
        if !request
            .to_ascii_lowercase()
            .contains("authorization: basic ")
        {
            return response("401 Unauthorized", "", "authentication required");
        }
        if request.starts_with("GET /phpinfo.php ") {
            response(
                "200 OK",
                "",
                "<h1>PHP Version 8.4.27</h1><h2>Configuration</h2><p>PHP Credits</p><table><tr><td>Server API</td><td>FPM/FastCGI</td></tr></table>",
            )
        } else if request.starts_with("GET /info.php ") {
            response("404 Not Found", "", "not found")
        } else {
            response("200 OK", "X-PHP-Version: 8.4.27\r\n", "OK")
        }
    });
    let output = command(&[
        "scan",
        &server.url,
        "--json",
        "--no-proxy",
        "--samples",
        "1",
        "--delay-ms",
        "0",
        "--basic-auth-env",
        "ANATOLY_TEST_BASIC",
        "--sarif",
        sarif.to_str().unwrap(),
    ])
    .env(
        "ANATOLY_TEST_BASIC",
        "fixture:ANATOLY_DIAGNOSTIC_AUTH_FIXTURE",
    )
    .output()
    .unwrap();
    assert!(output.status.success(), "{}", combined(&output));
    let report: Value = serde_json::from_slice(&fs::read(sarif).unwrap()).unwrap();
    let finding = report["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["ruleId"] == "ANATOLY-DIAGNOSTIC-DISCLOSURE")
        .unwrap();
    let message = finding["message"]["text"].as_str().unwrap();
    assert!(message.contains("to this request"));
    assert!(!message.to_ascii_lowercase().contains("public"));
    assert!(
        !report
            .to_string()
            .contains("ANATOLY_DIAGNOSTIC_AUTH_FIXTURE")
    );
}
