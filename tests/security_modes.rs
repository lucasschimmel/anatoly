#[allow(dead_code)]
mod common;

use anatoly::scan::{Report, scan};
use common::{Server, limits, response};
use serde_json::{Value, json};
use std::{fs, process::Command};

#[test]
fn duplicate_samesite_attributes_remain_ambiguous_without_exposing_cookie_values() {
    const PRIVATE: &str = "ANATOLY_AMBIGUOUS_COOKIE_FIXTURE";
    let server = Server::new(|_| {
        response(
            "200 OK",
            &format!(
                "Set-Cookie: PHPSESSID={PRIVATE}; Secure; HttpOnly; SameSite=Lax; SameSite=None\r\n"
            ),
            "OK",
        )
    });
    let result = Command::new(env!("CARGO_BIN_EXE_anatoly"))
        .args(["headers", &server.url, "--json", "--no-proxy"])
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    let findings = value["targets"][0]["findings"].as_array().unwrap();
    let cookie = findings
        .iter()
        .find(|f| f["name"] == "cookie PHPSESSID")
        .unwrap();
    assert_eq!(cookie["status"], "unknown");
    assert!(cookie["proof"].as_str().unwrap().contains("ambiguous"));
    assert!(!value.to_string().contains(PRIVATE));
}

#[test]
fn malformed_candidates_and_false_corroboration_cannot_pass_policy_validation() {
    let server = Server::new(|_| response("200 OK", "X-PHP-Version: 8.4.27\r\n", "OK"));
    let target = scan(&server.url, limits(), false, &[]).unwrap();
    let original = serde_json::to_value(Report::new(vec![target])).unwrap();
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("anatoly-invalid-candidates-{unique}.json"));
    for scenario in ["null_candidate", "false_corroboration"] {
        let mut report = original.clone();
        if scenario == "null_candidate" {
            report["targets"][0]["version_candidates"] = json!([null]);
        } else {
            report["targets"][0]["analysis"]["detection_level"] = json!("corroborated");
            report["targets"][0]["analysis"]["version_confidence"] = json!("corroborated");
            report["targets"][0]["version_candidates"][0]["level"] = json!("corroborated");
        }
        fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_anatoly"))
            .args(["policy", path.to_str().unwrap(), "--json"])
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(3), "scenario={scenario}");
    }
    fs::remove_file(path).unwrap();
}
