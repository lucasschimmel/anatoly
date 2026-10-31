#[allow(dead_code)]
mod common;

use common::{Server, response};
use std::process::{Command, Output};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_anatoly"))
        .args(args)
        .output()
        .unwrap()
}

fn plan(target: &str, flags: &[&str]) -> serde_json::Value {
    let mut args = vec!["scan", target, "--dry-run", "--json"];
    args.extend_from_slice(flags);
    let output = cli(&args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn profiles_produce_the_expected_validated_plan_without_network_requests() {
    let server = Server::new(|_| response("200 OK", "", "not requested"));
    for (profile, samples, budget, delay, discovery, deep) in [
        ("quick", 1, 4, 500.0, false, false),
        ("balanced", 3, 8, 150.0, true, false),
        ("thorough", 5, 32, 150.0, true, true),
    ] {
        let value = plan(&server.url, &["--profile", profile]);
        assert_eq!(value["type"], "scan_plan");
        assert_eq!(value["network_requests_sent"], 0);
        let config = &value["configuration"];
        assert_eq!(config["profile"], profile);
        assert_eq!(config["samples"], samples);
        assert_eq!(config["max_requests"], budget);
        assert_eq!(config["effective_delay_ms"].as_f64(), Some(delay));
        assert_eq!(config["discovery"], discovery);
        assert_eq!(config["deep"], deep);
    }
    assert!(server.paths.lock().unwrap().is_empty());
}

#[test]
fn explicit_numeric_controls_override_profiles_but_rate_cannot_weaken_spacing() {
    let server = Server::new(|_| response("200 OK", "", "not requested"));
    let value = plan(
        &server.url,
        &[
            "--profile",
            "thorough",
            "--samples",
            "2",
            "--max-requests",
            "7",
            "--delay-ms",
            "700",
            "--rate-limit",
            "10",
            "--connect-timeout",
            "2",
            "--target-timeout",
            "3",
            "--max-redirects",
            "1",
        ],
    );
    let config = &value["configuration"];
    assert_eq!(config["samples"], 2);
    assert_eq!(config["max_requests"], 7);
    assert_eq!(config["effective_delay_ms"].as_f64(), Some(700.0));
    assert_eq!(config["connect_timeout_seconds"], 2);
    assert_eq!(config["target_timeout_seconds"], 3);
    assert_eq!(config["max_redirects"], 1);
    let limited = plan(&server.url, &["--delay-ms", "0", "--rate-limit", "2"]);
    assert_eq!(
        limited["configuration"]["effective_delay_ms"].as_f64(),
        Some(500.0)
    );
    assert!(server.paths.lock().unwrap().is_empty());
}

#[test]
fn dry_run_redacts_target_queries_and_records_method_and_transport_controls() {
    let server = Server::new(|_| response("200 OK", "", "not requested"));
    let target = format!("{}?fixture=PRIVATE_FIXTURE_VALUE", server.url);
    let value = plan(
        &target,
        &[
            "--no-proxy",
            "--no-redirects",
            "--no-cookie-hints",
            "--no-hypotheses",
            "--no-linked-discovery",
        ],
    );
    assert_eq!(value["targets"][0], server.url);
    assert!(!value.to_string().contains("PRIVATE_FIXTURE_VALUE"));
    let config = &value["configuration"];
    assert_eq!(config["environment_proxies_disabled"], true);
    assert_eq!(config["max_redirects"], 0);
    for flag in ["no_cookie_hints", "no_hypotheses", "no_linked_discovery"] {
        assert_eq!(config[flag], true);
    }
    assert!(server.paths.lock().unwrap().is_empty());
}

#[test]
fn conflicting_flags_and_invalid_configuration_are_rejected_before_http() {
    let server = Server::new(|_| response("200 OK", "", "not requested"));
    let cases = [
        vec!["--profile", "quick", "--deep"],
        vec!["--profile", "quick", "--diagnostic-path", "phpinfo.php"],
        vec!["--proxy", "http://127.0.0.1:9", "--no-proxy"],
        vec!["--proxy", "socks5://127.0.0.1:9"],
        vec!["--proxy", "http://127.0.0.1:9/invalid-path"],
        vec!["--max-redirects", "1", "--no-redirects"],
        vec!["--jsonl", "--json"],
        vec!["--jsonl", "--summary-only"],
        vec!["--jsonl", "--dry-run"],
        vec!["--summary-only", "--json"],
        vec!["--summary-only", "--dry-run"],
        vec!["--rate-limit", "0"],
        vec!["--allow-host", "127.0.0.1:80"],
        vec!["--allow-host", "localhost:443"],
        vec![
            "--ca-cert",
            "this-public-fixture-certificate-does-not-exist.pem",
        ],
    ];
    for flags in cases {
        let mut args = vec!["scan", &server.url];
        args.extend_from_slice(&flags);
        let output = cli(&args);
        assert!(!output.status.success(), "accepted {flags:?}");
    }
    assert!(server.paths.lock().unwrap().is_empty());
}

#[test]
fn all_targets_are_scope_and_count_checked_before_the_first_request() {
    let server = Server::new(|_| response("200 OK", "", "not requested"));
    let second = format!("{}other", server.url);
    let denied_host = server.url.replace("127.0.0.1", "localhost");
    for args in [
        vec!["scan", &server.url, &second, "--max-targets", "1"],
        vec![
            "scan",
            &server.url,
            &denied_host,
            "--allow-host",
            "127.0.0.1",
        ],
        vec!["scan", &server.url, "--https-only"],
    ] {
        assert!(!cli(&args).status.success());
    }
    let accepted = plan(&server.url, &["--allow-host", "127.0.0.1"]);
    assert_eq!(accepted["configuration"]["allow_hosts"][0], "127.0.0.1");
    assert!(server.paths.lock().unwrap().is_empty());
}

#[test]
fn encoded_and_dot_normalized_excluded_targets_are_rejected_preflight() {
    let server = Server::new(|_| response("200 OK", "", "not requested"));
    for suffix in [
        "private/app.php",
        "%70rivate/app.php",
        "safe%2f..%2fprivate/app.php",
        "%2570rivate/app.php",
    ] {
        let target = format!("{}{suffix}", server.url);
        let output = cli(&["scan", &target, "--exclude-path", "/private"]);
        assert!(!output.status.success(), "allowed {suffix}");
    }
    assert!(server.paths.lock().unwrap().is_empty());
}
