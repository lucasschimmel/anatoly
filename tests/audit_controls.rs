#[allow(dead_code)]
mod audit_support;

use audit_support::{Files, Server, cli, combined, command, response};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;

#[test]
fn custom_headers_and_environment_auth_reach_the_target_without_entering_reports() {
    let server = Server::new(|_| response("200 OK", "X-PHP-Version: 8.4.27\r\n", "OK"));
    let header = "X-Audit-Context: ANATOLY_HEADER_FIXTURE";
    let output = command(&[
        "scan",
        &server.url,
        "--profile",
        "quick",
        "--no-proxy",
        "--json",
        "-H",
        header,
        "--basic-auth-env",
        "ANATOLY_TEST_BASIC",
    ])
    .env("ANATOLY_TEST_BASIC", "fixture:ANATOLY_BASIC_FIXTURE")
    .output()
    .unwrap();

    assert!(output.status.success(), "{}", combined(&output));
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .contains("x-audit-context: anatoly_header_fixture")
    );
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .contains("authorization: basic ")
    );
    for private in [
        "ANATOLY_HEADER_FIXTURE",
        "ANATOLY_BASIC_FIXTURE",
        "fixture:ANATOLY_BASIC_FIXTURE",
    ] {
        assert!(!combined(&output).contains(private));
    }
    assert!(!combined(&output).contains(&STANDARD.encode("fixture:ANATOLY_BASIC_FIXTURE")));
}

#[test]
fn dry_run_validates_auth_and_redacts_all_supplied_values_without_http() {
    let server = Server::new(|_| response("200 OK", "", "not requested"));
    let output = command(&[
        "scan",
        &server.url,
        "--dry-run",
        "--json",
        "-H",
        "Authorization: Bearer ANATOLY_BEARER_FIXTURE",
    ])
    .output()
    .unwrap();

    assert!(output.status.success(), "{}", combined(&output));
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["network_requests_sent"], 0);
    assert!(!combined(&output).contains("ANATOLY_BEARER_FIXTURE"));
    assert!(server.requests.lock().unwrap().is_empty());
}

#[test]
fn environment_header_values_reach_only_the_pinned_origin_and_stay_out_of_output() {
    let server = Server::new(|_| response("200 OK", "X-PHP-Version: 8.4.27\r\n", "OK"));
    let output = command(&[
        "scan",
        &server.url,
        "--profile",
        "quick",
        "--json",
        "--no-proxy",
        "--header-env",
        "ANATOLY_TEST_HEADER",
    ])
    .env(
        "ANATOLY_TEST_HEADER",
        "Cookie: custom_session=ANATOLY_ENV_COOKIE_FIXTURE",
    )
    .output()
    .unwrap();
    assert!(output.status.success(), "{}", combined(&output));
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("custom_session=ANATOLY_ENV_COOKIE_FIXTURE"));
    assert!(!combined(&output).contains("ANATOLY_ENV_COOKIE_FIXTURE"));
}

#[test]
fn duplicate_authorization_sources_are_rejected_without_exposing_either_value() {
    let server = Server::new(|_| response("200 OK", "", "not requested"));
    let output = command(&[
        "scan",
        &server.url,
        "--json",
        "-H",
        "Authorization: Bearer ANATOLY_DUPLICATE_FIXTURE",
        "--basic-auth-env",
        "ANATOLY_TEST_BASIC",
    ])
    .env(
        "ANATOLY_TEST_BASIC",
        "fixture:ANATOLY_BASIC_DUPLICATE_FIXTURE",
    )
    .output()
    .unwrap();
    assert!(!output.status.success());
    assert!(server.requests.lock().unwrap().is_empty());
    for private in [
        "ANATOLY_DUPLICATE_FIXTURE",
        "ANATOLY_BASIC_DUPLICATE_FIXTURE",
    ] {
        assert!(!combined(&output).contains(private));
    }
}

#[test]
fn malformed_or_reserved_headers_fail_before_network_and_do_not_echo_values() {
    let server = Server::new(|_| response("200 OK", "", "not requested"));
    for header in [
        "Host: ANATOLY_PRIVATE_HOST_FIXTURE",
        "Content-Length: ANATOLY_PRIVATE_LENGTH_FIXTURE",
        "Connection: ANATOLY_PRIVATE_CONNECTION_FIXTURE",
        "X-Audit: ANATOLY_PRIVATE_NEWLINE_FIXTURE\r\nInjected: yes",
    ] {
        let output = cli(&["scan", &server.url, "--json", "-H", header]);
        assert!(!output.status.success());
        assert!(!combined(&output).contains("ANATOLY_PRIVATE_"));
    }
    assert!(server.requests.lock().unwrap().is_empty());
}

#[test]
fn leading_hyphen_header_input_is_rejected_without_argument_echo_or_http() {
    let server = Server::new(|_| response("200 OK", "", "not requested"));
    let output = cli(&[
        "scan",
        &server.url,
        "--json",
        "-H",
        "--ANATOLY_HEADER_LEAK_FIXTURE",
    ]);
    assert!(!output.status.success());
    assert!(!combined(&output).contains("ANATOLY_HEADER_LEAK_FIXTURE"));
    assert!(server.requests.lock().unwrap().is_empty());
}

#[test]
fn missing_or_malformed_basic_auth_environment_values_fail_without_requests_or_disclosure() {
    let server = Server::new(|_| response("200 OK", "", "not requested"));
    for value in [None, Some("ANATOLY_INVALID_AUTH_FIXTURE")] {
        let mut invocation = command(&[
            "scan",
            &server.url,
            "--json",
            "--basic-auth-env",
            "ANATOLY_MISSING_TEST_AUTH",
        ]);
        invocation.env_remove("ANATOLY_MISSING_TEST_AUTH");
        if let Some(value) = value {
            invocation.env("ANATOLY_MISSING_TEST_AUTH", value);
        }
        let output = invocation.output().unwrap();
        assert!(!output.status.success());
        assert!(!combined(&output).contains("ANATOLY_INVALID_AUTH_FIXTURE"));
    }
    assert!(server.requests.lock().unwrap().is_empty());
}

#[test]
fn authenticated_multi_origin_input_is_rejected_before_either_target_is_contacted() {
    let first = Server::new(|_| response("200 OK", "", "not requested"));
    let second = Server::new(|_| response("200 OK", "", "not requested"));
    let output = command(&[
        "scan",
        "-u",
        &first.url,
        "-u",
        &second.url,
        "--json",
        "--basic-auth-env",
        "ANATOLY_TEST_BASIC",
    ])
    .env("ANATOLY_TEST_BASIC", "fixture:ANATOLY_ORIGIN_FIXTURE")
    .output()
    .unwrap();
    assert!(!output.status.success());
    assert!(!combined(&output).contains("ANATOLY_ORIGIN_FIXTURE"));
    assert!(first.requests.lock().unwrap().is_empty());
    assert!(second.requests.lock().unwrap().is_empty());
}

#[test]
fn cross_origin_redirect_does_not_forward_authentication_to_a_second_server() {
    let destination = Server::new(|_| response("200 OK", "", "not requested"));
    let location = destination.url.clone();
    let source =
        Server::new(move |_| response("302 Found", &format!("Location: {location}\r\n"), ""));
    let output = command(&[
        "scan",
        &source.url,
        "--profile",
        "quick",
        "--no-proxy",
        "--json",
        "--basic-auth-env",
        "ANATOLY_TEST_BASIC",
    ])
    .env("ANATOLY_TEST_BASIC", "fixture:ANATOLY_REDIRECT_FIXTURE")
    .output()
    .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["targets"][0]["verdict"], "inconclusive");
    assert_eq!(source.requests.lock().unwrap().len(), 1);
    assert!(destination.requests.lock().unwrap().is_empty());
    assert!(!combined(&output).contains("ANATOLY_REDIRECT_FIXTURE"));
}

#[test]
fn explicit_resolution_connects_to_loopback_and_preserves_the_application_host() {
    let server = Server::new(|_| response("200 OK", "X-PHP-Version: 8.4.27\r\n", "OK"));
    let mut target = reqwest::Url::parse(&server.url).unwrap();
    target.set_host(Some("anatoly-fixture.invalid")).unwrap();
    let output = cli(&[
        "scan",
        target.as_str(),
        "--profile",
        "quick",
        "--json",
        "--no-proxy",
        "--resolve",
        "anatoly-fixture.invalid:127.0.0.1",
    ]);
    assert!(output.status.success(), "{}", combined(&output));
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains(&format!(
        "anatoly-fixture.invalid:{}",
        target.port().unwrap()
    )));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["targets"][0]["target"], target.as_str());
}

#[test]
fn invalid_resolution_or_proxy_combination_is_rejected_before_http() {
    let server = Server::new(|_| response("200 OK", "", "not requested"));
    for flags in [
        vec!["--resolve", "anatoly-fixture.invalid:not-an-ip"],
        vec!["--resolve", "127.0.0.1:127.0.0.2", "--no-proxy"],
        vec![
            "--resolve",
            "anatoly-fixture.invalid:127.0.0.1",
            "--proxy",
            "http://127.0.0.1:9",
        ],
    ] {
        let mut args = vec!["scan", server.url.as_str(), "--json"];
        args.extend(flags);
        let output = cli(&args);
        assert!(!output.status.success());
    }
    assert!(server.requests.lock().unwrap().is_empty());
}

#[test]
fn wordlist_paths_are_discovered_within_the_existing_request_budget() {
    let mut files = Files::new();
    let words = files.write(
        "txt",
        "# authorized diagnostic paths\ncustom-php.php\ncustom-php.php\n\n",
    );
    let server = Server::new(|request| {
        if request.starts_with("GET /custom-php.php ") {
            response("200 OK", "X-PHP-Version: 8.4.26\r\n", "OK")
        } else {
            response("200 OK", "", "OK")
        }
    });
    let output = cli(&[
        "scan",
        &server.url,
        "--json",
        "--no-proxy",
        "--samples",
        "1",
        "--delay-ms",
        "0",
        "--max-requests",
        "4",
        "--wordlist",
        words.to_str().unwrap(),
    ]);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["targets"][0]["verdict"], "potentially_affected");
    let requests = server.requests.lock().unwrap();
    assert!(requests.len() <= 4);
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.starts_with("GET /custom-php.php "))
            .count(),
        1
    );
}

#[test]
fn oversized_or_cross_origin_wordlists_fail_before_requests() {
    let mut files = Files::new();
    let server = Server::new(|_| response("200 OK", "", "not requested"));
    for body in [
        "https://outside.invalid/diagnostic.php\n".to_owned(),
        "x\n".repeat(65),
        "x".repeat(65_537),
    ] {
        let path = files.write("txt", body);
        let output = cli(&[
            "scan",
            &server.url,
            "--json",
            "--wordlist",
            path.to_str().unwrap(),
        ]);
        assert!(!output.status.success());
    }
    assert!(server.requests.lock().unwrap().is_empty());
}
