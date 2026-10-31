mod common;

use anatoly::{assessment::Verdict, scan::scan};
use common::{Server, limits, response};
use std::process::Command;

#[test]
fn cookie_names_are_canonicalized_and_fixture_values_never_reach_reports_or_terminal() {
    const VALUE: &str = "FIXTURE_SESSION_VALUE_NOT_A_REAL_SESSION";
    const SUFFIX: &str = "FIXTURE_OPAQUE_SUFFIX";
    let server = Server::new(|_| {
        response(
            "200 OK",
            &format!(
                "Set-Cookie: PHPSESSID={VALUE}; HttpOnly\r\nSet-Cookie: wordpress_logged_in_{SUFFIX}={VALUE}; Secure\r\nSet-Cookie: unrecognized_{SUFFIX}={VALUE}\r\n"
            ),
            &format!("<html>PHPSESSID={VALUE} wordpress_logged_in_{SUFFIX}</html>"),
        )
    });
    let result = scan(&server.url, limits(), false, &[]).unwrap();
    let serialized = serde_json::to_string(&result).unwrap();
    assert!(serialized.contains("PHPSESSID"));
    assert!(serialized.contains("wordpress_logged_in_*"));
    assert!(serialized.contains("HttpOnly=true"));
    assert!(serialized.contains("Secure=true"));
    assert!(serialized.contains("bytes"));
    assert!(!serialized.contains(VALUE));
    assert!(!serialized.contains(SUFFIX));
    assert!(!serialized.contains("unrecognized_"));
    assert_eq!(result.verdict, Verdict::Inconclusive);
    for machine in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_anatoly"));
        command.args([
            "scan",
            &server.url,
            "--no-discover",
            "--samples",
            "1",
            "--no-banner",
            "--color",
            "never",
        ]);
        if machine {
            command.arg("--json");
        }
        let output = command.output().unwrap();
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains(VALUE), "machine={machine}");
        assert!(!text.contains(SUFFIX), "machine={machine}");
    }
}

#[test]
fn diagnostic_links_are_same_origin_query_free_capped_and_budgeted() {
    let outside = Server::new(|_| response("200 OK", "", "not requested"));
    let outside_url = outside.url.clone();
    let server = Server::new(move |path| {
        if path == "/" {
            response(
                "200 OK",
                "",
                &format!(
                    r#"
                <a href="{outside_url}phpinfo.php">outside</a><a href="/ordinary.php">ordinary</a>
                <a href="/debug/phpinfo.php?fixture_value=private">one</a><a href="/admin/version.php">two</a>
                <a href="/status.php">three</a><a href="/extra/info.php">four</a>"#
                ),
            )
        } else {
            response("200 OK", "", r#"{"php_version":"8.4.27"}"#)
        }
    });
    let result = scan(&server.url, limits(), true, &[]).unwrap();
    assert_eq!(result.discovered_paths.len(), 3);
    assert_eq!(result.requests_sent, 4);
    assert!(result.discovered_paths.iter().all(|s| !s.contains('?')));
    let paths = server.paths.lock().unwrap().clone();
    assert!(
        !paths
            .iter()
            .any(|p| p.contains("ordinary") || p.contains("extra") || p.contains('?'))
    );
    assert!(outside.paths.lock().unwrap().is_empty());
    let mut budget = limits();
    budget.max_requests = 2;
    let limited = scan(&server.url, budget, true, &[]).unwrap();
    assert_eq!(limited.requests_sent, 2);
    assert!(!limited.analysis.coverage_complete);
    assert_eq!(limited.verdict, Verdict::Inconclusive);
}

#[test]
fn robots_diagnostic_routes_use_the_same_discovery_scope() {
    let server = Server::new(|path| {
        if path == "/robots.txt" {
            response(
                "200 OK",
                "",
                "User-agent: *\nDisallow: /admin/phpinfo.php\nDisallow: /private/\n",
            )
        } else {
            response("200 OK", "", r#"{"PHP_VERSION_ID":80426}"#)
        }
    });
    let result = scan(&format!("{}robots.txt", server.url), limits(), true, &[]).unwrap();
    assert_eq!(result.requests_sent, 2);
    assert_eq!(result.discovered_paths.len(), 1);
    assert!(
        server
            .paths
            .lock()
            .unwrap()
            .iter()
            .any(|p| p == "/admin/phpinfo.php")
    );
    assert_eq!(result.verdict, Verdict::PotentiallyAffected);
}

#[test]
fn deep_cli_expands_the_default_budget_but_respects_an_explicit_lower_limit() {
    let server = Server::new(|path| {
        if path == "/" {
            response("200 OK", "X-PHP-Version: 8.4.27\r\n", "OK")
        } else {
            response("404 Not Found", "", "missing")
        }
    });
    for limit in [None, Some("4")] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_anatoly"));
        command.args(["scan", &server.url, "--deep", "--json", "--delay-ms", "0"]);
        if let Some(limit) = limit {
            command.args(["--max-requests", limit]);
        }
        let output = command.output().unwrap();
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let count = json["targets"][0]["requests_sent"].as_u64().unwrap();
        if limit.is_some() {
            assert_eq!(count, 4);
            assert_eq!(json["targets"][0]["analysis"]["coverage_complete"], false);
        } else {
            assert!(count > 8 && count <= 32);
        }
    }
}
