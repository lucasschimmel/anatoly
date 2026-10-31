mod common;

use anatoly::{
    assessment::Verdict,
    http::{Transport, validate_url},
    network::NetworkPolicy,
    scan::scan_configured,
    scan_options::ScanOptions,
};
use common::{Server, limits, response};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[test]
fn redirect_limits_stop_on_the_last_permitted_response() {
    let server = Server::new(|_| response("302 Found", "Location: /again\r\n", ""));
    for hops in [0, 1, 2] {
        let policy = NetworkPolicy {
            max_redirects: hops,
            ..Default::default()
        };
        let mut transport = Transport::with_policy(limits(), policy).unwrap();
        let page = transport.get(&validate_url(&server.url).unwrap()).unwrap();
        assert_eq!(page.status, 302);
        assert_eq!(transport.requests, hops + 1);
        assert!(transport.observations.last().unwrap().redirect_limited);
    }
    assert_eq!(server.paths.lock().unwrap().len(), 6);
}

#[test]
fn redirects_cannot_enter_an_encoded_excluded_path() {
    let server = Server::new(|_| {
        response(
            "302 Found",
            "Location: /%70rivate/phpinfo.php\r\nX-PHP-Version: 8.4.27\r\n",
            "",
        )
    });
    let options = ScanOptions {
        samples: 1,
        discover: false,
        network: NetworkPolicy {
            exclude_paths: vec!["/private".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let result = scan_configured(&server.url, limits(), &options).unwrap();
    assert_eq!(result.requests_sent, 1);
    assert_eq!(server.paths.lock().unwrap().len(), 1);
    assert!(result.observations[0].scope_blocked);
    assert!(!result.analysis.coverage_complete);
    assert_eq!(result.verdict, Verdict::Inconclusive);
}

#[test]
fn exclusions_apply_to_configured_diagnostic_paths_without_requesting_them() {
    let server = Server::new(|_| response("200 OK", "X-PHP-Version: 8.4.27\r\n", "OK"));
    let options = ScanOptions {
        samples: 1,
        paths: vec!["/%70rivate/phpinfo.php".into()],
        network: NetworkPolicy {
            exclude_paths: vec!["/private".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let result = scan_configured(&server.url, limits(), &options).unwrap();
    assert_eq!(result.requests_sent, 1);
    assert_eq!(server.paths.lock().unwrap().len(), 1);
    assert!(
        result
            .analysis
            .skipped_checks
            .iter()
            .any(|s| s.contains("excluded"))
    );
}

#[test]
fn target_deadline_does_not_wait_for_a_delay_that_cannot_fit() {
    let server = Server::new(|_| response("200 OK", "", "OK"));
    let policy = NetworkPolicy {
        target_timeout: Some(Duration::from_millis(300)),
        ..Default::default()
    };
    let mut bounds = limits();
    bounds.delay = Duration::from_secs(2);
    let mut transport = Transport::with_policy(bounds, policy).unwrap();
    let target = validate_url(&server.url).unwrap();
    transport.get(&target).unwrap();
    let started = Instant::now();
    let error = transport
        .get(&target)
        .err()
        .expect("second request must not fit");
    assert!(error.to_string().contains("budget"));
    assert!(started.elapsed() < Duration::from_millis(900));
    assert_eq!(transport.requests, 1);
}

#[test]
fn target_deadline_also_bounds_waiting_for_a_slow_response() {
    let server = Server::new(|_| {
        std::thread::sleep(Duration::from_millis(600));
        response("200 OK", "", "delayed response")
    });
    let policy = NetworkPolicy {
        target_timeout: Some(Duration::from_millis(150)),
        ..Default::default()
    };
    let mut transport = Transport::with_policy(limits(), policy).unwrap();
    let started = Instant::now();
    assert!(transport.get(&validate_url(&server.url).unwrap()).is_err());
    assert!(started.elapsed() < Duration::from_millis(550));
    assert_eq!(transport.requests, 1);
}

#[test]
fn configured_delay_is_observed_between_actual_request_starts() {
    let times = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&times);
    let server = Server::new(move |_| {
        seen.lock().unwrap().push(Instant::now());
        response("200 OK", "", "OK")
    });
    let mut bounds = limits();
    bounds.delay = Duration::from_millis(100);
    let mut transport = Transport::with_policy(bounds, NetworkPolicy::default()).unwrap();
    let target = validate_url(&server.url).unwrap();
    transport.get(&target).unwrap();
    transport.get(&target).unwrap();
    let starts = times.lock().unwrap();
    assert!(starts[1].duration_since(starts[0]) >= Duration::from_millis(90));
}

#[test]
fn hint_filters_preserve_exact_php_evidence_and_explain_skipped_methods() {
    let server = Server::new(|_| {
        response(
            "200 OK",
            "X-PHP-Version: 8.4.27\r\nSet-Cookie: PHPSESSID=fixture-value\r\n",
            r#"<meta name="generator" content="WordPress 7.1">PHP 8.4 is required"#,
        )
    });
    for (no_cookie_hints, no_hypotheses) in [(true, false), (false, true)] {
        let options = ScanOptions {
            samples: 1,
            discover: false,
            no_cookie_hints,
            no_hypotheses,
            ..Default::default()
        };
        let result = scan_configured(&server.url, limits(), &options).unwrap();
        assert!(!result.evidence.is_empty());
        assert!(result.signals.iter().all(|s| s.category != "cookie"));
        assert!(!result.analysis.skipped_checks.is_empty());
        if no_hypotheses {
            assert!(result.signals.is_empty());
        } else {
            assert!(result.signals.iter().any(|s| s.category == "application"));
        }
    }
}

#[test]
fn disabling_linked_discovery_keeps_explicit_paths_and_skips_disclosed_routes() {
    let server = Server::new(|path| {
        if path == "/" {
            response(
                "200 OK",
                "X-PHP-Version: 8.4.27\r\n",
                r#"<a href="/debug/phpinfo.php">debug</a>"#,
            )
        } else {
            response("404 Not Found", "", "missing")
        }
    });
    let options = ScanOptions {
        samples: 1,
        paths: vec!["/info.php".into()],
        no_linked_discovery: true,
        ..Default::default()
    };
    let result = scan_configured(&server.url, limits(), &options).unwrap();
    assert_eq!(result.requests_sent, 2);
    let paths = server.paths.lock().unwrap();
    assert!(paths.iter().any(|p| p == "/info.php"));
    assert!(paths.iter().all(|p| !p.contains("debug")));
    assert!(
        result
            .analysis
            .skipped_checks
            .iter()
            .any(|s| s.to_ascii_lowercase().contains("link"))
    );
}

#[test]
fn a_target_deadline_remains_effective_after_response_headers_arrive() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let worker = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut headers = Vec::new();
        let mut chunk = [0; 1024];
        while !headers.windows(4).any(|w| w == b"\r\n\r\n") {
            let size = socket.read(&mut chunk).unwrap();
            if size == 0 {
                break;
            }
            headers.extend_from_slice(&chunk[..size]);
        }
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\n")
            .unwrap();
        socket.flush().unwrap();
        std::thread::sleep(Duration::from_millis(600));
        let _ = socket.write_all(b"OK");
    });
    let policy = NetworkPolicy {
        target_timeout: Some(Duration::from_millis(150)),
        ..Default::default()
    };
    let mut transport = Transport::with_policy(limits(), policy).unwrap();
    let started = Instant::now();
    assert!(transport.get(&validate_url(&url).unwrap()).is_err());
    let elapsed = started.elapsed();
    worker.join().unwrap();
    assert!(elapsed < Duration::from_millis(550));
}

#[test]
fn explicit_proxy_routes_the_request_through_the_proxy_fixture() {
    let direct = Server::new(|_| response("200 OK", "", "not requested directly"));
    let proxy = Server::new(|_| response("200 OK", "X-PHP-Version: 8.4.27\r\n", "proxied"));
    let policy = NetworkPolicy {
        proxy: Some(proxy.url.clone()),
        ..Default::default()
    };
    let mut transport = Transport::with_policy(limits(), policy).unwrap();
    let page = transport.get(&validate_url(&direct.url).unwrap()).unwrap();
    assert_eq!(page.body, "proxied");
    assert!(direct.paths.lock().unwrap().is_empty());
    assert_eq!(
        proxy.paths.lock().unwrap().as_slice(),
        std::slice::from_ref(&direct.url)
    );
}
