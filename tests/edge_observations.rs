use anatoly::{tls_observation, waf};
use reqwest::{
    Url,
    header::{HeaderMap, HeaderName, HeaderValue},
};

#[allow(dead_code)]
mod audit_support;

fn headers(entries: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in entries {
        headers.append(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    headers
}

#[test]
fn generic_denial_or_throttling_does_not_identify_a_waf() {
    let url = Url::parse("https://app.example/").unwrap();
    for status in [200, 403, 429, 503] {
        assert!(waf::inspect(&url, status, &HeaderMap::new()).is_empty());
    }
}

#[test]
fn cloudflare_edge_headers_are_observations_without_claiming_php_protection() {
    let url = Url::parse("https://app.example/?fixture=ANATOLY_QUERY_FIXTURE").unwrap();
    let evidence = waf::inspect(
        &url,
        200,
        &headers(&[
            ("cf-ray", "ANATOLY_EDGE_ID_FIXTURE"),
            ("server", "cloudflare"),
        ]),
    );
    assert!(!evidence.is_empty());
    assert!(evidence.iter().all(|e| e.source == "https://app.example/"));
    assert!(evidence.iter().any(|e| e.product == "Cloudflare"));
    assert!(
        evidence
            .iter()
            .any(|e| e.interpretation.contains("does not establish"))
    );
    let serialized = serde_json::to_string(&evidence).unwrap();
    assert!(!serialized.contains("ANATOLY_EDGE_ID_FIXTURE"));
    assert!(!serialized.contains("ANATOLY_QUERY_FIXTURE"));
}

#[test]
fn challenge_markers_are_distinguished_from_generic_edge_presence() {
    let url = Url::parse("https://app.example/").unwrap();
    let edge = waf::inspect(&url, 200, &headers(&[("cf-ray", "fixture")]));
    let challenge = waf::inspect(&url, 403, &headers(&[("cf-mitigated", "challenge")]));
    assert!(!challenge.is_empty());
    assert!(
        challenge
            .iter()
            .any(|e| e.signal.to_ascii_lowercase().contains("challenge"))
    );
    assert!(
        edge.iter()
            .all(|e| !e.signal.to_ascii_lowercase().contains("challenge"))
    );
    assert!(
        challenge
            .iter()
            .any(|e| e.interpretation.contains("does not prove"))
    );
}

#[test]
fn waf_header_values_and_opaque_vendor_identifiers_are_never_exported() {
    let url = Url::parse("https://app.example/").unwrap();
    let evidence = waf::inspect(
        &url,
        403,
        &headers(&[
            ("x-amzn-waf-action", "ANATOLY_ACTION_FIXTURE"),
            ("x-sucuri-id", "ANATOLY_SUCURI_FIXTURE"),
            ("akamai-grn", "ANATOLY_AKAMAI_FIXTURE"),
        ]),
    );
    let serialized = serde_json::to_string(&evidence).unwrap();
    assert!(evidence.len() >= 3);
    for private in [
        "ANATOLY_ACTION_FIXTURE",
        "ANATOLY_SUCURI_FIXTURE",
        "ANATOLY_AKAMAI_FIXTURE",
    ] {
        assert!(!serialized.contains(private));
    }
}

#[test]
fn missing_tls_metadata_is_unknown_and_keeps_certificate_fields_empty() {
    let url = Url::parse("https://app.example/?fixture=ANATOLY_TLS_QUERY_FIXTURE").unwrap();
    let observation = tls_observation::inspect(&url, None);
    assert_eq!(observation.status, "unavailable");
    assert_eq!(observation.source, "https://app.example/");
    assert!(observation.subject.is_none());
    assert!(observation.issuer.is_none());
    assert!(observation.not_before_unix.is_none());
    assert!(observation.not_after_unix.is_none());
    assert!(observation.protocol.is_none());
    assert!(observation.limitation.contains("native TLS"));
    assert!(
        !serde_json::to_string(&observation)
            .unwrap()
            .contains("ANATOLY_TLS_QUERY_FIXTURE")
    );
}

#[test]
fn optional_waf_marker_request_uses_the_shared_budget_and_no_attack_payload() {
    use audit_support::{Server, cli, combined, response};
    let server = Server::new(|_| {
        response(
            "200 OK",
            "X-PHP-Version: 8.4.27\r\ncf-ray: ANATOLY_PROBE_RAY_FIXTURE\r\n",
            "OK",
        )
    });
    let output = cli(&[
        "scan",
        &server.url,
        "--profile",
        "quick",
        "--json",
        "--no-proxy",
        "--waf-probe",
        "--delay-ms",
        "0",
        "--max-requests",
        "2",
    ]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["targets"][0]["requests_sent"], 2);
    assert!(!report["targets"][0]["waf"].as_array().unwrap().is_empty());
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].starts_with("GET /?anatoly_probe=1 "));
    assert!(!combined(&output).contains("ANATOLY_PROBE_RAY_FIXTURE"));
}

#[test]
fn exhausted_budget_never_permits_an_extra_waf_request_and_http_has_no_tls_metadata() {
    use audit_support::{Server, cli, response};
    let server = Server::new(|_| response("200 OK", "X-PHP-Version: 8.4.27\r\n", "OK"));
    let output = cli(&[
        "scan",
        &server.url,
        "--profile",
        "quick",
        "--json",
        "--no-proxy",
        "--waf-probe",
        "--max-requests",
        "1",
    ]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["targets"][0]["requests_sent"], 1);
    assert_eq!(server.requests.lock().unwrap().len(), 1);
    assert!(report["targets"][0]["tls"].as_array().unwrap().is_empty());
}
