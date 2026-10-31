mod common;

use anatoly::{
    assessment::Verdict,
    fingerprint::{DetectionLevel, EvidenceKind},
    policy::VersionStatus,
    scan::{Report, scan, scan_with_samples},
};
use common::{Server, limits, response};

#[test]
fn dedicated_php_headers_accept_plain_versions_but_generic_runtime_digits_do_not() {
    for header in [
        "X-PHP-Version",
        "PHP-Version",
        "X-Runtime",
        "X-Runtime-Version",
    ] {
        let server =
            Server::new(move |_| response("200 OK", &format!("{header}: 8.4.26\r\n"), "OK"));
        let report = scan(&server.url, limits(), false, &[]).unwrap();
        if matches!(header, "X-PHP-Version" | "PHP-Version") {
            assert_eq!(report.version_status, VersionStatus::AffectedRange);
            assert_eq!(report.analysis.detection_level, DetectionLevel::Declared);
            assert_eq!(report.evidence[0].excerpt, "PHP/8.4.26");
            assert_eq!(report.evidence[0].http_status, Some(200));
        } else {
            assert_eq!(report.version_status, VersionStatus::Unknown);
            assert!(report.version.is_none());
            assert_eq!(report.verdict, Verdict::Inconclusive);
        }
    }
}

#[test]
fn generic_runtime_header_requires_an_explicit_php_token() {
    let server = Server::new(|_| response("200 OK", "X-Runtime: PHP/8.4.26\r\n", "OK"));
    let result = scan(&server.url, limits(), false, &[]).unwrap();
    assert_eq!(result.version_status, VersionStatus::AffectedRange);
    assert_eq!(result.evidence[0].kind, EvidenceKind::Header);
}

#[test]
fn structured_runtime_metadata_accepts_explicit_php_fields_and_numeric_version_id() {
    for body in [
        r#"{"PHP_VERSION_ID":80426}"#,
        r#"{"runtime":{"php_version":"8.4.26"}}"#,
        r#"{"environment":{"phpversion":"8.4.26"}}"#,
        r#"{"system":{"php":{"version":"8.4.26"}}}"#,
    ] {
        let server =
            Server::new(move |_| response("200 OK", "Content-Type: application/json\r\n", body));
        let result = scan(&server.url, limits(), false, &[]).unwrap();
        assert_eq!(
            result.version_status,
            VersionStatus::AffectedRange,
            "{body}"
        );
        assert!(
            result
                .evidence
                .iter()
                .all(|e| e.kind == EvidenceKind::StructuredMetadata)
        );
        assert_eq!(result.evidence[0].excerpt, "PHP/8.4.26");
    }
}

#[test]
fn unrelated_versions_and_invalid_php_metadata_do_not_select_a_runtime() {
    for body in [
        r#"{"version":"8.4.26","name":"a-library"}"#,
        r#"{"package":{"php_version":"8.4.26"}}"#,
        r#"{"PHP_VERSION_ID":"80426"}"#,
        r#"{"PHP_VERSION_ID":0}"#,
        r#"{"PHP_VERSION_ID":80426.5}"#,
        r#"{"php_version":true}"#,
        r#"{"php_version":"^8.4"}"#,
        "<article>Our blog explains PHP/8.4.26 and the PHP Version 8.4.27 release.</article>",
    ] {
        let server = Server::new(move |_| response("200 OK", "", body));
        let result = scan(&server.url, limits(), false, &[]).unwrap();
        assert_eq!(result.version_status, VersionStatus::Unknown, "{body}");
        assert_eq!(result.analysis.detection_level, DetectionLevel::Unknown);
        assert!(result.version_candidates.is_empty());
    }
}

#[test]
fn cms_and_behavior_hypotheses_never_change_the_cve_verdict() {
    let server = Server::new(|_| {
        response(
            "200 OK",
            "Set-Cookie: PHPSESSID=fixture-session-value; HttpOnly\r\n",
            r#"<meta name="generator" content="WordPress 8.4.26"><a href="/index.php">App</a>
        Deprecated: Creation of dynamic property Demo::$data is deprecated"#,
        )
    });
    let result = scan(&server.url, limits(), false, &[]).unwrap();
    assert!(result.signals.iter().any(|s| s.category == "application"));
    assert!(
        result
            .signals
            .iter()
            .any(|s| s.category == "error_behavior")
    );
    assert!(result.signals.iter().any(|s| s.category == "cookie"));
    assert_eq!(result.version_status, VersionStatus::Unknown);
    assert_eq!(result.analysis.detection_level, DetectionLevel::Unknown);
    assert_eq!(result.verdict, Verdict::Inconclusive);
    assert!(result.version.is_none() && result.version_candidates.is_empty());
}

#[test]
fn composer_platform_constraints_remain_hypotheses_not_runtime_versions() {
    let server = Server::new(|_| {
        response(
            "200 OK",
            "Content-Type: application/json\r\n",
            r#"{"require":{"php":"^8.4"},"config":{"platform":{"php":"8.4.26"}}}"#,
        )
    });
    let result = scan(
        &format!("{}composer.json", server.url),
        limits(),
        false,
        &[],
    )
    .unwrap();
    assert!(
        result
            .signals
            .iter()
            .any(|s| s.category == "composer_constraint")
    );
    assert!(
        result
            .signals
            .iter()
            .any(|s| s.version_hint.as_deref() == Some("8.4.26"))
    );
    assert_eq!(result.version_status, VersionStatus::Unknown);
    assert_eq!(result.verdict, Verdict::Inconclusive);
}

#[test]
fn exact_php_error_footer_is_evidence_but_an_article_or_unmarked_error_is_not() {
    for (status, body, exact) in [
        (
            "500 Internal Server Error",
            "<address>Apache Server PHP/8.4.26</address>",
            true,
        ),
        (
            "500 Internal Server Error",
            "Error building package 8.4.26",
            false,
        ),
        (
            "200 OK",
            "<address>Article about PHP/8.4.26</address>",
            false,
        ),
    ] {
        let server = Server::new(move |_| response(status, "", body));
        let result = scan(&server.url, limits(), false, &[]).unwrap();
        assert_eq!(!result.evidence.is_empty(), exact, "{status} {body}");
        if exact {
            assert_eq!(result.evidence[0].kind, EvidenceKind::ErrorDisclosure);
            assert_eq!(result.evidence[0].http_status, Some(500));
        }
        assert_eq!(result.verdict, Verdict::Inconclusive);
    }
}

#[test]
fn intermediate_redirect_headers_participate_in_conflict_resolution() {
    let server = Server::new(|path| {
        if path == "/" {
            response(
                "302 Found",
                "Location: /app\r\nX-PHP-Version: 8.4.26\r\n",
                "",
            )
        } else {
            response("200 OK", "X-PHP-Version: 8.4.27\r\n", "OK")
        }
    });
    let result = scan(&server.url, limits(), false, &[]).unwrap();
    assert_eq!(result.requests_sent, 2);
    assert_eq!(server.paths.lock().unwrap().len(), 2);
    assert_eq!(
        result.analysis.detection_level,
        DetectionLevel::Contradictory
    );
    assert_eq!(result.verdict, Verdict::Inconclusive);
    assert_eq!(result.version_candidates.len(), 2);
    assert!(result.evidence.iter().any(|e| e.http_status == Some(302)));
    assert!(result.evidence.iter().any(|e| e.http_status == Some(200)));
}

#[test]
fn agreeing_header_and_json_proofs_are_grouped_and_corroborated() {
    let server = Server::new(|_| {
        response(
            "200 OK",
            "X-PHP-Version: 8.4.27\r\n",
            r#"{"php_version":"8.4.27"}"#,
        )
    });
    let result = scan(&server.url, limits(), false, &[]).unwrap();
    assert_eq!(
        result.analysis.detection_level,
        DetectionLevel::Corroborated
    );
    assert_eq!(result.version_candidates.len(), 1);
    assert_eq!(
        result.version_candidates[0].level,
        DetectionLevel::Corroborated
    );
    assert_eq!(result.version_candidates[0].proofs.len(), 2);
    assert_eq!(result.verdict, Verdict::FixFloorObserved);
    assert!(!result.analysis.certified && !result.analysis.secure);
    let summary = Report::new(vec![result]).summary;
    assert_eq!(summary.php_corroborated, 1);
    assert_eq!(summary.secure, 0);
}

#[test]
fn cache_markers_are_explained_without_upgrading_detection_to_corroborated() {
    for headers in [
        "Age: 30\r\n",
        "X-Cache: HIT\r\n",
        "CF-Cache-Status: HIT\r\n",
    ] {
        let server = Server::new(move |_| {
            response(
                "200 OK",
                &format!("X-PHP-Version: 8.4.27\r\n{headers}"),
                "OK",
            )
        });
        let result = scan_with_samples(&server.url, limits(), false, &[], 2).unwrap();
        assert!(result.observations.iter().all(|o| o.cached));
        assert!(result.signals.iter().any(|s| s.category == "cache"));
        assert_eq!(result.analysis.detection_level, DetectionLevel::Declared);
        assert!(!result.analysis.certified && !result.analysis.secure);
    }
}

#[test]
fn only_php_specific_numeric_endpoints_declare_the_runtime_version() {
    let server = Server::new(|_| response("200 OK", "Content-Type: text/plain\r\n", "8.4.26\n"));
    for path in ["phpversion.php", "php-version.php", "version.php"] {
        let result = scan(&format!("{}{path}", server.url), limits(), false, &[]).unwrap();
        if path == "version.php" {
            assert_eq!(result.analysis.detection_level, DetectionLevel::Unknown);
            assert!(result.version.is_none());
        } else {
            assert_eq!(result.analysis.detection_level, DetectionLevel::Declared);
            assert_eq!(result.evidence[0].kind, EvidenceKind::StructuredMetadata);
            assert_eq!(result.version_status, VersionStatus::AffectedRange);
        }
    }
}

#[test]
fn plain_text_phpinfo_with_diagnostic_markers_is_exact_evidence() {
    let server = Server::new(|_| {
        response(
            "200 OK",
            "Content-Type: text/plain\r\n",
            "PHP Version => 8.4.26\nConfiguration\nServer API => FPM/FastCGI\n",
        )
    });
    let result = scan(&server.url, limits(), false, &[]).unwrap();
    assert_eq!(result.version_status, VersionStatus::AffectedRange);
    assert_eq!(result.evidence[0].kind, EvidenceKind::Diagnostic);
    assert_eq!(result.evidence[0].http_status, Some(200));
}

#[test]
fn body_mentions_and_deprecation_wording_stay_hypotheses() {
    for body in ["PHP 8.4.26", "PHP/8.4.26", "PHP8.4.26"] {
        let server = Server::new(move |_| response("200 OK", "", body));
        let result = scan(&server.url, limits(), false, &[]).unwrap();
        assert_eq!(result.analysis.detection_level, DetectionLevel::Unknown);
        assert_eq!(result.verdict, Verdict::Inconclusive);
        assert!(
            result.signals.iter().any(|s| s.category == "body_mention"),
            "{body}"
        );
    }
    for body in [
        "Deprecated: Creation of dynamic property Demo::$data is deprecated",
        "Deprecated: strlen(): Passing null to parameter #1 ($string) of type string is deprecated",
    ] {
        let server = Server::new(move |_| response("200 OK", "", body));
        let result = scan(&server.url, limits(), false, &[]).unwrap();
        assert_eq!(result.analysis.detection_level, DetectionLevel::Unknown);
        assert_eq!(result.verdict, Verdict::Inconclusive);
        assert!(
            result
                .signals
                .iter()
                .any(|s| s.category == "error_behavior")
        );
    }
}

#[test]
fn the_four_detection_levels_partition_the_summary_without_certification() {
    let server = Server::new(|path| match path {
        "/declared" => response("200 OK", "X-PHP-Version: 8.4.26\r\n", "OK"),
        "/corroborated" => response(
            "200 OK",
            "X-PHP-Version: 8.4.27\r\n",
            r#"{"php_version":"8.4.27"}"#,
        ),
        "/contradictory" => response(
            "200 OK",
            "X-PHP-Version: 8.4.27\r\n",
            r#"{"php_version":"8.4.26"}"#,
        ),
        _ => response(
            "200 OK",
            "Set-Cookie: PHPSESSID=fixture-value\r\n",
            "PHP 8.4.26 might be installed",
        ),
    });
    let paths = ["declared", "corroborated", "contradictory", "unknown"];
    let reports = paths
        .iter()
        .map(|p| scan(&format!("{}{p}", server.url), limits(), false, &[]).unwrap())
        .collect();
    let report = Report::new(reports);
    let summary = report.summary;
    assert_eq!(summary.php_declared, 1);
    assert_eq!(summary.php_corroborated, 1);
    assert_eq!(summary.php_contradictory, 1);
    assert_eq!(summary.php_unknown, 1);
    assert_eq!(
        summary.php_declared
            + summary.php_corroborated
            + summary.php_contradictory
            + summary.php_unknown,
        summary.urls_analyzed
    );
    assert_eq!(summary.certified + summary.secure, 0);
}

#[test]
fn partial_php_declarations_are_hints_without_an_assigned_patch_level() {
    for header in [
        "X-PHP-Version: 8.4\r\n",
        "PHP-Version: 8.4\r\n",
        "X-Powered-By: PHP/8.4\r\n",
    ] {
        let server = Server::new(move |_| response("200 OK", header, "OK"));
        let result = scan(&server.url, limits(), false, &[]).unwrap();
        assert_eq!(result.version_status, VersionStatus::Unknown);
        assert_eq!(result.analysis.detection_level, DetectionLevel::Unknown);
        assert!(
            result
                .signals
                .iter()
                .any(|s| s.category == "partial_version"
                    && s.version_hint.as_deref() == Some("8.4.x"))
        );
        assert!(result.version_candidates.is_empty());
    }
}

#[test]
fn ordinary_paragraphs_with_phpinfo_words_are_not_runtime_diagnostics() {
    let server = Server::new(|_| {
        response(
            "200 OK",
            "",
            "<html><article><p>PHP Version 8.4.27 introduced changes. Read the Configuration guide and PHP Credits.</p></article></html>",
        )
    });
    let result = scan(&server.url, limits(), false, &[]).unwrap();
    assert_eq!(result.version_status, VersionStatus::Unknown);
    assert_eq!(result.analysis.detection_level, DetectionLevel::Unknown);
    assert_eq!(result.verdict, Verdict::Inconclusive);
    assert!(result.evidence.is_empty());
}
