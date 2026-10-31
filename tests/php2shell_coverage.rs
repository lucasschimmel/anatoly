#[allow(dead_code)]
mod common;

use anatoly::{
    assessment::{Verdict, configuration_checks},
    fingerprint::{Directive, Patterns, resolve},
    policy::VersionStatus,
    scan::scan,
};
use common::{Server, limits, response};
use std::collections::BTreeMap;

// Release-number facts from 56 devploit/php2shell profile JSON files (41 unique
// versions). No offsets, payloads or exploit code are needed by these fixtures.
const PROFILE_VERSIONS: &[&str] = &[
    "7.4.33", "8.0.30", "8.1.33", "8.1.34", "8.2.28", "8.2.34", "8.3.0", "8.3.20", "8.3.33",
    "8.3.35", "8.4.0", "8.4.2", "8.4.5", "8.4.6", "8.4.7", "8.4.8", "8.4.10", "8.4.11", "8.4.12",
    "8.4.13", "8.4.14", "8.4.15", "8.4.16", "8.4.17", "8.4.18", "8.4.19", "8.4.20", "8.4.25",
    "8.4.26", "8.5.0", "8.5.1", "8.5.2", "8.5.3", "8.5.4", "8.5.5", "8.5.6", "8.5.7", "8.5.8",
    "8.5.9", "8.5.10", "8.5.11",
];

const FIELDS: &[(&str, &str, Option<&str>)] = &[
    ("session.upload_progress.enabled", "Off", Some("On")),
    ("memory_limit", "-1", Some("128M")),
    ("post_max_size", "8M", Some("8M")),
    ("upload_max_filesize", "2M", Some("2M")),
    ("display_errors", "Off", Some("On")),
    ("server api", "FPM/FastCGI", None),
    ("fatal_error_backtraces", "Off", Some("On")),
    ("opcache.enable", "On", Some("On")),
    ("opcache.enable_cli", "Off", Some("Off")),
    ("file_uploads", "On", Some("On")),
    ("max_file_uploads", "20", Some("20")),
    ("max_input_vars", "1000", Some("1000")),
    ("max_input_nesting_level", "64", Some("64")),
    ("max_multipart_body_parts", "-1", Some("-1")),
    ("enable_post_data_reading", "On", Some("On")),
    ("session.serialize_handler", "php", Some("php_serialize")),
];

fn diagnostic(version: &str, html: bool) -> String {
    if html {
        let mut body = format!(
            "<h1>PHP Version {version}</h1><h2>Configuration</h2><p>PHP Credits</p><table>"
        );
        for (name, local, master) in FIELDS {
            body.push_str(&format!("<tr><td>{name}</td><td>{local}</td>"));
            if let Some(master) = master {
                body.push_str(&format!("<td>{master}</td>"));
            }
            body.push_str("</tr>");
        }
        body.push_str("</table>");
        body
    } else {
        let mut body = format!("phpinfo()\nPHP Version => {version}\nConfiguration\nPHP Credits\n");
        for (name, local, master) in FIELDS {
            body.push_str(&format!("{name} => {local}"));
            if let Some(master) = master {
                body.push_str(&format!(" => {master}"));
            }
            body.push('\n');
        }
        body
    }
}

fn values(directives: &[Directive]) -> BTreeMap<String, (String, Option<String>)> {
    directives
        .iter()
        .map(|d| {
            (
                d.name.clone(),
                (d.local_value.clone(), d.master_value.clone()),
            )
        })
        .collect()
}

#[test]
fn every_profile_release_produces_a_potential_exposure_indicator_from_an_http_header() {
    let server = Server::new(|path| {
        let version = path.strip_prefix("/v/").unwrap_or("8.4.26");
        response("200 OK", &format!("X-Powered-By: PHP/{version}\r\n"), "OK")
    });
    for version in PROFILE_VERSIONS {
        let report = scan(&format!("{}v/{version}", server.url), limits(), false, &[]).unwrap();
        assert_eq!(report.verdict, Verdict::PotentiallyAffected, "{version}");
        assert_eq!(
            report.version.as_ref().map(ToString::to_string).as_deref(),
            Some(*version)
        );
        assert_eq!(report.requests_sent, 1);
        assert!(!report.analysis.secure && !report.analysis.certified);
        assert!(
            report
                .cves
                .iter()
                .all(|c| c.status == "potentially_affected" && c.exploitation == "not_attempted")
        );
    }
    assert_eq!(server.paths.lock().unwrap().len(), PROFILE_VERSIONS.len());
}

#[test]
fn fixed_release_floors_remain_observations_without_certifying_the_running_build() {
    let server = Server::new(|path| {
        response(
            "200 OK",
            &format!("X-PHP-Version: {}\r\n", path.trim_start_matches('/')),
            "OK",
        )
    });
    for version in ["8.2.35", "8.3.36", "8.4.27", "8.5.12"] {
        let report = scan(&format!("{}{version}", server.url), limits(), false, &[]).unwrap();
        assert_eq!(
            report.version_status,
            VersionStatus::FixFloorMet,
            "{version}"
        );
        assert_eq!(report.verdict, Verdict::FixFloorObserved);
        assert!(!report.analysis.secure && !report.analysis.certified);
        assert!(
            report
                .cves
                .iter()
                .all(|c| c.exploitation == "not_attempted")
        );
    }
}

#[test]
fn html_and_plain_text_phpinfo_preserve_the_same_allowlisted_local_and_master_values() {
    let patterns = Patterns::new().unwrap();
    let (html_proofs, html_fields) =
        patterns.phpinfo(&diagnostic("8.4.26", true), "fixture [phpinfo]");
    let (text_proofs, text_fields) =
        patterns.phpinfo(&diagnostic("8.4.26", false), "fixture [phpinfo]");
    let expected: BTreeMap<_, _> = FIELDS
        .iter()
        .map(|(name, local, master)| {
            (
                name.to_string(),
                (local.to_string(), master.map(str::to_owned)),
            )
        })
        .collect();
    assert_eq!(values(&html_fields), expected);
    assert_eq!(values(&text_fields), expected);
    assert_eq!(resolve(&html_proofs), resolve(&text_proofs));
    assert_eq!(resolve(&text_proofs).1, VersionStatus::AffectedRange);
}

#[test]
fn fpm_disabled_upload_progress_and_unlimited_memory_never_exonerate_an_affected_release() {
    for (version, html) in [("8.4.26", true), ("8.5.11", false)] {
        let body = diagnostic(version, html);
        let server = Server::new(move |_| response("200 OK", "", &body));
        let report = scan(&server.url, limits(), false, &[]).unwrap();
        assert_eq!(report.verdict, Verdict::PotentiallyAffected, "{version}");
        let fields = values(&report.directives);
        assert_eq!(fields["server api"].0, "FPM/FastCGI");
        assert_eq!(fields["session.upload_progress.enabled"].0, "Off");
        assert_eq!(fields["memory_limit"].0, "-1");
        assert!(!report.analysis.secure && !report.analysis.certified);
        assert!(
            report
                .cves
                .iter()
                .all(|c| c.status == "potentially_affected")
        );
    }
}

#[test]
fn contradictory_duplicate_phpinfo_directives_are_retained_and_reported_as_conflicting() {
    let patterns = Patterns::new().unwrap();
    for html in [true, false] {
        let mut body = diagnostic("8.4.26", html);
        if html {
            body.push_str("<table><tr><td>memory_limit</td><td>64M</td><td>128M</td></tr></table>");
        } else {
            body.push_str("memory_limit => 64M => 128M\n");
        }
        let (_, directives) = patterns.phpinfo(&body, "fixture [phpinfo]");
        assert_eq!(
            directives
                .iter()
                .filter(|d| d.name == "memory_limit")
                .count(),
            2
        );
        let checks = configuration_checks(&directives);
        assert_eq!(
            checks
                .iter()
                .find(|c| c.name == "memory_limit")
                .unwrap()
                .status,
            "conflicting"
        );
    }
}

#[test]
fn ordinary_documentation_does_not_turn_directive_examples_into_phpinfo_evidence() {
    let patterns = Patterns::new().unwrap();
    for body in [
        "Guide to PHP Version 8.4.26\nConfiguration and PHP Credits examples\nmemory_limit => -1 => 128M\nfatal_error_backtraces => Off => On\n",
        "<h1>Documentation</h1><p>PHP Version 8.4.26, Configuration, PHP Credits</p><table><tr><td>memory_limit</td><td>-1</td><td>128M</td></tr></table>",
    ] {
        let (proofs, directives) = patterns.phpinfo(body, "article");
        assert!(proofs.is_empty() && directives.is_empty());
    }
}

#[test]
fn recognized_diagnostics_do_not_export_non_allowlisted_fields() {
    let patterns = Patterns::new().unwrap();
    for html in [true, false] {
        let mut body = diagnostic("8.4.26", html);
        if html {
            body.push_str("<table><tr><td>application_fixture</td><td>ANATOLY_PRIVATE_DIAGNOSTIC_FIXTURE</td></tr></table>");
        } else {
            body.push_str("application_fixture => ANATOLY_PRIVATE_DIAGNOSTIC_FIXTURE\n");
        }
        let (proofs, directives) = patterns.phpinfo(&body, "fixture [phpinfo]");
        assert!(!proofs.is_empty());
        assert_eq!(directives.len(), FIELDS.len());
        assert!(
            !serde_json::to_string(&directives)
                .unwrap()
                .contains("ANATOLY_PRIVATE_DIAGNOSTIC_FIXTURE")
        );
    }
}

#[test]
fn unrelated_angle_brackets_in_plain_phpinfo_do_not_hide_allowlisted_directives() {
    let patterns = Patterns::new().unwrap();
    let body = "phpinfo()\nPHP Version => 8.5.11\nConfiguration\nServer API => FPM/FastCGI\nmemory_limit => -1 => 128M\napplication_fixture => value <fixture> ANATOLY_PRIVATE_DIAGNOSTIC_FIXTURE\n";
    let (proofs, directives) = patterns.phpinfo(body, "fixture [phpinfo]");
    assert_eq!(resolve(&proofs).1, VersionStatus::AffectedRange);
    let memory = directives
        .iter()
        .find(|d| d.name == "memory_limit")
        .unwrap();
    assert_eq!(memory.local_value, "-1");
    assert_eq!(memory.master_value.as_deref(), Some("128M"));
    assert!(
        !serde_json::to_string(&directives)
            .unwrap()
            .contains("ANATOLY_PRIVATE_DIAGNOSTIC_FIXTURE")
    );
}
