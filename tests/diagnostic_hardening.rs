use anatoly::{
    fingerprint::{EvidenceKind, Patterns, resolve},
    policy::VersionStatus,
};

const INFO: &str = "<h1>PHP Version 8.4.27</h1><h2>Configuration</h2><a>PHP Credits</a>";

#[test]
fn inert_hidden_and_documentation_phpinfo_examples_are_not_runtime_evidence() {
    let patterns = Patterns::new().unwrap();
    for body in [
        format!("<!-- {INFO} -->"),
        format!("<script>const example = '{INFO}'</script>"),
        format!("<template>{INFO}</template>"),
        format!("<div hidden>{INFO}</div>"),
        format!("<div aria-hidden=true>{INFO}</div>"),
        format!("<article>{INFO}</article>"),
        format!("<pre>{INFO}</pre>"),
    ] {
        let (evidence, directives) = patterns.phpinfo(&body, "fixture");
        assert!(evidence.is_empty() && directives.is_empty(), "{body}");
    }
}

#[test]
fn hidden_diagnostic_rows_and_paragraph_mentions_do_not_override_visible_runtime_version() {
    let patterns = Patterns::new().unwrap();
    let body = format!(
        "{INFO}<p>Previously PHP Version 8.4.26 was installed.</p>\
        <table><tr hidden><td>PHP Version</td><td>8.4.26</td></tr>\
        <tr hidden><td>memory_limit</td><td>-1</td></tr>\
        <tr><td>memory_limit</td><td>128M</td><td>256M</td></tr></table>"
    );
    let (evidence, directives) = patterns.phpinfo(&body, "fixture");
    assert_eq!(resolve(&evidence).1, VersionStatus::FixFloorMet);
    assert_eq!(directives.len(), 1);
    assert_eq!(directives[0].local_value, "128M");
    assert_eq!(directives[0].master_value.as_deref(), Some("256M"));
}

#[test]
fn phpinfo_markers_must_be_visible_and_not_only_script_or_comment_text() {
    let patterns = Patterns::new().unwrap();
    for body in [
        "<h1>PHP Version 8.4.27</h1><!-- Configuration PHP Credits -->",
        "<h1>PHP Version 8.4.27</h1><script>Configuration PHP Credits</script>",
        "<h1>PHP Version 8.4.27</h1><div hidden><h2>Configuration</h2><a>PHP Credits</a></div>",
    ] {
        assert!(patterns.phpinfo(body, "fixture").0.is_empty());
    }
}

#[test]
fn diagnostic_kind_does_not_depend_on_the_callers_source_label() {
    let patterns = Patterns::new().unwrap();
    for body in [
        INFO,
        "phpinfo()\nPHP Version => 8.4.27\nConfiguration\nServer API => FPM/FastCGI\n",
    ] {
        let (evidence, _) = patterns.phpinfo(body, "custom label");
        assert!(!evidence.is_empty());
        assert!(
            evidence
                .iter()
                .all(|proof| proof.kind == EvidenceKind::Diagnostic)
        );
    }
}

#[test]
fn plain_phpinfo_reads_runtime_only_from_explicit_php_version_lines() {
    let patterns = Patterns::new().unwrap();
    let body = "phpinfo()\nPHP Version => 8.4.27\nConfiguration\nServer API => FPM/FastCGI\n\
        arbitrary_field => PHP Version 8.4.26\narbitrary_html => <fixture>\n\
        memory_limit => 128M => 256M\n";
    let (evidence, directives) = patterns.phpinfo(body, "fixture");
    assert_eq!(resolve(&evidence).1, VersionStatus::FixFloorMet);
    assert!(
        directives
            .iter()
            .any(|directive| directive.name == "memory_limit")
    );
}

#[test]
fn inline_heading_markup_and_real_conflicting_version_rows_keep_diagnostic_provenance() {
    let patterns = Patterns::new().unwrap();
    let body = "<h1>PHP Version <strong>8.4.27</strong></h1><h2>Configuration</h2>\
        <a>PHP Credits</a><table><tr><td>PHP Version</td><td>8.4.26</td></tr></table>";
    let (evidence, _) = patterns.phpinfo(body, "fixture");
    assert_eq!(resolve(&evidence).1, VersionStatus::Conflicting);
    assert!(
        evidence
            .iter()
            .all(|proof| proof.kind == EvidenceKind::Diagnostic)
    );
}
