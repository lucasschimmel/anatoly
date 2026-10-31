#[allow(dead_code)]
mod audit_support;

use audit_support::{Files, Server, cli, combined, response};
use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct EmptyDirectory(PathBuf);

impl EmptyDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "anatoly-embedded-wordlist-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for EmptyDirectory {
    fn drop(&mut self) {
        // The test requires the CLI to leave its initially empty working directory empty.
        fs::remove_dir(&self.0).unwrap();
    }
}

struct StandaloneBinary {
    directory: EmptyDirectory,
    path: PathBuf,
}

impl StandaloneBinary {
    fn new() -> Self {
        let directory = EmptyDirectory::new();
        let path = directory
            .0
            .join(format!("anatoly{}", std::env::consts::EXE_SUFFIX));
        fs::copy(env!("CARGO_BIN_EXE_anatoly"), &path).unwrap();
        Self { directory, path }
    }
}

impl Drop for StandaloneBinary {
    fn drop(&mut self) {
        fs::remove_file(&self.path).unwrap();
    }
}

fn plan(target: &str, flags: &[&str]) -> Value {
    let mut args = vec!["scan", target, "--json", "--dry-run", "--no-proxy"];
    args.extend_from_slice(flags);
    let output = cli(&args);
    assert!(output.status.success(), "{}", combined(&output));
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
// One end-to-end scenario keeps standalone binary setup and discovery/file invariants together.
fn embedded_paths_find_a_nested_php_runtime_without_files_beside_the_binary_or_in_the_working_directory()
 {
    let empty = EmptyDirectory::new();
    let standalone = StandaloneBinary::new();
    let server = Server::new(|request| {
        if request.starts_with("GET /app/debug/info.php ") {
            response(
                "200 OK",
                "Content-Type: application/json\r\n",
                r#"{"php_version":"8.4.26"}"#,
            )
        } else {
            response(
                "200 OK",
                "",
                "application response without runtime metadata",
            )
        }
    });
    let target = format!("{}app/", server.url);
    let output = Command::new(&standalone.path)
        .args([
            "scan",
            &target,
            "--samples",
            "3",
            "--no-linked-discovery",
            "--delay-ms",
            "0",
            "--no-proxy",
            "--builtin-wordlist",
            "--json",
        ])
        .current_dir(&empty.0)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{}", combined(&output));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let result = &report["targets"][0];
    assert_eq!(result["verdict"], "potentially_affected");
    assert_eq!(result["version"]["major"], 8);
    assert_eq!(result["version"]["minor"], 4);
    assert_eq!(result["version"]["patch"], 26);
    assert_eq!(result["requests_sent"], 27);
    assert_eq!(result["analysis"]["samples_completed"], 3);
    assert_eq!(result["analysis"]["diagnostics_requested"], 24);
    assert_eq!(result["analysis"]["diagnostics_completed"], 24);
    assert_eq!(result["analysis"]["coverage_complete"], true);
    assert_eq!(result["analysis"]["certified"], false);
    assert!(result["evidence"].as_array().unwrap().iter().any(|proof| {
        proof["source"]
            .as_str()
            .is_some_and(|source| source.contains("/app/debug/info.php"))
            && proof["kind"] == "structured_metadata"
    }));
    assert_eq!(server.requests.lock().unwrap().len(), 27);
    assert!(fs::read_dir(&empty.0).unwrap().next().is_none());
    assert_eq!(fs::read_dir(&standalone.directory.0).unwrap().count(), 1);
}

#[test]
fn embedded_wordlist_is_opt_in_and_preserves_explicit_request_limits() {
    let server = Server::new(|_| response("200 OK", "", "not requested"));
    let ordinary = plan(&server.url, &[]);
    assert_eq!(ordinary["configuration"]["max_requests"], 8);
    assert_eq!(ordinary["configuration"]["builtin_wordlist"], false);

    for (flags, maximum) in [
        (vec!["--builtin-wordlist"], 32),
        (vec!["--builtin-wordlist", "--max-requests", "8"], 8),
    ] {
        let result = plan(&server.url, &flags);
        let configuration = &result["configuration"];
        assert_eq!(result["network_requests_sent"], 0);
        assert_eq!(configuration["max_requests"], maximum);
        assert_eq!(configuration["builtin_wordlist"], true);
        assert_eq!(configuration["wordlist_configured"], true);
        let paths = configuration["diagnostic_paths"].as_array().unwrap();
        assert_eq!(paths.len(), 24);
        assert_eq!(
            paths.iter().filter(|path| **path == "phpinfo.php").count(),
            1
        );
        assert_eq!(paths.iter().filter(|path| **path == "info.php").count(), 1);
    }
    assert!(server.requests.lock().unwrap().is_empty());
}

#[test]
fn embedded_discovery_conflicts_are_rejected_before_http() {
    let server = Server::new(|_| response("200 OK", "", "not requested"));
    for flags in [vec!["--profile", "quick"], vec!["--no-discover"]] {
        let mut args = vec!["scan", server.url.as_str(), "--builtin-wordlist", "--json"];
        args.extend(flags);
        let output = cli(&args);
        assert!(!output.status.success());
    }
    assert!(server.requests.lock().unwrap().is_empty());
}

#[test]
fn embedded_and_external_paths_are_combined_and_deduplicated_without_raising_the_cap() {
    let mut files = Files::new();
    let wordlist = files.write(
        "txt",
        "phpinfo.php\ndebug/info.php\ncustom/health.php\ncustom/health.php\n",
    );
    let server = Server::new(|_| response("200 OK", "", "not requested"));
    let result = plan(
        &server.url,
        &[
            "--builtin-wordlist",
            "--wordlist",
            wordlist.to_str().unwrap(),
        ],
    );
    let paths = result["configuration"]["diagnostic_paths"]
        .as_array()
        .unwrap();
    assert_eq!(paths.len(), 25);
    assert_eq!(
        paths
            .iter()
            .filter(|path| **path == "debug/info.php")
            .count(),
        1
    );
    assert_eq!(
        paths
            .iter()
            .filter(|path| **path == "custom/health.php")
            .count(),
        1
    );
    assert_eq!(result["configuration"]["max_requests"], 32);
    assert!(server.requests.lock().unwrap().is_empty());
}

#[test]
fn a_lower_operator_budget_limits_actual_embedded_discovery_and_reports_the_gap() {
    let server = Server::new(|_| response("200 OK", "", "application response"));
    let output = cli(&[
        "scan",
        &server.url,
        "--builtin-wordlist",
        "--max-requests",
        "8",
        "--delay-ms",
        "0",
        "--no-linked-discovery",
        "--no-proxy",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let result = &report["targets"][0];
    assert_eq!(result["requests_sent"], 8);
    assert_eq!(result["analysis"]["coverage_complete"], false);
    assert!(!result["analysis"]["gaps"].as_array().unwrap().is_empty());
    assert_eq!(result["verdict"], "inconclusive");
    assert_eq!(server.requests.lock().unwrap().len(), 8);
}
