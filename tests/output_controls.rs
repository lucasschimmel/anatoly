#[allow(dead_code)]
mod common;

use common::{Server, response};
use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

#[test]
fn exit_policies_distinguish_affected_unknown_and_transport_errors() {
    let server = Server::new(|path| match path {
        "/affected" => response("200 OK", "X-PHP-Version: 8.4.26\r\n", "OK"),
        "/fixed" => response("200 OK", "X-PHP-Version: 8.4.27\r\n", "OK"),
        "/error" => String::new(),
        _ => response("200 OK", "", "unknown runtime"),
    });
    for (policy, codes) in [
        ("any", [1, 0, 2, 3]),
        ("affected", [1, 0, 0, 3]),
        ("error", [0, 0, 0, 3]),
        ("never", [0, 0, 0, 0]),
    ] {
        for (path, expected) in ["affected", "fixed", "unknown", "error"]
            .into_iter()
            .zip(codes)
        {
            let output = Command::new(env!("CARGO_BIN_EXE_anatoly"))
                .args([
                    "scan",
                    &format!("{}{path}", server.url),
                    "--profile",
                    "quick",
                    "--delay-ms",
                    "0",
                    "--fail-on",
                    policy,
                    "--json",
                ])
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(expected),
                "policy={policy} path={path}"
            );
            let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(json["summary"]["urls_analyzed"], 1);
        }
    }
    assert_eq!(server.paths.lock().unwrap().len(), 16);
}

#[test]
fn summary_only_suppresses_target_cards_while_preserving_the_final_summary() {
    let server = Server::new(|_| response("200 OK", "X-PHP-Version: 8.4.27\r\n", "OK"));
    let output = Command::new(env!("CARGO_BIN_EXE_anatoly"))
        .args([
            "scan",
            &server.url,
            "--profile",
            "quick",
            "--summary-only",
            "--no-banner",
            "--color",
            "never",
            "--delay-ms",
            "0",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("SCAN SUMMARY"));
    assert!(!text.contains(&server.url));
    assert!(!text.contains("VERSION EVIDENCE"));
}

#[test]
fn jsonl_flushes_each_target_before_the_next_target_finishes() {
    let release = Arc::new(AtomicBool::new(false));
    let released = Arc::clone(&release);
    let server = Server::new(move |path| {
        if path == "/slow" {
            let end = Instant::now() + Duration::from_secs(5);
            while !released.load(Ordering::Relaxed) && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        response("200 OK", "X-PHP-Version: 8.4.27\r\n", "OK")
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_anatoly"))
        .args([
            "scan",
            &server.url,
            &format!("{}slow", server.url),
            "--profile",
            "quick",
            "--delay-ms",
            "0",
            "--jsonl",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (send, receive) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            send.send(line.unwrap()).unwrap();
        }
    });
    let first = receive
        .recv_timeout(Duration::from_secs(3))
        .expect("first target must be flushed independently");
    let first: serde_json::Value = serde_json::from_str(&first).unwrap();
    assert_eq!(first["type"], "target");
    assert_eq!(first["index"], 1);
    release.store(true, Ordering::Relaxed);
    let status = child.wait().unwrap();
    reader.join().unwrap();
    assert!(status.success());
    let events: Vec<serde_json::Value> = receive
        .try_iter()
        .map(|line| serde_json::from_str(&line).unwrap())
        .collect();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["type"], "target");
    assert_eq!(events[0]["index"], 2);
    assert_eq!(events[1]["type"], "summary");
    assert_eq!(events[1]["data"]["urls_analyzed"], 2);
    assert!(events[1]["configuration"].is_object());
    assert_eq!(server.paths.lock().unwrap().len(), 2);
}

#[test]
fn diagnostic_queries_are_requested_but_redacted_from_all_machine_exports() {
    const MARKER: &str = "SYNTHETIC_QUERY_VALUE_NOT_A_REAL_KEY";
    let server = Server::new(|path| {
        if path == "/" {
            response("200 OK", "X-PHP-Version: 8.4.27\r\n", "OK")
        } else {
            response("404 Not Found", "", "missing")
        }
    });
    let path = format!("info.php?api_key={MARKER}#not-sent");
    // URL fragments are invalid for explicit diagnostic requests; query-only paths are accepted.
    let path = path.split('#').next().unwrap();
    for output_mode in ["--json", "--jsonl"] {
        let output = Command::new(env!("CARGO_BIN_EXE_anatoly"))
            .args([
                "scan",
                &server.url,
                "--samples",
                "1",
                "--delay-ms",
                "0",
                "--diagnostic-path",
                path,
                output_mode,
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(!String::from_utf8(output.stdout).unwrap().contains(MARKER));
    }
    let plan = Command::new(env!("CARGO_BIN_EXE_anatoly"))
        .args([
            "scan",
            &server.url,
            "--dry-run",
            "--json",
            "--diagnostic-path",
            path,
        ])
        .output()
        .unwrap();
    assert!(plan.status.success());
    assert!(!String::from_utf8(plan.stdout).unwrap().contains(MARKER));
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let file = std::env::temp_dir().join(format!("anatoly-export-fixture-{unique}.json"));
    let output = Command::new(env!("CARGO_BIN_EXE_anatoly"))
        .args([
            "scan",
            &server.url,
            "--samples",
            "1",
            "--delay-ms",
            "0",
            "--diagnostic-path",
            path,
            "--json",
            "--output",
            file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let contents = std::fs::read_to_string(&file).unwrap();
    std::fs::remove_file(&file).unwrap();
    assert!(!contents.contains(MARKER));
    assert!(
        server
            .paths
            .lock()
            .unwrap()
            .iter()
            .any(|p| p.contains(MARKER))
    );
}
