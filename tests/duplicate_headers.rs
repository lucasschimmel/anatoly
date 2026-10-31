mod common;

use common::{Server, limits, response};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::Duration,
};

use anatoly::{assessment::Verdict, http::Limits, policy::VersionStatus, scan::scan};

#[test]
fn contradictory_duplicate_version_headers_remain_inconclusive_in_either_order() {
    for header in ["X-Powered-By", "Server"] {
        for versions in [["8.4.27", "8.4.26"], ["8.4.26", "8.4.27"]] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let target = format!("http://{}/", listener.local_addr().unwrap());
            let worker = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let mut chunk = [0; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let size = stream.read(&mut chunk).unwrap();
                    assert!(size > 0 && request.len() < 8192);
                    request.extend_from_slice(&chunk[..size]);
                }
                write!(stream,
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n{header}: PHP/{}\r\n{header}: PHP/{}\r\n\r\nOK",
                    versions[0], versions[1]
                ).unwrap();
            });
            let bounds = Limits {
                timeout: Duration::from_secs(5),
                max_requests: 1,
                max_body: 4096,
                delay: Duration::ZERO,
            };
            let result = scan(&target, bounds, false, &[]).unwrap();
            worker.join().unwrap();
            assert_eq!(
                result.version_status,
                VersionStatus::Conflicting,
                "{header} {versions:?}"
            );
            assert_eq!(
                result.verdict,
                Verdict::Inconclusive,
                "{header} {versions:?}"
            );
            assert_eq!(result.evidence.len(), 2);
            assert!(result.version.is_none());
        }
    }
}

#[test]
fn complete_and_comma_separated_runtime_headers_keep_every_conflicting_version() {
    let long_value = format!("PHP/8.4.27 {} PHP/8.4.26", "x".repeat(2048));
    for (name, value) in [
        ("X-Powered-By", long_value),
        ("X-PHP-Version", "8.4.27,8.4.26".into()),
        ("PHP-Version", "8.4.27,8.4.26".into()),
    ] {
        let server =
            Server::new(move |_| response("200 OK", &format!("{name}: {value}\r\n"), "OK"));
        let report = scan(&server.url, limits(), false, &[]).unwrap();
        assert_eq!(server.paths.lock().unwrap().len(), 1);
        assert_eq!(report.version_status, VersionStatus::Conflicting, "{name}");
        assert_eq!(report.verdict, Verdict::Inconclusive, "{name}");
        assert_eq!(report.version_candidates.len(), 2, "{name}");
        assert!(report.version.is_none());
    }
}
