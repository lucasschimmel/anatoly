//! Reproducible local batch benchmark; no network targets or external dependencies.
#[allow(dead_code)]
#[path = "../tests/common/mod.rs"]
mod common;

use anatoly::{
    scan::{Scanner, scan_configured},
    scan_options::ScanOptions,
};
use anyhow::{Result, ensure};
use common::{Server, limits, response};
use std::time::Instant;

const TARGETS: usize = 16;
const ROUNDS: usize = 3;

fn main() -> Result<()> {
    let server = Server::new(|path| {
        response(
            "200 OK",
            "X-Powered-By: Craft CMS\r\n",
            &if path == "/deep" {
                format!(
                    "{}<p>Welcome</p>{}",
                    "<div>".repeat(10_000),
                    "</div>".repeat(10_000)
                )
            } else {
                "<p>Powered by CraftCMS</p>".into()
            },
        )
    });
    let mut options = ScanOptions {
        samples: 1,
        discover: false,
        ..ScanOptions::default()
    };
    options.network.no_proxy = true;
    let mut fresh = vec![];
    let mut shared = vec![];
    for round in 0..ROUNDS {
        // Alternate order so the same implementation does not always get a warm cache.
        for reuse in if round % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        } {
            let started = Instant::now();
            let scanner = reuse.then(Scanner::new).transpose()?;
            for _ in 0..TARGETS {
                let report = if let Some(scanner) = &scanner {
                    scanner.scan(&server.url, limits(), &options)?
                } else {
                    scan_configured(&server.url, limits(), &options)?
                };
                ensure!(
                    report.requests_sent == 1
                        && report.version.is_none()
                        && report.technologies.iter().any(|t| t.name == "Craft CMS"),
                    "Benchmark behavior changed"
                );
            }
            if reuse {
                shared.push(started.elapsed().as_secs_f64());
            } else {
                fresh.push(started.elapsed().as_secs_f64());
            }
        }
    }
    let mut budget = limits();
    budget.max_body = 262_144;
    let started = Instant::now();
    let guarded = Scanner::new()?.scan(&format!("{}deep", server.url), budget, &options)?;
    let deep_seconds = started.elapsed().as_secs_f64();
    ensure!(
        !guarded.analysis.coverage_complete
            && guarded.analysis.gaps.iter().any(|gap| gap.contains("HTML")),
        "Structural guard did not report incomplete analysis"
    );
    let mut sorted_fresh = fresh.clone();
    sorted_fresh.sort_by(f64::total_cmp);
    let mut sorted_shared = shared.clone();
    sorted_shared.sort_by(f64::total_cmp);
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "targets_per_round":TARGETS,"rounds":ROUNDS,"requests_per_target":1,
            "fresh_seconds":fresh,"shared_seconds":shared,
            "median_speedup":sorted_fresh[ROUNDS/2]/sorted_shared[ROUNDS/2],
            "nested_10000_elements_seconds":deep_seconds,
            "scope":"Local fixture, zero pacing, this machine/build only; no general network throughput claim"
        }))?
    );
    Ok(())
}
