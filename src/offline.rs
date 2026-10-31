//! Bounded, network-free consumers of aggregate Anatoly JSON reports.
#[path = "offline_render.rs"]
mod render;
#[path = "offline_validation.rs"]
mod validation;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, io::Read, path::Path};

const MAX_REPORT_BYTES: u64 = 16 * 1024 * 1024;
const ASSURANCE: &str =
    "Untrusted public HTTP observations; neither patch state nor security is certified.";

pub fn run(
    command: &str,
    input: &Path,
    second: Option<&Path>,
    output: Option<&Path>,
    json_output: bool,
    ui: &anatoly::ui::Ui,
) -> Result<u8> {
    let report = load_report(input)?;
    let (result, code) = match command {
        "compare" => compare(
            &report,
            &load_report(second.context("A current report is required")?)?,
        )?,
        "explain" => (explain(&report), 0),
        "policy" => evaluate(&report, second)?,
        "report" => {
            let path = output.context("HTML report requires --output with a new filename")?;
            render::write_html(path, &report)?;
            let result = json!({"type":"html_report", "targets": targets(&report).len(),
                "written":true, "assurance":ASSURANCE});
            emit(&result, json_output, ui)?;
            return Ok(0);
        }
        _ => bail!("Unknown offline command"),
    };
    if let Some(path) = output {
        render::write_json(path, &result)?;
    }
    emit(&result, json_output, ui)?;
    Ok(code)
}

fn read_json(path: &Path, maximum: u64) -> Result<Value> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .context("Opening input JSON")?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .context("Reading input JSON")?;
    if bytes.len() as u64 > maximum {
        bail!("Input JSON exceeds its size limit");
    }
    serde_json::from_slice(&bytes).context("Invalid input JSON")
}

fn load_report(path: &Path) -> Result<Value> {
    let report = read_json(path, MAX_REPORT_BYTES)?;
    if report["tool"] != "anatoly" {
        bail!("Expected an aggregate Anatoly JSON report");
    }
    let entries = report["targets"]
        .as_array()
        .context("Report targets must be an array")?;
    if entries.is_empty() || entries.len() > 256 {
        bail!("Report must contain between 1 and 256 targets");
    }
    let mut seen = std::collections::HashSet::new();
    for target in entries {
        validation::validate_target(target)?;
        if !seen.insert(text(target, "target")) {
            bail!("Report contains duplicate target URLs");
        }
    }
    Ok(report)
}

fn targets(report: &Value) -> &[Value] {
    report["targets"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or("")
}

fn index(report: &Value) -> BTreeMap<&str, &Value> {
    targets(report)
        .iter()
        .map(|t| (text(t, "target"), t))
        .collect()
}

fn snapshot(target: &Value) -> Value {
    let mut result = json!({});
    for key in [
        "final_url",
        "verdict",
        "version",
        "version_status",
        "analysis",
        "directives",
        "signals",
    ] {
        result[key] = target[key].clone();
    }
    // Samples and duplicate proof ordering are transport details; compare unique proofs.
    for key in [
        "samples_requested",
        "samples_completed",
        "samples_with_version",
        "diagnostics_requested",
        "diagnostics_completed",
    ] {
        if let Some(object) = result["analysis"].as_object_mut() {
            object.remove(key);
        }
    }
    for key in ["evidence", "directives", "signals"] {
        let unique: std::collections::BTreeSet<_> = target[key]
            .as_array()
            .into_iter()
            .flatten()
            .map(Value::to_string)
            .collect();
        result[key] = json!(unique);
    }
    result
}

fn compare(baseline: &Value, current: &Value) -> Result<(Value, u8)> {
    let before = index(baseline);
    let after = index(current);
    let mut changes = Vec::new();
    for (url, target) in &after {
        match before.get(url) {
            None => changes.push(json!({"target":url,"change":"added", "current":snapshot(target)})),
            Some(old) if snapshot(old) != snapshot(target) => changes.push(json!({
                "target":url,"change":"changed","baseline":snapshot(old),"current":snapshot(target)})),
            _ => {}
        }
    }
    for (url, target) in &before {
        if !after.contains_key(url) {
            changes.push(json!({"target":url,"change":"removed","baseline":snapshot(target)}));
        }
    }
    let changed = !changes.is_empty() || baseline["policy_date"] != current["policy_date"];
    Ok((
        json!({"type":"comparison", "changed":changed,
        "baseline_policy_date":baseline["policy_date"], "current_policy_date":current["policy_date"],
        "changes":changes, "assurance":ASSURANCE}),
        u8::from(changed),
    ))
}

fn explain(report: &Value) -> Value {
    let entries: Vec<_> = targets(report).iter().map(|t| json!({
        "target":t["target"], "verdict":t["verdict"], "version":t["version"],
        "detection_level":t["analysis"]["detection_level"],
        "version_candidates":t["version_candidates"], "proofs":t["evidence"],
        "hypotheses":t["signals"], "coverage_complete":t["analysis"]["coverage_complete"],
        "missing_evidence":t["analysis"]["gaps"], "skipped_checks":t["analysis"]["skipped_checks"],
        "limitations":t["limitations"], "recommendations":t["recommendations"]
    })).collect();
    json!({"type":"explanation", "policy_date":report["policy_date"], "targets":entries,
        "interpretation":"Declared means a remote source announced the version; corroborated means different evidence methods agree. Hypotheses never prove a PHP release. Contradictory versions require investigation.",
        "assurance":ASSURANCE})
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Rules {
    require_https: bool,
    no_affected: bool,
    no_diagnostics: bool,
    require_version: bool,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            require_https: true,
            no_affected: true,
            no_diagnostics: true,
            require_version: false,
        }
    }
}

fn rule(name: &str, status: &str, detail: &str) -> Value {
    json!({"rule":name,"status":status,"detail":detail})
}

fn target_rules(target: &Value, rules: &Rules) -> Vec<Value> {
    let mut checks = vec![];
    if rules.require_https {
        let http = text(target, "target").starts_with("http:")
            || text(target, "final_url").starts_with("http:");
        checks.push(rule("require_https", if http { "fail" } else if target["analysis"]["http_verified"] == true { "pass" } else { "unknown" },
            "Observed entry and final URL transport only; HTTP availability on other routes is not tested."));
    }
    if rules.no_affected {
        let status = match text(target, "verdict") {
            "potentially_affected" => "fail",
            "fix_floor_observed" => "pass",
            _ => "unknown",
        };
        checks.push(rule("no_affected", status,"Uses recorded advisory snapshot and advertised release; vendor patch state remains unattested."));
    }
    if rules.no_diagnostics {
        let exposed = target["evidence"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|e| e["kind"] == "diagnostic")
            || target["directives"]
                .as_array()
                .is_some_and(|a| !a.is_empty());
        checks.push(rule("no_diagnostics", if exposed { "fail" } else { "unknown" },
            "A disclosed diagnostic is a failure; absence in a bounded scan cannot establish that no diagnostic exists."));
    }
    if rules.require_version {
        let level = text(&target["analysis"], "detection_level");
        checks.push(rule("require_version", if matches!(level,"declared"|"corroborated") { "pass" } else { "fail" },
            "Requires a non-contradictory public version declaration, not a certified runtime version."));
    }
    checks
}

fn evaluate(report: &Value, path: Option<&Path>) -> Result<(Value, u8)> {
    let rules = match path {
        Some(path) => serde_json::from_value(read_json(path, 65_536)?)
            .context("Invalid policy configuration")?,
        None => Rules::default(),
    };
    let entries: Vec<_> = targets(report)
        .iter()
        .map(|t| {
            json!({
                "target":t["target"], "checks":target_rules(t, &rules)
            })
        })
        .collect();
    let checks = entries
        .iter()
        .flat_map(|t| t["checks"].as_array().into_iter().flatten());
    let statuses: Vec<_> = checks.map(|c| text(c, "status")).collect();
    let (status, code) = if statuses.contains(&"fail") {
        ("fail", 1)
    } else if statuses.is_empty() || statuses.contains(&"unknown") {
        ("unknown", 2)
    } else {
        ("pass", 0)
    };
    Ok((
        json!({"type":"policy_evaluation","status":status,"targets":entries,
        "assurance":ASSURANCE}),
        code,
    ))
}

fn emit(result: &Value, json_output: bool, ui: &anatoly::ui::Ui) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(result)?);
    } else {
        ui.details(
            &text(result, "type").replace('_', " ").to_ascii_uppercase(),
            result,
        );
    }
    Ok(())
}
