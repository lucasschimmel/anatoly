use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{fs::OpenOptions, io::Write, path::Path};

pub fn preflight(paths: &[Option<&Path>]) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for path in paths.iter().flatten() {
        if path.symlink_metadata().is_ok() {
            bail!("Output already exists or output paths overlap; choose distinct new filenames");
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if !parent.is_dir() {
            bail!("Output directory must already exist");
        }
        let mut normalized = parent
            .canonicalize()
            .context("Resolving output directory")?;
        normalized.push(path.file_name().context("Output must name a file")?);
        let key = normalized.to_string_lossy().into_owned();
        #[cfg(windows)]
        let key = key.to_lowercase();
        if !seen.insert(key) {
            bail!("Output paths overlap; choose distinct new filenames");
        }
    }
    Ok(())
}

pub fn write(path: &Path, format: &str, report: &Value) -> Result<()> {
    let text = match format {
        "csv" => csv(report),
        "sarif" => serde_json::to_string_pretty(&sarif(report))?,
        _ => bail!("Unsupported export format"),
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("Creating new export file")?;
    file.write_all(text.as_bytes()).context("Writing export")
}

fn targets(report: &Value) -> impl Iterator<Item = &Value> {
    report["targets"].as_array().into_iter().flatten()
}
fn text(value: &Value) -> String {
    value.as_str().map_or_else(
        || {
            if value.is_null() {
                String::new()
            } else {
                value.to_string()
            }
        },
        str::to_owned,
    )
}
fn joined(value: &Value) -> String {
    value
        .as_array()
        .into_iter()
        .flatten()
        .map(text)
        .collect::<Vec<_>>()
        .join("; ")
}
fn version(target: &Value) -> String {
    let v = &target["version"];
    if v.is_null() {
        return "unknown".into();
    }
    format!(
        "{}.{}.{}{}",
        v["major"],
        v["minor"],
        v["patch"],
        if v["prerelease"] == true {
            " (prerelease)"
        } else {
            ""
        }
    )
}
fn url(value: &Value) -> String {
    value
        .as_str()
        .and_then(|s| anatoly::http::validate_url(s).ok())
        .map_or_else(String::new, |u| anatoly::http::display_url(&u))
}
fn cell(value: &str) -> String {
    let mut clean = anatoly::ui::safe_text(value);
    if clean
        .trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
        .starts_with(['=', '+', '-', '@'])
    {
        clean.insert(0, '\'');
    }
    format!("\"{}\"", clean.replace('"', "\"\""))
}
fn csv(report: &Value) -> String {
    let mut lines=vec!["target,verdict,php_version,detection_level,coverage_complete,requests_sent,proof_methods,proof_sources,limitations,waf_indicators,tls_status,security_certified".to_owned()];
    for target in targets(report) {
        let proofs = target["evidence"]
            .as_array()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let columns = [
            url(&target["target"]),
            text(&target["verdict"]),
            version(target),
            text(&target["analysis"]["detection_level"]),
            text(&target["analysis"]["coverage_complete"]),
            text(&target["requests_sent"]),
            proofs
                .iter()
                .map(|e| text(&e["kind"]))
                .collect::<Vec<_>>()
                .join("; "),
            proofs
                .iter()
                .map(|e| text(&e["source"]))
                .collect::<Vec<_>>()
                .join("; "),
            joined(&target["limitations"]),
            target["waf"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|w| text(&w["product"]))
                .collect::<Vec<_>>()
                .join("; "),
            target["tls"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|t| text(&t["status"]))
                .collect::<Vec<_>>()
                .join("; "),
            "false".into(),
        ];
        lines.push(
            columns
                .iter()
                .map(|s| cell(s))
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    format!("{}\r\n", lines.join("\r\n"))
}

fn result(rule: &str, level: &str, message: &str, target: &Value) -> Value {
    json!({"ruleId":rule,"level":level,"message":{"text":anatoly::ui::safe_text(message)},
        "locations":[{"physicalLocation":{"artifactLocation":{"uri":url(&target["target"])}}}],
        "properties":{"verdict":target["verdict"],"detection_level":target["analysis"]["detection_level"],
            "policy_date_scope":"Recorded public evidence; actual vendor patches are not attested", "certified":false}})
}
fn sarif(report: &Value) -> Value {
    let mut results = vec![];
    for target in targets(report) {
        match target["verdict"].as_str() {
            Some("potentially_affected")=>results.push(result("ANATOLY-PHP2SHELL-VERSION","warning",
                &format!("Advertised PHP {} is potentially affected or unsupported. Verify the actual vendor patch state; exploitability was not tested.",version(target)),target)),
            Some("inconclusive"|"error")=>results.push(result("ANATOLY-ASSESSMENT-INCOMPLETE","note",
                "PHP2Shell assessment is incomplete or inconclusive. This is not evidence of protection.",target)),
            _=>{}
        }
        if target["evidence"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|e| e["kind"] == "diagnostic")
        {
            results.push(result("ANATOLY-DIAGNOSTIC-DISCLOSURE","warning","A PHP diagnostic disclosed runtime information to this request. Review route access controls.",target));
        }
    }
    let rules = vec![
        json!({"id":"ANATOLY-PHP2SHELL-VERSION","shortDescription":{"text":"Potentially affected PHP declaration"}}),
        json!({"id":"ANATOLY-ASSESSMENT-INCOMPLETE","shortDescription":{"text":"Inconclusive public assessment"}}),
        json!({"id":"ANATOLY-DIAGNOSTIC-DISCLOSURE","shortDescription":{"text":"PHP diagnostic disclosure accessible to this request"}}),
    ];
    json!({"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{
        "tool":{"driver":{"name":"Anatoly","version":env!("CARGO_PKG_VERSION"),"informationUri":"https://github.com/lucasschimmel/anatoly","rules":rules}},
        "results":results,"properties":{"advisory_snapshot":report["policy_date"],"assurance":"Public observations only; security is not certified"}}]})
}
