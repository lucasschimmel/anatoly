use anyhow::{Context, Result};
use serde_json::Value;
use std::{fs::OpenOptions, io::Write, path::Path};

pub(super) fn write_json(path: &Path, value: &Value) -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("Creating new output file; existing files are never overwritten")?;
    serde_json::to_writer_pretty(file, value).context("Writing JSON output")
}

fn escape(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => escaped.push(' '),
            c => escaped.push(c),
        }
    }
    escaped
}

fn string(value: &Value) -> &str {
    value.as_str().unwrap_or("unknown")
}

fn section(html: &mut String, label: &str, value: &Value) -> Result<()> {
    html.push_str(&format!(
        "<h3>{}</h3><pre>{}</pre>",
        escape(label),
        escape(&serde_json::to_string_pretty(value)?)
    ));
    Ok(())
}

// Keep the complete static document template together so its CSP and escaped fields
// can be reviewed as one unit; dynamic sections delegate to the small section helper.
pub(super) fn write_html(path: &Path, report: &Value) -> Result<()> {
    let mut html = String::from(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Anatoly — PHP exposure intelligence</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#090f18;color:#dce7f2;font:16px/1.6 system-ui,sans-serif}
main{max-width:1100px;margin:auto;padding:48px 24px}header{border-top:3px solid #67dcff;border-bottom:1px solid #254158;padding:24px 0;margin-bottom:32px}
.eyebrow{color:#67dcff;letter-spacing:.2em;font-size:12px}h1{font-size:52px;letter-spacing:.12em;margin:12px 0}h2{overflow-wrap:anywhere;font-size:21px}
h3{font-size:14px;color:#80dfff;text-transform:uppercase;letter-spacing:.08em;margin-top:28px}article{background:#101b29;border:1px solid #254158;border-radius:12px;padding:24px;margin:20px 0}
.badge{display:inline-block;border:1px solid #67dcff;color:#8ce5ff;border-radius:6px;padding:4px 10px;font:13px ui-monospace,monospace}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1420;border-radius:8px;padding:16px;font:13px/1.6 ui-monospace,monospace}
.muted{color:#9bb0c4}footer{border-top:1px solid #254158;margin-top:40px;padding-top:20px;font-size:13px}
@media print{body,article,pre{background:white;color:black}main{padding:0}article{break-inside:avoid}h3,.eyebrow,.badge{color:#174e68}}
</style></head><body><main><header><div class="eyebrow">PHP EXPOSURE INTELLIGENCE</div><h1>ANATOLY</h1>
<p class="muted">Public HTTP evidence · offline assessment report</p></header>
<p>No security certification: version declarations, hypotheses and missing evidence remain distinct. A matching release number does not attest vendor patches or running worker builds.</p>"#,
    );
    html.push_str(&format!(
        "<p class=\"muted\">Recorded advisory snapshot: {}</p>",
        escape(string(&report["policy_date"]))
    ));
    for target in super::targets(report) {
        html.push_str(&format!(
            "<article><span class=\"badge\">{}</span><h2>{}</h2>",
            escape(string(&target["verdict"])),
            escape(string(&target["target"]))
        ));
        html.push_str(&format!(
            "<p>Detection level: <strong>{}</strong> · Coverage complete: {}</p>",
            escape(string(&target["analysis"]["detection_level"])),
            target["analysis"]["coverage_complete"] == true
        ));
        for (label, value) in [
            ("Selected version", &target["version"]),
            (
                "Version candidates and proofs",
                &target["version_candidates"],
            ),
            ("All explicit version evidence", &target["evidence"]),
            ("Unverified hypotheses", &target["signals"]),
            ("Coverage and missing evidence", &target["analysis"]),
            ("Recorded checks", &target["checks"]),
            ("Recommendations", &target["recommendations"]),
            ("Limitations", &target["limitations"]),
        ] {
            section(&mut html, label, value)?;
        }
        html.push_str("</article>");
    }
    html.push_str("<footer class=\"muted\">Generated locally from an existing Anatoly JSON report. No network requests were sent. Imported reports are untrusted observations, not signed attestations.</footer></main></body></html>");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("Creating HTML report; existing files are never overwritten")?;
    file.write_all(html.as_bytes())
        .context("Writing HTML report")
}
