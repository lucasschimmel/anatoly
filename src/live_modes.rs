use crate::{
    cli::{Profile, ScanArgs, WatchArgs},
    runner,
};
use anatoly::{
    http::{Transport, display_url, validate_url},
    scan::{self, Report},
    ui::Ui,
};
use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::{
    io::Write,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub fn exposure(mut args: ScanArgs, json: bool, ui: &Ui) -> Result<u8> {
    if matches!(args.profile, Profile::Quick) || args.no_discover {
        bail!("Exposure requires discovery; choose balanced or thorough without --no-discover");
    }
    args.deep = true;
    runner::run(args, json, ui)
}

pub fn doctor(args: ScanArgs, json_output: bool, ui: &Ui) -> Result<u8> {
    reject_exports(&args)?;
    if args.jsonl || args.summary_only {
        bail!(
            "Doctor produces one configuration result; use --json without --jsonl or --summary-only"
        );
    }
    let targets = runner::targets(&args)?;
    let (limits, options) = runner::configure(&args)?;
    runner::validate_scope(&targets, &options)?;
    Transport::with_policy(limits.clone(), options.network.clone())?;
    let output = json!({"type":"doctor", "status":"configuration_valid", "network_requests_sent":0,
        "target_count":targets.len(), "configuration":runner::configuration(&args,&limits,&options),
        "limitations":["DNS, remote TLS, connectivity and application security were not tested."]});
    if let Some(path) = &args.output {
        runner::write_new(path, &output)?;
    }
    emit(&output, json_output, ui)
}

pub fn headers(args: ScanArgs, json_output: bool, ui: &Ui) -> Result<u8> {
    reject_exports(&args)?;
    if args.waf_probe {
        bail!("--waf-probe is available in scan, exposure and watch");
    }
    if args.dry_run {
        return runner::run(args, json_output, &Ui::new(anatoly::ui::Color::Never));
    }
    let targets = runner::targets(&args)?;
    let (limits, options) = runner::configure(&args)?;
    runner::validate_scope(&targets, &options)?;
    ensure_new(&args)?;
    let mut results = vec![];
    for target in targets {
        let url = validate_url(&target)?;
        let mut transport = Transport::with_policy(limits.clone(), options.network.clone())?;
        let item = match transport.get(&url) {
            Ok(page) => json!({"target":display_url(&url),"final_url":display_url(&page.url),
                "http_status":page.status,"findings":anatoly::header_audit::assess(&page),
                "observations":transport.observations,"requests_sent":transport.requests,"tls":transport.tls,"waf":transport.waf}),
            Err(_) => {
                json!({"target":display_url(&url),"error":"HTTP observation failed; verify DNS, TLS, connection and budgets", "requests_sent":transport.requests})
            }
        };
        if args.jsonl {
            event(&json!({"type":"target","data":item}))?;
        } else if !args.summary_only && !json_output {
            emit(&item, false, ui)?;
        }
        results.push(item);
    }
    let errors = results.iter().filter(|r| r.get("error").is_some()).count();
    let output = json!({"type":"headers","targets":results,"errors":errors,
        "configuration":runner::configuration(&args,&limits,&options),
        "limitations":["One response chain per supplied URL; headers are configuration observations, not proof of application security.",
            "Only recognized PHP session cookie names are inspected; no cookie values are stored or replayed."]});
    if let Some(path) = &args.output {
        runner::write_new(path, &output)?;
    }
    if args.jsonl {
        event(
            &json!({"type":"summary","targets_checked":output["targets"].as_array().map_or(0,Vec::len),"errors":errors}),
        )?;
    } else if json_output || args.summary_only {
        emit(&output, json_output, ui)?;
    }
    Ok(
        if errors > 0 && !matches!(args.fail_on, crate::cli::FailOn::Never) {
            3
        } else {
            0
        },
    )
}

// Rounds share prevalidated inputs; each target retains its own request and time budgets.
pub fn watch(args: WatchArgs, json_output: bool, ui: &Ui) -> Result<u8> {
    reject_exports(&args.scan)?;
    if args.scan.jsonl || args.scan.summary_only {
        bail!(
            "Watch uses change events; use --json for one aggregate result, without --jsonl or --summary-only"
        );
    }
    if args.scan.dry_run {
        return runner::run(args.scan, json_output, ui);
    }
    let targets = runner::targets(&args.scan)?;
    let (limits, options) = runner::configure(&args.scan)?;
    runner::validate_scope(&targets, &options)?;
    ensure_new(&args.scan)?;
    let mut previous = vec![];
    let mut events = vec![];
    let mut final_report = Report::new(vec![]);
    let scanner = scan::Scanner::new()?;
    for round in 1..=args.iterations {
        if round > 1 {
            std::thread::sleep(Duration::from_secs(args.interval.into()));
        }
        let mut results = vec![];
        for (index, target) in targets.iter().enumerate() {
            let report = scanner.scan(target, limits.clone(), &options)?;
            let state = state(&report)?;
            let changed = previous.get(index) != Some(&state);
            if changed {
                let change = json!({"type":if round==1 {"baseline"} else {"change"},"round":round,
                    "observed_at_unix":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    "target":report.target,"state":state});
                if !json_output {
                    emit(&change, false, ui)?;
                    std::io::stdout().flush()?;
                }
                events.push(change);
            }
            if round == 1 {
                previous.push(state);
            } else {
                previous[index] = state;
            }
            results.push(report);
        }
        final_report = Report::new(results);
    }
    final_report.run_configuration = Some(runner::configuration(&args.scan, &limits, &options));
    let code = runner::exit_code(&final_report, args.scan.fail_on);
    let output = json!({"type":"watch","rounds_completed":args.iterations,"interval_seconds":args.interval,
        "events":events,"final_report":final_report});
    if let Some(path) = &args.scan.output {
        runner::write_new(path, &output)?;
    }
    if json_output {
        emit(&output, true, ui)?;
    } else {
        ui.summary(&final_report.summary);
    }
    Ok(code)
}

fn state(report: &scan::ScanReport) -> Result<Value> {
    let mut evidence = report
        .evidence
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()?;
    evidence.sort_by_key(Value::to_string);
    evidence.dedup();
    Ok(
        json!({"version":report.version,"verdict":report.verdict,"detection_level":report.analysis.detection_level,
        "coverage_complete":report.analysis.coverage_complete,"gaps":report.analysis.gaps,
        "final_url":report.final_url,"evidence":evidence,"signals":report.signals,"directives":report.directives,
        "tls":report.tls,"waf":report.waf,"technologies":report.technologies,"runtime":report.runtime,
        "statuses":report.observations.iter().map(|o|o.status).collect::<Vec<_>>()}),
    )
}

fn ensure_new(args: &ScanArgs) -> Result<()> {
    if args.output.as_ref().is_some_and(|p| p.exists()) {
        bail!("Output already exists; choose a new report filename");
    }
    Ok(())
}
fn reject_exports(args: &ScanArgs) -> Result<()> {
    if args.csv.is_some() || args.sarif.is_some() {
        bail!(
            "CSV/SARIF flags are supported by scan/exposure; use report --format for saved scan reports"
        );
    }
    Ok(())
}
fn event(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string(value)?);
    std::io::stdout().flush()?;
    Ok(())
}
fn emit(value: &Value, json_output: bool, ui: &Ui) -> Result<u8> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        ui.details("ANATOLY / OBSERVATIONS", value);
    }
    Ok(0)
}
