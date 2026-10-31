use crate::cli::{FailOn, Profile, ScanArgs};
use anatoly::{
    http::{Limits, allowed_redirect, display_url, validate_url},
    network::{NetworkPolicy, normalize_host},
    scan::{self, Report},
    scan_options::ScanOptions,
    ui::Ui,
};
use anyhow::{Context, Result, bail};
use std::{
    collections::HashSet,
    fs,
    io::{Read, Write},
    time::Duration,
};

pub fn run(args: ScanArgs, json: bool, ui: &Ui) -> Result<u8> {
    let targets = targets(&args)?;
    let (limits, options) = configure(&args)?;
    validate_scope(&targets, &options)?;
    crate::exports::preflight(&[
        args.output.as_deref(),
        args.csv.as_deref(),
        args.sarif.as_deref(),
    ])?;
    if args.dry_run && (args.csv.is_some() || args.sarif.is_some()) {
        bail!("CSV/SARIF require completed scan results, not a dry run");
    }
    if args.output.as_ref().is_some_and(|p| p.exists()) {
        bail!("Output already exists; choose a new report filename");
    }
    let configuration = configuration(&args, &limits, &options);
    if args.dry_run {
        let plan = serde_json::json!({ "type": "scan_plan", "network_requests_sent": 0,
            "targets": targets.iter().map(|t| validate_url(t).map(|u| display_url(&u))).collect::<Result<Vec<_>>>()?,
            "configuration": configuration });
        if let Some(path) = &args.output {
            write_new(path, &plan)?;
        }
        if !json {
            println!("  DRY RUN / validated plan; no HTTP requests sent\n");
        }
        println!("{}", serde_json::to_string_pretty(&plan)?);
        return Ok(0);
    }
    let mut results = vec![];
    for (i, target) in targets.iter().enumerate() {
        let result = scan::scan_configured(target, limits.clone(), &options)?;
        if args.jsonl {
            event(&serde_json::json!({"type": "target", "index": i + 1, "data": result}))?;
        } else if !json && !args.summary_only {
            ui.report(i + 1, targets.len(), &result);
        }
        results.push(result);
    }
    let mut report = Report::new(results);
    report.run_configuration = Some(configuration);
    if args.jsonl {
        event(
            &serde_json::json!({"type": "summary", "data": report.summary, "configuration": report.run_configuration}),
        )?;
    } else if !json {
        ui.summary(&report.summary);
    }
    if let Some(path) = &args.output {
        write_new(path, &report)?;
    }
    if args.csv.is_some() || args.sarif.is_some() {
        let value = serde_json::to_value(&report)?;
        if let Some(path) = &args.csv {
            crate::exports::write(path, "csv", &value)?;
        }
        if let Some(path) = &args.sarif {
            crate::exports::write(path, "sarif", &value)?;
        }
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }
    Ok(exit_code(&report, args.fail_on))
}

fn event(value: &serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string(value)?);
    std::io::stdout().flush().context("Flushing JSONL event")
}

pub(crate) fn write_new(path: &std::path::Path, value: &impl serde::Serialize) -> Result<()> {
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("Creating output file")?;
    serde_json::to_writer_pretty(file, value).context("Writing JSON output")
}

pub(crate) fn exit_code(report: &Report, policy: FailOn) -> u8 {
    match policy {
        FailOn::Any => report.exit_code(),
        FailOn::Never => 0,
        FailOn::Error => {
            if report.summary.errors > 0 {
                3
            } else {
                0
            }
        }
        FailOn::Affected => {
            if report.summary.errors > 0 {
                3
            } else if report.summary.potentially_affected > 0 {
                1
            } else {
                0
            }
        }
    }
}

pub(crate) fn configure(args: &ScanArgs) -> Result<(Limits, ScanOptions)> {
    if matches!(args.profile, Profile::Quick)
        && (args.deep || !args.diagnostic_path.is_empty() || args.wordlist.is_some())
    {
        bail!(
            "The quick profile cannot be combined with --deep or --diagnostic-path; choose balanced or thorough"
        );
    }
    let (default_samples, default_budget, default_delay) = match args.profile {
        Profile::Quick => (1, 4, 500),
        Profile::Balanced => (3, 8, 150),
        Profile::Thorough => (5, 32, 150),
    };
    let deep = args.deep || matches!(args.profile, Profile::Thorough);
    let spacing = Duration::from_millis(args.delay_ms.unwrap_or(default_delay).into());
    let rate_spacing = args.rate_limit.map_or(Duration::ZERO, |r| {
        Duration::from_secs_f64(1.0 / f64::from(r))
    });
    let limits = Limits {
        timeout: Duration::from_secs(args.timeout.into()),
        max_requests: args
            .max_requests
            .unwrap_or(if deep { 32 } else { default_budget })
            .into(),
        max_body: args.max_body as usize,
        delay: spacing.max(rate_spacing),
    };
    let ca_pem = if let Some(path) = &args.ca_cert {
        let mut bytes = vec![];
        fs::File::open(path)
            .context("Opening public CA certificate")?
            .take(1_048_577)
            .read_to_end(&mut bytes)
            .context("Reading public CA certificate")?;
        Some(bytes)
    } else {
        None
    };
    let network = NetworkPolicy {
        request: crate::cli_inputs::request(args)?,
        connect_timeout: Some(Duration::from_secs(args.connect_timeout.into())),
        target_timeout: Some(Duration::from_secs(args.target_timeout.into())),
        max_redirects: if args.no_redirects {
            0
        } else {
            args.max_redirects.unwrap_or(5).into()
        },
        https_only: args.https_only,
        allow_hosts: args
            .allow_host
            .iter()
            .map(|h| normalize_host(h))
            .collect::<Result<_>>()?,
        exclude_paths: args.exclude_path.clone(),
        proxy: args.proxy.clone(),
        no_proxy: args.no_proxy,
        ca_pem,
    };
    network.validate()?;
    Ok((
        limits,
        ScanOptions {
            samples: args.samples.unwrap_or(default_samples).into(),
            discover: !args.no_discover && !matches!(args.profile, Profile::Quick),
            deep,
            paths: crate::cli_inputs::paths(args)?,
            network,
            no_cookie_hints: args.no_cookie_hints,
            no_hypotheses: args.no_hypotheses,
            no_linked_discovery: args.no_linked_discovery,
            waf_probe: args.waf_probe,
        },
    ))
}

pub(crate) fn configuration(
    args: &ScanArgs,
    limits: &Limits,
    options: &ScanOptions,
) -> serde_json::Value {
    serde_json::json!({ "profile": args.profile, "samples": options.samples, "deep": options.deep,
        "discovery": options.discover, "diagnostic_paths": options.paths.iter().map(|p| p.split(['?', '#']).next().unwrap_or("")).collect::<Vec<_>>(),
        "max_requests": limits.max_requests, "max_body_bytes": limits.max_body,
        "request_timeout_seconds": args.timeout, "connect_timeout_seconds": args.connect_timeout,
        "target_timeout_seconds": args.target_timeout, "effective_delay_ms": limits.delay.as_secs_f64() * 1000.0,
        "rate_limit": args.rate_limit, "max_redirects": options.network.max_redirects,
        "https_only": options.network.https_only, "allow_hosts": options.network.allow_hosts,
        "exclude_paths": options.network.exclude_paths, "no_cookie_hints": options.no_cookie_hints,
        "no_hypotheses": options.no_hypotheses, "no_linked_discovery": options.no_linked_discovery,
        "proxy_configured": options.network.proxy.is_some(), "environment_proxies_disabled": options.network.no_proxy,
        "custom_ca": options.network.ca_pem.is_some(), "tls_validation": true,
        "custom_header_count": options.network.request.headers.len(), "authentication_configured":args.basic_auth_env.is_some(),
        "resolution_overrides":options.network.request.resolves.iter().map(|(h,ip)|serde_json::json!({"host":h,"address":ip.to_string()})).collect::<Vec<_>>(),
        "wordlist_configured":args.wordlist.is_some(),"waf_probe":options.waf_probe,
        "fail_on": args.fail_on, "scope": "same-origin HTTP observations; no security certification" })
}

pub(crate) fn validate_scope(targets: &[String], options: &ScanOptions) -> Result<()> {
    for target in targets {
        let base = validate_url(target)?;
        if !options.network.permits(&base) {
            bail!("A target is outside the HTTPS/host/path scope; no requests sent");
        }
        for path in &options.paths {
            let next = validate_url(base.join(path)?.as_str())?;
            if !allowed_redirect(&base, &next) {
                bail!("Diagnostic paths must remain on the target origin");
            }
        }
    }
    Ok(())
}

pub(crate) fn targets(args: &ScanArgs) -> Result<Vec<String>> {
    let mut targets = args.targets.clone();
    targets.extend(args.url.clone());
    if let Some(path) = &args.list {
        let mut contents = String::new();
        fs::File::open(path)
            .context("Opening target list")?
            .take(1_048_577)
            .read_to_string(&mut contents)?;
        if contents.len() > 1_048_576 {
            bail!("Target list exceeds 1 MiB");
        }
        targets.extend(
            contents
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty() && !s.starts_with('#'))
                .map(str::to_owned),
        );
    }
    let mut seen = HashSet::new();
    let mut normalized = vec![];
    for target in targets {
        let url = validate_url(&target)?;
        if seen.insert(url.as_str().to_owned()) {
            normalized.push(url.to_string());
        }
    }
    if normalized.is_empty() || normalized.len() > usize::from(args.max_targets) {
        bail!("Target count exceeds --max-targets or the list is empty");
    }
    Ok(normalized)
}
