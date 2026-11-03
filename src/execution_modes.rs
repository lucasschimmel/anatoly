use crate::{
    cli::{ConnectArgs, ExploitArgs},
    exports, runner,
};
use anatoly::{
    exploit::{
        COMMAND_NAMES, ExecutionCommand, ExecutionTarget, ExploitMode, ExploitReport,
        Php2ShellBackend, Php2ShellProfile,
    },
    scan::{ScanReport, Scanner},
    ui::{Ui, safe_text},
};
use anyhow::{Result, bail};
use std::io::{self, Write};

pub fn exploit(args: ExploitArgs, json: bool, ui: &Ui) -> Result<u8> {
    run_exploit(ExploitMode::Exploit, args, ExecutionCommand::Id, json, ui)
}

pub fn connect(args: ConnectArgs, json: bool, ui: &Ui) -> Result<u8> {
    if let Some(command) = args.command {
        return run_exploit(
            ExploitMode::Connect,
            args.exploit,
            ExecutionCommand::parse(&command)?,
            json,
            ui,
        );
    }
    if json || args.exploit.scan.output.is_some() {
        bail!("Interactive connect requires neither --json nor --output; use --command");
    }
    interactive(args.exploit, ui)
}

struct PreparedExecution {
    target: ExecutionTarget,
    backend: Php2ShellBackend,
    profile: Php2ShellProfile,
    scan: ScanReport,
    forced: bool,
}

fn run_exploit(
    mode: ExploitMode,
    args: ExploitArgs,
    command: ExecutionCommand,
    json: bool,
    ui: &Ui,
) -> Result<u8> {
    let prepared = prepare(&args, json, ui)?;
    let proof = prepared.backend.execute(&prepared.target, command)?;
    let report = ExploitReport::new(
        mode,
        &prepared.target,
        &prepared.profile,
        proof,
        prepared.forced,
        &prepared.scan,
    );
    if let Some(path) = &args.scan.output {
        runner::write_new(path, &report)?;
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        ui.details("ANATOLY / PHP2SHELL PROOF", &serde_json::to_value(&report)?);
    }
    Ok(0)
}

fn execution_target(args: &ExploitArgs) -> Result<ExecutionTarget> {
    let targets = runner::target_inputs(&args.scan.input, 1)?;
    ExecutionTarget::from_targets(&targets, args.lab)
}

fn prepare(args: &ExploitArgs, json: bool, ui: &Ui) -> Result<PreparedExecution> {
    if args.scan.dry_run {
        bail!(
            "Exploit/connect cannot use --dry-run: profile selection requires scanner evidence; no requests or payloads were sent"
        );
    }
    if args.scan.jsonl {
        bail!("Exploit/connect does not support --jsonl; use --json for the execution report");
    }
    if args.scan.csv.is_some() || args.scan.sarif.is_some() {
        bail!(
            "Exploit/connect CSV/SARIF exports are unsupported; use --output for the execution report"
        );
    }

    // Target, output and runtime safeguards run before the first HTTP request.
    let target = execution_target(args)?;
    exports::preflight(&[args.scan.output.as_deref()])?;
    Php2ShellBackend::validate_root(&args.lab_dir)?;
    let (limits, options) = runner::configure(&args.scan)?;
    runner::validate_scope(&[target.as_str().to_owned()], &options)?;

    let scan = Scanner::new()?.scan(target.as_str(), limits, &options)?;
    if !json && !args.scan.summary_only {
        ui.report(1, 1, &scan);
    }
    let profile = Php2ShellProfile::select_from_scan(
        scan.version.as_ref(),
        scan.version_status,
        &scan.verdict,
        args.force,
    )?;
    let backend = Php2ShellBackend::with_profile(&args.lab_dir, profile.clone())?;
    Ok(PreparedExecution {
        target,
        backend,
        profile,
        scan,
        forced: args.force,
    })
}

fn interactive(args: ExploitArgs, ui: &Ui) -> Result<u8> {
    let prepared = prepare(&args, false, ui)?;
    ui.details(
        "ANATOLY / LOCAL LAB SESSION",
        &serde_json::json!({
            "target": prepared.target.display(),
            "php_version": prepared.profile.php_version,
            "profile": prepared.profile.name,
            "forced": prepared.forced,
            "commands": COMMAND_NAMES,
            "session": "The scanner selected one exact profile. Each command reruns the chain and requires fresh proof. Type exit to stop.",
            "persistent_shell": false,
        }),
    );
    let stdin = io::stdin();
    loop {
        print!("anatoly-docker$ ");
        io::stdout().flush()?;
        let mut input = String::new();
        if stdin.read_line(&mut input)? == 0 {
            println!();
            break;
        }
        let input = input.trim();
        if input == "exit" {
            break;
        }
        if input.is_empty() {
            continue;
        }
        if let Err(error) = interactive_command(input, &prepared, ui) {
            eprintln!("anatoly: {}", safe_text(&format!("{error:#}")));
        }
    }
    Ok(0)
}

fn interactive_command(input: &str, prepared: &PreparedExecution, ui: &Ui) -> Result<()> {
    let command = ExecutionCommand::parse(input)?;
    let proof = prepared.backend.execute(&prepared.target, command)?;
    let report = ExploitReport::new(
        ExploitMode::Connect,
        &prepared.target,
        &prepared.profile,
        proof,
        prepared.forced,
        &prepared.scan,
    );
    ui.details("ANATOLY / PHP2SHELL PROOF", &serde_json::to_value(&report)?);
    Ok(())
}
