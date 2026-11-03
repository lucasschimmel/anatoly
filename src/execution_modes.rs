use crate::{
    cli::{ConnectArgs, ExploitArgs},
    exports, runner,
};
use anatoly::{
    exploit::{
        COMMAND_NAMES, ExecutionCommand, ExecutionTarget, ExploitMode, ExploitReport,
        Php2ShellBackend,
    },
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
    if json || args.exploit.output.is_some() {
        bail!("Interactive connect requires neither --json nor --output; use --command");
    }
    interactive(args.exploit, ui)
}

fn run_exploit(
    mode: ExploitMode,
    args: ExploitArgs,
    command: ExecutionCommand,
    json: bool,
    ui: &Ui,
) -> Result<u8> {
    let target = execution_target(&args)?;
    exports::preflight(&[args.output.as_deref()])?;
    let backend = Php2ShellBackend::new(&args.lab_dir)?;
    let proof = backend.execute(&target, command)?;
    let report = ExploitReport::new(mode, &target, backend.profile_name(), proof);
    if let Some(path) = &args.output {
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
    let targets = runner::target_inputs(&args.input, 1)?;
    ExecutionTarget::from_targets(&targets, args.lab)
}

fn interactive(args: ExploitArgs, ui: &Ui) -> Result<u8> {
    let target = execution_target(&args)?;
    let backend = Php2ShellBackend::new(&args.lab_dir)?;
    ui.details(
        "ANATOLY / LOCAL LAB SESSION",
        &serde_json::json!({
            "target": target.display(),
            "profile": backend.profile_name(),
            "commands": COMMAND_NAMES,
            "session": "Each command reruns the chain and requires fresh proof. Type exit to stop.",
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
        if let Err(error) = interactive_command(input, &backend, &target, ui) {
            eprintln!("anatoly: {}", safe_text(&format!("{error:#}")));
        }
    }
    Ok(0)
}

fn interactive_command(
    input: &str,
    backend: &Php2ShellBackend,
    target: &ExecutionTarget,
    ui: &Ui,
) -> Result<()> {
    let command = ExecutionCommand::parse(input)?;
    let proof = backend.execute(target, command)?;
    let report = ExploitReport::new(ExploitMode::Connect, target, backend.profile_name(), proof);
    ui.details("ANATOLY / PHP2SHELL PROOF", &serde_json::to_value(&report)?);
    Ok(())
}
