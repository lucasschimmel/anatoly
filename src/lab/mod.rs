mod backend;
mod command;
mod profile;
mod proof;
mod report;
mod target;

use crate::{
    cli::{ConnectArgs, LabArgs},
    exports,
};
use anatoly::ui::Ui;
use anyhow::{Result, bail};
use backend::Php2ShellBackend;
use command::{COMMAND_NAMES, LabCommand};
use report::LabReport;
use std::io::{self, Write};
use target::LabTarget;

pub fn exploit(args: LabArgs, json: bool, ui: &Ui) -> Result<u8> {
    run_once("exploit", args, LabCommand::Id, json, ui)
}

pub fn connect(args: ConnectArgs, json: bool, ui: &Ui) -> Result<u8> {
    if let Some(command) = args.command {
        return run_once("connect", args.lab, LabCommand::parse(&command)?, json, ui);
    }
    if json || args.lab.output.is_some() {
        bail!("Interactive connect requires neither --json nor --output; use --command");
    }
    interactive(args.lab)
}

fn run_once(
    mode: &'static str,
    args: LabArgs,
    command: LabCommand,
    json: bool,
    ui: &Ui,
) -> Result<u8> {
    let target = LabTarget::from_inputs(&args.input, args.lab)?;
    exports::preflight(&[args.output.as_deref()])?;
    let proof = Php2ShellBackend::calibrated().execute(&target, command, json)?;
    LabReport::new(mode, &target, proof).emit(json, ui, args.output.as_deref())
}

fn interactive(args: LabArgs) -> Result<u8> {
    let target = LabTarget::from_inputs(&args.input, args.lab)?;
    let backend = Php2ShellBackend::calibrated();
    println!("Connected to the REAL LOCAL Docker lab.");
    println!(
        "Each command reruns the chain and requires fresh proof; this is not a persistent shell."
    );
    println!("Commands: {}, exit", COMMAND_NAMES.join(", "));
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
        let result =
            LabCommand::parse(input).and_then(|command| backend.execute(&target, command, false));
        match result {
            Ok(proof) => println!("{}", proof.output),
            Err(error) => eprintln!("[-] {error:#}"),
        }
    }
    Ok(0)
}
