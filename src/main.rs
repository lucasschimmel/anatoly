mod cli;
mod live_modes;
mod offline;
mod runner;
use anatoly::{policy, ui::Ui};
use anyhow::Result;
use clap::{CommandFactory, Parser};
use cli::{Cli, Command};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("anatoly: {}", anatoly::ui::safe_text(&format!("{error:#}")));
            ExitCode::from(3)
        }
    }
}

fn run() -> Result<u8> {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = error.exit_code() as u8;
            error.print()?;
            return Ok(code);
        }
    };
    let ui = Ui::new(cli.color);
    let jsonl = matches!(&cli.command, Some(Command::Scan(args) | Command::Exposure(args) | Command::Headers(args)) if args.jsonl);
    if !cli.no_banner && !cli.json && !jsonl {
        ui.banner();
    }
    match cli.command {
        Some(Command::Version) => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "tool": "anatoly", "version": env!("CARGO_PKG_VERSION"), "policy_date": policy::POLICY_DATE, "advisories": policy::ADVISORIES
                    }))?
                );
            } else {
                println!(
                    "  anatoly {} / advisory snapshot {}",
                    env!("CARGO_PKG_VERSION"),
                    policy::POLICY_DATE
                );
                for source in policy::ADVISORIES {
                    println!("  {source}");
                }
            }
        }
        Some(Command::Builds) => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({ "policy_date": policy::POLICY_DATE, "builds": policy::BUILDS, "advisories": policy::ADVISORIES })
                    )?
                );
            } else {
                ui.builds();
            }
        }
        Some(Command::Credits) => {
            let credits = serde_json::json!({
                "implementation": "Anatoly: independent Rust implementation for Lucas Schimmel",
                "research": "Wiz Research / PHP2Shell; PHP maintainers and advisory authors",
                "primary_sources": policy::ADVISORIES,
                "local_reference_repositories": ["aarsaputra/php2shell", "cumakurt/php2shell-scan", "KtebhTeam/php2shell", "testerxma/php2shell"],
                "note": "Reference repositories informed behavior analysis; no exploit code or artwork was copied. No upstream endorsement."
            });
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&credits)?);
            } else {
                println!("  ANATOLY / independent Rust implementation for Lucas Schimmel\n");
                println!(
                    "  Research: Wiz Research / PHP2Shell; PHP maintainers and advisory authors."
                );
                println!("  References: aarsaputra, cumakurt, KtebhTeam, testerxma.");
                println!("  No exploit code or artwork copied; no upstream endorsement.\n");
                for source in policy::ADVISORIES {
                    println!("  {source}");
                }
            }
        }
        Some(Command::Scan(args)) => return runner::run(*args, cli.json, &ui),
        Some(Command::Exposure(args)) => return live_modes::exposure(*args, cli.json, &ui),
        Some(Command::Headers(args)) => return live_modes::headers(*args, cli.json, &ui),
        Some(Command::Doctor(args)) => return live_modes::doctor(*args, cli.json, &ui),
        Some(Command::Watch(args)) => return live_modes::watch(*args, cli.json, &ui),
        Some(Command::Compare {
            before,
            after,
            output,
        }) => {
            return offline::run(
                "compare",
                &before,
                Some(&after),
                output.as_deref(),
                cli.json,
                &ui,
            );
        }
        Some(Command::Report { input, output }) => {
            return offline::run("report", &input, None, Some(&output), cli.json, &ui);
        }
        Some(Command::Policy { input, rules }) => {
            return offline::run("policy", &input, rules.as_deref(), None, cli.json, &ui);
        }
        Some(Command::Explain { input }) => {
            return offline::run("explain", &input, None, None, cli.json, &ui);
        }
        None => {
            Cli::command().print_help()?;
            println!();
        }
    }
    Ok(0)
}
