use crate::{cli::ScanArgs, runner};
use anatoly::{http::validate_url, request_settings::RequestSettings};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{fs, io::Read};

fn environment(name: &str) -> Result<String> {
    if name.is_empty()
        || name.len() > 128
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        bail!("Invalid environment variable name; input omitted");
    }
    std::env::var(name).map_err(|_|anyhow::anyhow!("Required authentication/header environment variable is missing or unreadable; value omitted"))
}

pub fn request(args: &ScanArgs) -> Result<RequestSettings> {
    let mut settings = RequestSettings::default();
    for header in &args.header {
        settings.insert(header)?;
    }
    for name in &args.header_env {
        settings.insert(&environment(name)?)?;
    }
    if let Some(name) = &args.basic_auth_env {
        let value = environment(name)?;
        if value.len() > 4096
            || value.chars().any(char::is_control)
            || !value.split_once(':').is_some_and(|(u, _)| !u.is_empty())
        {
            bail!(
                "Basic authentication environment value must contain user:password without control characters; value omitted"
            );
        }
        settings.insert(&format!(
            "Authorization: Basic {}",
            STANDARD.encode(value.as_bytes())
        ))?;
    }
    for resolve in &args.resolve {
        settings.resolve(resolve)?;
    }
    if !settings.headers.is_empty() {
        let targets = runner::targets(args)?;
        let first = validate_url(&targets[0])?;
        if targets
            .iter()
            .any(|target| validate_url(target).is_ok_and(|url| url.origin() != first.origin()))
        {
            bail!(
                "Custom headers/authentication require targets on one exact scheme, host and port; no requests sent"
            );
        }
        settings.origin = Some(first);
    }
    Ok(settings)
}

pub fn paths(args: &ScanArgs) -> Result<Vec<String>> {
    let mut paths = if args.diagnostic_path.is_empty() {
        vec!["phpinfo.php".into(), "info.php".into()]
    } else {
        args.diagnostic_path.clone()
    };
    if let Some(path) = &args.wordlist {
        if args.no_discover {
            bail!("--wordlist requires discovery");
        }
        let mut contents = String::new();
        fs::File::open(path)
            .context("Opening diagnostic wordlist")?
            .take(65_537)
            .read_to_string(&mut contents)
            .map_err(|_| anyhow::anyhow!("Diagnostic wordlist must be readable UTF-8"))?;
        if contents.len() > 65_536 {
            bail!("Diagnostic wordlist exceeds 64 KiB");
        }
        let extra: Vec<_> = contents
            .lines()
            .map(str::trim)
            .filter(|p| !p.is_empty() && !p.starts_with('#'))
            .collect();
        if extra.len() > 64 {
            bail!("Diagnostic wordlist exceeds 64 paths");
        }
        for entry in extra {
            if entry.len() > 256
                || entry.contains(['?', '#', '\\'])
                || entry.contains("://")
                || entry.chars().any(char::is_control)
            {
                bail!(
                    "Diagnostic wordlist accepts paths only, without query values, fragments or control characters; input omitted"
                );
            }
            if !paths.iter().any(|p| p == entry) {
                paths.push(entry.to_owned());
            }
        }
    }
    Ok(paths)
}
