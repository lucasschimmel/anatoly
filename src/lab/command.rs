use anyhow::{Result, bail};
use serde::Serialize;

pub const COMMAND_NAMES: [&str; 6] = ["id", "whoami", "pwd", "hostname", "php -v", "uname -a"];

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LabCommand {
    Id,
    Whoami,
    Pwd,
    Hostname,
    PhpVersion,
    Uname,
}

impl LabCommand {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "id" => Ok(Self::Id),
            "whoami" => Ok(Self::Whoami),
            "pwd" => Ok(Self::Pwd),
            "hostname" => Ok(Self::Hostname),
            "php -v" => Ok(Self::PhpVersion),
            "uname -a" => Ok(Self::Uname),
            _ => bail!(
                "Command refused; choose one of: {}",
                COMMAND_NAMES.join(", ")
            ),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Id => "id",
            Self::Whoami => "whoami",
            Self::Pwd => "pwd",
            Self::Hostname => "hostname",
            Self::PhpVersion => "php -v",
            Self::Uname => "uname -a",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_allowlist_is_exact() {
        for command in COMMAND_NAMES {
            assert_eq!(LabCommand::parse(command).unwrap().as_str(), command);
        }
        for command in ["id;whoami", "sh", "/bin/sh", "whoami\nid", ""] {
            assert!(LabCommand::parse(command).is_err(), "accepted {command:?}");
        }
    }
}
