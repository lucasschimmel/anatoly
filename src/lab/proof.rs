use super::command::LabCommand;
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::{fs, io, path::PathBuf, process::ExitStatus};

#[derive(Debug, Serialize)]
pub struct ExecutionProof {
    pub command: LabCommand,
    pub output: String,
}

pub struct ProofStore {
    directory: PathBuf,
    proof: PathBuf,
    script: PathBuf,
}

impl ProofStore {
    pub fn new(root: PathBuf) -> Self {
        let directory = root.join("lab/out");
        Self {
            proof: directory.join("p1"),
            script: directory.join("x"),
            directory,
        }
    }

    pub fn proof_file(&self) -> &PathBuf {
        &self.proof
    }

    pub fn prepare(&self, command: LabCommand) -> Result<()> {
        fs::create_dir_all(&self.directory).context("Cannot create the lab proof directory")?;
        match fs::remove_file(&self.proof) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("Cannot remove the stale lab proof"),
        }
        // LF is mandatory: a CRLF shebang makes runuser fail inside the Linux container.
        fs::write(
            &self.script,
            format!("#!/bin/sh\n{{ {} ; }} >/out/p1 2>&1\n", command.as_str()),
        )
        .context("Cannot write the allowlisted lab command")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.script, fs::Permissions::from_mode(0o755))?;
        }
        Ok(())
    }

    pub fn verify(
        &self,
        command: LabCommand,
        status: ExitStatus,
        stdout: &str,
        stderr: &str,
        quiet: bool,
    ) -> Result<ExecutionProof> {
        let output = stdout
            .lines()
            .rev()
            .find_map(|line| line.strip_prefix("PROOF: "))
            .unwrap_or_default()
            .to_owned();
        let fresh_file = fs::read_to_string(&self.proof)
            .ok()
            .is_some_and(|contents| !contents.trim().is_empty());
        if !status.success() || output.is_empty() || !fresh_file {
            if quiet {
                bail!("RCE was not proven: {stdout}{stderr}");
            }
            bail!("RCE was not proven; inspect the reproducer output above");
        }
        Ok(ExecutionProof { command, output })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_script_uses_lf_and_fixed_proof_path() {
        let root = std::env::temp_dir().join(format!("anatoly-proof-test-{}", std::process::id()));
        let store = ProofStore::new(root.clone());
        store.prepare(LabCommand::Whoami).unwrap();
        let bytes = fs::read(&store.script).unwrap();
        assert_eq!(bytes, b"#!/bin/sh\n{ whoami ; } >/out/p1 2>&1\n");
        assert!(!bytes.contains(&b'\r'));
        let _ = fs::remove_dir_all(root);
    }
}
