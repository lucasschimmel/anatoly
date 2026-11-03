use super::{command::LabCommand, proof::ExecutionProof, target::LabTarget};
use crate::runner;
use anatoly::ui::Ui;
use anyhow::Result;
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
pub struct LabReport {
    pub mode: &'static str,
    pub status: &'static str,
    pub target: String,
    pub profile: &'static str,
    pub command: LabCommand,
    pub proof: String,
    pub persistent_shell: bool,
}

impl LabReport {
    pub fn new(mode: &'static str, target: &LabTarget, proof: ExecutionProof) -> Self {
        Self {
            mode,
            status: "real_rce_proven",
            target: target.display(),
            profile: super::profile::LabProfile::php_8_4_26_bookworm().name,
            command: proof.command,
            proof: proof.output,
            persistent_shell: false,
        }
    }

    pub fn emit(self, json: bool, ui: &Ui, output: Option<&Path>) -> Result<u8> {
        if let Some(path) = output {
            runner::write_new(path, &self)?;
        }
        if json {
            println!("{}", serde_json::to_string_pretty(&self)?);
        } else {
            ui.details("ANATOLY / LOCAL LAB PROOF", &serde_json::to_value(&self)?);
        }
        Ok(0)
    }
}
