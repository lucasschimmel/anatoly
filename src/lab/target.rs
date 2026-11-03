use crate::{cli::TargetArgs, runner};
use anatoly::http::{display_url, validate_url};
use anyhow::{Result, bail};
use reqwest::Url;

const EXPECTED_TARGET: &str = "http://127.0.0.1:18108/index.php";

#[derive(Clone, Debug)]
pub struct LabTarget {
    url: Url,
}

impl LabTarget {
    pub fn from_inputs(input: &TargetArgs, lab_acknowledged: bool) -> Result<Self> {
        if !lab_acknowledged {
            bail!("Real local exploitation requires the explicit --lab flag");
        }
        let targets = runner::target_inputs(input, 1)?;
        let url = validate_url(&targets[0])?;
        if url.scheme() != "http"
            || url.host_str() != Some("127.0.0.1")
            || url.port_or_known_default() != Some(18108)
            || !matches!(url.path(), "/" | "/index.php")
            || url.query().is_some()
        {
            bail!("Refused: the only accepted target is {EXPECTED_TARGET}");
        }
        Ok(Self { url })
    }

    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    pub fn display(&self) -> String {
        display_url(&self.url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(target: &str) -> TargetArgs {
        TargetArgs {
            targets: vec![],
            url: vec![target.to_owned()],
            list: None,
        }
    }

    #[test]
    fn requires_lab_and_exact_loopback_endpoint() {
        assert!(LabTarget::from_inputs(&input(EXPECTED_TARGET), true).is_ok());
        assert!(LabTarget::from_inputs(&input(EXPECTED_TARGET), false).is_err());
        for target in [
            "http://65.108.38.218:18108/index.php",
            "http://localhost:18108/index.php",
            "https://127.0.0.1:18108/index.php",
            "http://127.0.0.1:8080/index.php",
            "http://127.0.0.1:18108/other.php",
            "http://127.0.0.1:18108/index.php?x=1",
            "http://user@127.0.0.1:18108/index.php",
        ] {
            assert!(
                LabTarget::from_inputs(&input(target), true).is_err(),
                "accepted {target}"
            );
        }
    }
}
