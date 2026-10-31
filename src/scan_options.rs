use crate::network::NetworkPolicy;

#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub samples: usize,
    pub discover: bool,
    pub deep: bool,
    pub paths: Vec<String>,
    pub network: NetworkPolicy,
    pub no_cookie_hints: bool,
    pub no_hypotheses: bool,
    pub no_linked_discovery: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            samples: 3,
            discover: true,
            deep: false,
            paths: vec!["phpinfo.php".into(), "info.php".into()],
            network: NetworkPolicy::default(),
            no_cookie_hints: false,
            no_hypotheses: false,
            no_linked_discovery: false,
        }
    }
}
