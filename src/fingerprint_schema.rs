use serde::Deserialize;
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Document {
    pub schema_version: u8,
    pub technologies: Vec<Definition>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Definition {
    pub name: String,
    pub kind: String,
    pub runtime: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub composer: Vec<String>,
    #[serde(default)]
    pub npm: Vec<String>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Channel {
    Header,
    Cookie,
    Asset,
    Html,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rule {
    pub channel: Channel,
    pub key: Option<String>,
    pub selector: Option<String>,
    pub attribute: Option<String>,
    pub pattern: String,
    pub version_group: Option<usize>,
    #[serde(default)]
    pub context: Vec<String>,
    #[serde(default = "minimum_status")]
    pub min_status: u16,
    #[serde(default = "yes")]
    pub same_origin: bool,
}

fn minimum_status() -> u16 {
    100
}
fn yes() -> bool {
    true
}
