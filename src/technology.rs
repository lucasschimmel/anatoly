//! Technology declarations and runtime presence are independent of PHP version proof.
use crate::fingerprint::Evidence;
pub use crate::fingerprints::Catalog;
use serde::Serialize;

const MAX_OBSERVATIONS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TechnologyObservation {
    pub version: Option<String>,
    pub source: String,
    pub method: String,
    pub http_status: u16,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Technology {
    pub runtime_hint: Option<String>,
    pub truncated: bool,
    pub name: String,
    pub kind: String,
    pub versions: Vec<String>,
    pub observations: Vec<TechnologyObservation>,
}

#[derive(Debug, Default, Serialize)]
pub struct RuntimePresence {
    pub status: Presence,
    pub sources: Vec<String>,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Presence {
    Declared,
    Inferred,
    #[default]
    Unknown,
}

pub(crate) fn observe(
    output: &mut Vec<Technology>,
    name: &str,
    kind: &str,
    version: Option<String>,
    mut observation: TechnologyObservation,
) {
    observation.version = version.clone();
    if let Some(tech) = output.iter_mut().find(|t| t.name == name) {
        if tech.observations.contains(&observation) {
            return;
        }
        if tech.observations.len() >= MAX_OBSERVATIONS {
            tech.truncated = true;
            return;
        }
        if let Some(version) = version
            && !tech.versions.contains(&version)
        {
            tech.versions.push(version);
        }
        tech.observations.push(observation);
    } else if output.len() < 256 {
        output.push(Technology {
            runtime_hint: None,
            truncated: false,
            name: name.into(),
            kind: kind.into(),
            versions: version.into_iter().collect(),
            observations: vec![observation],
        });
    } else if let Some(last) = output.last_mut() {
        last.truncated = true;
    }
}

pub(crate) fn merge(output: &mut Vec<Technology>, additions: Vec<Technology>) {
    for tech in additions {
        let runtime_hint = tech.runtime_hint.clone();
        for observation in tech.observations {
            observe(
                output,
                &tech.name,
                &tech.kind,
                observation.version.clone(),
                observation,
            );
        }
        if let Some(existing) = output.iter_mut().find(|t| t.name == tech.name) {
            existing.runtime_hint = runtime_hint;
        }
        if tech.truncated
            && let Some(existing) = output.iter_mut().find(|t| t.name == tech.name)
        {
            existing.truncated = true;
        }
    }
}

pub(crate) fn presence(
    technologies: &[Technology],
    evidence: &[Evidence],
    infer: bool,
) -> RuntimePresence {
    let mut result = RuntimePresence::default();
    for proof in evidence {
        if !result.sources.contains(&proof.source) {
            result.sources.push(proof.source.clone());
        }
    }
    if !evidence.is_empty() {
        result.status = Presence::Declared;
        return result;
    }
    for tech in technologies {
        for observation in &tech.observations {
            let explicit = tech.name == "PHP" && observation.method == "header";
            if explicit || (infer && tech.runtime_hint.as_deref() == Some("PHP")) {
                if explicit {
                    result.status = Presence::Declared;
                } else if result.status != Presence::Declared {
                    result.status = Presence::Inferred;
                }
                if !result.sources.contains(&observation.source) {
                    result.sources.push(observation.source.clone());
                }
            }
        }
    }
    result
}

pub(crate) fn application_signals(technologies: &[Technology]) -> Vec<crate::recon::Signal> {
    technologies.iter().filter(|t| t.kind != "server" && t.kind != "runtime").flat_map(|tech| {
        tech.observations.iter().map(|observation| crate::recon::signal("application", &observation.source,
            &format!("Application marker: {}{}", tech.name, if tech.versions.is_empty() { String::new() } else { format!(" {}", tech.versions.join(" / ")) }),
            if tech.runtime_hint.as_deref() == Some("PHP") { "PHP is plausible from this application marker; the declaration can be imitated or served statically. Application versions are not PHP versions." } else { "Technology observation only; no PHP runtime or PHP version is inferred from this marker." }, None,
            "https://www.php.net/manual/en/security.hiding.php"))
    }).collect()
}
