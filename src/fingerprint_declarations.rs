use crate::{
    fingerprints::{Catalog, normalize, version},
    http::{PublicMetadata, display_url},
    technology::{Technology, TechnologyObservation, merge, observe},
};

impl Catalog {
    pub(crate) fn declarations(
        &self,
        text: &str,
        source: &str,
        method: &str,
        status: u16,
    ) -> Vec<Technology> {
        let text = if method == "attribution" {
            text.get("powered by ".len()..).unwrap_or("")
        } else {
            text
        }
        .trim();
        let mut output = vec![];
        for captures in self.declaration.captures_iter(text) {
            if matches!(method, "attribution" | "generator")
                && captures.get(0).is_none_or(|m| m.start() != 0)
            {
                continue;
            }
            let Some(index) = self.names.get(&normalize(&captures[1])) else {
                continue;
            };
            self.record(
                &mut output,
                *index,
                captures.get(2).and_then(|m| version(m.as_str())),
                source,
                method,
                status,
            );
        }
        if method != "attribution" {
            self.generic_declaration(text, source, method, status, &mut output);
        }
        output
    }

    fn generic_declaration(
        &self,
        text: &str,
        source: &str,
        method: &str,
        status: u16,
        output: &mut Vec<Technology>,
    ) {
        // Unknown provider declarations remain observations; they imply no runtime.
        for part in text.split([',', ';']).take(16) {
            if self.declaration.is_match(part) {
                continue;
            }
            if let Some(captures) = self.generic.captures(part.trim()) {
                let name = captures[1].trim();
                if name.len() < 2 || name.eq_ignore_ascii_case("unknown") {
                    continue;
                }
                observe(output, name, if source.ends_with("[server]") { "server" } else { "application" }, captures.get(2).and_then(|m|version(m.as_str())), TechnologyObservation {
                    hypothesis:None,version:None,source:source.into(),method:method.into(),http_status:status,
                    detail:"Unrecognized provider declaration; no runtime association or security conclusion is assigned".into(),
                });
            }
        }
    }

    pub(crate) fn record(
        &self,
        output: &mut Vec<Technology>,
        index: usize,
        version: Option<String>,
        source: &str,
        method: &str,
        status: u16,
    ) {
        self.record_observation(
            output,
            index,
            version,
            TechnologyObservation {
                hypothesis: None,
                version: None,
                source: source.into(),
                method: method.into(),
                http_status: status,
                detail: String::new(),
            },
        );
    }

    pub(crate) fn record_rule(
        &self,
        output: &mut Vec<Technology>,
        rule: &crate::fingerprints::CompiledRule,
        version: Option<String>,
        source: &str,
        method: &str,
        status: u16,
    ) {
        self.record_observation(
            output,
            rule.technology,
            version,
            TechnologyObservation {
                hypothesis: rule.rule.hypothesis.clone(),
                version: None,
                source: source.into(),
                method: method.into(),
                http_status: status,
                detail: String::new(),
            },
        );
    }

    fn record_observation(
        &self,
        output: &mut Vec<Technology>,
        index: usize,
        version: Option<String>,
        mut observation: TechnologyObservation,
    ) {
        let definition = &self.definitions[index];
        observation.detail = format!(
            "{}{} marker ({}); remotely supplied, deployment unverified",
            definition.name,
            version.as_ref().map_or(String::new(), |v| format!(" {v}")),
            observation.method,
        );
        observe(
            output,
            &definition.name,
            &definition.kind,
            version,
            observation,
        );
        if let Some(tech) = output.iter_mut().find(|t| t.name == definition.name) {
            tech.runtime_hint = definition.runtime.clone();
        }
    }

    pub(crate) fn metadata(&self, data: &PublicMetadata, cookies: bool) -> Vec<Technology> {
        let mut output = vec![];
        let url = display_url(&data.url);
        for (name, value) in &data.headers {
            if matches!(
                name.as_str(),
                "server"
                    | "x-powered-by"
                    | "x-generator"
                    | "x-php-version"
                    | "php-version"
                    | "x-runtime"
                    | "x-runtime-version"
                    | "x-framework"
            ) {
                let text = if matches!(name.as_str(), "x-php-version" | "php-version") {
                    format!("PHP/{value}")
                } else {
                    value.clone()
                };
                merge(
                    &mut output,
                    self.declarations(&text, &format!("{url} [{name}]"), "header", data.status),
                );
            }
        }
        self.header_rules(data, &mut output);
        if cookies {
            for name in &data.technology_cookies {
                if !data
                    .cookie_hypotheses
                    .iter()
                    .any(|(technology, _)| technology == name)
                    && let Some(index) = self.names.get(&normalize(name))
                {
                    self.record(&mut output, *index, None, &url, "cookie_name", data.status);
                }
            }
            for (name, hint) in &data.cookie_hypotheses {
                if let Some(index) = self.names.get(&normalize(name)) {
                    self.record_observation(
                        &mut output,
                        *index,
                        None,
                        TechnologyObservation {
                            hypothesis: Some(hint.clone()),
                            version: None,
                            source: url.clone(),
                            method: "cookie_name".into(),
                            http_status: data.status,
                            detail: String::new(),
                        },
                    );
                }
            }
        }
        output
    }
}
