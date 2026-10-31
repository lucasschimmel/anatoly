use crate::{
    fingerprints::{Catalog, Channel, version},
    html::{Facts, element_text, visible},
    http::{Page, PublicMetadata, allowed_redirect, display_url},
    technology::Technology,
};

impl Catalog {
    pub(crate) fn cookie_technologies(&self, name: &str, status: u16) -> Vec<String> {
        if name.len() > 256 {
            return vec![];
        }
        self.rules
            .iter()
            .filter(|r| {
                r.rule.channel == Channel::Cookie
                    && status >= r.rule.min_status
                    && r.pattern.is_match(name)
            })
            .map(|r| self.definitions[r.technology].name.clone())
            .collect()
    }

    pub(crate) fn header_rules(&self, data: &PublicMetadata, output: &mut Vec<Technology>) {
        for rule in self
            .rules
            .iter()
            .filter(|r| r.rule.channel == Channel::Header && data.status >= r.rule.min_status)
        {
            for (name, value) in &data.headers {
                if rule.rule.key.as_ref() == Some(name)
                    && let Some(captures) = rule.pattern.captures(value)
                {
                    let version = rule
                        .rule
                        .version_group
                        .and_then(|g| captures.get(g))
                        .and_then(|m| version(m.as_str()));
                    self.record(
                        output,
                        rule.technology,
                        version,
                        &format!("{} [{name}]", display_url(&data.url)),
                        "header",
                        data.status,
                    );
                }
            }
        }
    }

    pub(crate) fn resources(&self, facts: &Facts, page: &Page) -> Vec<Technology> {
        let mut output = vec![];
        for resource in &facts.resources {
            let Ok(url) = page.url.join(resource) else {
                continue;
            };
            if !matches!(url.scheme(), "http" | "https")
                || !url.username().is_empty()
                || url.password().is_some()
            {
                continue;
            }
            for rule in self
                .rules
                .iter()
                .filter(|r| r.rule.channel == Channel::Asset && page.status >= r.rule.min_status)
            {
                if rule.rule.same_origin && !allowed_redirect(&page.url, &url) {
                    continue;
                }
                if let Some(captures) = rule.pattern.captures(url.path()) {
                    let version = rule
                        .rule
                        .version_group
                        .and_then(|g| captures.get(g))
                        .and_then(|m| version(m.as_str()));
                    self.record(
                        &mut output,
                        rule.technology,
                        version,
                        &display_url(&page.url),
                        "asset_path",
                        page.status,
                    );
                }
            }
        }
        output
    }

    pub(crate) fn html(&self, facts: &Facts, page: &Page) -> (Vec<Technology>, bool) {
        let mut output = vec![];
        let mut limited = false;
        let Some(document) = &facts.document else {
            return (output, limited);
        };
        for rule in self
            .rules
            .iter()
            .filter(|r| r.rule.channel == Channel::Html && page.status >= r.rule.min_status)
        {
            let Some(selector) = &rule.selector else {
                continue;
            };
            let mut nodes = document.select(selector).filter(|node| visible(*node));
            for node in nodes.by_ref().take(32) {
                let text = if let Some(attribute) = &rule.rule.attribute {
                    node.attr(attribute).unwrap_or("").to_owned()
                } else {
                    let (text, clipped) = element_text(node);
                    limited |= clipped;
                    text
                };
                if text.len() > 4096 {
                    limited = true;
                    continue;
                }
                if !rule.context.iter().all(|context| context.is_match(&text)) {
                    continue;
                }
                if let Some(captures) = rule.pattern.captures(&text) {
                    let version = rule
                        .rule
                        .version_group
                        .and_then(|g| captures.get(g))
                        .and_then(|m| version(m.as_str()));
                    self.record(
                        &mut output,
                        rule.technology,
                        version,
                        &format!("{} [HTML fingerprint]", display_url(&page.url)),
                        "html_marker",
                        page.status,
                    );
                }
            }
            limited |= nodes.next().is_some();
        }
        (output, limited)
    }
}
