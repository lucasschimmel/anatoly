//! Exact native welcome disclosures require an independently recognized template.
use crate::{
    fingerprint::{Evidence, EvidenceKind, Patterns},
    html::{Facts, element_text, visible},
    http::{Page, display_url},
    laravel_patterns::record,
    technology::Technology,
};
use anyhow::Result;
use regex::Regex;
use scraper::Selector;

const NODE_LIMIT: usize = 32;

pub(crate) struct WelcomeFooter {
    selector: Selector,
    declaration: Regex,
}

impl WelcomeFooter {
    pub fn new() -> Result<Self> {
        Ok(Self {
            selector: Selector::parse("footer, div.text-sm")
                .map_err(|_| anyhow::anyhow!("Invalid Laravel footer selector"))?,
            declaration: Regex::new(concat!(
                r"^Laravel v([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,6}(?:[-+][a-zA-Z0-9._-]{1,32})?)",
                r" \(PHP v([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,6}(?:[-~]?[a-zA-Z][a-zA-Z0-9]{0,15})?)\)$"
            ))?,
        })
    }

    pub fn inspect(
        &self,
        facts: &Facts,
        page: &Page,
        patterns: &Patterns,
        templates: &[Technology],
    ) -> (Vec<Technology>, Vec<Evidence>, bool) {
        let (mut output, mut proofs, mut limited) = (vec![], vec![], false);
        if !templates.iter().any(|t| {
            t.name == "Laravel"
                && t.observations
                    .iter()
                    .any(|o| o.method == "laravel_template")
        }) {
            return (output, proofs, limited);
        }
        let Some(document) = &facts.document else {
            return (output, proofs, limited);
        };
        let mut nodes = document.select(&self.selector);
        for node in nodes.by_ref().take(NODE_LIMIT).filter(|n| visible(*n)) {
            let (text, clipped) = element_text(node);
            limited |= clipped;
            if clipped {
                continue;
            }
            let Some(captures) = self.declaration.captures(&text) else {
                continue;
            };
            record(
                &mut output,
                page,
                "laravel_welcome_footer",
                Some(captures[1].to_owned()),
                None,
            );
            proofs.extend(patterns.named_version(
                &captures[2],
                &format!(
                    "{} [Laravel welcome PHP declaration]",
                    display_url(&page.url)
                ),
                EvidenceKind::StructuredMetadata,
            ));
        }
        limited |= nodes.next().is_some();
        (output, proofs, limited)
    }
}
