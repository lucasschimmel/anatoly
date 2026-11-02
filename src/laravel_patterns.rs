//! Conjunctive default-template families and narrowly scoped renderer disclosures.
use crate::{
    fingerprint::{Evidence, EvidenceKind, Patterns},
    fingerprints::version,
    html::{Facts, element_text, visible},
    http::{Page, display_url},
    hypothesis::{Confidence, VersionHint},
    technology::{Technology, TechnologyObservation, observe},
};
use anyhow::Result;
use regex::Regex;
use scraper::{ElementRef, Html, Selector};

const NODE_LIMIT: usize = 32;
const DOCS: &str = "https://laravel.com/docs";
const CLOUD: &str = "https://cloud.laravel.com";
const CHANGELOG: &str = "https://github.com/laravel/laravel/blob/13.x/CHANGELOG.md";
const TEMPLATE_REASON: &str = "Default welcome template family; conditional on its generation matching the framework. Customized, copied or retained templates can differ from the installed version.";

pub(crate) struct LaravelPatterns {
    anchors: Selector,
    fonts: Selector,
    legacy_copy: Selector,
    images: Selector,
    headings: Selector,
    ids: Selector,
    spans: Selector,
    old_root: Selector,
    old_context: Selector,
    old_header: Regex,
    old_version: Regex,
    release: Regex,
}

impl LaravelPatterns {
    pub fn new() -> Result<Self> {
        let selector =
            |value| Selector::parse(value).map_err(|_| anyhow::anyhow!("Invalid Laravel selector"));
        Ok(Self {
            anchors: selector("a[href]")?,
            fonts: selector("link[href]")?,
            legacy_copy: selector("div.mt-2, p")?,
            images: selector("img[src]")?,
            headings: selector("h1, h2, h3")?,
            ids: selector("#docs-card-content, #previous-exceptions")?,
            spans: selector("span")?,
            old_root: selector(".renderer")?,
            old_context: selector(".renderer span.text-xl")?,
            old_header: Regex::new(r"^PHP .{1,64} [—-] Laravel(?: .{1,64})?$")?,
            old_version: Regex::new(r"^PHP (.{1,64}) [—-] Laravel (.{1,64})$")?,
            release: Regex::new(
                r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,6}(?:[-+][a-zA-Z0-9._-]{1,32})?$",
            )?,
        })
    }

    pub fn inspect(
        &self,
        facts: &Facts,
        page: &Page,
        patterns: &Patterns,
    ) -> (Vec<Technology>, Vec<Evidence>, bool, bool) {
        let (mut output, mut proofs, mut limited) = (vec![], vec![], false);
        let Some(document) = &facts.document else {
            return (output, proofs, limited, false);
        };
        let anchors = nodes(document, &self.anchors, &mut limited);
        let headings = nodes(document, &self.headings, &mut limited);
        let ids = nodes(document, &self.ids, &mut limited);
        let fonts = nodes(document, &self.fonts, &mut limited);
        let images = nodes(document, &self.images, &mut limited);
        let strict_renderer = page.status >= 400 && modern_shape(&headings);
        let legacy_copy = nodes(document, &self.legacy_copy, &mut limited)
            .iter()
            .any(|n| {
                text(*n)
                    .is_some_and(|s| s.starts_with("Laravel has wonderful, thorough documentation"))
            });
        self.welcome(
            page,
            &anchors,
            &headings,
            &ids,
            &fonts,
            &images,
            legacy_copy,
            &mut output,
        );
        if page.status >= 400 {
            self.renderer(
                document,
                page,
                patterns,
                &headings,
                &ids,
                &anchors,
                &mut output,
                &mut proofs,
                &mut limited,
            );
        }
        (output, proofs, limited, strict_renderer)
    }

    // Each selector is compiled once; the shared DOM and visibility guards are reused.
    #[allow(clippy::too_many_arguments)]
    fn welcome(
        &self,
        page: &Page,
        anchors: &[ElementRef<'_>],
        headings: &[ElementRef<'_>],
        ids: &[ElementRef<'_>],
        fonts: &[ElementRef<'_>],
        images: &[ElementRef<'_>],
        legacy_copy: bool,
        output: &mut Vec<Technology>,
    ) {
        let docs = anchors.iter().any(|n| {
            n.attr("href") == Some(DOCS)
                && text(*n).is_some_and(|s| s == "Documentation" || s.starts_with("Documentation "))
        });
        if !docs {
            return;
        }
        let modern = headings
            .iter()
            .any(|n| n.value().name() == "h1" && text(*n).as_deref() == Some("Let's get started"))
            && anchors.iter().any(|n| n.attr("href") == Some(CLOUD));
        let mut families = vec![];
        if modern {
            families.push(
                if anchors.iter().any(|n| n.attr("href") == Some(CHANGELOG)) {
                    ("13.x", "v13.0.0")
                } else {
                    (">=12,<14", "v12.0.0")
                },
            );
        }
        if anchors
            .iter()
            .any(|n| n.attr("id") == Some("docs-card") && n.attr("href") == Some(DOCS))
            && ids
                .iter()
                .any(|n| n.attr("id") == Some("docs-card-content"))
            && images.iter().any(|n| {
                n.attr("id") == Some("background")
                    && n.attr("src")
                        == Some("https://laravel.com/assets/img/welcome/background.svg")
            })
        {
            families.push(("11.x", "v11.0.0"));
        }
        if fonts.iter().any(|n| {
            n.attr("href")
                .is_some_and(|s| s.starts_with("https://fonts.bunny.net/css?family=figtree:"))
        }) && anchors.iter().any(|n| {
            n.attr("href") == Some(DOCS)
                && n.attr("id") != Some("docs-card")
                && n.select(&self.headings).take(NODE_LIMIT).any(|h| {
                    visible(h)
                        && h.value().name() == "h2"
                        && text(h).as_deref() == Some("Documentation")
                })
        }) && headings
            .iter()
            .any(|n| n.value().name() == "h2" && text(*n).as_deref() == Some("Vibrant Ecosystem"))
        {
            families.push(("10.x", "v10.0.0"));
        }
        if legacy_copy
            && fonts.iter().any(|n| {
                n.attr("href").is_some_and(|s| {
                    s.starts_with("https://fonts.googleapis.com/css2?family=Nunito:")
                        || s.starts_with("https://fonts.bunny.net/css2?family=Nunito:")
                })
            })
            && anchors.iter().any(|n| {
                n.attr("href")
                    .is_some_and(|s| s.trim_end_matches('/') == "https://laravel-news.com")
                    && text(*n).as_deref() == Some("Laravel News")
            })
        {
            families.push((">=8,<10", "v9.0.0"));
        }
        for (range, tag) in families {
            record(
                output,
                page,
                "laravel_template",
                None,
                Some(hint(
                    range,
                    TEMPLATE_REASON,
                    &format!(
                        "https://github.com/laravel/laravel/blob/{tag}/resources/views/welcome.blade.php"
                    ),
                )),
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn renderer(
        &self,
        document: &Html,
        page: &Page,
        patterns: &Patterns,
        headings: &[ElementRef<'_>],
        ids: &[ElementRef<'_>],
        anchors: &[ElementRef<'_>],
        output: &mut Vec<Technology>,
        proofs: &mut Vec<Evidence>,
        limited: &mut bool,
    ) {
        let spans = nodes(document, &self.spans, limited);
        let modern_shape = modern_shape(headings);
        let mut laravel = vec![];
        let mut php = vec![];
        let (mut laravel_label, mut php_label) = (false, false);
        if modern_shape {
            for node in &spans {
                let Some(label) = text(*node) else { continue };
                if !matches!(label.as_str(), "LARAVEL" | "PHP") {
                    continue;
                }
                let Some(parent) = node.parent().and_then(ElementRef::wrap) else {
                    continue;
                };
                let children: Vec<_> = parent
                    .children()
                    .filter_map(ElementRef::wrap)
                    .take(3)
                    .collect();
                if children.len() != 2
                    || children[0].id() != node.id()
                    || children[1].value().name() != "span"
                    || !visible(children[1])
                {
                    continue;
                }
                let Some(value) = text(children[1]).filter(|v| v.len() <= 64) else {
                    continue;
                };
                let exact = self
                    .release
                    .is_match(&value)
                    .then(|| version(&value))
                    .flatten();
                if label == "LARAVEL" {
                    laravel_label = true;
                    laravel.extend(exact);
                } else {
                    php_label = true;
                    php.extend(exact);
                }
            }
        }
        if modern_shape && laravel_label && php_label {
            let previous = ids
                .iter()
                .any(|n| n.attr("id") == Some("previous-exceptions"))
                && anchors
                    .iter()
                    .any(|n| n.attr("href") == Some("#previous-exceptions"));
            let range = if previous { ">=13.0.0" } else { ">=12.29.0" };
            let tag = if previous { "v13.0.0" } else { "v12.29.0" };
            self.renderer_record(output, proofs, page, patterns, &laravel, &php, range, tag);
        }
        // Independently retain old renderer declarations on mixed or aggregated pages.
        let old_shape = !nodes(document, &self.old_root, limited).is_empty()
            && nodes(document, &self.old_context, limited)
                .iter()
                .any(|n| text(*n).as_deref() == Some("Request"));
        if !old_shape {
            return;
        }
        laravel.clear();
        php.clear();
        let mut matched = false;
        for node in spans {
            if !node
                .ancestors()
                .filter_map(ElementRef::wrap)
                .any(|n| n.value().classes().any(|c| c == "renderer"))
            {
                continue;
            }
            let Some(value) = text(node).filter(|v| self.old_header.is_match(v)) else {
                continue;
            };
            matched = true;
            let captures = self.old_version.captures(&value);
            laravel.extend(captures.as_ref().and_then(|c| {
                self.release
                    .is_match(&c[2])
                    .then(|| version(&c[2]))
                    .flatten()
            }));
            php.extend(captures.as_ref().and_then(|c| {
                self.release
                    .is_match(&c[1])
                    .then(|| version(&c[1]))
                    .flatten()
            }));
        }
        if matched {
            self.renderer_record(
                output,
                proofs,
                page,
                patterns,
                &laravel,
                &php,
                ">=11.9.0,<12.29.0",
                "v11.9.0",
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn renderer_record(
        &self,
        output: &mut Vec<Technology>,
        proofs: &mut Vec<Evidence>,
        page: &Page,
        patterns: &Patterns,
        laravel: &[String],
        php: &[String],
        range: &str,
        tag: &str,
    ) {
        let hypothesis = laravel.is_empty().then(|| hint(range,
            "Native exception renderer family; conditional on unmodified upstream rendering. Custom, copied or backported renderers can differ from the installed framework.",
            &format!("https://github.com/laravel/framework/blob/{tag}/src/Illuminate/Foundation/resources/exceptions/renderer/show.blade.php")));
        if hypothesis.is_some() {
            record(output, page, "laravel_renderer", None, hypothesis);
        }
        for value in laravel {
            record(output, page, "laravel_renderer", Some(value.clone()), None);
        }
        for php in php {
            let source = format!(
                "{} [Laravel exception renderer PHP label]",
                display_url(&page.url)
            );
            proofs.extend(patterns.named_version(php, &source, EvidenceKind::ErrorDisclosure));
        }
    }
}

fn modern_shape(headings: &[ElementRef<'_>]) -> bool {
    headings
        .iter()
        .any(|n| n.value().name() == "h3" && text(*n).as_deref() == Some("Exception trace"))
        && headings.iter().any(|n| n.value().name() == "h1")
}

fn nodes<'a>(document: &'a Html, selector: &Selector, limited: &mut bool) -> Vec<ElementRef<'a>> {
    let mut matches = document.select(selector);
    let output = matches
        .by_ref()
        .take(NODE_LIMIT)
        .filter(|node| visible(*node))
        .collect();
    *limited |= matches.next().is_some();
    output
}

fn text(node: ElementRef<'_>) -> Option<String> {
    let (text, clipped) = element_text(node);
    (!clipped).then_some(text)
}

fn hint(range: &str, reason: &str, reference: &str) -> VersionHint {
    VersionHint {
        range: range.into(),
        confidence: Confidence::Medium,
        reason: reason.into(),
        reference: reference.into(),
    }
}

pub(crate) fn record(
    output: &mut Vec<Technology>,
    page: &Page,
    method: &str,
    version: Option<String>,
    hypothesis: Option<VersionHint>,
) {
    observe(output, "Laravel", "framework", version, TechnologyObservation {
        hypothesis, version: None, source: format!("{} [Laravel {}]", display_url(&page.url), if method == "laravel_renderer" { "exception renderer" } else { "welcome template" }),
        method: method.into(), http_status: page.status,
        detail: "Conjunctive active DOM markers; remotely supplied declaration, deployment unverified".into(),
    });
    if let Some(technology) = output.iter_mut().find(|t| t.name == "Laravel") {
        technology.runtime_hint = Some("PHP".into());
    }
}
