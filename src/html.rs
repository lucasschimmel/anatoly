//! One bounded-depth walk; attribution buffers avoid repeated descendant scans.
use scraper::{ElementRef, Html};

const MAX_DEPTH: usize = 128;
const MAX_ATTRIBUTION_BYTES: usize = 256;
// Bound work before html5ever builds its tree, including adversarial nesting.
const MAX_OPEN_TAG_TOKENS: usize = 1024;

#[derive(Default)]
pub(crate) struct Facts {
    pub document: Option<Html>,
    pub generators: Vec<String>,
    pub attributions: Vec<String>,
    pub resources: Vec<String>,
    pub links: Vec<String>,
    pub limited: bool,
}

impl Facts {
    pub fn parse(body: &str) -> Self {
        let boundary = body
            .match_indices('<')
            .filter(|(index, _)| {
                body.as_bytes()
                    .get(index + 1)
                    .is_some_and(u8::is_ascii_alphabetic)
            })
            .nth(MAX_OPEN_TAG_TOKENS)
            .map(|(index, _)| index);
        let document = Html::parse_document(boundary.map_or(body, |end| &body[..end]));
        let mut facts = Self {
            limited: boundary.is_some(),
            ..Self::default()
        };
        walk(document.root_element(), false, 0, &mut vec![], &mut facts);
        facts.document = Some(document);
        facts
    }
}

fn walk(
    node: ElementRef<'_>,
    article: bool,
    depth: usize,
    buffers: &mut Vec<Option<String>>,
    facts: &mut Facts,
) {
    if depth >= MAX_DEPTH {
        facts.limited = true;
        return;
    }
    let name = node.value().name();
    if inert(node) {
        if name == "script" && !hidden(node) {
            retain_attribute(node, "src", &mut facts.resources);
        }
        return;
    }
    let article = article || name == "article";
    attributes(node, facts);
    let attribution = !article && matches!(name, "p" | "small" | "footer" | "address" | "div");
    if attribution {
        buffers.push(Some(String::new()));
    }
    for child in node.children() {
        if let Some(text) = child.value().as_text() {
            for buffer in buffers.iter_mut() {
                if let Some(value) = buffer {
                    if value.len() + text.len() <= MAX_ATTRIBUTION_BYTES {
                        value.push_str(text);
                    } else {
                        *buffer = None;
                    }
                }
            }
        } else if let Some(element) = ElementRef::wrap(child) {
            walk(element, article, depth + 1, buffers, facts);
        }
    }
    if attribution && let Some(Some(text)) = buffers.pop() {
        let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if text.to_ascii_lowercase().starts_with("powered by ") {
            facts.attributions.push(text);
        }
    }
}

fn attributes(node: ElementRef<'_>, facts: &mut Facts) {
    match node.value().name() {
        "meta"
            if node
                .attr("name")
                .is_some_and(|n| n.eq_ignore_ascii_case("generator")) =>
        {
            retain_attribute(node, "content", &mut facts.generators)
        }
        "a" => retain_attribute(node, "href", &mut facts.links),
        "form" => retain_attribute(node, "action", &mut facts.links),
        "img" => retain_attribute(node, "src", &mut facts.resources),
        "link" => retain_attribute(node, "href", &mut facts.resources),
        _ => {}
    }
}

fn retain_attribute(node: ElementRef<'_>, name: &str, output: &mut Vec<String>) {
    if let Some(value) = node.attr(name) {
        output.push(value.to_owned());
    }
}

fn hidden(node: ElementRef<'_>) -> bool {
    node.attr("hidden").is_some()
        || node
            .attr("aria-hidden")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

fn inert(node: ElementRef<'_>) -> bool {
    hidden(node)
        || matches!(
            node.value().name(),
            "script" | "template" | "noscript" | "style" | "pre" | "code"
        )
}

pub(crate) fn visible(node: ElementRef<'_>) -> bool {
    for (depth, ancestor) in node
        .ancestors()
        .filter_map(ElementRef::wrap)
        .chain(std::iter::once(node))
        .enumerate()
    {
        if depth >= MAX_DEPTH || inert(ancestor) || ancestor.value().name() == "article" {
            return false;
        }
    }
    true
}

pub(crate) fn element_text(node: ElementRef<'_>) -> (String, bool) {
    let mut text = String::new();
    let mut limited = false;
    collect_text(node, 0, &mut text, &mut limited);
    (
        text.split_whitespace().collect::<Vec<_>>().join(" "),
        limited,
    )
}

fn collect_text(node: ElementRef<'_>, depth: usize, output: &mut String, limited: &mut bool) {
    if *limited || inert(node) || node.value().name() == "article" {
        return;
    }
    if depth >= MAX_DEPTH || output.len() > 4096 {
        *limited = true;
        return;
    }
    for child in node.children() {
        if let Some(text) = child.value().as_text() {
            if output.len() + text.len() <= 4096 {
                output.push_str(text);
                output.push(' ');
            } else {
                *limited = true;
                return;
            }
        } else if let Some(element) = ElementRef::wrap(child) {
            collect_text(element, depth + 1, output, limited);
        }
    }
}
