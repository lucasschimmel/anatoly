//! Validated, compiled declarative fingerprints. Catalogs extend data, never execute code.
use crate::fingerprint_schema::{Definition, Document, Rule};
use anyhow::{Context, Result, ensure};
use regex::{Regex, RegexBuilder};
use scraper::Selector;
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::Read,
    path::Path,
    sync::{Arc, OnceLock},
};

pub(crate) use crate::fingerprint_schema::Channel;
pub const MAX_CATALOG_BYTES: usize = 1_048_576;
const MAX_TECHNOLOGIES: usize = 256;
const MAX_RULES: usize = 512;
const MAX_PATTERN_BYTES: usize = 512;
const BUILTIN: &str = include_str!("../fingerprints/catalog.json");
static SHARED_BUILTIN: OnceLock<Arc<Catalog>> = OnceLock::new();

#[derive(Debug)]
pub(crate) struct CompiledRule {
    pub technology: usize,
    pub rule: Rule,
    pub pattern: Regex,
    pub selector: Option<Selector>,
    pub context: Vec<Regex>,
}

#[derive(Debug)]
pub struct Catalog {
    pub(crate) composer_packages: HashMap<String, Vec<usize>>,
    pub(crate) npm_packages: HashMap<String, Vec<usize>>,
    pub(crate) definitions: Vec<Definition>,
    pub(crate) rules: Vec<CompiledRule>,
    pub(crate) names: HashMap<String, usize>,
    pub(crate) declaration: Regex,
    pub(crate) generic: Regex,
}

impl Catalog {
    pub fn shared_builtin() -> Result<Arc<Self>> {
        if let Some(catalog) = SHARED_BUILTIN.get() {
            return Ok(Arc::clone(catalog));
        }
        let catalog = Arc::new(Self::new()?);
        // Concurrent first callers may compile twice; the winning immutable catalog is reused.
        let _ = SHARED_BUILTIN.set(Arc::clone(&catalog));
        Ok(SHARED_BUILTIN.get().cloned().unwrap_or(catalog))
    }
    pub fn new() -> Result<Self> {
        Self::compile(document(BUILTIN)?.technologies)
    }

    pub fn with_extra_json(json: &str) -> Result<Self> {
        let mut definitions = document(BUILTIN)?.technologies;
        definitions.extend(document(json)?.technologies);
        Self::compile(definitions)
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        File::open(path)
            .context("Opening fingerprint catalog")?
            .take((MAX_CATALOG_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .context("Reading fingerprint catalog")?;
        ensure!(
            bytes.len() <= MAX_CATALOG_BYTES,
            "Fingerprint catalog exceeds 1 MiB"
        );
        Self::with_extra_json(
            std::str::from_utf8(&bytes).context("Fingerprint catalog must be UTF-8")?,
        )
    }

    pub fn technology_count(&self) -> usize {
        self.definitions.len()
    }
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn header_names(&self) -> Vec<&str> {
        self.rules
            .iter()
            .filter(|r| r.rule.channel == Channel::Header)
            .filter_map(|r| r.rule.key.as_deref())
            .collect()
    }

    fn compile(definitions: Vec<Definition>) -> Result<Self> {
        ensure!(
            !definitions.is_empty() && definitions.len() <= MAX_TECHNOLOGIES,
            "Fingerprint catalog must contain 1..=256 technologies"
        );
        let mut names = HashMap::new();
        let mut products = HashSet::new();
        let mut aliases = Vec::new();
        let mut rules = Vec::new();
        for (index, definition) in definitions.iter().enumerate() {
            validate_definition(definition)?;
            ensure!(
                products.insert(normalize(&definition.name)),
                "Duplicate fingerprint technology name"
            );
            for alias in definition
                .aliases
                .iter()
                .chain(std::iter::once(&definition.name))
            {
                validate_label(alias, 64)?;
                let key = normalize(alias);
                ensure!(
                    names.get(&key).is_none_or(|old| *old == index),
                    "Ambiguous fingerprint alias"
                );
                names.insert(key, index);
                let pattern = alias
                    .split_whitespace()
                    .map(regex::escape)
                    .collect::<Vec<_>>()
                    .join(r"\s+");
                if !aliases.contains(&pattern) {
                    aliases.push(pattern);
                }
            }
            for rule in &definition.rules {
                ensure!(
                    rules.len() < MAX_RULES,
                    "Fingerprint catalog exceeds 512 rules"
                );
                rules.push(compile_rule(index, rule)?);
            }
        }
        aliases.sort_by_key(|s| std::cmp::Reverse(s.len()));
        let declaration = compile_pattern(&format!(
            r"(?i)\b({})\b!?(?:\s*[/ ]\s*v?([0-9]+(?:\.[0-9]+){{0,3}}(?:[-+][a-z0-9._-]+)?))?",
            aliases.join("|")
        ))?;
        let generic = compile_pattern(
            r"(?i)^([a-z][a-z0-9_. -]{1,47}?)(?:[/ ]+v?([0-9]+(?:\.[0-9]+){0,3}(?:[-+][a-z0-9._-]+)?))?$",
        )?;
        let composer_packages = package_index(&definitions, false);
        let npm_packages = package_index(&definitions, true);
        Ok(Self {
            composer_packages,
            npm_packages,
            definitions,
            rules,
            names,
            declaration,
            generic,
        })
    }
}

fn document(json: &str) -> Result<Document> {
    ensure!(
        json.len() <= MAX_CATALOG_BYTES,
        "Fingerprint catalog exceeds 1 MiB"
    );
    let document: Document = serde_json::from_str(json)
        .map_err(|_| anyhow::anyhow!("Invalid fingerprint catalog schema"))?;
    ensure!(
        document.schema_version == 1,
        "Unsupported fingerprint schema version"
    );
    Ok(document)
}

fn validate_definition(definition: &Definition) -> Result<()> {
    ensure!(
        definition.composer.len() <= 64 && definition.npm.len() <= 64,
        "Too many fingerprint package mappings"
    );
    let mut packages = HashSet::new();
    for (ecosystem, names) in [("composer", &definition.composer), ("npm", &definition.npm)] {
        for name in names {
            ensure!(
                packages.insert((ecosystem, name)),
                "Duplicate fingerprint package mapping"
            );
        }
    }
    validate_label(&definition.name, 64)?;
    validate_label(&definition.kind, 32)?;
    if let Some(runtime) = &definition.runtime {
        validate_label(runtime, 32)?;
    }
    ensure!(
        definition.aliases.len() <= 16,
        "Too many fingerprint aliases"
    );
    for package in definition.composer.iter().chain(&definition.npm) {
        ensure!(
            !package.is_empty()
                && package.len() <= 120
                && package
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "/@._-".contains(c)),
            "Invalid fingerprint package name"
        );
    }
    Ok(())
}

fn package_index(definitions: &[Definition], npm: bool) -> HashMap<String, Vec<usize>> {
    let mut result: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, definition) in definitions.iter().enumerate() {
        for package in if npm {
            &definition.npm
        } else {
            &definition.composer
        } {
            result.entry(package.clone()).or_default().push(index);
        }
    }
    result
}

fn validate_label(value: &str, maximum: usize) -> Result<()> {
    ensure!(
        !value.trim().is_empty()
            && value.len() <= maximum
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || " ._!+-".contains(c)),
        "Invalid fingerprint label"
    );
    Ok(())
}

fn compile_rule(technology: usize, rule: &Rule) -> Result<CompiledRule> {
    ensure!(
        !rule.pattern.is_empty() && rule.pattern.len() <= MAX_PATTERN_BYTES,
        "Invalid fingerprint pattern length"
    );
    ensure!(
        (100..=599).contains(&rule.min_status),
        "Invalid fingerprint HTTP status"
    );
    match rule.channel {
        Channel::Header => {
            ensure!(
                rule.key.as_deref().is_some_and(safe_header),
                "Invalid or sensitive fingerprint header"
            );
        }
        Channel::Html => {
            ensure!(
                rule.selector
                    .as_ref()
                    .is_some_and(|s| !s.is_empty() && s.len() <= 128),
                "HTML fingerprint requires a bounded selector"
            );
        }
        Channel::Cookie => {
            ensure!(
                rule.version_group.is_none(),
                "Cookie fingerprinting accepts names only, never versions"
            );
        }
        Channel::Asset => {}
    }
    ensure!(
        rule.channel == Channel::Header || rule.key.is_none(),
        "Header key on a non-header rule"
    );
    ensure!(
        rule.channel == Channel::Html || (rule.selector.is_none() && rule.attribute.is_none()),
        "HTML selector on a non-HTML rule"
    );
    ensure!(
        rule.context.len() <= 4 && (rule.context.is_empty() || rule.channel == Channel::Html),
        "Invalid fingerprint context rules"
    );
    let context = rule
        .context
        .iter()
        .map(|pattern| {
            ensure!(
                pattern.len() <= MAX_PATTERN_BYTES,
                "Invalid fingerprint context length"
            );
            compile_pattern(pattern)
                .map_err(|_| anyhow::anyhow!("Invalid fingerprint context expression"))
        })
        .collect::<Result<Vec<_>>>()?;
    if let Some(attribute) = &rule.attribute {
        ensure!(
            safe_attribute(attribute),
            "Invalid or sensitive fingerprint attribute"
        );
    }
    let pattern = compile_pattern(&rule.pattern)
        .map_err(|_| anyhow::anyhow!("Invalid fingerprint regular expression"))?;
    if let Some(group) = rule.version_group {
        ensure!(
            group > 0 && group < pattern.captures_len(),
            "Fingerprint version capture group does not exist"
        );
    }
    let selector = rule
        .selector
        .as_ref()
        .map(|s| {
            Selector::parse(s).map_err(|_| anyhow::anyhow!("Invalid fingerprint HTML selector"))
        })
        .transpose()?;
    let copied = Rule {
        channel: rule.channel,
        key: rule.key.as_ref().map(|s| s.to_ascii_lowercase()),
        selector: rule.selector.clone(),
        attribute: rule.attribute.clone(),
        pattern: rule.pattern.clone(),
        version_group: rule.version_group,
        context: rule.context.clone(),
        min_status: rule.min_status,
        same_origin: rule.same_origin,
    };
    Ok(CompiledRule {
        technology,
        rule: copied,
        pattern,
        selector,
        context,
    })
}

fn compile_pattern(pattern: &str) -> Result<Regex> {
    Ok(RegexBuilder::new(pattern)
        .size_limit(4 * 1024 * 1024)
        .dfa_size_limit(1024 * 1024)
        .build()?)
}

fn safe_header(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    !value.is_empty()
        && value.len() <= 64
        && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && ![
            "cookie",
            "authorization",
            "authentication",
            "token",
            "secret",
            "credential",
            "api-key",
            "apikey",
            "x-auth",
            "password",
            "location",
            "etag",
            "request-id",
        ]
        .iter()
        .any(|word| lower.contains(word))
}

fn safe_attribute(value: &str) -> bool {
    matches!(
        value,
        "content" | "src" | "href" | "class" | "id" | "ng-version"
    ) || (value.starts_with("data-") && safe_header(value))
}

pub(crate) fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

pub(crate) fn version(value: &str) -> Option<String> {
    let value = value.trim().trim_start_matches('v');
    let core = value.split(['-', '+']).next().unwrap_or("");
    let parts: Vec<_> = core.split('.').collect();
    (value.len() <= 64
        && (2..=4).contains(&parts.len())
        && parts.iter().all(|part| {
            !part.is_empty() && part.len() <= 6 && part.bytes().all(|b| b.is_ascii_digit())
        })
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".+-_".contains(c)))
    .then(|| value.to_owned())
}
