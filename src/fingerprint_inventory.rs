//! Narrow diagnostic and resource inventories; no script evaluation or extra requests.
use crate::{
    fingerprints::{Catalog, version},
    html::{Facts, element_text, visible},
    http::{Page, display_url},
    technology::{Technology, TechnologyObservation, observe},
};
use reqwest::Url;

impl Catalog {
    pub(crate) fn wordpress_components(&self, url: &Url, page: &Page, out: &mut Vec<Technology>) {
        let parts: Vec<_> = url.path().split('/').collect();
        for parts in parts.windows(4) {
            if parts[0] != "wp-content" || !matches!(parts[1], "plugins" | "themes") {
                continue;
            }
            let slug = parts[2];
            if slug.is_empty()
                || slug.len() > 80
                || !slug
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                || parts[3].is_empty()
            {
                continue;
            }
            let kind = if parts[1] == "plugins" {
                "plugin"
            } else {
                "theme"
            };
            let name = format!("WordPress {kind}:{slug}");
            inventory(
                out,
                &name,
                kind,
                None,
                page,
                "asset_path",
                "Same-origin WordPress component path; presence and activation unverified",
            );
            if let Some(hint) = asset_hint(url) {
                inventory(
                    out,
                    &name,
                    kind,
                    None,
                    page,
                    "asset_version_hint",
                    &format!(
                        "Asset version hint {hint}; cache key, not an installed component version"
                    ),
                );
            }
            if let Some(technology) = out.iter_mut().find(|t| t.name == name) {
                technology.runtime_hint = Some("PHP".into());
            }
        }
    }

    pub(crate) fn diagnostic_inventory(&self, facts: &Facts, page: &Page) -> Vec<Technology> {
        let mut output = vec![];
        if let Some(document) = &facts.document {
            // Constant selectors; compilation failure leaves this optional channel empty.
            if let (Ok(rows), Ok(cells)) = (
                scraper::Selector::parse("tr"),
                scraper::Selector::parse("th, td"),
            ) {
                for row in document.select(&rows).take(1024) {
                    if !visible(row) {
                        continue;
                    }
                    let values: Vec<_> = row
                        .select(&cells)
                        .filter(|cell| visible(*cell))
                        .take(3)
                        .map(|cell| element_text(cell).0)
                        .collect();
                    if values.len() >= 2 {
                        let key = if scoped_version_key(&values[0]) {
                            diagnostic_section(row)
                                .map(|section| format!("{section} {}", values[0]))
                        } else {
                            Some(values[0].clone())
                        };
                        if let Some(key) = key {
                            diagnostic_row(&key, &values[1], page, &mut output);
                        }
                    }
                }
            }
        }
        if page.body.trim_start().starts_with("phpinfo()") || !page.body.contains('<') {
            let mut section = None;
            for line in page.body.lines().take(4096) {
                if let Some((key, value)) = line.split_once("=>") {
                    let key = if scoped_version_key(key.trim()) {
                        section.map(|name| format!("{name} {}", key.trim()))
                    } else {
                        Some(key.trim().to_owned())
                    };
                    let Some(key) = key else {
                        continue;
                    };
                    diagnostic_row(
                        &key,
                        value.split("=>").next().unwrap_or("").trim(),
                        page,
                        &mut output,
                    );
                } else if !line.trim().is_empty() {
                    section = section_name(line.trim());
                }
            }
        }
        output
    }
}

fn diagnostic_row(key: &str, text: &str, page: &Page, output: &mut Vec<Technology>) {
    let name = match key.trim().to_ascii_lowercase().as_str() {
        "redis version" => "Redis",
        "imagick module version" => "Imagick",
        "curl information" => "cURL",
        "openssl library version" => "OpenSSL",
        "libxml compiled version" => "libxml",
        "zend opcache version" | "opcache version" => "Zend OPcache",
        "xdebug version" => "Xdebug",
        "apcu version" => "APCu",
        "memcached version" => "Memcached",
        "mongodb version" | "mongodb extension version" => "MongoDB",
        "igbinary version" => "igbinary",
        "msgpack version" => "msgpack",
        "zip version" => "Zip",
        "zlib version" | "zlib compiled version" | "zlib linked version" => "zlib",
        _ => return,
    };
    if text.len() > 160 {
        return;
    }
    // Never retain arbitrary phpinfo cells: only validated version tokens from allowlisted rows.
    for token in text.split_whitespace().take(8) {
        if let Some(value) = version(token) {
            inventory(
                output,
                name,
                "extension",
                Some(value),
                page,
                "phpinfo_component",
                &format!(
                    "Allowlisted diagnostic field {}; actual binary unverified",
                    key.trim().to_ascii_lowercase()
                ),
            );
            return;
        }
    }
}

fn section_name(text: &str) -> Option<&'static str> {
    match text.to_ascii_lowercase().as_str() {
        "zend opcache" => Some("Zend OPcache"),
        "xdebug" => Some("Xdebug"),
        "redis" => Some("Redis"),
        "apcu" => Some("APCu"),
        "memcached" => Some("Memcached"),
        "mongodb" => Some("MongoDB"),
        "igbinary" => Some("igbinary"),
        "msgpack" => Some("msgpack"),
        "zip" => Some("Zip"),
        "zlib" => Some("zlib"),
        _ => None,
    }
}

fn scoped_version_key(key: &str) -> bool {
    matches!(
        key.trim().to_ascii_lowercase().as_str(),
        "version" | "compiled version" | "linked version"
    )
}

fn diagnostic_section(row: scraper::ElementRef<'_>) -> Option<&'static str> {
    let table = row
        .ancestors()
        .filter_map(scraper::ElementRef::wrap)
        .find(|node| node.value().name() == "table")?;
    for sibling in table.prev_siblings().take(8) {
        if let Some(element) = scraper::ElementRef::wrap(sibling) {
            return if element.value().name() == "h2" {
                section_name(element_text(element).0.trim())
            } else {
                None
            };
        }
    }
    None
}

fn asset_hint(url: &Url) -> Option<String> {
    let values: Vec<_> = url
        .query_pairs()
        .filter(|(key, _)| key == "ver" || key == "version")
        .collect();
    if values.len() != 1 {
        return None;
    }
    let value = values[0].1.trim_start_matches('v');
    // Query suffixes may carry private data; only numeric release hints are retained.
    if !value.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return None;
    }
    version(value)
}

fn inventory(
    output: &mut Vec<Technology>,
    name: &str,
    kind: &str,
    version: Option<String>,
    page: &Page,
    method: &str,
    detail: &str,
) {
    observe(
        output,
        name,
        kind,
        version,
        TechnologyObservation {
            hypothesis: None,
            version: None,
            source: display_url(&page.url),
            method: method.into(),
            http_status: page.status,
            detail: detail.into(),
        },
    );
}
