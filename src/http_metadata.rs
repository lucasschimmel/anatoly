use crate::http::{CookieShape, PublicMetadata};
use reqwest::Url;
pub(crate) fn public_metadata(
    url: &Url,
    status: u16,
    headers: &reqwest::header::HeaderMap,
    catalog: Option<&crate::fingerprints::Catalog>,
) -> PublicMetadata {
    let mut selected = vec![];
    let mut security_headers = vec![];
    for name in [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "content-type",
    ] {
        for value in headers.get_all(name) {
            security_headers.push((name.to_owned(), value.to_str().unwrap_or("").to_owned()));
        }
    }
    for name in [
        "server",
        "x-powered-by",
        "x-php-version",
        "php-version",
        "x-runtime",
        "x-runtime-version",
        "x-generator",
        "x-framework",
        "x-drupal-cache",
        "x-drupal-dynamic-cache",
    ] {
        for value in headers.get_all(name).iter().filter_map(|v| v.to_str().ok()) {
            // Parse the complete field; cutting it can hide a later contradictory version.
            selected.push((name.to_owned(), value.to_owned()));
        }
    }
    // Retain only canonical, recognized names. Never retain cookie values or opaque suffixes.
    if let Some(catalog) = catalog {
        for name in catalog.header_names() {
            if selected.iter().any(|(existing, _)| existing == name) {
                continue;
            }
            for value in headers.get_all(name).iter().filter_map(|v| v.to_str().ok()) {
                selected.push((name.to_owned(), value.to_owned()));
            }
        }
    }
    let mut technology_cookies = vec![];
    let mut cookies: Vec<CookieShape> = vec![];
    for cookie in headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|h| h.to_str().ok())
    {
        let name = cookie.split_once('=').map_or("", |(n, _)| n.trim());
        if let Some(catalog) = catalog {
            for technology in catalog.cookie_technologies(name, status) {
                if !technology_cookies.contains(&technology) {
                    technology_cookies.push(technology);
                }
            }
        }
        let lower = name.to_ascii_lowercase();
        let canonical = if lower == "phpsessid" {
            "PHPSESSID"
        } else if lower == "laravel_session" {
            "laravel_session"
        } else if lower == "craftsessionid" {
            "CraftSessionId"
        } else if lower == "craft_csrf_token" {
            "CRAFT_CSRF_TOKEN"
        } else if lower.starts_with("wordpress_logged_in_") {
            "wordpress_logged_in_*"
        } else if lower.starts_with("wordpress_sec_") {
            "wordpress_sec_*"
        } else if lower.starts_with("prestashop-") {
            "PrestaShop-*"
        } else if lower.starts_with("phpbb3_") {
            "phpbb3_*"
        } else {
            continue;
        };
        if !cookies.iter().any(|c| c.name == canonical) {
            let value = cookie
                .split_once('=')
                .map_or("", |(_, v)| v.split(';').next().unwrap_or(""));
            let alphabet = if !value.is_empty() && value.chars().all(|c| c.is_ascii_hexdigit()) {
                "hexadecimal"
            } else if !value.is_empty() && value.chars().all(|c| c.is_ascii_alphanumeric()) {
                "alphanumeric"
            } else {
                "other/custom"
            };
            let attributes: Vec<_> = cookie
                .split(';')
                .skip(1)
                .map(|s| s.trim().to_ascii_lowercase())
                .collect();
            let same_sites: Vec<_> = attributes
                .iter()
                .filter(|a| a.split('=').next().is_some_and(|n| n.trim() == "samesite"))
                .collect();
            let same_site = if same_sites.len() > 1 {
                "multiple attributes; ambiguous"
            } else if same_sites
                .first()
                .is_some_and(|a| a.as_str() == "samesite=lax")
            {
                "Lax"
            } else if same_sites
                .first()
                .is_some_and(|a| a.as_str() == "samesite=strict")
            {
                "Strict"
            } else if same_sites
                .first()
                .is_some_and(|a| a.as_str() == "samesite=none")
            {
                "None"
            } else {
                "not disclosed"
            };
            cookies.push(CookieShape {
                name: canonical.into(),
                length: value.len(),
                alphabet,
                secure: attributes.iter().any(|a| a == "secure"),
                http_only: attributes.iter().any(|a| a == "httponly"),
                same_site,
            });
        } else if let Some(existing) = cookies.iter_mut().find(|c| c.name == canonical) {
            // Canonical names can collapse distinct paths/domains or opaque suffixes.
            // Never infer safe attributes from the first of multiple declarations.
            existing.secure = false;
            existing.http_only = false;
            existing.same_site = "multiple declarations; ambiguous";
        }
    }
    let age = headers
        .get("age")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|v| v > 0);
    let cache_hit = ["x-cache", "cf-cache-status"].iter().any(|name| {
        headers
            .get(*name)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("hit"))
    });
    PublicMetadata {
        technology_cookies,
        url: url.clone(),
        status,
        headers: selected,
        security_headers,
        cookies,
        cached: age || cache_hit,
    }
}
