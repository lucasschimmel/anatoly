//! Passive vendor markers, deliberately distinct from proof of WAF effectiveness.
use crate::http::display_url;
use reqwest::{Url, header::HeaderMap};
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct WafEvidence {
    pub source: String,
    pub product: String,
    pub signal: String,
    pub interpretation: String,
}

/// Keep normalized marker names only, never header values, identifiers or cookies.
/// The explicit vendor cases intentionally keep each marker beside its limits.
pub fn inspect(url: &Url, status: u16, headers: &HeaderMap) -> Vec<WafEvidence> {
    let mut result = vec![];
    let mut add = |product: &str, signal: &str, interpretation: &str| {
        result.push(WafEvidence {
            source: display_url(url),
            product: product.into(),
            signal: signal.into(),
            interpretation: interpretation.into(),
        });
    };
    if headers.contains_key("cf-ray") || has_value(headers, "server", "cloudflare") {
        add(
            "Cloudflare",
            "edge marker observed",
            "Remote headers advertise a Cloudflare edge. This does not establish that a WAF is enabled or that either PHP2Shell CVE is blocked.",
        );
    }
    if has_value(headers, "cf-mitigated", "challenge") {
        add(
            "Cloudflare",
            "challenge response declared",
            "The response declares a Cloudflare challenge. Headers can be spoofed; a challenge does not prove PHP2Shell protection.",
        );
    }
    if headers.contains_key("x-amzn-waf-action") {
        add(
            "AWS WAF",
            "x-amzn-waf-action header observed",
            "A vendor-specific WAF action marker was observed. Its value and identifiers are omitted; the action and rule effectiveness remain unverified.",
        );
    }
    if headers.contains_key("x-sucuri-id") || headers.contains_key("x-sucuri-cache") {
        add(
            "Sucuri",
            "edge marker observed",
            "Remote headers advertise Sucuri infrastructure; WAF enforcement and PHP2Shell protection are unverified.",
        );
    }
    if headers.contains_key("x-sucuri-block") {
        add(
            "Sucuri",
            "x-sucuri-block header observed",
            "A vendor-specific blocking marker was observed. This does not establish why the response was blocked or whether PHP2Shell is prevented.",
        );
    }
    if headers.contains_key("x-akamai-transformed")
        || headers.contains_key("akamai-grn")
        || has_value(headers, "server", "akamaighost")
    {
        add(
            "Akamai",
            "edge marker observed",
            "Remote headers advertise Akamai infrastructure; this is not evidence of WAF effectiveness or of origin patch state.",
        );
    }
    // A generic denial or throttling response alone cannot identify a WAF.
    if matches!(status, 403 | 429) && !result.is_empty() {
        result.push(WafEvidence {
            source: display_url(url),
            product: "Unverified".into(),
            signal: "denial or throttling response with vendor markers".into(),
            interpretation: "HTTP 403/429 can originate from authentication, application policy, rate limits or an edge. Causality and WAF protection are not established.".into(),
        });
    }
    result
}

fn has_value(headers: &HeaderMap, name: &str, expected: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value
            .to_str()
            .is_ok_and(|value| value.trim().eq_ignore_ascii_case(expected))
    })
}
