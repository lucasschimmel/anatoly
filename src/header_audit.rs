use crate::http::{Page, display_url};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Finding {
    pub name: String,
    pub status: String,
    pub proof: String,
    pub remediation: String,
}

fn finding(name: &str, status: &str, proof: &str, remediation: &str) -> Finding {
    Finding {
        name: name.into(),
        status: status.into(),
        proof: proof.into(),
        remediation: remediation.into(),
    }
}

fn values<'a>(page: &'a Page, name: &str) -> Vec<&'a str> {
    page.metadata
        .security_headers
        .iter()
        .filter(|(n, _)| n == name)
        .map(|(_, v)| v.trim())
        .collect()
}

fn single<'a>(page: &'a Page, name: &str) -> Option<&'a str> {
    let fields = values(page, name);
    (fields.len() == 1)
        .then(|| fields[0])
        .filter(|v| !v.is_empty())
}

fn field_check(
    page: &Page,
    name: &str,
    valid: impl Fn(&str) -> bool,
    remediation: &str,
) -> Finding {
    let fields = values(page, name);
    let (status, proof) = if fields.is_empty() {
        ("missing", "Header was not observed on this response.")
    } else if fields.len() != 1 || fields[0].is_empty() {
        (
            "unknown",
            "Duplicate or unreadable header fields require manual interpretation.",
        )
    } else if valid(fields[0]) {
        (
            "observed",
            "One header field matched the stated syntax check; effectiveness is not certified.",
        )
    } else {
        (
            "review",
            "Header was present but did not match the stated syntax check.",
        )
    };
    finding(name, status, proof, remediation)
}

fn positive_hsts(value: &str) -> bool {
    let ages: Vec<_> = value
        .split(';')
        .filter_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            name.trim()
                .eq_ignore_ascii_case("max-age")
                .then_some(value.trim())
        })
        .collect();
    ages.len() == 1 && ages[0].parse::<u64>().is_ok_and(|age| age > 0)
}

fn frame_ancestors(value: &str) -> bool {
    if value.contains(',') {
        return false;
    }
    value.split(';').any(|directive| {
        let mut parts = directive.split_whitespace();
        parts
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case("frame-ancestors"))
            && parts.next().is_some()
    })
}

/// Results describe one observed response, not application-wide browser protection.
pub fn assess(page: &Page) -> Vec<Finding> {
    let mut result = vec![finding(
        "scope",
        "context",
        &format!(
            "{} returned HTTP {}. Only selected headers and recognized PHP cookie names are inspected.",
            display_url(&page.url),
            page.status
        ),
        "Review all routes, authenticated responses and browser behavior separately. Presence alone does not prove a policy is effective.",
    )];
    result.push(if page.url.scheme() == "https" {
        field_check(page, "strict-transport-security", positive_hsts, "Set an intentional positive max-age on HTTPS after checking domain and subdomain readiness.")
    } else {
        finding("strict-transport-security", "not_applicable", "HSTS delivered over HTTP is ignored by browsers.", "Serve the application over HTTPS and configure HSTS there; this check does not test an HTTPS alternative.")
    });
    result.push(field_check(page, "content-security-policy", |v| !v.contains(',') && !v.trim().is_empty(),
        "Review an enforcing CSP for this application. This check only establishes presence, not directive validity, strength or coverage; report-only policies do not enforce."));
    result.push(field_check(
        page,
        "x-content-type-options",
        |v| v.eq_ignore_ascii_case("nosniff"),
        "Return X-Content-Type-Options: nosniff alongside correct response MIME types.",
    ));
    result.push(framing(page));
    result.push(field_check(page, "referrer-policy", |v| matches!(v, "no-referrer" | "same-origin" | "strict-origin" | "strict-origin-when-cross-origin"),
        "Choose an application-appropriate Referrer-Policy; missing or alternative values require context, not a vulnerability verdict."));
    result.extend(cookies(page));
    result
}

fn framing(page: &Page) -> Finding {
    let xfo = single(page, "x-frame-options");
    let csp = single(page, "content-security-policy");
    if xfo.is_some_and(|v| v.eq_ignore_ascii_case("deny") || v.eq_ignore_ascii_case("sameorigin"))
        || csp.is_some_and(frame_ancestors)
    {
        finding(
            "framing",
            "observed",
            "A single X-Frame-Options DENY/SAMEORIGIN field or a CSP frame-ancestors directive was observed. Allowed ancestors were not evaluated.",
            "Verify the allowed embedding origins against application requirements; presence alone does not establish clickjacking protection.",
        )
    } else {
        finding(
            "framing",
            "review",
            "No unambiguous supported framing declaration was observed.",
            "For HTML documents, configure CSP frame-ancestors with intended origins. Framing controls may be irrelevant for non-document responses.",
        )
    }
}

fn cookies(page: &Page) -> Vec<Finding> {
    if page.metadata.cookies.is_empty() {
        return vec![finding(
            "cookies",
            "unknown",
            "No recognized PHP session cookie was observed. Custom names and cookies set by JavaScript are outside this check.",
            "Review session cookies on authenticated routes; absence here does not establish safe cookie configuration.",
        )];
    }
    page.metadata.cookies.iter().map(|cookie| {
        let acceptable = cookie.secure && cookie.http_only && matches!(cookie.same_site, "Lax" | "Strict");
        let status = if cookie.same_site.contains("ambiguous") {
            "unknown"
        } else if acceptable {
            "observed"
        } else {
            "review"
        };
        finding(&format!("cookie {}", cookie.name), status,
            &format!("Secure={}; HttpOnly={}; SameSite={}. Cookie values and opaque name suffixes are omitted.", cookie.secure, cookie.http_only, cookie.same_site),
            "Check Secure and HttpOnly for session cookies. Choose SameSite for application flows; None requires Secure. Attributes do not prove CSRF or session security.")
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_duplicate_or_malformed_hsts_never_matches_positive_age() {
        for value in [
            "max-age=0",
            "max-age=abc",
            "max-age=1; max-age=2",
            "max-age=1, max-age=2",
            "max-age=-1",
        ] {
            assert!(!positive_hsts(value), "{value}");
        }
        assert!(positive_hsts("max-age=31536000; includeSubDomains"));
    }

    #[test]
    fn framing_requires_the_actual_directive_and_a_value() {
        assert!(!frame_ancestors("report-uri /frame-ancestors"));
        assert!(!frame_ancestors("frame-ancestors"));
        assert!(frame_ancestors(
            "default-src 'self'; frame-ancestors 'none'"
        ));
    }
}
