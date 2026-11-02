//! Package declarations are inventoried even when absent from the product catalog.
use crate::{
    fingerprints::{Catalog, version},
    http::{Page, display_url},
    technology::{Technology, TechnologyObservation, observe},
};
use serde_json::Value;

impl Catalog {
    pub(crate) fn composer(&self, json: &Value, page: &Page) -> Vec<Technology> {
        let mut output = vec![];
        if !(200..300).contains(&page.status) {
            return output;
        }
        let (lock, npm) = match page.url.path().rsplit('/').next() {
            Some("composer.lock") => (true, false),
            Some("composer.json") => (false, false),
            Some("package-lock.json") => (true, true),
            Some("package.json") => (false, true),
            _ => return output,
        };
        if !lock {
            let key = if npm { "dependencies" } else { "require" };
            if let Some(packages) = json.get(key).and_then(Value::as_object) {
                for (name, constraint) in packages {
                    if constraint.is_string() {
                        self.package(&mut output, name, None, npm, false, page);
                    }
                }
            }
        } else if npm {
            if let Some(packages) = json.get("packages").and_then(Value::as_object) {
                for (path, entry) in packages {
                    let Some((_, name)) = path.rsplit_once("node_modules/") else {
                        continue;
                    };
                    if entry.get("dev") != Some(&Value::Bool(true)) {
                        self.package(&mut output, name, entry.get("version"), true, true, page);
                    }
                }
            } else if json.get("lockfileVersion").and_then(Value::as_u64) == Some(1) {
                self.npm_v1(&mut output, json, page, 0);
            }
        } else if let Some(packages) = json.get("packages").and_then(Value::as_array) {
            for entry in packages {
                if let Some(name) = entry.get("name").and_then(Value::as_str) {
                    self.package(&mut output, name, entry.get("version"), false, true, page);
                }
            }
        }
        if !npm
            && lock
            && let Some(platform) = json.get("platform").and_then(Value::as_object)
        {
            for (name, constraint) in platform {
                if constraint.is_string() {
                    self.package(&mut output, name, None, false, false, page);
                }
            }
        }
        output
    }

    fn npm_v1(&self, output: &mut Vec<Technology>, json: &Value, page: &Page, depth: usize) {
        let Some(packages) = json.get("dependencies").and_then(Value::as_object) else {
            return;
        };
        const MAX_NPM_DEPTH: usize = 8;
        if depth >= MAX_NPM_DEPTH {
            if !packages.is_empty()
                && let Some(last) = output.last_mut()
            {
                last.truncated = true;
            }
            return;
        }
        for (name, entry) in packages {
            if entry.get("dev") == Some(&Value::Bool(true)) {
                continue;
            }
            self.package(output, name, entry.get("version"), true, true, page);
            self.npm_v1(output, entry, page, depth + 1);
        }
    }

    // One package may map to multiple products; otherwise retain its ecosystem name.
    fn package(
        &self,
        output: &mut Vec<Technology>,
        name: &str,
        value: Option<&Value>,
        npm: bool,
        locked: bool,
        page: &Page,
    ) {
        if !valid_package(name, npm) {
            return;
        }
        let source = display_url(&page.url);
        let method = match (npm, locked) {
            (false, false) => "composer_requirement",
            (false, true) => "composer_package",
            (true, false) => "npm_requirement",
            (true, true) => "npm_package",
        };
        let version = value.and_then(Value::as_str).and_then(version);
        let bindings = if npm {
            &self.npm_packages
        } else {
            &self.composer_packages
        };
        if let Some(indices) = bindings.get(name) {
            for index in indices {
                self.record(
                    output,
                    *index,
                    version.clone(),
                    &source,
                    method,
                    page.status,
                );
            }
            return;
        }
        let extension = !npm && name.starts_with("ext-");
        let label = if extension {
            format!("PHP extension:{}", &name[4..])
        } else {
            format!("{}:{name}", if npm { "npm" } else { "composer" })
        };
        observe(
            output,
            &label,
            if extension { "extension" } else { "library" },
            version,
            TechnologyObservation {
                hypothesis: None,
                version: None,
                source,
                method: method.into(),
                http_status: page.status,
                detail: if locked {
                    "Production lock entry; installation and runtime loading are unverified".into()
                } else {
                    "Declared production requirement; no installed version is inferred".into()
                },
            },
        );
        if !npm && let Some(technology) = output.iter_mut().find(|t| t.name == label) {
            technology.runtime_hint = Some("PHP".into());
        }
    }
}

fn valid_package(name: &str, npm: bool) -> bool {
    if name.is_empty() || name.len() > 120 || name.contains("..") {
        return false;
    }
    if !npm && name.starts_with("ext-") {
        return valid_segment(&name[4..]);
    }
    if npm && name.contains('/') != name.starts_with('@') {
        return false;
    }
    let name = if npm {
        name.strip_prefix('@').unwrap_or(name)
    } else {
        name
    };
    let parts: Vec<_> = name.split('/').collect();
    (if npm {
        (1..=2).contains(&parts.len())
    } else {
        parts.len() == 2
    }) && parts.iter().all(|part| valid_segment(part))
}

fn valid_segment(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}
