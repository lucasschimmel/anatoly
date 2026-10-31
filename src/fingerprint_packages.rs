use crate::{
    fingerprints::{Catalog, version},
    http::{Page, display_url},
    technology::Technology,
};
use serde_json::Value;

impl Catalog {
    pub(crate) fn composer(&self, json: &Value, page: &Page) -> Vec<Technology> {
        let mut output = vec![];
        let (lock, npm) = match page.url.path().rsplit('/').next() {
            Some("composer.lock") => (true, false),
            Some("composer.json") => (false, false),
            Some("package-lock.json") => (true, true),
            Some("package.json") => (false, true),
            _ => return output,
        };
        let bindings = if npm {
            &self.npm_packages
        } else {
            &self.composer_packages
        };
        if !lock {
            let key = if npm { "dependencies" } else { "require" };
            for (package, _) in json
                .get(key)
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
            {
                if let Some(indices) = bindings.get(package) {
                    for index in indices {
                        self.record(
                            &mut output,
                            *index,
                            None,
                            &display_url(&page.url),
                            if npm {
                                "npm_requirement"
                            } else {
                                "composer_requirement"
                            },
                            page.status,
                        );
                    }
                }
            }
        } else if npm {
            for (path, entry) in json
                .get("packages")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
            {
                let Some((_, name)) = path.rsplit_once("node_modules/") else {
                    continue;
                };
                if entry.get("dev") == Some(&Value::Bool(true)) {
                    continue;
                }
                if let Some(indices) = bindings.get(name) {
                    for index in indices {
                        self.record(
                            &mut output,
                            *index,
                            entry
                                .get("version")
                                .and_then(Value::as_str)
                                .and_then(version),
                            &display_url(&page.url),
                            "npm_package",
                            page.status,
                        );
                    }
                }
            }
        } else {
            for entry in json
                .get("packages")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(name) = entry.get("name").and_then(Value::as_str) else {
                    continue;
                };
                if let Some(indices) = bindings.get(name) {
                    for index in indices {
                        self.record(
                            &mut output,
                            *index,
                            entry
                                .get("version")
                                .and_then(Value::as_str)
                                .and_then(version),
                            &display_url(&page.url),
                            "composer_package",
                            page.status,
                        );
                    }
                }
            }
        }
        output
    }
}
