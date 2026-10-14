//! Interpret the canonical forbidden-wire registry for actual protocol documents.

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;

pub struct ForbiddenWireScanner {
    registry: Value,
    kinds: Value,
}

fn pointers<'a>(value: &'a Value, pointer: &str) -> Vec<&'a Value> {
    if pointer.is_empty() {
        return vec![value];
    }
    let mut tokens = pointer.trim_start_matches('/').splitn(2, '/');
    let raw = tokens.next().unwrap();
    let token = raw.replace("~1", "/").replace("~0", "~");
    let tail = tokens
        .next()
        .map(|part| format!("/{part}"))
        .unwrap_or_default();
    match value {
        Value::Object(object) => object
            .iter()
            .filter(|(key, _)| raw == "*" || **key == token)
            .flat_map(|(_, child)| pointers(child, &tail))
            .collect(),
        Value::Array(array) => array
            .iter()
            .enumerate()
            .filter(|(index, _)| raw == "*" || index.to_string() == token)
            .flat_map(|(_, child)| pointers(child, &tail))
            .collect(),
        _ => vec![],
    }
}

fn descendants(value: &Value) -> Vec<&Value> {
    let mut values = vec![value];
    match value {
        Value::Object(object) => values.extend(object.values().flat_map(descendants)),
        Value::Array(array) => values.extend(array.iter().flat_map(descendants)),
        _ => {}
    }
    values
}

fn patch_hit(value: &Value, expected: &str) -> bool {
    value
        .get("patch")
        .and_then(Value::as_object)
        .is_some_and(|patch| {
            patch.iter().any(|(path, operation)| {
                if path == expected || path.starts_with(&format!("{expected}.")) {
                    return true;
                }
                let Some(remainder) = expected.strip_prefix(&format!("{path}.")) else {
                    return false;
                };
                let replacement = if let Some(op) = operation.get("$op") {
                    if op != "set" && op != "add" {
                        return false;
                    }
                    let Some(value) = operation.get("value") else {
                        return false;
                    };
                    value
                } else {
                    operation
                };
                !pointers(replacement, &format!("/{}", remainder.replace('.', "/"))).is_empty()
            })
        })
}

impl ForbiddenWireScanner {
    pub fn new(registry: Value, kinds: Value) -> Result<Self> {
        let entries = registry["entries"]
            .as_array()
            .context("forbidden-wire entries")?;
        ensure!(!entries.is_empty(), "forbidden-wire registry is empty");
        for entry in entries {
            let context = entry["context"]
                .as_str()
                .context("forbidden-wire context")?;
            ensure!(
                registry["context_definitions"][context]["selectors"].is_array()
                    && entry["match"].is_object(),
                "undefined forbidden-wire contract {context}"
            );
        }
        ensure!(
            kinds["event_kinds"]
                .as_array()
                .is_some_and(|rows| !rows.is_empty()),
            "event kind registry is empty"
        );
        Ok(Self { registry, kinds })
    }

    pub fn scan(&self, document: &Value, kind: &str, schema: &str) -> Result<Vec<String>> {
        let schema = schema
            .trim_start_matches("./")
            .trim_start_matches("schemas/");
        let mut violations = vec![];
        for entry in self.registry["entries"].as_array().unwrap() {
            if entry["rejection_level"] != "hard_reject" {
                continue;
            }
            let context = entry["context"].as_str().unwrap();
            for selector in self.registry["context_definitions"][context]["selectors"]
                .as_array()
                .unwrap()
            {
                let document_kind = selector["document_kind"]
                    .as_str()
                    .context("document kind")?;
                if document_kind != kind
                    && document_kind != "schema_instance"
                    && !(document_kind == "wire" && kind != "executable_artifact")
                {
                    continue;
                }
                if selector["schema_ref"] != "*" && selector["schema_ref"] != schema {
                    continue;
                }
                for root in pointers(
                    document,
                    selector["instance_pointer"]
                        .as_str()
                        .context("instance pointer")?,
                ) {
                    let nodes = if selector["match_scope"] == "descendants" {
                        descendants(root)
                    } else {
                        vec![root]
                    };
                    for node in nodes {
                        let matcher = entry["match"]["kind"].as_str().context("match kind")?;
                        for expected in entry["match"]["values"]
                            .as_array()
                            .context("match values")?
                        {
                            let expected = expected.as_str().context("match string")?;
                            let matcher = if selector["match_scope"] == "patch"
                                && ["field", "path"].contains(&matcher)
                            {
                                "patch_path"
                            } else {
                                matcher
                            };
                            let hit = match matcher {
                                "field" => node
                                    .as_object()
                                    .is_some_and(|object| object.contains_key(expected)),
                                "path" => {
                                    !pointers(node, &format!("/{}", expected.replace('.', "/")))
                                        .is_empty()
                                }
                                "patch_path" => patch_hit(node, expected),
                                "value" | "prefix" | "pattern" => {
                                    let pattern = if matcher == "pattern" {
                                        Some(regex::Regex::new(expected)?)
                                    } else {
                                        None
                                    };
                                    pointers(
                                        node,
                                        entry["match"]["value_pointer"].as_str().unwrap_or(""),
                                    )
                                    .iter()
                                    .any(|value| {
                                        value.as_str().is_some_and(|value| match matcher {
                                            "value" => value == expected,
                                            "prefix" => value.starts_with(expected),
                                            _ => pattern.as_ref().unwrap().is_match(value),
                                        })
                                    })
                                }
                                other => bail!("unknown forbidden-wire matcher {other}"),
                            };
                            if hit {
                                violations.push(format!("{}:{matcher}:{expected}", entry["id"]));
                            }
                        }
                    }
                }
            }
        }
        Ok(violations)
    }

    pub fn scan_event(&self, event: &Value) -> Result<Vec<String>> {
        let mut violations = self.scan(event, "event_envelope", "event-envelope.schema.json")?;
        let descriptor = self.kinds["event_kinds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["event_kind"] == event["kind"])
            .context("unregistered Event kind")?;
        violations.extend(
            self.scan(
                &event["payload"],
                "event_payload",
                descriptor["payload_schema_ref"]
                    .as_str()
                    .context("payload schema")?,
            )?,
        );
        Ok(violations)
    }
}
