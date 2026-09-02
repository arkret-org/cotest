use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

pub(super) fn profile_claims(describe: &Value) -> BTreeSet<String> {
    let mut claims = BTreeSet::new();
    for field in ["supported_profiles", "profiles", "claimed_profiles"] {
        collect_profile_array(describe.get(field), &mut claims);
    }
    if let Some(claims_value) = describe.get("profile_claims") {
        match claims_value {
            Value::Array(_) => collect_profile_array(Some(claims_value), &mut claims),
            Value::Object(object) => {
                for (profile, value) in object {
                    if value.as_bool().unwrap_or(true) {
                        claims.insert(profile.to_owned());
                    }
                    collect_profile_array(Some(value), &mut claims);
                }
            }
            _ => {}
        }
    }
    claims
}

fn collect_profile_array(value: Option<&Value>, claims: &mut BTreeSet<String>) {
    let Some(items) = value.and_then(Value::as_array) else {
        return;
    };
    for item in items {
        if let Some(profile) = item.as_str() {
            claims.insert(profile.to_owned());
            continue;
        }
        if let Some(profile) = item
            .get("profile")
            .or_else(|| item.get("id"))
            .and_then(Value::as_str)
        {
            claims.insert(profile.to_owned());
        }
    }
}

/// Whether any object key anywhere under `value` is exactly `needle`.
///
/// Privacy vectors use this to prove a forbidden field never leaks, at any
/// nesting depth, into a payload a peer can observe.
pub(super) fn contains_key_recursive(value: &Value, needle: &str) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(key, value)| key == needle || contains_key_recursive(value, needle)),
        Value::Array(items) => items
            .iter()
            .any(|item| contains_key_recursive(item, needle)),
        _ => false,
    }
}

/// Whether `needle` occurs as a substring of any key or string value anywhere
/// under `value`. Broader than [`contains_key_recursive`]: it also catches a
/// forbidden literal embedded inside a string.
pub(super) fn contains_literal_recursive(value: &Value, needle: &str) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(key, value)| key.contains(needle) || contains_literal_recursive(value, needle)),
        Value::Array(items) => items
            .iter()
            .any(|item| contains_literal_recursive(item, needle)),
        Value::String(raw) => raw.contains(needle),
        _ => false,
    }
}

/// Whether a JSON value carries no information: null, an empty array/object,
/// or a blank string.
pub(super) fn is_empty_json_value(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(items) => items.is_empty(),
        Value::Object(object) => object.is_empty(),
        Value::String(text) => text.trim().is_empty(),
        _ => false,
    }
}

/// Read a non-blank string at `pointer`, naming `context` in the error.
pub(super) fn require_non_empty<'a>(
    value: &'a Value,
    pointer: &str,
    context: &str,
) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| anyhow!("{context} missing non-empty {pointer}"))
}

pub(super) fn assert_expected_subset(name: &str, expected: &Value, observed: &Value) -> Result<()> {
    let expected = expected
        .as_object()
        .ok_or_else(|| anyhow!("{name} expected value must be an object"))?;
    let observed = observed
        .as_object()
        .ok_or_else(|| anyhow!("{name} observed value must be an object"))?;
    for (key, expected_value) in expected {
        match observed.get(key) {
            Some(observed_value) if observed_value == expected_value => {}
            Some(observed_value) => {
                bail!("{name} expected {key}={expected_value}, got {observed_value}");
            }
            None => bail!("{name} observed result missing expected key {key}"),
        }
    }
    Ok(())
}
