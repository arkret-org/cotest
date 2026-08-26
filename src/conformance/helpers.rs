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
