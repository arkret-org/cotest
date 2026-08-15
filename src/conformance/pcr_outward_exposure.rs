use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::load_artifact_json;

pub fn run_pcr_outward_exposure_suite() -> Result<()> {
    let fixture = load_artifact_json("fixtures/pcr-outward-exposure-fixture.json")?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("PCR outward exposure fixture has no cases"))?;
    let case = |name: &str| {
        cases
            .iter()
            .find(|case| case.get("name").and_then(Value::as_str) == Some(name))
            .ok_or_else(|| anyhow!("PCR outward exposure fixture omits `{name}`"))
    };

    let public = case("public_resolution_returns_attested_projection_only")?;
    let schema = load_artifact_json("schemas/identity-resolution.schema.json")?;
    let public_properties = schema
        .pointer("/$defs/public_principal_resolution/properties")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("public principal resolution is not a closed object"))?;
    for field in public["expected_required_fields"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if !public_properties.contains_key(field) {
            bail!("public principal resolution omits required field `{field}`");
        }
    }
    for field in public["forbidden_fields"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if public_properties.contains_key(field) {
            bail!("public principal resolution leaks PCR field `{field}`");
        }
    }

    let merged = case("actor_profile_unknown_unauthorized_and_wrong_selector_are_equivalent")?;
    if merged["expected_reason"] != "profile_unavailable"
        || merged["http_status"] != 200
        || merged["internal_causes"].as_array().map(Vec::len) != Some(5)
    {
        bail!("Actor Profile anti-enumeration bucket drifted");
    }
    case("private_pcr_kind_has_no_outward_annotation")?;
    case("outward_annotation_requires_exact_registry_reverse_edge")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn pcr_outward_exposure_is_minimized_and_closed() {
        super::run_pcr_outward_exposure_suite().unwrap();
    }
}
