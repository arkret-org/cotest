use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::{load_fixture_value, required_str, validate_profile};

const FIXTURE_FILE: &str = "did-webvh-v1-fixture.json";
const PROFILE: &str = "ak.profile.identity_registry.v1";
const VECTOR_ID: &str = "ak.vector.identity.did_webvh_v1_adapter.v1";
const METHOD: &str = "did:webvh:1.0";

pub fn run_did_webvh_v1_adapter_fixture_suite() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE_FILE)?;
    validate_profile(&fixture, PROFILE)?;
    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("did:webvh fixture missing covers_vectors[]"))?;
    if !covers.iter().any(|value| value.as_str() == Some(VECTOR_ID)) {
        bail!("did:webvh fixture does not cover {VECTOR_ID}");
    }
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("did:webvh fixture missing cases[]"))?;
    for case in cases {
        run_case(case)?;
    }
    Ok(())
}

fn run_case(case: &Value) -> Result<()> {
    let name = required_str(case, "name")?;
    let method = case
        .pointer("/input/parameters/method")
        .and_then(Value::as_str);
    let actual = if method == Some(METHOD) {
        "accept"
    } else {
        "reject"
    };
    let expected = case
        .pointer("/expected/decision")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{name} missing expected decision"))?;
    if actual != expected {
        bail!("{name} decision drifted: expected {expected}, got {actual}");
    }
    if actual == "reject"
        && case.pointer("/expected/error_code").and_then(Value::as_str)
            != Some("unsupported_did_method")
    {
        bail!("{name} must reject with unsupported_did_method");
    }
    Ok(())
}
