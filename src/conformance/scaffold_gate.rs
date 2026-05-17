use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{load_local_fixture_value, required_str, validate_profile, value_array};
use crate::transcripts::record_vector_event;

const FIXTURE: &str = "scaffold-profile-gate-fixture.json";
const FIXTURE_PROFILE: &str = "cx.profile.privacy_security_vectors.v1";

const FULL_PROFILE_CLAIMS: &[&str] = &[
    "cx.profile.principal_server.v1",
    "cx.profile.full_client.v1",
    "cx.profile.e2ee_client.v1",
];

const SCAFFOLD_MARKERS: &[&str] = &[
    "501",
    "not implemented",
    "not_implemented",
    "scaffold",
    "placeholder",
    "stub",
];

pub fn run_scaffold_profile_gate_suite() -> Result<()> {
    let fixture = load_local_fixture_value(FIXTURE)?;
    validate_profile(&fixture, FIXTURE_PROFILE)?;
    let cases = value_array(
        fixture
            .get("cases")
            .ok_or_else(|| anyhow!("{FIXTURE} missing cases[]"))?,
        "scaffold profile gate cases",
    )?;

    for case in cases {
        let name = required_str(case, "name")?;
        let expected = required_str(case, "expect")?;
        let describe = case
            .get("describe")
            .ok_or_else(|| anyhow!("{name} missing describe object"))?;
        let result = validate_scaffold_profile_gate(describe);
        match (expected, result.is_ok()) {
            ("pass", true) | ("reject", false) => {}
            ("pass", false) => {
                bail!("{name} expected pass but failed: {}", result.unwrap_err());
            }
            ("reject", true) => {
                bail!("{name} expected reject but passed");
            }
            _ => bail!("{name} uses unknown expect value {expected}"),
        }

        record_vector_event(
            "scaffold_profile_gate.case",
            &json!({
                "name": name,
                "service": describe.get("service").and_then(Value::as_str),
            }),
            &json!({ "expect": expected }),
            &json!({ "status": "ok" }),
        );
    }

    Ok(())
}

pub fn validate_scaffold_profile_gate(describe: &Value) -> Result<()> {
    validate_starid_production_health(describe)?;

    if !claims_full_profile(describe) {
        return Ok(());
    }

    let mut blockers = Vec::new();
    collect_blockers(describe, "$", &mut blockers);
    if !blockers.is_empty() {
        bail!(
            "full profile claim is incompatible with scaffold/profile blockers: {}",
            blockers.join(", ")
        );
    }

    Ok(())
}

fn claims_full_profile(describe: &Value) -> bool {
    describe
        .get("supported_profiles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|profile| FULL_PROFILE_CLAIMS.contains(&profile))
}

fn validate_starid_production_health(describe: &Value) -> Result<()> {
    if describe.get("service").and_then(Value::as_str) != Some("starid") {
        return Ok(());
    }
    let production = describe
        .get("development_mode")
        .and_then(Value::as_bool)
        .is_some_and(|development| !development);
    let unstable_receipt_key = describe
        .get("receipt_signing_key_stable")
        .and_then(Value::as_bool)
        == Some(false);
    let claims_ok = describe.get("ok").and_then(Value::as_bool) == Some(true)
        || describe.get("ready").and_then(Value::as_bool) == Some(true);
    if production && unstable_receipt_key && claims_ok {
        bail!("starid production health/readiness cannot be ok with an ephemeral receipt key");
    }
    Ok(())
}

fn collect_blockers(value: &Value, path: &str, blockers: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            let lower = text.to_ascii_lowercase();
            if SCAFFOLD_MARKERS.iter().any(|marker| lower.contains(marker)) {
                blockers.push(format!("{path}={text:?}"));
            }
        }
        Value::Number(number) if number.as_u64() == Some(501) => {
            blockers.push(format!("{path}=501"));
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_blockers(item, &format!("{path}[{index}]"), blockers);
            }
        }
        Value::Object(object) => {
            for (key, value) in object {
                collect_blockers(value, &format!("{path}.{key}"), blockers);
            }
        }
        _ => {}
    }
}
