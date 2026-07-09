use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{load_local_fixture_value, required_str, validate_profile, value_array};
use crate::transcripts::record_vector_event;

const SCAFFOLD_FIXTURE: &str = "scaffold-profile-gate-fixture.json";
const SCAFFOLD_FIXTURE_PROFILE: &str = "ak.vector_group.privacy_security.v1";
const LIVE_DESCRIBE_FIXTURE: &str = "live-describe-profile-gate-fixture.json";
const LIVE_DESCRIBE_FIXTURE_PROFILE: &str = "ak.profile.live_describe_profile_gate_vectors.v1";

const FULL_PROFILE_CLAIMS: &[&str] = &[
    "ak.profile.principal_server_events_api.v1",
    "ak.profile.principal_server.v1",
    "ak.profile.full_client.v1",
    "ak.profile.e2ee_client.v1",
];

const SCAFFOLD_MARKERS: &[&str] = &[
    "501",
    "not implemented",
    "not_implemented",
    "scaffold",
    "limitation",
    "placeholder",
    "stub",
];

pub fn run_scaffold_profile_gate_suite() -> Result<()> {
    run_gate_fixture(SCAFFOLD_FIXTURE, SCAFFOLD_FIXTURE_PROFILE, false)
}

pub fn run_live_describe_profile_gate_suite() -> Result<()> {
    run_gate_fixture(LIVE_DESCRIBE_FIXTURE, LIVE_DESCRIBE_FIXTURE_PROFILE, true)
}

fn run_gate_fixture(
    file_name: &str,
    expected_profile: &str,
    require_live_coverage: bool,
) -> Result<()> {
    let fixture = load_local_fixture_value(file_name)?;
    validate_profile(&fixture, expected_profile)?;
    let cases = value_array(
        fixture
            .get("cases")
            .ok_or_else(|| anyhow!("{file_name} missing cases[]"))?,
        "scaffold profile gate cases",
    )?;

    let mut services = BTreeSet::new();
    let mut saw_full_claim_limitation_reject = false;
    let mut saw_full_claim_scaffold_reject = false;
    let mut saw_full_claim_501_reject = false;

    for case in cases {
        let name = required_str(case, "name")?;
        let expected = required_str(case, "expect")?;
        let describe = case
            .get("describe")
            .ok_or_else(|| anyhow!("{name} missing describe object"))?;
        let result = validate_scaffold_profile_gate(describe);
        let blockers = describe_blockers(describe);
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

        if require_live_coverage {
            let service = describe
                .get("service")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("{name} missing describe.service"))?;
            services.insert(service.to_owned());
            if expected == "reject" && claims_full_profile(describe) {
                saw_full_claim_limitation_reject |= blockers.has_limitation;
                saw_full_claim_scaffold_reject |= blockers.has_scaffold;
                saw_full_claim_501_reject |= blockers.has_501;
            }
        }

        record_vector_event(
            if require_live_coverage {
                "live_describe_profile_gate.case"
            } else {
                "scaffold_profile_gate.case"
            },
            &json!({
                "name": name,
                "service": describe.get("service").and_then(Value::as_str),
            }),
            &json!({ "expect": expected }),
            &json!({ "status": "ok" }),
        );
    }

    if require_live_coverage {
        for service in ["soland", "floria", "teabay", "starid", "coauth"] {
            if !services.contains(service) {
                bail!("{file_name} missing live describe sample for {service}");
            }
        }
        if !(saw_full_claim_limitation_reject
            && saw_full_claim_scaffold_reject
            && saw_full_claim_501_reject)
        {
            bail!(
                "{file_name} must hard-fail full profile claims with limitation, scaffold, and 501 blockers"
            );
        }
    }

    Ok(())
}

pub fn validate_scaffold_profile_gate(describe: &Value) -> Result<()> {
    validate_starid_production_health(describe)?;

    if !claims_full_profile(describe) {
        return Ok(());
    }

    let blockers = describe_blockers(describe);
    if !blockers.items.is_empty() {
        bail!(
            "full profile claim is incompatible with scaffold/profile blockers: {}",
            blockers.items.join(", ")
        );
    }

    Ok(())
}

fn claims_full_profile(describe: &Value) -> bool {
    profile_claims(describe)
        .iter()
        .any(|profile| FULL_PROFILE_CLAIMS.contains(&profile.as_str()))
}

fn profile_claims(describe: &Value) -> BTreeSet<String> {
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

#[derive(Default)]
struct BlockerSummary {
    items: Vec<String>,
    has_501: bool,
    has_scaffold: bool,
    has_limitation: bool,
}

fn describe_blockers(describe: &Value) -> BlockerSummary {
    let mut summary = BlockerSummary::default();
    collect_blockers(describe, "$", &mut summary);
    summary
}

fn collect_blockers(value: &Value, path: &str, summary: &mut BlockerSummary) {
    match value {
        Value::String(text) => {
            let lower = text.to_ascii_lowercase();
            if SCAFFOLD_MARKERS.iter().any(|marker| lower.contains(marker)) {
                if lower.contains("501") {
                    summary.has_501 = true;
                }
                if lower.contains("limitation") {
                    summary.has_limitation = true;
                }
                if lower.contains("scaffold")
                    || lower.contains("placeholder")
                    || lower.contains("stub")
                    || lower.contains("not implemented")
                    || lower.contains("not_implemented")
                {
                    summary.has_scaffold = true;
                }
                summary.items.push(format!("{path}={text:?}"));
            }
        }
        Value::Number(number) if number.as_u64() == Some(501) => {
            summary.has_501 = true;
            summary.items.push(format!("{path}=501"));
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_blockers(item, &format!("{path}[{index}]"), summary);
            }
        }
        Value::Object(object) => {
            for (key, value) in object {
                let lower_key = key.to_ascii_lowercase();
                if matches!(lower_key.as_str(), "limitation" | "limitations")
                    && !is_empty_json_value(value)
                {
                    summary.has_limitation = true;
                    summary.items.push(format!("{path}.{key}=<non-empty>"));
                }
                collect_blockers(value, &format!("{path}.{key}"), summary);
            }
        }
        _ => {}
    }
}

fn is_empty_json_value(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(items) => items.is_empty(),
        Value::Object(object) => object.is_empty(),
        Value::String(text) => text.trim().is_empty(),
        _ => false,
    }
}
