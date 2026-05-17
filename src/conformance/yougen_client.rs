use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{load_local_fixture_value, required_str, validate_profile};
use crate::transcripts::record_vector_event;

const FIXTURE: &str = "yougen-client-profile-conformance.json";
const FIXTURE_PROFILE: &str = "cx.profile.yougen_client_blackbox_manifest.v1";

const REQUIRED_TARGET_PROFILES: &[&str] =
    &["cx.profile.full_client.v1", "cx.profile.e2ee_client.v1"];

const REQUIRED_FLOWS: &[&str] = &[
    "oidc_session_grant",
    "secure_store_handoff",
    "device_verification",
    "e2ee_fail_closed",
];

pub fn run_yougen_client_profile_manifest_suite() -> Result<()> {
    let fixture = load_local_fixture_value(FIXTURE)?;
    validate_profile(&fixture, FIXTURE_PROFILE)?;
    if fixture.get("service").and_then(Value::as_str) != Some("yougen") {
        bail!("{FIXTURE} must target service=yougen");
    }

    let target_profiles = string_set(&fixture, "target_profiles")?;
    for profile in REQUIRED_TARGET_PROFILES {
        if !target_profiles.contains(*profile) {
            bail!("{FIXTURE} missing target profile {profile}");
        }
    }

    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("{FIXTURE} missing cases[]"))?;
    if cases.is_empty() {
        bail!("{FIXTURE} has no black-box cases");
    }

    let mut covered_flows = BTreeSet::new();
    let mut saw_explicit_unsupported = false;
    for case in cases {
        let name = required_str(case, "name")?;
        let flow = required_str(case, "flow")?;
        let profile = required_str(case, "profile")?;
        let expect = required_str(case, "expect")?;
        if !target_profiles.contains(profile) {
            bail!("{name} references profile {profile} outside target_profiles");
        }

        match expect {
            "pass" | "fail" => {
                covered_flows.insert(flow.to_owned());
            }
            "unsupported" => {
                saw_explicit_unsupported = true;
                require_non_empty(case, "/unsupported/reason", name)?;
            }
            other => bail!("{name} has unsupported expect value {other}"),
        }

        if production_mode(case) && has_silent_fallback(case)? {
            bail!("{name} runs in production mode but allows a silent fallback");
        }

        validate_case_shape(name, flow, profile, expect, case)?;
        record_vector_event(
            "yougen_client_profile.case",
            case,
            &json!({ "expect": expect, "flow": flow }),
            &json!({ "status": "ok" }),
        );
    }

    for flow in REQUIRED_FLOWS {
        if !covered_flows.contains(*flow) {
            bail!("{FIXTURE} missing required black-box flow {flow}");
        }
    }
    if !saw_explicit_unsupported {
        bail!("{FIXTURE} must include at least one explicit unsupported row");
    }
    let certification = validate_runnable_harness(&fixture, &covered_flows)?;
    record_vector_event(
        "yougen_client_profile.certification",
        certification,
        &json!({ "profiles": REQUIRED_TARGET_PROFILES }),
        &json!({ "status": "ok" }),
    );

    Ok(())
}

fn validate_runnable_harness<'a>(
    fixture: &'a Value,
    covered_flows: &BTreeSet<String>,
) -> Result<&'a Value> {
    let harness = fixture
        .get("runnable_harness")
        .ok_or_else(|| anyhow!("{FIXTURE} missing runnable_harness"))?;
    if harness.get("kind").and_then(Value::as_str) != Some("headless_contract") {
        bail!("{FIXTURE} runnable_harness.kind must be headless_contract");
    }
    require_non_empty(harness, "/runner", "runnable_harness")?;
    if harness
        .pointer("/certification/status")
        .and_then(Value::as_str)
        != Some("certified")
    {
        bail!("{FIXTURE} runnable_harness must emit certification.status=certified");
    }
    if harness
        .pointer("/certification/format")
        .and_then(Value::as_str)
        != Some("json")
    {
        bail!("{FIXTURE} runnable_harness certification output must be JSON");
    }

    let triggered = harness
        .get("triggered_paths")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("{FIXTURE} runnable_harness missing triggered_paths[]"))?;
    let mut triggered_flows = BTreeSet::new();
    for path in triggered {
        let name = required_str(path, "flow")?;
        if path.get("executed").and_then(Value::as_bool) != Some(true) {
            bail!("runnable_harness flow {name} was not actually executed");
        }
        let operations = string_set(path, "operations")?;
        match name {
            "oidc_session_grant" => {
                for operation in ["oidc_callback", "session_grant_exchange"] {
                    if !operations.contains(operation) {
                        bail!("runnable_harness {name} missing operation {operation}");
                    }
                }
            }
            "secure_store_handoff" => {
                if !operations.contains("secure_store_handoff") {
                    bail!("runnable_harness {name} missing secure_store_handoff");
                }
            }
            "device_verification" => {
                for operation in ["device_verification_start", "device_verification_complete"] {
                    if !operations.contains(operation) {
                        bail!("runnable_harness {name} missing operation {operation}");
                    }
                }
            }
            "e2ee_fail_closed" => {
                for operation in ["encrypted_event_open", "encrypted_reply_attempt"] {
                    if !operations.contains(operation) {
                        bail!("runnable_harness {name} missing operation {operation}");
                    }
                }
            }
            other => bail!("runnable_harness contains unknown flow {other}"),
        }
        triggered_flows.insert(name.to_owned());
    }
    for flow in REQUIRED_FLOWS {
        if !triggered_flows.contains(*flow) || !covered_flows.contains(*flow) {
            bail!("{FIXTURE} runnable_harness missing required executed flow {flow}");
        }
    }

    Ok(harness
        .get("certification")
        .ok_or_else(|| anyhow!("{FIXTURE} runnable_harness missing certification"))?)
}

fn validate_case_shape(
    name: &str,
    flow: &str,
    profile: &str,
    expect: &str,
    case: &Value,
) -> Result<()> {
    match flow {
        "oidc_session_grant" => {
            require_profile(profile, "cx.profile.full_client.v1", name)?;
            require_expect(expect, "pass", name)?;
            require_operation(case, "oidc_callback")?;
            require_operation(case, "session_grant_exchange")?;
            require_non_empty(case, "/observed/session_grant_token_type", name)?;
            if case
                .pointer("/observed/dev_login_used")
                .and_then(Value::as_bool)
                == Some(true)
            {
                bail!("{name} used dev-login in an OIDC/session-grant conformance path");
            }
        }
        "secure_store_handoff" => {
            require_expect(expect, "pass", name)?;
            require_operation(case, "secure_store_handoff")?;
            if case
                .pointer("/observed/plaintext_session_in_local_storage")
                .and_then(Value::as_bool)
                != Some(false)
            {
                bail!("{name} must prove no plaintext session token persisted in localStorage");
            }
            if case
                .pointer("/observed/host_secret_bridge_called")
                .and_then(Value::as_bool)
                != Some(true)
            {
                bail!("{name} must exercise the host secure-store bridge");
            }
        }
        "device_verification" => {
            require_profile(profile, "cx.profile.e2ee_client.v1", name)?;
            require_expect(expect, "pass", name)?;
            require_operation(case, "device_verification_start")?;
            require_operation(case, "device_verification_complete")?;
            let methods = string_set(
                case.get("observed")
                    .ok_or_else(|| anyhow!("{name} missing observed"))?,
                "verification_methods",
            )?;
            for method in ["cross_signing", "sas"] {
                if !methods.contains(method) {
                    bail!("{name} missing verification method {method}");
                }
            }
            if case
                .pointer("/observed/trust_state_after")
                .and_then(Value::as_str)
                != Some("trusted")
            {
                bail!("{name} must finish with trust_state_after=trusted");
            }
        }
        "e2ee_fail_closed" => {
            require_profile(profile, "cx.profile.e2ee_client.v1", name)?;
            require_expect(expect, "fail", name)?;
            if case
                .pointer("/expected/failure_mode")
                .and_then(Value::as_str)
                != Some("fail_closed")
            {
                bail!("{name} must declare expected.failure_mode=fail_closed");
            }
            if case
                .pointer("/expected/plaintext_fallback")
                .and_then(Value::as_bool)
                != Some(false)
            {
                bail!("{name} must forbid plaintext fallback");
            }
            if case
                .pointer("/expected/write_blocked")
                .and_then(Value::as_bool)
                != Some(true)
            {
                bail!("{name} must block the unsafe write/decrypt path");
            }
        }
        "platform_secure_enclave" => {
            require_expect(expect, "unsupported", name)?;
            if case
                .pointer("/unsupported/claim_status")
                .and_then(Value::as_str)
                != Some("not_claimed")
            {
                bail!("{name} unsupported optional platform feature must be not_claimed");
            }
        }
        other => bail!("{name} uses unknown flow {other}"),
    }
    Ok(())
}

fn string_set(value: &Value, field: &str) -> Result<BTreeSet<String>> {
    let items = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("missing {field}[]"))?;
    let mut out = BTreeSet::new();
    for item in items {
        let Some(text) = item.as_str() else {
            bail!("{field}[] entries must be strings");
        };
        if text.trim().is_empty() {
            bail!("{field}[] contains an empty string");
        }
        out.insert(text.to_owned());
    }
    Ok(out)
}

fn require_profile(actual: &str, expected: &str, name: &str) -> Result<()> {
    if actual != expected {
        bail!("{name} must target {expected}, got {actual}");
    }
    Ok(())
}

fn require_expect(actual: &str, expected: &str, name: &str) -> Result<()> {
    if actual != expected {
        bail!("{name} must expect {expected}, got {actual}");
    }
    Ok(())
}

fn require_operation(case: &Value, operation: &str) -> Result<()> {
    let name = required_str(case, "name")?;
    let operations = string_set(case, "black_box_operations")?;
    if !operations.contains(operation) {
        bail!("{name} missing black_box_operations entry {operation}");
    }
    Ok(())
}

fn require_non_empty<'a>(value: &'a Value, pointer: &str, name: &str) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| anyhow!("{name} missing non-empty {pointer}"))
}

fn production_mode(case: &Value) -> bool {
    case.pointer("/environment/production")
        .and_then(Value::as_bool)
        == Some(true)
}

fn has_silent_fallback(case: &Value) -> Result<bool> {
    let Some(items) = case
        .pointer("/observed/fallbacks")
        .and_then(Value::as_array)
    else {
        return Ok(false);
    };
    for item in items {
        let fallback = item.as_str().ok_or_else(|| {
            anyhow!(
                "{} observed.fallbacks[] entries must be strings",
                case.get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("<unknown>")
            )
        })?;
        if fallback != "none" {
            return Ok(true);
        }
    }
    Ok(false)
}
