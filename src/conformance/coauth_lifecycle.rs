use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{load_local_fixture_value, required_str, validate_profile};
use crate::transcripts::record_vector_event;

const FIXTURE: &str = "coauth-account-lifecycle-fixture.json";
const FIXTURE_PROFILE: &str = "ak.profile.coauth_account_lifecycle_vectors.v1";

const REQUIRED_PHASES: &[&str] = &[
    "oidc_callback_session_grant",
    "account_did_binding",
    "device_revoke_account_status_lifecycle",
    "policy_dry_run_audit",
    "production_no_silent_fallback",
];

pub fn run_coauth_account_lifecycle_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture_value(FIXTURE)?;
    validate_profile(&fixture, FIXTURE_PROFILE)?;
    if fixture.get("service").and_then(Value::as_str) != Some("coauth") {
        bail!("{FIXTURE} must target service=coauth");
    }

    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("{FIXTURE} missing cases[]"))?;
    if cases.is_empty() {
        bail!("{FIXTURE} has no lifecycle cases");
    }

    let mut covered = BTreeSet::new();
    for case in cases {
        let name = required_str(case, "name")?;
        let phase = required_str(case, "phase")?;
        let expect = required_str(case, "expect")?;
        match expect {
            "pass" | "reject" => {}
            other => bail!("{name} has unsupported expect value {other}"),
        }
        validate_phase(name, phase, expect, case)?;
        covered.insert(phase.to_owned());
        record_vector_event(
            "coauth_account_lifecycle.case",
            case,
            &json!({ "expect": expect, "phase": phase }),
            &json!({ "status": "ok" }),
        );
    }

    for phase in REQUIRED_PHASES {
        if !covered.contains(*phase) {
            bail!("{FIXTURE} missing required phase {phase}");
        }
    }

    Ok(())
}

fn validate_phase(name: &str, phase: &str, expect: &str, case: &Value) -> Result<()> {
    match phase {
        "oidc_callback_session_grant" => {
            require_expect(name, expect, "pass")?;
            require_local_oidc_provider(name, case)?;
            require_operation(case, "oidc_authorization_callback")?;
            require_operation(case, "session_grant_issue")?;
            if case
                .pointer("/observed/callback_status")
                .and_then(Value::as_u64)
                != Some(302)
            {
                bail!("{name} must model a successful OIDC callback redirect");
            }
            if case
                .pointer("/observed/session_grant/active")
                .and_then(Value::as_bool)
                != Some(true)
            {
                bail!("{name} must issue an active session grant");
            }
            assert_no_silent_fallback(name, case)?;
        }
        "account_did_binding" => {
            require_expect(name, expect, "pass")?;
            require_operation(case, "account_did_bind")?;
            let did = require_non_empty(case, "/observed/account/did", name)?;
            if !did.starts_with("did:") {
                bail!("{name} account DID must be a DID, got {did}");
            }
            if case
                .pointer("/observed/binding/status")
                .and_then(Value::as_str)
                != Some("bound")
            {
                bail!("{name} DID binding must finish with status=bound");
            }
            require_non_empty(case, "/observed/binding/proof_jws", name)?;
            assert_no_silent_fallback(name, case)?;
        }
        "device_revoke_account_status_lifecycle" => {
            require_expect(name, expect, "pass")?;
            require_operation(case, "device_revoke")?;
            require_operation(case, "account_status_update")?;
            let device_states = string_array_at(case, "/observed/device_status_sequence", name)?;
            if device_states != ["active", "revoked"] {
                bail!(
                    "{name} device_status_sequence must be [active, revoked], got {device_states:?}"
                );
            }
            if case
                .pointer("/observed/revoked_device_session_active")
                .and_then(Value::as_bool)
                != Some(false)
            {
                bail!("{name} revoked device session must be inactive");
            }
            let account_states = string_array_at(case, "/observed/account_status_sequence", name)?;
            for required in ["active", "suspended", "reactivated", "closed"] {
                if !account_states.iter().any(|state| state == required) {
                    bail!("{name} account_status_sequence missing {required}");
                }
            }
        }
        "policy_dry_run_audit" => {
            require_expect(name, expect, "pass")?;
            require_operation(case, "policy_dry_run")?;
            if case.pointer("/request/dry_run").and_then(Value::as_bool) != Some(true) {
                bail!("{name} policy request must set dry_run=true");
            }
            if case
                .pointer("/observed/persisted_effect")
                .and_then(Value::as_bool)
                != Some(false)
            {
                bail!("{name} policy dry-run must not persist an enforcement effect");
            }
            if case
                .pointer("/observed/audit/action")
                .and_then(Value::as_str)
                != Some("policy.dry_run")
            {
                bail!("{name} must emit policy.dry_run audit action");
            }
            require_non_empty(case, "/observed/audit/decision", name)?;
        }
        "production_no_silent_fallback" => {
            require_expect(name, expect, "reject")?;
            if case
                .pointer("/environment/production")
                .and_then(Value::as_bool)
                != Some(true)
            {
                bail!("{name} must run with environment.production=true");
            }
            if case
                .pointer("/fault/upstream_oidc_available")
                .and_then(Value::as_bool)
                != Some(false)
            {
                bail!("{name} must model an unavailable upstream OIDC provider");
            }
            if case.pointer("/observed/rejected").and_then(Value::as_bool) != Some(true) {
                bail!("{name} must reject instead of continuing");
            }
            assert_no_silent_fallback(name, case)?;
        }
        other => bail!("{name} uses unknown phase {other}"),
    }
    Ok(())
}

fn require_expect(name: &str, actual: &str, expected: &str) -> Result<()> {
    if actual != expected {
        bail!("{name} must expect {expected}, got {actual}");
    }
    Ok(())
}

fn require_local_oidc_provider(name: &str, case: &Value) -> Result<()> {
    if case.pointer("/idp/kind").and_then(Value::as_str) != Some("local_oidc_provider") {
        bail!("{name} must use a local_oidc_provider fixture");
    }
    require_non_empty(case, "/idp/issuer", name)?;
    require_non_empty(case, "/idp/subject", name)?;
    let keys = case
        .pointer("/idp/jwks/keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("{name} missing /idp/jwks/keys[]"))?;
    if keys.is_empty() {
        bail!("{name} local OIDC provider must expose at least one JWKS key");
    }
    require_non_empty(case, "/idp/authorization_code/code", name)?;
    require_non_empty(case, "/idp/callback/state", name)?;
    require_non_empty(case, "/idp/callback/nonce", name)?;
    let callback_nonce = require_non_empty(case, "/idp/callback/nonce", name)?;
    let token_nonce = require_non_empty(case, "/idp/id_token_claims/nonce", name)?;
    if callback_nonce != token_nonce {
        bail!("{name} callback nonce must match id_token_claims.nonce");
    }
    require_non_empty(case, "/idp/id_token_claims/aud", name)?;
    Ok(())
}

fn require_operation(case: &Value, operation: &str) -> Result<()> {
    let name = required_str(case, "name")?;
    let operations = string_array(case, "operations")?;
    if !operations.iter().any(|item| item == operation) {
        bail!("{name} missing operations entry {operation}");
    }
    Ok(())
}

fn assert_no_silent_fallback(name: &str, case: &Value) -> Result<()> {
    let fallbacks = string_array(case, "fallbacks").unwrap_or_default();
    for fallback in fallbacks {
        if fallback != "none" {
            bail!("{name} must not allow silent fallback, got {fallback}");
        }
    }
    if case
        .pointer("/observed/dev_or_password_fallback_used")
        .and_then(Value::as_bool)
        == Some(true)
    {
        bail!("{name} used a dev/password fallback in a production-grade path");
    }
    Ok(())
}

fn string_array(value: &Value, field: &str) -> Result<Vec<String>> {
    let items = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("missing {field}[]"))?;
    items
        .iter()
        .map(|item| {
            item.as_str()
                .filter(|text| !text.trim().is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| anyhow!("{field}[] entries must be non-empty strings"))
        })
        .collect()
}

fn string_array_at(value: &Value, pointer: &str, name: &str) -> Result<Vec<String>> {
    let items = value
        .pointer(pointer)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("{name} missing {pointer}[]"))?;
    items
        .iter()
        .map(|item| {
            item.as_str()
                .filter(|text| !text.trim().is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| anyhow!("{name} {pointer}[] entries must be non-empty strings"))
        })
        .collect()
}

fn require_non_empty<'a>(value: &'a Value, pointer: &str, name: &str) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| anyhow!("{name} missing non-empty {pointer}"))
}
