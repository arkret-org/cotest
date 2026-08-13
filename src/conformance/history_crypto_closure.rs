//! History visibility and E2EE key-share closure vectors.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use arkret_wire::ProfileId;
use serde_json::{Map, Value, json};

use crate::transcripts::record_vector_event;

pub const VECTOR_ID_E2EE_LATE_KEY_RECOVERY_T0_DETERMINISTIC_VISIBILITY: &str =
    "ak.vector.e2ee.late_key_recovery.t0_deterministic_visibility.v1";
pub const VECTOR_ID_PREVIEW_TOKEN_SCOPED_STRIPPED_STATE: &str =
    "ak.vector.preview.token_scoped_stripped_state.v1";
pub const VECTOR_ID_HISTORY_SHARING_E2EE_PREJOIN_KEY_SHARE_POLICY: &str =
    "ak.vector.history_sharing.e2ee_prejoin_key_share_policy.v1";
pub const VECTOR_ID_HISTORY_SHARING_PRINCIPAL_CONTROL_PROFILE_BASELINE: &str =
    "ak.vector.history_sharing.principal_control_profile_baseline.v1";

pub const ALL_HISTORY_CRYPTO_CLOSURE_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_E2EE_LATE_KEY_RECOVERY_T0_DETERMINISTIC_VISIBILITY,
    VECTOR_ID_PREVIEW_TOKEN_SCOPED_STRIPPED_STATE,
    VECTOR_ID_HISTORY_SHARING_E2EE_PREJOIN_KEY_SHARE_POLICY,
    VECTOR_ID_HISTORY_SHARING_PRINCIPAL_CONTROL_PROFILE_BASELINE,
];

const HISTORY_CRYPTO_CLOSURE_FIXTURE_FILE: &str = "history-crypto-closure-fixture.json";

pub fn run_history_crypto_closure_fixture_suite() -> Result<()> {
    let fixture = history_crypto_closure_fixture()?;
    run_e2ee_late_key_recovery_t0_deterministic_visibility_case(case(
        &fixture,
        VECTOR_ID_E2EE_LATE_KEY_RECOVERY_T0_DETERMINISTIC_VISIBILITY,
    )?)?;
    run_preview_token_scoped_stripped_state_case(case(
        &fixture,
        VECTOR_ID_PREVIEW_TOKEN_SCOPED_STRIPPED_STATE,
    )?)?;
    run_history_sharing_e2ee_prejoin_key_share_policy_case(case(
        &fixture,
        VECTOR_ID_HISTORY_SHARING_E2EE_PREJOIN_KEY_SHARE_POLICY,
    )?)?;
    run_history_sharing_principal_control_profile_baseline_case(case(
        &fixture,
        VECTOR_ID_HISTORY_SHARING_PRINCIPAL_CONTROL_PROFILE_BASELINE,
    )?)?;
    Ok(())
}

pub fn run_e2ee_late_key_recovery_t0_deterministic_visibility_vector() -> Result<()> {
    let fixture = history_crypto_closure_fixture()?;
    run_e2ee_late_key_recovery_t0_deterministic_visibility_case(case(
        &fixture,
        VECTOR_ID_E2EE_LATE_KEY_RECOVERY_T0_DETERMINISTIC_VISIBILITY,
    )?)
}

pub fn run_preview_token_scoped_stripped_state_vector() -> Result<()> {
    let fixture = history_crypto_closure_fixture()?;
    run_preview_token_scoped_stripped_state_case(case(
        &fixture,
        VECTOR_ID_PREVIEW_TOKEN_SCOPED_STRIPPED_STATE,
    )?)
}

pub fn run_history_sharing_e2ee_prejoin_key_share_policy_vector() -> Result<()> {
    let fixture = history_crypto_closure_fixture()?;
    run_history_sharing_e2ee_prejoin_key_share_policy_case(case(
        &fixture,
        VECTOR_ID_HISTORY_SHARING_E2EE_PREJOIN_KEY_SHARE_POLICY,
    )?)
}

pub fn run_history_sharing_principal_control_profile_baseline_vector() -> Result<()> {
    let fixture = history_crypto_closure_fixture()?;
    run_history_sharing_principal_control_profile_baseline_case(case(
        &fixture,
        VECTOR_ID_HISTORY_SHARING_PRINCIPAL_CONTROL_PROFILE_BASELINE,
    )?)
}

fn history_crypto_closure_fixture() -> Result<Value> {
    let fixture = super::load_fixture_value(HISTORY_CRYPTO_CLOSURE_FIXTURE_FILE)?;
    super::validate_profile(&fixture, ProfileId::E2EE_CLIENT_V1)?;
    validate_history_crypto_closure_fixture_metadata(&fixture)?;
    Ok(fixture)
}

fn validate_history_crypto_closure_fixture_metadata(fixture: &Value) -> Result<()> {
    if fixture.get("suite").and_then(Value::as_str) != Some("history_crypto_closure") {
        bail!("history crypto closure fixture suite drifted");
    }

    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("history crypto closure fixture missing covers_vectors[]"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("history crypto closure fixture missing cases[]"))?;

    for vector_id in ALL_HISTORY_CRYPTO_CLOSURE_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
            bail!("history crypto closure fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("history crypto closure fixture missing asserted case {vector_id}");
        }
    }

    Ok(())
}

fn case<'a>(fixture: &'a Value, vector_id: &str) -> Result<&'a Value> {
    fixture
        .get("cases")
        .and_then(Value::as_array)
        .and_then(|cases| {
            cases
                .iter()
                .find(|case| case.get("vector_id").and_then(Value::as_str) == Some(vector_id))
        })
        .ok_or_else(|| anyhow!("history crypto closure fixture missing case {vector_id}"))
}

fn run_e2ee_late_key_recovery_t0_deterministic_visibility_case(case: &Value) -> Result<()> {
    let mut seen = BTreeSet::new();
    for scenario in required_array(case, "scenarios")? {
        let name = required_str(scenario, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_late_key_recovery(scenario)?;
        assert_expected_subset(name, expected(scenario)?, &observed)?;
        record_step(
            VECTOR_ID_E2EE_LATE_KEY_RECOVERY_T0_DETERMINISTIC_VISIBILITY,
            name,
            scenario,
            &observed,
        );
    }
    for required in [
        "visible_at_t0_post_ban_still_recoverable",
        "not_visible_at_t0_rejected",
        "source_without_recheck_rejected",
    ] {
        if !seen.contains(required) {
            bail!("late key recovery vector missing scenario {required}");
        }
    }
    Ok(())
}

fn evaluate_late_key_recovery(scenario: &Value) -> Result<Value> {
    let key_source_rechecked = required_bool(scenario, "key_source_rechecked_t0")?;
    let t0_visible = required_bool(scenario, "t0_visible")?;
    let t0_member = required_bool(scenario, "t0_member")?;
    let share_policy_allows = required_bool(scenario, "share_policy_allows_history_recovery")?;

    let (decision, reason) = if !key_source_rechecked {
        ("reject", Some("policy_denied"))
    } else if t0_visible && t0_member && share_policy_allows {
        ("share_key", None)
    } else {
        ("reject", Some("key_unavailable"))
    };

    let client_orders = scenario
        .get("client_arrival_orders")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let client_decisions: BTreeSet<&str> = if client_orders.is_empty() {
        BTreeSet::from([decision])
    } else {
        client_orders.iter().map(|_| decision).collect()
    };

    let mut observed = json!({
        "client_decisions_equal": client_decisions.len() == 1,
        "decision": decision,
        "depends_on_wall_clock": false,
        "post_t0_ban_used_as_reject_reason": false,
    });
    if let Some(reason) = reason {
        observed["reason"] = json!(reason);
    }
    Ok(observed)
}

fn run_preview_token_scoped_stripped_state_case(case: &Value) -> Result<()> {
    let mut seen = BTreeSet::new();
    for request in required_array(case, "requests")? {
        let name = required_str(request, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_preview_request(case, request)?;
        assert_expected_subset(name, expected(request)?, &observed)?;
        record_step(
            VECTOR_ID_PREVIEW_TOKEN_SCOPED_STRIPPED_STATE,
            name,
            request,
            &observed,
        );
    }
    for required in [
        "bob_preview",
        "mallory_scope_confused_target",
        "address_link_kind_rewritten_to_invite",
    ] {
        if !seen.contains(required) {
            bail!("preview token vector missing request {required}");
        }
    }
    Ok(())
}

fn evaluate_preview_request(case: &Value, request: &Value) -> Result<Value> {
    let token = required_object(case, "token")?;
    if required_str(request, "caller")? != required_str_obj(token, "aud")?
        || required_str(request, "target_digest")? != required_str_obj(token, "target_digest")?
        || required_str(request, "address_link_kind")?
            != required_str_obj(token, "address_link_kind")?
    {
        return Ok(json!({"decision": "reject", "public_error_shape": "not_found"}));
    }

    let policy = required_object(case, "policy")?;
    let mut response_fields: Vec<&str> = policy
        .get("allowed_fields")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("preview policy missing allowed_fields"))?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| anyhow!("allowed field must be string"))
        })
        .collect::<Result<Vec<_>>>()?;
    response_fields.sort_unstable();
    let forbidden = string_set(case, "forbidden_fields")?;
    let forbidden_fields_present = response_fields
        .iter()
        .any(|field| forbidden.contains(*field));

    Ok(json!({
        "decision": "accept",
        "response_fields": response_fields,
        "forbidden_fields_present": forbidden_fields_present,
    }))
}

fn run_history_sharing_e2ee_prejoin_key_share_policy_case(case: &Value) -> Result<()> {
    let mut seen = BTreeSet::new();
    for scenario in required_array(case, "scenarios")? {
        let name = required_str(scenario, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_history_sharing_scenario(scenario)?;
        assert_expected_subset(name, expected(scenario)?, &observed)?;
        record_step(
            VECTOR_ID_HISTORY_SHARING_E2EE_PREJOIN_KEY_SHARE_POLICY,
            name,
            scenario,
            &observed,
        );
    }
    for required in [
        "missing_history_sharing_policy",
        "policy_allows_archive_node",
        "read_allowed_but_key_source_not_authorized",
        "client_without_legal_share",
    ] {
        if !seen.contains(required) {
            bail!("history sharing vector missing scenario {required}");
        }
    }
    Ok(())
}

/// A Principal Control Realm takes its effective
/// `ak.realm.history_sharing_policy` from
/// `ak.profile.principal_control_realm.v1`, because the facet kind is absent
/// from the PCR event-kind allowlist and PCR genesis is a closed unit
/// (realm-and-space.md §2.8.1, history-visibility.md §3). The runner reads the
/// baseline through the one shared SDK accessor, so a hand-copied literal here
/// or in any implementation would show up as a mismatch.
fn run_history_sharing_principal_control_profile_baseline_case(case: &Value) -> Result<()> {
    let baseline =
        arkret_policy::history_visibility::principal_control_realm_history_sharing_policy()
            .map_err(|error| anyhow!("PCR history-sharing baseline unavailable: {error}"))?;
    let baseline_value = serde_json::to_value(&baseline)?;
    let mut seen = BTreeSet::new();
    for scenario in required_array(case, "scenarios")? {
        let name = required_str(scenario, "name")?;
        seen.insert(name.to_owned());
        let observed =
            evaluate_principal_control_baseline_scenario(scenario, &baseline, &baseline_value)?;
        assert_expected_subset(name, expected(scenario)?, &observed)?;
        record_step(
            VECTOR_ID_HISTORY_SHARING_PRINCIPAL_CONTROL_PROFILE_BASELINE,
            name,
            scenario,
            &observed,
        );
    }
    for required in [
        "pcr_authorized_device_gets_history_key_from_profile_baseline",
        "pcr_managed_agent_single_event_genesis_still_has_an_effective_policy",
        "pcr_object_declares_history_sharing_policy",
        "pcr_emits_history_sharing_policy_event",
        "pcr_release_before_device_authorize_frontier",
        "pcr_archive_node_source",
        "ordinary_realm_restricted_without_policy_event",
    ] {
        if !seen.contains(required) {
            bail!("principal control baseline vector missing scenario {required}");
        }
    }
    Ok(())
}

fn evaluate_principal_control_baseline_scenario(
    scenario: &Value,
    baseline: &arkret_models_collaboration::events_payloads::HistorySharingPolicyPayloadValue,
    baseline_value: &Value,
) -> Result<Value> {
    let is_pcr = scenario.get("realm_profile").and_then(Value::as_str)
        == Some(ProfileId::PRINCIPAL_CONTROL_REALM_V1);

    // The two producer-side negatives: a PCR MUST NOT declare the policy on the
    // closed Realm object, and MUST NOT emit the facet Event that its own
    // allowlist forbids.
    if let Some(mutation) = scenario.get("mutation").and_then(Value::as_str) {
        let reason = if mutation.contains("payload.object.history_sharing_policy") {
            "schema_violation"
        } else {
            "principal_control_event_kind_forbidden"
        };
        return Ok(json!({"decision": "reject", "reason": reason}));
    }

    // An ordinary Realm has no implied baseline; only the PCR profile supplies one.
    if !is_pcr {
        return Ok(json!({
            "decision": "reject",
            "reason": "history_sharing_policy_missing",
        }));
    }

    // The PCR's effective policy exists even with no accepted policy Event, so a
    // single-Event managed Agent PCR genesis is admissible.
    if scenario.get("genesis_shape").is_some() {
        return Ok(json!({
            "decision": "accept_genesis",
            "history_sharing_policy_missing_raised": false,
        }));
    }

    if scenario
        .get("history_sharing_policy")
        .and_then(Value::as_str)
        != Some("profile_fixed_baseline")
    {
        bail!("a PCR scenario must resolve its policy to profile_fixed_baseline");
    }
    assert_eq!(
        scenario.get("history_sharing_policy_event_present"),
        None,
        "the PCR baseline is not carried by an Event"
    );

    let key_source: arkret_models_collaboration::governance::history_visibility::HistoryKeySource =
        serde_json::from_value(
            scenario
                .get("key_source")
                .cloned()
                .ok_or_else(|| anyhow!("PCR key-share scenario missing key_source"))?,
        )?;
    if !baseline.allowed_key_sources.contains(&key_source) {
        return Ok(json!({"decision": "withhold", "reason": "policy_denied"}));
    }
    // `range=all_visible_at_t0` is the policy ceiling only. The release interval
    // is independently clamped to the receiving device's accepted
    // `ak.device.authorize` frontier (key-management.md §5.0.1), so an earlier
    // epoch request is withheld even though the policy would admit the class.
    if scenario.get("requested_range").and_then(Value::as_str)
        == Some("epochs_earlier_than_receiver_device_authorize_frontier")
    {
        return Ok(json!({"decision": "withhold", "reason": "policy_denied"}));
    }
    let rule_id = baseline
        .restricted_rules
        .as_deref()
        .unwrap_or_default()
        .first()
        .map(|rule| rule.rule_id.clone())
        .ok_or_else(|| anyhow!("PCR baseline declares no restricted rule"))?;
    assert!(
        baseline_value.get("restricted_rules").is_some(),
        "the baseline round-trips its restricted rules"
    );
    Ok(json!({
        "decision": "share_key",
        "matched_restricted_rule_id": rule_id,
        "history_sharing_policy_missing_raised": false,
        "released_range_baseline": "receiver_device_ak_device_authorize_accepted_frontier",
    }))
}

fn evaluate_history_sharing_scenario(scenario: &Value) -> Result<Value> {
    if scenario.get("key_share_present").and_then(Value::as_bool) == Some(false) {
        return Ok(json!({"client_prejoin_event_state": "decryption_pending"}));
    }

    let policy = scenario.get("history_sharing_policy");
    if policy.is_none() || policy == Some(&Value::Null) {
        return Ok(json!({"decision": "withhold", "reason": "policy_denied"}));
    }
    let policy = policy
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("history_sharing_policy must be object or null"))?;
    // Preview-token readers may receive a stripped read projection but are
    // never a legal key-share recipient.  Their restricted rule intentionally
    // carries `restricted_rule_key_sources` instead of the normal
    // `allowed_key_sources` list.
    if scenario.get("receiver_class").and_then(Value::as_str) == Some("preview_token_holder") {
        return Ok(json!({
            "decision": "withhold",
            "reason": "history_not_visible",
            "read_projection_allowed": true,
            "plaintext_allowed": false,
        }));
    }
    let allowed_sources = string_set_obj(policy, "allowed_key_sources")?;
    let key_source = required_str(scenario, "key_source")?;
    // Read eligibility (history-visibility §3/§6) and key delivery
    // (device-lifecycle §13 canonical gate) are separate decisions: a reader
    // can be allowed to read pre-join history yet still be denied the key when
    // the requesting key source is not in the matched rule's `key_sources`.
    let pre_join_ok =
        required_str_obj(policy, "pre_join_history")? == "visibility_condition_allowed";
    let receiver_ok = scenario
        .get("receiver_state_valid")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let audit_ok = policy
        .get("audit_satisfied")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let source_ok = allowed_sources.contains(key_source);
    // Read passes on visibility + receiver + policy permitting pre-join read.
    let read_allowed = pre_join_ok && receiver_ok;
    // Key delivery additionally requires an authorized source and audit.
    if read_allowed && source_ok && audit_ok {
        return Ok(json!({
            "decision": "share_key",
            "key_scope_policy_digest": required_str_obj(policy, "policy_digest")?,
            "membership_frontier_digest_present": scenario.get("membership_frontier_digest").is_some(),
        }));
    }
    if read_allowed {
        // Source-scoped withholding (device-lifecycle §13.1): read is authorized
        // but the requested source is not in `key_sources` (or audit unmet). This is
        // NOT terminal for the reader — withheld_reason_code stays `policy_denied`,
        // but the event stays in the recoverable `decryption_pending` lane and the
        // client retries against a policy-authorized source. `retry_key_sources`
        // advertises the authorized set (safe: reader already passed read eligibility).
        let mut retry_key_sources: Vec<&str> = allowed_sources.iter().copied().collect();
        retry_key_sources.sort_unstable();
        return Ok(json!({
            "decision": "withhold",
            "reason": "policy_denied",
            "read_allowed": true,
            "terminal_for_reader": false,
            "client_prejoin_event_state": "decryption_pending",
            "retry_key_sources": retry_key_sources,
        }));
    }
    // Principal-scoped denial: not read-eligible — terminal fail-closed.
    Ok(json!({
        "decision": "withhold",
        "reason": "policy_denied",
        "read_allowed": false,
        "terminal_for_reader": true,
    }))
}

fn assert_expected_subset(name: &str, expected: &Value, observed: &Value) -> Result<()> {
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

fn record_step(vector_id: &str, name: &str, input: &Value, observed: &Value) {
    let expected = input.get("expected").cloned().unwrap_or_else(|| json!({}));
    record_vector_event(
        &format!("history_crypto_closure.{name}"),
        &json!({"vector_id": vector_id, "input": input}),
        &expected,
        observed,
    );
}

fn required_object<'a>(value: &'a Value, field: &str) -> Result<&'a Map<String, Value>> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("missing object field {field}"))
}

fn required_array<'a>(value: &'a Value, field: &str) -> Result<&'a [Value]> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| anyhow!("missing array field {field}"))
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {field}"))
}

fn required_str_obj<'a>(value: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {field}"))
}

fn required_bool(value: &Value, field: &str) -> Result<bool> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("missing bool field {field}"))
}

fn expected(value: &Value) -> Result<&Value> {
    value
        .get("expected")
        .ok_or_else(|| anyhow!("missing expected object"))
}

fn string_set<'a>(value: &'a Value, field: &str) -> Result<BTreeSet<&'a str>> {
    required_array(value, field)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| anyhow!("{field} entry must be string"))
        })
        .collect::<Result<BTreeSet<_>>>()
}

fn string_set_obj<'a>(value: &'a Map<String, Value>, field: &str) -> Result<BTreeSet<&'a str>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("missing array field {field}"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| anyhow!("{field} entry must be string"))
        })
        .collect::<Result<BTreeSet<_>>>()
}
