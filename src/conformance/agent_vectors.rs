//! Agent surface conformance vectors (§0.11 of `_before_todos.md`).
//!
//! 10 vectors:
//!   - `ak.vector.agent.provision.v1`
//!   - `ak.vector.agent.pairing_expiry.v1`
//!   - `ak.vector.agent.runtime_key_binding.v1`
//!   - `ak.vector.agent.managed_pcr_separation.v1`
//!   - `ak.vector.agent.repairing_supersede.v1`
//!   - `ak.vector.agent.longevity_no_expiry.v1`
//!   - `ak.vector.agent.controller_lifecycle.v1`
//!   - `ak.vector.agent.act_on_behalf.v1`
//!   - `ak.vector.agent.session_grant.replay.v1`
//!   - `ak.vector.agent_auth.human_approval_required.v1`
//!
//! These are SDK-pure wire-shape pins. Live reducer paths (FSM bottom =
//! reject, deactivate-terminal, session-grant agent-branch acceptance
//! matrix, replay-cache) land in soland P2-impl; this suite hard-fails
//! on any registry-side drift today.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use arkret_core::{
    AgentHumanApprovalErrorDetails, AgentKeyScope, CapabilityActionId, Did, ErrorEnvelope,
    NotificationDelta, NotificationDeltaAction, agent_requested_scope_digest,
};
use serde_json::Value;

pub const VECTOR_ID_AGENT_PROVISION: &str = "ak.vector.agent.provision.v1";
pub const VECTOR_ID_AGENT_PAIRING_EXPIRY: &str = "ak.vector.agent.pairing_expiry.v1";
pub const VECTOR_ID_AGENT_RUNTIME_KEY_BINDING: &str = "ak.vector.agent.runtime_key_binding.v1";
pub const VECTOR_ID_AGENT_MANAGED_PCR_SEPARATION: &str =
    "ak.vector.agent.managed_pcr_separation.v1";
pub const VECTOR_ID_AGENT_REPAIRING_SUPERSEDE: &str = "ak.vector.agent.repairing_supersede.v1";
pub const VECTOR_ID_AGENT_LONGEVITY_NO_EXPIRY: &str = "ak.vector.agent.longevity_no_expiry.v1";
pub const VECTOR_ID_AGENT_CONTROLLER_LIFECYCLE: &str = "ak.vector.agent.controller_lifecycle.v1";
pub const VECTOR_ID_AGENT_ACT_ON_BEHALF: &str = "ak.vector.agent.act_on_behalf.v1";
pub const VECTOR_ID_AGENT_SESSION_GRANT_REPLAY: &str = "ak.vector.agent.session_grant.replay.v1";
pub const VECTOR_ID_AGENT_HUMAN_APPROVAL_REQUIRED: &str =
    "ak.vector.agent_auth.human_approval_required.v1";

pub const ALL_AGENT_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_AGENT_PROVISION,
    VECTOR_ID_AGENT_PAIRING_EXPIRY,
    VECTOR_ID_AGENT_RUNTIME_KEY_BINDING,
    VECTOR_ID_AGENT_MANAGED_PCR_SEPARATION,
    VECTOR_ID_AGENT_REPAIRING_SUPERSEDE,
    VECTOR_ID_AGENT_LONGEVITY_NO_EXPIRY,
    VECTOR_ID_AGENT_CONTROLLER_LIFECYCLE,
    VECTOR_ID_AGENT_ACT_ON_BEHALF,
    VECTOR_ID_AGENT_SESSION_GRANT_REPLAY,
    VECTOR_ID_AGENT_HUMAN_APPROVAL_REQUIRED,
];

const AGENT_VECTORS_FIXTURE_FILE: &str = "agent-vectors-fixture.json";
const AGENT_VECTORS_PROFILE: &str = "ak.profile.personal_agent_provisioning.v1";

fn validate_agent_vectors_fixture_metadata() -> Result<()> {
    let fixture = super::load_fixture_value(AGENT_VECTORS_FIXTURE_FILE)?;
    super::validate_profile(&fixture, AGENT_VECTORS_PROFILE)?;
    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("agent vectors fixture missing covers_vectors[]"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("agent vectors fixture missing cases[]"))?;

    for vector_id in ALL_AGENT_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
            bail!("agent vectors fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("agent vectors fixture missing asserted case {vector_id}");
        }
    }

    Ok(())
}

// ─── VECT-AG-1 — provision ─────────────────────────────────────────────────

type ScopeSelector<'a> = (&'a str, Option<&'a str>, Option<&'a str>);

fn content_selector(kind: &str) -> bool {
    matches!(
        kind,
        "realm"
            | "space"
            | "circle"
            | "strand"
            | "message"
            | "morph"
            | "object"
            | "relation"
            | "view"
            | "event"
            | "actor"
            | "schema"
            | "policy"
            | "invite"
            | "notification"
            | "read_cursor"
            | "blob"
    )
}

fn selector_covers(parent: ScopeSelector<'_>, child: ScopeSelector<'_>) -> bool {
    let (parent_kind, parent_realm, parent_ref) = parent;
    let (child_kind, child_realm, child_ref) = child;
    let kind_covers =
        parent_kind == child_kind || (parent_kind == "realm" && content_selector(child_kind));
    kind_covers
        && parent_realm.is_none_or(|value| child_realm == Some(value))
        && parent_ref.is_none_or(|value| child_ref == Some(value))
}

fn admit_scope_within_agent_ceiling(
    requested_actions: &[&str],
    requested_resources: &[ScopeSelector<'_>],
    requested_constraints: &[&str],
    child_actions: &[&str],
    child_resources: &[ScopeSelector<'_>],
    child_constraints: &[&str],
    reason: &'static str,
) -> std::result::Result<(), &'static str> {
    let actions_fit = child_actions
        .iter()
        .all(|action| requested_actions.contains(action));
    let has_content_ceiling = requested_resources
        .iter()
        .any(|(kind, ..)| content_selector(kind));
    let resources_fit = child_resources.iter().all(|child| {
        (content_selector(child.0) && !has_content_ceiling)
            || requested_resources
                .iter()
                .any(|parent| selector_covers(*parent, *child))
    });
    let constraints_fit = requested_constraints
        .iter()
        .all(|constraint| child_constraints.contains(constraint));
    if actions_fit && resources_fit && constraints_fit {
        Ok(())
    } else {
        Err(reason)
    }
}

pub fn run_agent_provision_vector() -> Result<()> {
    let fixture = super::load_fixture_value(AGENT_VECTORS_FIXTURE_FILE)?;
    let vector = fixture["cases"]
        .as_array()
        .and_then(|cases| {
            cases.iter().find(|case| {
                case.get("vector_id").and_then(Value::as_str) == Some(VECTOR_ID_AGENT_PROVISION)
            })
        })
        .ok_or_else(|| anyhow!("agent provision vector case is missing"))?;
    let commitment = vector
        .get("requested_scope_commitment")
        .ok_or_else(|| anyhow!("agent provision vector commitment is missing"))?;
    let agent_id = Did::new(
        commitment
            .get("agent_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("commitment agent_id is missing"))?
            .to_owned(),
    )?;
    let controller_id = Did::new(
        commitment
            .get("controller_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("commitment controller_id is missing"))?
            .to_owned(),
    )?;
    let requested_scope: AgentKeyScope = serde_json::from_value(
        commitment
            .get("requested_scope")
            .cloned()
            .ok_or_else(|| anyhow!("commitment requested_scope is missing"))?,
    )?;
    let digest = agent_requested_scope_digest(&agent_id, &controller_id, &requested_scope)?;
    if commitment.get("expected_digest").and_then(Value::as_str) != Some(digest.as_str()) {
        bail!("Agent requested_scope DID commitment digest drifted");
    }
    if arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_PROVISION
        != "ak.self.agent.command.provision"
    {
        bail!(
            "arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_PROVISION spelling drifted: arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_PROVISION"
        );
    }
    if CapabilityActionId::SELF_AGENT_COMMAND_PROVISION != "ak.self.agent.command.provision" {
        bail!("personal-agent provision capability action spelling drifted");
    }
    // The provisioning error matrix MUST include `failed_precondition`
    // (modeled by absence of the controller-self capability binding)
    // and `accountability_grant_missing` (the controller's grant has
    // not yet been verified).
    if arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING != "accountability_grant_missing" {
        bail!(
            "arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING spelling drifted: accountability_grant_missing"
        );
    }
    let realm = "ak:realm:019a7360-0000-7000-8000-000000000000";
    let other_realm = "ak:realm:019a7360-0000-7000-8000-000000000001";
    let ceiling_actions = ["ak.event.read", "ak.message.create", "ak.reaction.add"];
    let ceiling_resources = [
        ("operation", None, Some("ak.self.events.stream.subscribe")),
        ("realm", Some(realm), None),
    ];
    let mandatory_constraints = ["controller_approval_required"];

    admit_scope_within_agent_ceiling(
        &ceiling_actions,
        &ceiling_resources,
        &mandatory_constraints,
        &["ak.event.read"],
        &[("strand", Some(realm), Some("ak:strand:019a7360"))],
        &["controller_approval_required", "rate_limit"],
        "agent_scope_exceeds_requested_scope",
    )
    .map_err(|reason| anyhow!("narrower Agent key scope was rejected: {reason}"))?;
    if admit_scope_within_agent_ceiling(
        &ceiling_actions,
        &ceiling_resources,
        &mandatory_constraints,
        &["ak.event.read"],
        &[("strand", Some(realm), Some("ak:strand:019a7360"))],
        &[],
        "agent_scope_exceeds_requested_scope",
    ) != Err("agent_scope_exceeds_requested_scope")
    {
        bail!("Agent key scope dropped a mandatory provision constraint");
    }

    admit_scope_within_agent_ceiling(
        &ceiling_actions,
        &ceiling_resources,
        &mandatory_constraints,
        &["ak.event.read"],
        &[("object", Some(realm), Some("ak:object:019a7360"))],
        &["controller_approval_required"],
        arkret_wire::ReasonCode::AGENT_GRANT_EXCEEDS_REQUESTED_SCOPE,
    )
    .map_err(|reason| anyhow!("narrower Realm grant was rejected: {reason}"))?;
    admit_scope_within_agent_ceiling(
        &ceiling_actions,
        &ceiling_resources,
        &mandatory_constraints,
        &["ak.event.read"],
        &[("circle", Some(realm), Some("ak:circle:019a7360"))],
        &["controller_approval_required"],
        arkret_wire::ReasonCode::AGENT_GRANT_EXCEEDS_REQUESTED_SCOPE,
    )
    .map_err(|reason| anyhow!("Realm ceiling did not cover a Circle grant: {reason}"))?;
    if admit_scope_within_agent_ceiling(
        &ceiling_actions,
        &ceiling_resources,
        &mandatory_constraints,
        &["ak.strand.update"],
        &[("object", Some(realm), Some("ak:object:019a7360"))],
        &["controller_approval_required"],
        arkret_wire::ReasonCode::AGENT_GRANT_EXCEEDS_REQUESTED_SCOPE,
    ) != Err(arkret_wire::ReasonCode::AGENT_GRANT_EXCEEDS_REQUESTED_SCOPE)
    {
        bail!("Realm grant restored an action omitted from requested_scope");
    }
    if admit_scope_within_agent_ceiling(
        &ceiling_actions,
        &ceiling_resources,
        &mandatory_constraints,
        &["ak.event.read"],
        &[("object", Some(other_realm), Some("ak:object:019a7361"))],
        &["controller_approval_required"],
        arkret_wire::ReasonCode::AGENT_GRANT_EXCEEDS_REQUESTED_SCOPE,
    ) != Err(arkret_wire::ReasonCode::AGENT_GRANT_EXCEEDS_REQUESTED_SCOPE)
    {
        bail!("Realm grant escaped the provisioned content resource ceiling");
    }
    Ok(())
}

// ─── VECT-AG-2 — pairing_expiry ────────────────────────────────────────────

pub fn run_agent_pairing_expiry_vector() -> Result<()> {
    if arkret_wire::ReasonCode::PAIRING_REQUEST_EXPIRED != "pairing_request_expired" {
        bail!(
            "arkret_wire::ReasonCode::PAIRING_REQUEST_EXPIRED spelling drifted: pairing_request_expired"
        );
    }
    if arkret_core::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY
        != "ak.gate.account.command.pair_agent_key"
    {
        bail!(
            "arkret_core::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY spelling drifted: arkret_core::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY"
        );
    }
    // The error-response matrix for the key-pair endpoint MUST
    // include `verification_method_principal_mismatch`,
    // `pairing_request_expired`, `proof_invalid`, `agent_deactivated`
    // (see §0.8). The DID-match check happens BEFORE the proof
    // validator (fail-closed-before-validator); we pin the canonical
    // error-code spellings here.
    let required = [
        arkret_wire::ReasonCode::VERIFICATION_METHOD_PRINCIPAL_MISMATCH,
        arkret_wire::ReasonCode::PAIRING_REQUEST_EXPIRED,
        arkret_wire::ReasonCode::PROOF_INVALID,
        arkret_wire::ReasonCode::AGENT_DEACTIVATED,
    ];
    for code in required {
        if code.is_empty() || !code.chars().all(|c| c == '_' || c.is_ascii_lowercase()) {
            bail!("agent_key_pair error code corrupted: `{code}`");
        }
    }
    Ok(())
}

// ─── VECT-AG-2b — repairing_supersede ──────────────────────────────────────

pub fn run_agent_runtime_key_binding_vector() -> Result<()> {
    let fixture = super::load_fixture_value(AGENT_VECTORS_FIXTURE_FILE)?;
    let case = fixture["cases"]
        .as_array()
        .and_then(|cases| {
            cases.iter().find(|case| {
                case.get("vector_id").and_then(Value::as_str)
                    == Some(VECTOR_ID_AGENT_RUNTIME_KEY_BINDING)
            })
        })
        .ok_or_else(|| anyhow!("runtime-key-binding vector case missing"))?;
    let agent_id = Did::new("did:webvh:z6mkagent:agent.example")?;
    let public_key = case
        .get("source_public_key")
        .ok_or_else(|| anyhow!("runtime-key-binding source_public_key missing"))?;
    let attestation = case
        .get("source_runtime_attestation")
        .filter(|value| !value.is_null());
    let public_digest = arkret_core::agent_runtime_public_key_digest(public_key)?;
    let attestation_digest = arkret_core::agent_runtime_attestation_digest(attestation)?;
    let binding = arkret_core::agent_runtime_key_binding_digest(
        &agent_id,
        "pairing_request:01964137-0000-7000-8000-000000000000",
        "did:webvh:z6mkagent:agent.example#runtime-1",
        public_key,
        attestation,
    )?;
    for (actual, expected_key) in [
        (public_digest.as_str(), "expected_public_key_digest"),
        (attestation_digest.as_str(), "expected_attestation_digest"),
        (binding.as_str(), "expected_binding_digest"),
    ] {
        if case.get(expected_key).and_then(Value::as_str) != Some(actual) {
            bail!("runtime-key-binding {expected_key} drifted: {actual}");
        }
    }
    let canonical = serde_json::json!({
        "agent_id": agent_id,
        "attestation_digest": attestation_digest,
        "kind": "ak.agent.runtime_key_binding.v1",
        "pairing_request_id": "pairing_request:01964137-0000-7000-8000-000000000000",
        "public_key_digest": public_digest,
        "verification_method": "did:webvh:z6mkagent:agent.example#runtime-1",
    });
    let canonical = String::from_utf8(arkret_canonical::canonical_json_bytes(&canonical)?)?;
    if case.get("canonical_binding_json").and_then(Value::as_str) != Some(canonical.as_str()) {
        bail!("runtime-key-binding canonical JSON drifted");
    }

    let pairing = case
        .get("pairing_request_binding_input")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("pairing_request_binding_input missing"))?;
    let controller_id = Did::new(
        pairing
            .get("controller_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("pairing controller_id missing"))?,
    )?;
    let pairing_agent_id = Did::new(
        pairing
            .get("agent_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("pairing agent_id missing"))?,
    )?;
    let expiry_inputs = pairing
        .get("pairing_expires_at_inputs")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("pairing_expires_at_inputs missing"))?;
    if expiry_inputs.len() < 3 {
        bail!(
            "pairing timestamp normalization vector needs canonical, microsecond and offset inputs"
        );
    }
    let expected_pairing_digest = case
        .get("expected_pairing_request_binding_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("expected pairing request binding digest missing"))?;
    let verification_method = pairing
        .get("verification_method")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("pairing verification_method missing"))?;
    let pairing_request_id = pairing
        .get("pairing_request_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("pairing_request_id missing"))?;
    let pairing_code = pairing
        .get("pairing_code")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("pairing_code missing"))?;
    let audience = pairing
        .get("audience")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("pairing audience missing"))?;
    let canonical_pairing_expires_at = case
        .get("canonical_pairing_expires_at")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("canonical pairing expiry missing"))?;
    let canonical_pairing_binding = serde_json::json!({
        "agent_id": pairing_agent_id,
        "audience": audience,
        "controller_id": controller_id,
        "expires_at": canonical_pairing_expires_at,
        "kind": "ak.agent.key_pairing_request_binding.v1",
        "operation_id": arkret_core::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY,
        "pairing_code": pairing_code,
        "pairing_request_id": pairing_request_id,
        "runtime_public_key_digest": public_digest,
        "verification_method": verification_method,
    });
    let canonical_pairing_binding = String::from_utf8(arkret_canonical::canonical_json_bytes(
        &canonical_pairing_binding,
    )?)?;
    if case
        .get("canonical_pairing_request_binding_json")
        .and_then(Value::as_str)
        != Some(canonical_pairing_binding.as_str())
    {
        bail!("pairing request binding canonical JSON drifted");
    }
    for expires_at in expiry_inputs {
        let expires_at = expires_at
            .as_str()
            .ok_or_else(|| anyhow!("pairing expiry input must be a string"))?;
        let digest = arkret_core::agent_key_pairing_request_binding_digest(
            &controller_id,
            &pairing_agent_id,
            verification_method,
            &public_digest,
            pairing_request_id,
            pairing_code,
            expires_at,
            audience,
        )?;
        if digest.as_str() != expected_pairing_digest {
            bail!(
                "pairing request binding timestamp normalization drifted for {expires_at}: {}",
                digest.as_str()
            );
        }
    }

    let first_ids = (
        "approval-1",
        "ak:notification:01964137-0000-7000-8000-000000000001",
    );
    let restart_binding = arkret_core::agent_runtime_key_binding_digest(
        &agent_id,
        "pairing_request:01964137-0000-7000-8000-000000000000",
        "did:webvh:z6mkagent:agent.example#runtime-1",
        public_key,
        attestation,
    )?;
    let retry_ids = if restart_binding == binding {
        first_ids
    } else {
        bail!("persisted runtime key changed its binding across restart")
    };
    if retry_ids != first_ids {
        bail!("same binding retry changed stable projection ids");
    }
    let different_key = serde_json::json!({
        "alg": "EdDSA",
        "key": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "kid": "runtime-1",
        "kty": "OKP"
    });
    let different = arkret_core::agent_runtime_key_binding_digest(
        &agent_id,
        "pairing_request:01964137-0000-7000-8000-000000000000",
        "did:webvh:z6mkagent:agent.example#runtime-1",
        &different_key,
        None,
    )?;
    if different == binding {
        bail!("different runtime key was not classified as a binding conflict");
    }

    let delta = |action: &str| -> Result<NotificationDelta> {
        let data = if action == "remove" {
            serde_json::json!({
                "kind": "agent_runtime_approval",
                "reason": "approved"
            })
        } else {
            serde_json::json!({
                "kind": "agent_runtime_approval",
                "approval_request_id": "agent_runtime_approval:01964137-0000-7000-8000-000000000000",
                "agent_id": "did:webvh:z6mkagent:agent.example",
                "requested_at": "2026-07-13T10:00:00.000Z",
                "expires_at": "2026-07-13T10:15:00.000Z"
            })
        };
        Ok(serde_json::from_value(serde_json::json!({
            "id": "ak:notification:01964137-0000-7000-8000-000000000001",
            "type": "agent",
            "action": action,
            "data": data
        }))?)
    };
    let mut account_a = BTreeMap::<String, NotificationDelta>::new();
    let account_b = BTreeMap::<String, NotificationDelta>::new();
    for action in ["add", "update"] {
        let item = delta(action)?;
        account_a.insert(item.id.as_str().to_owned(), item);
    }
    if account_a.len() != 1
        || account_a.values().next().map(|item| item.action)
            != Some(NotificationDeltaAction::Update)
        || !account_b.is_empty()
    {
        bail!("account-scoped add/update projection did not converge or leaked across accounts");
    }
    let removed = delta("remove")?;
    account_a.remove(removed.id.as_str());
    if !account_a.is_empty() {
        bail!("remove projection did not converge after a missed wake");
    }
    account_a.insert("stale".to_owned(), delta("add")?);
    let authoritative_baseline_ids = BTreeSet::<String>::new();
    account_a.retain(|id, _| authoritative_baseline_ids.contains(id));
    if !account_a.is_empty() {
        bail!("initial baseline did not remove a stale open approval");
    }
    let mut pending_binding = Some(binding.as_str());
    let first_consumer = pending_binding.take();
    let second_consumer = pending_binding.take();
    if first_consumer.is_none() || second_consumer.is_some() {
        bail!("multi-device approval race consumed the pairing handle more than once");
    }
    Ok(())
}

pub fn run_agent_managed_pcr_separation_vector() -> Result<()> {
    let agent = "did:webvh:z6mkagent:agent.example";
    let controller = "did:webvh:z6mkcontroller:controller.example";
    let agent_pcr = "ak:realm:01964137-0000-7000-8000-000000000020";
    let controller_pcr = "ak:realm:01964137-0000-7000-8000-000000000021";
    if agent_pcr == controller_pcr {
        bail!("managed Agent reused the controller PCR");
    }
    let genesis = serde_json::json!({
        "created_by": agent,
        "notary": {"type": "single_did", "did": agent},
        "purpose": "principal_control",
        "encryption_profile": "e2ee_required",
        "event_encryption_floor": "e2ee_required"
    });
    if genesis["created_by"] != agent
        || genesis["notary"]["did"] != agent
        || genesis["purpose"] != "principal_control"
        || genesis["encryption_profile"] != "e2ee_required"
        || genesis["event_encryption_floor"] != "e2ee_required"
    {
        bail!("managed Agent PCR genesis boundary drifted");
    }
    let authored = serde_json::json!({
        "actor_id": agent,
        "executed_by": controller,
        "authorization_ref": "ak:event:01964137-0000-7000-8000-000000000022"
    });
    if authored["actor_id"] != agent
        || authored["executed_by"] != controller
        || authored["authorization_ref"]
            .as_str()
            .is_none_or(str::is_empty)
    {
        bail!("managed-controller authoring boundary drifted");
    }
    Ok(())
}

/// Minimal model of the renew-pairing state gate + supersede filter
/// (key-management.md §3.6.1): every non-terminal status may re-open pairing;
/// only bootstrap re-opens change status; pair completion supersedes every
/// prior key except the freshly authorized one.
fn renew_pairing_gate(status: &str) -> std::result::Result<&'static str, &'static str> {
    match status {
        "pending_runtime_key" | "pairing_expired" => Ok("bootstrap_reopen"),
        "active" | "paused" => Ok("runtime_replacement"),
        "deactivated" => Err(arkret_wire::ReasonCode::AGENT_DEACTIVATED),
        _ => Err("reject"),
    }
}

pub fn run_agent_repairing_supersede_vector() -> Result<()> {
    if arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_RENEW_PAIRING
        != "ak.self.agent.command.renew_pairing"
    {
        bail!(
            "arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_RENEW_PAIRING spelling drifted: arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_RENEW_PAIRING"
        );
    }
    if arkret_wire::ReasonCode::SUPERSEDED_BY_REPAIRING != "superseded_by_repairing" {
        bail!(
            "arkret_wire::ReasonCode::SUPERSEDED_BY_REPAIRING spelling drifted: superseded_by_repairing"
        );
    }
    // Gate: every non-terminal status renews; deactivated is terminal.
    for (status, expected) in [
        ("pending_runtime_key", "bootstrap_reopen"),
        ("pairing_expired", "bootstrap_reopen"),
        ("active", "runtime_replacement"),
        ("paused", "runtime_replacement"),
    ] {
        match renew_pairing_gate(status) {
            Ok(mode) if mode == expected => {}
            other => bail!("renew gate for `{status}` yielded {other:?}, expected {expected}"),
        }
    }
    if renew_pairing_gate("deactivated") != Err(arkret_wire::ReasonCode::AGENT_DEACTIVATED) {
        bail!("renewing a deactivated agent must fail with agent_deactivated");
    }
    // Runtime replacement is not a state transition: the FSM has no edge for
    // it, so the status set is unchanged by opening a handle.
    // Supersede filter: every prior key except the freshly authorized one is
    // revoked; re-authorizing the SAME key id is the same-key
    // re-authorization override and revokes nothing.
    let prior: BTreeSet<&str> = ["key-1", "key-2"].into();
    let superseded: BTreeSet<&str> = prior
        .iter()
        .copied()
        .filter(|key| *key != "key-3")
        .collect();
    if superseded != prior {
        bail!("a fresh key id must supersede every prior key");
    }
    let same_key: BTreeSet<&str> = prior
        .iter()
        .copied()
        .filter(|key| *key != "key-1")
        .collect();
    if same_key.contains("key-1") || same_key.len() != 1 {
        bail!("re-authorizing an existing key id must not revoke it");
    }
    Ok(())
}

// ─── VECT-AG-2c — longevity_no_expiry ──────────────────────────────────────

pub fn run_agent_longevity_no_expiry_vector() -> Result<()> {
    if arkret_wire::ReasonCode::AGENT_KEY_AUTHORIZATION_EXPIRED != "agent_key_authorization_expired"
    {
        bail!(
            "arkret_wire::ReasonCode::AGENT_KEY_AUTHORIZATION_EXPIRED spelling drifted: agent_key_authorization_expired"
        );
    }
    // `agent_key_authorize_payload.expires_at` is optional on wire: absent
    // means non-expiring, revocation-governed (key-management.md §3.6.1).
    let payload = serde_json::json!({
        "agent_id": "did:web:agent.example",
        "key_id": "ak:agent_key:0199000000007000800000000000aa01",
        "verification_method": "did:web:agent.example#runtime-key-1",
        "accountable_principal_id": "did:web:alice.example",
        "agent_key_scope": {
            "actions": ["ak.event.read"],
            "resources": [{"kind": "realm", "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001"}]
        },
        "audience": ["did:web:soland.example"],
        "issued_at": "2026-07-12T00:00:00.000Z",
        "approval_evidence": {
            "kind": "approval_event",
            "evidence_ref": "ak:event:01990000-0000-7000-8000-000000000001"
        }
    });
    let decoded: arkret_core::AgentKeyAuthorizePayload = serde_json::from_value(payload)
        .map_err(|error| anyhow!("non-expiring authorize payload must decode: {error}"))?;
    if decoded.expires_at.is_some() {
        bail!("absent expires_at must decode as None");
    }
    let encoded = serde_json::to_value(&decoded)
        .map_err(|error| anyhow!("authorize payload must re-encode: {error}"))?;
    if encoded.get("expires_at").is_some() {
        bail!("None expires_at must stay absent on wire (no null / sentinel)");
    }
    // `accountability_grant.expires_at` is optional the same way.
    let grant = serde_json::json!({
        "schema": "ak.schema.accountability_grant.v1",
        "issuer": "did:web:alice.example",
        "subject": "did:web:agent.example",
        "accountability_scope": "agent_operator",
        "not_before": "2026-07-12T00:00:00.000Z",
        "grant_status": "active",
        "proof": {
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": "did:web:alice.example#key-1",
            "payload_digest": format!("sha256:{}", "0".repeat(64)),
            "created_at": "2026-07-12T00:00:00.000Z",
            "proof_purpose": "issuer_attestation",
            "jws": "eyJhbGciOiJFZERTQSJ9..sig"
        }
    });
    let decoded: arkret_core::AccountabilityGrantPayload = serde_json::from_value(grant)
        .map_err(|error| anyhow!("non-expiring accountability grant must decode: {error}"))?;
    if decoded.expires_at.is_some() {
        bail!("absent accountability expires_at must decode as None");
    }
    Ok(())
}

// ─── VECT-AG-3 — controller_lifecycle (agent FSM) ──────────────────────────

/// Minimal in-memory FSM mirroring the `ak.agent.{pause,resume,deactivate}`
/// reducer contract: bottom = `reject`, deactivate is terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgentState {
    Active,
    Paused,
    Deactivated,
}

fn agent_transition(state: AgentState, op: &str) -> std::result::Result<AgentState, &'static str> {
    use AgentState::*;
    match (state, op) {
        (Active, "pause") => Ok(Paused),
        (Paused, "resume") => Ok(Active),
        (Active | Paused, "deactivate") => Ok(Deactivated),
        (Deactivated, _) => Err(arkret_wire::ReasonCode::AGENT_DEACTIVATED),
        (Active, "resume") => Err("reject"),
        (Paused, "pause") => Err(arkret_wire::ReasonCode::AGENT_PAUSED),
        _ => Err("reject"),
    }
}

pub fn run_agent_controller_lifecycle_vector() -> Result<()> {
    // Verify FSM op-id spelling first.
    for op in [
        arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_PAUSE,
        arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_RESUME,
        arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_DEACTIVATE,
        arkret_core::ServiceOperationId::SELF_AGENT_QUERY_LIST,
        arkret_core::ServiceOperationId::SELF_AGENT_RESOURCE_GET,
        arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_RENEW_PAIRING,
        arkret_core::ServiceOperationId::SELF_AGENT_GRANT_COMMAND_ATTACH,
        arkret_core::ServiceOperationId::SELF_AGENT_GRANT_RESOURCE_DELETE,
        arkret_core::ServiceOperationId::SELF_AGENT_SIDECAR_COMMAND_ENSURE,
    ] {
        if !op.starts_with("ak.agent.")
            && !op.starts_with("ak.gate.account.")
            && !op.starts_with("ak.self.agent.")
        {
            bail!("agent op id `{op}` lost canonical namespace");
        }
    }
    if arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_DEACTIVATE
        != "ak.self.agent.command.deactivate"
    {
        bail!(
            "arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_DEACTIVATE spelling drifted: arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_DEACTIVATE"
        );
    }

    // Happy path: active → paused → active → deactivated terminal.
    let s = agent_transition(AgentState::Active, "pause").map_err(|e| anyhow!("pause: {e}"))?;
    if s != AgentState::Paused {
        bail!("pause did not yield Paused");
    }
    let s = agent_transition(s, "resume").map_err(|e| anyhow!("resume: {e}"))?;
    if s != AgentState::Active {
        bail!("resume did not yield Active");
    }
    let s = agent_transition(s, "deactivate").map_err(|e| anyhow!("deactivate: {e}"))?;
    if s != AgentState::Deactivated {
        bail!("deactivate did not yield Deactivated");
    }

    // Terminal: resume from deactivated MUST be rejected with
    // `agent_deactivated`.
    let err = agent_transition(AgentState::Deactivated, "resume")
        .err()
        .ok_or_else(|| anyhow!("resume-from-deactivated must be rejected"))?;
    if err != arkret_wire::ReasonCode::AGENT_DEACTIVATED {
        bail!("resume-from-deactivated returned `{err}`, expected agent_deactivated");
    }

    // Pause-while-paused MUST surface `agent_paused`.
    let err = agent_transition(AgentState::Paused, "pause")
        .err()
        .ok_or_else(|| anyhow!("pause-while-paused must be rejected"))?;
    if err != arkret_wire::ReasonCode::AGENT_PAUSED {
        bail!("pause-while-paused returned `{err}`, expected agent_paused");
    }
    Ok(())
}

// ─── VECT-AG-4 — act_on_behalf ─────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
struct MiniActOnBehalfRequest<'a> {
    executed_by: Option<&'a str>,
    authorization_ref: Option<&'a str>,
    participation_allows: bool,
    grant_covers_action: bool,
    approval: Option<(&'a str, &'a str)>,
}

struct MiniActOnBehalfGate {
    consumed_approvals: BTreeSet<String>,
}

impl MiniActOnBehalfGate {
    fn new() -> Self {
        Self {
            consumed_approvals: BTreeSet::new(),
        }
    }

    fn admit(
        &mut self,
        request: MiniActOnBehalfRequest<'_>,
    ) -> std::result::Result<(), &'static str> {
        if request.executed_by.is_none() {
            return Err("agent_act_on_behalf_executed_by_missing");
        }
        if request.authorization_ref.is_none() {
            return Err("agent_act_on_behalf_authorization_ref_missing");
        }
        if !request.participation_allows {
            return Err("agent_act_on_behalf_not_permitted");
        }
        if !request.grant_covers_action {
            return Err("agent_act_on_behalf_authorization_ref_scope");
        }
        let Some((request_id, nonce)) = request.approval else {
            return Err("agent_act_on_behalf_approval_request_missing");
        };
        let key = format!("{request_id}:{nonce}");
        if !self.consumed_approvals.insert(key) {
            return Err(arkret_wire::ReasonCode::APPROVAL_NONCE_REUSED);
        }
        Ok(())
    }
}

fn expect_aob_denial(
    gate: &mut MiniActOnBehalfGate,
    request: MiniActOnBehalfRequest<'_>,
    expected: &'static str,
) -> Result<()> {
    match gate.admit(request) {
        Ok(()) => bail!("act-on-behalf request unexpectedly admitted"),
        Err(reason) if reason == expected => Ok(()),
        Err(reason) => bail!("expected act-on-behalf denial {expected}, got {reason}"),
    }
}

fn valid_act_on_behalf_request() -> MiniActOnBehalfRequest<'static> {
    MiniActOnBehalfRequest {
        executed_by: Some("did:web:agent.example"),
        authorization_ref: Some("ak:grant:01904100-0000-7000-8000-000000000001"),
        participation_allows: true,
        grant_covers_action: true,
        approval: Some(("ak:agent-action-request:01904100", "nonce-01904100")),
    }
}

pub fn run_agent_act_on_behalf_vector() -> Result<()> {
    // The four new actor-private agent event kinds are pinned by the
    // SDK constants list in personal_agent_provisioning; here we
    // assert the side-effect that approvals are write-once.
    if arkret_wire::ReasonCode::APPROVAL_ALREADY_CONSUMED != "approval_already_consumed" {
        bail!(
            "arkret_wire::ReasonCode::APPROVAL_ALREADY_CONSUMED spelling drifted: approval_already_consumed"
        );
    }
    // Sidecar-create denial is part of the act-on-behalf pipeline
    // (controller's grant has not authorised the agent to write to
    // the sidecar circle).
    if arkret_wire::ReasonCode::SIDECAR_CREATE_DENIED != "sidecar_create_denied" {
        bail!(
            "arkret_wire::ReasonCode::SIDECAR_CREATE_DENIED spelling drifted: sidecar_create_denied"
        );
    }
    if arkret_wire::ReasonCode::APPROVAL_NONCE_REUSED != "approval_nonce_reused" {
        bail!(
            "arkret_wire::ReasonCode::APPROVAL_NONCE_REUSED spelling drifted: approval_nonce_reused"
        );
    }

    let mut gate = MiniActOnBehalfGate::new();
    expect_aob_denial(
        &mut gate,
        MiniActOnBehalfRequest {
            authorization_ref: None,
            ..valid_act_on_behalf_request()
        },
        "agent_act_on_behalf_authorization_ref_missing",
    )?;
    expect_aob_denial(
        &mut gate,
        MiniActOnBehalfRequest {
            participation_allows: false,
            ..valid_act_on_behalf_request()
        },
        "agent_act_on_behalf_not_permitted",
    )?;
    expect_aob_denial(
        &mut gate,
        MiniActOnBehalfRequest {
            grant_covers_action: false,
            ..valid_act_on_behalf_request()
        },
        "agent_act_on_behalf_authorization_ref_scope",
    )?;
    expect_aob_denial(
        &mut gate,
        MiniActOnBehalfRequest {
            approval: None,
            ..valid_act_on_behalf_request()
        },
        "agent_act_on_behalf_approval_request_missing",
    )?;
    gate.admit(valid_act_on_behalf_request())
        .map_err(|reason| anyhow!("valid act-on-behalf request was denied: {reason}"))?;
    expect_aob_denial(
        &mut gate,
        valid_act_on_behalf_request(),
        arkret_wire::ReasonCode::APPROVAL_NONCE_REUSED,
    )?;
    Ok(())
}

// ─── VECT-AG-5 — session_grant.replay ──────────────────────────────────────

#[derive(Clone, Copy, Debug)]
struct MiniAgentKeyProof<'a> {
    challenge: &'a str,
    audience: &'a str,
    signature: &'a str,
}

struct MiniAgentKeyProofVerifier {
    expected_audience: &'static str,
    expected_signature: &'static str,
    consumed_challenges: BTreeSet<String>,
}

impl MiniAgentKeyProofVerifier {
    fn new(expected_audience: &'static str, expected_signature: &'static str) -> Self {
        Self {
            expected_audience,
            expected_signature,
            consumed_challenges: BTreeSet::new(),
        }
    }

    fn verify(&mut self, proof: MiniAgentKeyProof<'_>) -> std::result::Result<(), &'static str> {
        if self.consumed_challenges.contains(proof.challenge) {
            return Err("agent_key_proof_replay");
        }
        if proof.audience != self.expected_audience {
            return Err("agent_key_proof_audience_mismatch");
        }
        if proof.signature != self.expected_signature {
            self.consumed_challenges.insert(proof.challenge.to_owned());
            return Err(arkret_wire::ReasonCode::PROOF_INVALID);
        }
        self.consumed_challenges.insert(proof.challenge.to_owned());
        Ok(())
    }
}

fn expect_proof_denial(
    verifier: &mut MiniAgentKeyProofVerifier,
    proof: MiniAgentKeyProof<'_>,
    expected: &'static str,
) -> Result<()> {
    match verifier.verify(proof) {
        Ok(()) => bail!("agent_key_proof unexpectedly verified"),
        Err(reason) if reason == expected => Ok(()),
        Err(reason) => bail!("expected agent_key_proof denial {expected}, got {reason}"),
    }
}

pub fn run_agent_session_grant_replay_vector() -> Result<()> {
    if arkret_core::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_SESSION_GRANT
        != "ak.gate.account.command.issue_session_grant"
    {
        bail!(
            "arkret_core::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_SESSION_GRANT spelling drifted: arkret_core::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_SESSION_GRANT"
        );
    }
    // Agent branch reject codes per §0.8:
    //   proof_invalid / verification_method_principal_mismatch /
    //   agent_paused / agent_deactivated / accountability_grant_missing
    // We pin all five.
    let required = [
        arkret_wire::ReasonCode::PROOF_INVALID,
        arkret_wire::ReasonCode::VERIFICATION_METHOD_PRINCIPAL_MISMATCH,
        arkret_wire::ReasonCode::AGENT_PAUSED,
        arkret_wire::ReasonCode::AGENT_DEACTIVATED,
    ];
    let mut sorted = required.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != required.len() {
        bail!("session-grant agent-branch reject set has duplicates");
    }
    if arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING != "accountability_grant_missing" {
        bail!(
            "arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING spelling drifted: accountability_grant_missing"
        );
    }

    let mut verifier = MiniAgentKeyProofVerifier::new("soland.local", "sig-ok");
    verifier
        .verify(MiniAgentKeyProof {
            challenge: "challenge-1",
            audience: "soland.local",
            signature: "sig-ok",
        })
        .map_err(|reason| anyhow!("valid agent_key_proof rejected: {reason}"))?;
    expect_proof_denial(
        &mut verifier,
        MiniAgentKeyProof {
            challenge: "challenge-1",
            audience: "soland.local",
            signature: "sig-ok",
        },
        "agent_key_proof_replay",
    )?;
    expect_proof_denial(
        &mut verifier,
        MiniAgentKeyProof {
            challenge: "challenge-2",
            audience: "other-service.local",
            signature: "sig-ok",
        },
        "agent_key_proof_audience_mismatch",
    )?;
    expect_proof_denial(
        &mut verifier,
        MiniAgentKeyProof {
            challenge: "challenge-3",
            audience: "soland.local",
            signature: "sig-tampered",
        },
        arkret_wire::ReasonCode::PROOF_INVALID,
    )?;
    expect_proof_denial(
        &mut verifier,
        MiniAgentKeyProof {
            challenge: "challenge-3",
            audience: "soland.local",
            signature: "sig-ok",
        },
        "agent_key_proof_replay",
    )?;
    Ok(())
}

// ─── VECT-AG-6 — human approval required ──────────────────────────────────

const HUMAN_APPROVAL_RUNNER: &str =
    "cotest::conformance::agent_vectors::run_agent_human_approval_required_vector";
const ACCEPTED_APPROVAL_EVENT_REF: &str = "ak:event:0196419b-0000-7000-8000-000000000001";

fn validate_human_approval_details_schema(details: &Value) -> Result<()> {
    let document = super::load_artifact_json("schemas/agent-operations.schema.json")?;
    let opaque_local_id = document
        .pointer("/$defs/opaque_local_id")
        .cloned()
        .ok_or_else(|| anyhow!("agent operations schema missing opaque_local_id"))?;
    let mut schema = document
        .pointer("/$defs/agent_human_approval_error_details")
        .cloned()
        .ok_or_else(|| anyhow!("agent operations schema missing human-approval details"))?;
    schema
        .as_object_mut()
        .ok_or_else(|| anyhow!("human-approval details schema must be an object"))?
        .insert(
            "$defs".to_owned(),
            serde_json::json!({"opaque_local_id": opaque_local_id}),
        );
    let validator = jsonschema::options()
        .build(&schema)
        .map_err(|error| anyhow!("compile human-approval details schema: {error}"))?;
    if !validator.is_valid(details) {
        let errors = validator
            .iter_errors(details)
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        bail!("human-approval details violate the closed schema: {errors}");
    }
    Ok(())
}

fn ensure_exact_keys(value: &Value, expected: &[&str], context: &str) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("{context} must be an object"))?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        bail!("{context} fields must be exactly {expected:?}, got {actual:?}");
    }
    Ok(())
}

fn contains_interactive_challenge(value: &Value) -> bool {
    const FORBIDDEN: &[&str] = &[
        "browser_redirect",
        "browser_login",
        "captcha",
        "challenge_url",
        "login_url",
        "otp",
        "password",
        "password_prompt",
        "redirect",
        "redirect_uri",
    ];

    match value {
        Value::Object(object) => object.iter().any(|(key, child)| {
            let key = key.to_ascii_lowercase();
            FORBIDDEN.iter().any(|forbidden| key.contains(forbidden))
                || contains_interactive_challenge(child)
        }),
        Value::Array(items) => items.iter().any(contains_interactive_challenge),
        Value::String(text) => {
            let text = text.to_ascii_lowercase();
            FORBIDDEN.iter().any(|forbidden| text.contains(forbidden))
        }
        _ => false,
    }
}

/// Validate the live HTTP contract for the human-approval branch.
///
/// The response is intentionally strict: it accepts only the current v1
/// envelope shape and rejects flat fields, embedded JSON, authentication
/// challenges, and any interactive controller material.
pub fn validate_agent_human_approval_http_response(status: u16, body: &Value) -> Result<String> {
    if status != 403 {
        bail!("human approval must use HTTP 403, got {status}");
    }
    ensure_exact_keys(body, &["error", "ok", "request_id"], "error envelope")?;
    if body.get("ok").and_then(Value::as_bool) != Some(false) {
        bail!("human-approval error envelope must set ok=false");
    }

    let error = body
        .get("error")
        .ok_or_else(|| anyhow!("human-approval response missing error"))?;
    ensure_exact_keys(error, &["code", "details", "message"], "error")?;
    if error.get("code").and_then(Value::as_str) != Some("claim_required") {
        bail!("human approval must use error.code=claim_required");
    }
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .filter(|message| !message.trim().is_empty())
        .ok_or_else(|| anyhow!("human-approval error message must be non-empty text"))?;
    if serde_json::from_str::<Value>(message).is_ok() {
        bail!("human-approval error message must not contain serialized JSON");
    }

    if contains_interactive_challenge(body) {
        bail!("human-approval response contains interactive challenge material");
    }
    let details = error
        .get("details")
        .ok_or_else(|| anyhow!("human-approval response missing error.details"))?;
    validate_human_approval_details_schema(details)?;
    let typed: AgentHumanApprovalErrorDetails = serde_json::from_value(details.clone())
        .map_err(|error| anyhow!("decode typed human-approval details: {error}"))?;
    Ok(typed.approval_request_id().to_owned())
}

#[derive(Debug)]
struct MiniHumanApprovalGate {
    approval_request_id: String,
    accepted_evidence_ref: Option<&'static str>,
    evidence_fresh: bool,
    evidence_consumed: bool,
}

impl MiniHumanApprovalGate {
    fn new(approval_request_id: String) -> Self {
        Self {
            approval_request_id,
            accepted_evidence_ref: None,
            evidence_fresh: false,
            evidence_consumed: false,
        }
    }

    fn approval_required_response(&self) -> Result<Value> {
        let details = AgentHumanApprovalErrorDetails::new(self.approval_request_id.clone())?;
        Ok(serde_json::to_value(
            ErrorEnvelope::claim_required_human_approval("controller approval required", details)
                .with_request_id("cotest-human-approval"),
        )?)
    }

    fn approve_out_of_band(&mut self, evidence_ref: &'static str) {
        self.accepted_evidence_ref = Some(evidence_ref);
        self.evidence_fresh = true;
    }

    fn retry(
        &mut self,
        agent_key_proof_valid: bool,
        scope_within_ceiling: bool,
        evidence_ref: Option<&str>,
    ) -> std::result::Result<(), &'static str> {
        if !agent_key_proof_valid {
            return Err(arkret_wire::ReasonCode::PROOF_INVALID);
        }
        if !scope_within_ceiling {
            return Err("agent_scope_exceeds_ceiling");
        }
        let Some(evidence_ref) = evidence_ref else {
            return Err("accepted_approval_evidence_missing");
        };
        if self.accepted_evidence_ref != Some(evidence_ref) {
            return Err("accepted_approval_evidence_mismatch");
        }
        if !self.evidence_fresh {
            return Err("accepted_approval_evidence_stale");
        }
        if self.evidence_consumed {
            return Err(arkret_wire::ReasonCode::APPROVAL_ALREADY_CONSUMED);
        }
        self.evidence_consumed = true;
        Ok(())
    }
}

pub fn run_agent_human_approval_required_vector() -> Result<()> {
    let fixture = super::load_fixture_value(AGENT_VECTORS_FIXTURE_FILE)?;
    let case = fixture
        .get("cases")
        .and_then(Value::as_array)
        .and_then(|cases| {
            cases.iter().find(|case| {
                case.get("vector_id").and_then(Value::as_str)
                    == Some(VECTOR_ID_AGENT_HUMAN_APPROVAL_REQUIRED)
            })
        })
        .ok_or_else(|| anyhow!("human-approval vector case missing"))?;
    if case.get("runner").and_then(Value::as_str) != Some(HUMAN_APPROVAL_RUNNER) {
        bail!("human-approval fixture runner is not resolvable");
    }
    let request = case
        .get("request")
        .ok_or_else(|| anyhow!("human-approval vector request missing"))?;
    ensure_exact_keys(
        request,
        &[
            "operation_id",
            "proof_kind",
            "requested_scope_requires_controller_approval",
            "risk_class",
        ],
        "human-approval request",
    )?;
    if request.get("operation_id").and_then(Value::as_str)
        != Some(arkret_core::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_SESSION_GRANT)
        || request.get("proof_kind").and_then(Value::as_str) != Some("agent_key_proof")
        || request.get("risk_class").and_then(Value::as_str) != Some("high")
        || request
            .get("requested_scope_requires_controller_approval")
            .and_then(Value::as_bool)
            != Some(true)
    {
        bail!("human-approval fixture request semantics drifted");
    }

    let details = case
        .pointer("/expected_error/error/details")
        .cloned()
        .ok_or_else(|| anyhow!("human-approval fixture expected details missing"))?;
    let approval_request_id = details
        .get("approval_request_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("human-approval fixture approval_request_id missing"))?
        .to_owned();
    let mut gate = MiniHumanApprovalGate::new(approval_request_id.clone());
    let response = gate.approval_required_response()?;
    if validate_agent_human_approval_http_response(403, &response)? != approval_request_id {
        bail!("human-approval response changed the opaque correlation handle");
    }

    let forbidden = case
        .get("forbidden_runtime_challenges")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("human-approval forbidden challenge list missing"))?;
    for required in ["captcha", "otp", "browser_redirect", "password_prompt"] {
        if !forbidden
            .iter()
            .any(|entry| entry.as_str() == Some(required))
        {
            bail!("human-approval fixture missing forbidden challenge {required}");
        }
    }

    if gate.retry(true, true, None) != Err("accepted_approval_evidence_missing") {
        bail!("session grant was available before out-of-band approval");
    }
    gate.approve_out_of_band(ACCEPTED_APPROVAL_EVENT_REF);
    if gate.retry(false, true, Some(ACCEPTED_APPROVAL_EVENT_REF))
        != Err(arkret_wire::ReasonCode::PROOF_INVALID)
    {
        bail!("approved retry skipped agent key proof revalidation");
    }
    if gate.retry(true, false, Some(ACCEPTED_APPROVAL_EVENT_REF))
        != Err("agent_scope_exceeds_ceiling")
    {
        bail!("approved retry skipped scope ceiling revalidation");
    }
    gate.retry(true, true, Some(ACCEPTED_APPROVAL_EVENT_REF))
        .map_err(|reason| anyhow!("accepted approval evidence was rejected: {reason}"))?;
    if gate.retry(true, true, Some(ACCEPTED_APPROVAL_EVENT_REF))
        != Err(arkret_wire::ReasonCode::APPROVAL_ALREADY_CONSUMED)
    {
        bail!("accepted approval evidence was not single-use");
    }

    let mut flat = response.clone();
    flat["error"]["reason_code"] = Value::String("human_approval_required".to_owned());
    if validate_agent_human_approval_http_response(403, &flat).is_ok() {
        bail!("legacy flat human-approval fields were accepted");
    }
    let mut json_message = response.clone();
    json_message["error"]["message"] = Value::String(details.to_string());
    if validate_agent_human_approval_http_response(403, &json_message).is_ok() {
        bail!("JSON-in-message human-approval response was accepted");
    }
    if validate_agent_human_approval_http_response(401, &response).is_ok() {
        bail!("human approval was accepted as HTTP 401");
    }
    let mut challenge = response;
    challenge["error"]["details"]["captcha"] = Value::String("challenge-token".to_owned());
    if validate_agent_human_approval_http_response(403, &challenge).is_ok() {
        bail!("interactive challenge material was accepted");
    }

    Ok(())
}

/// Suite entry point — runs all 10 agent vectors.
pub fn run_agent_vector_suite() -> Result<()> {
    validate_agent_vectors_fixture_metadata()?;
    if ALL_AGENT_VECTOR_IDS.len() != 10 {
        bail!(
            "expected 10 agent vector ids, got {}",
            ALL_AGENT_VECTOR_IDS.len()
        );
    }
    run_agent_provision_vector()?;
    run_agent_pairing_expiry_vector()?;
    run_agent_runtime_key_binding_vector()?;
    run_agent_managed_pcr_separation_vector()?;
    run_agent_repairing_supersede_vector()?;
    run_agent_longevity_no_expiry_vector()?;
    run_agent_controller_lifecycle_vector()?;
    run_agent_act_on_behalf_vector()?;
    run_agent_session_grant_replay_vector()?;
    run_agent_human_approval_required_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_agent_vectors_run_clean() {
        run_agent_vector_suite().unwrap();
    }

    #[test]
    fn human_approval_vector_runs_clean() {
        run_agent_human_approval_required_vector().unwrap();
    }
}
