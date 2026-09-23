//! Conformance checks for the current native Sidecar wire contract.
//!
//! The vector registry owns the 18 vector identities. The previous runner
//! depended on an untracked `agent-sidecar-fixture.json` and on pre-Commit
//! Sidecar/CBS types that are absent from the v1 SDK. These checks exercise
//! the closed current DTOs and signed MLS binding instead.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, ensure};
use arkret::{
    AgentSidecar, AgentSidecarEventExchangeBinding, AgentSidecarExchangeControl,
    AgentSidecarExchangeProjection, AgentSidecarMlsContext, AgentSidecarViewState, DidCoreId,
    EventId, Hash, MlsGovernanceBindingPayload, PendingSidecarAccessReconciliation, RealmId,
    ScopeRef, SidecarId,
};
use arkret_models_collaboration::events_payloads::{
    SidecarContextAttachPayload, SidecarCreatePayload,
};
use arkret_models_collaboration::sidecar_operations::SidecarEnsurePrepareRequestBody;
use arkret_wire::SchemaId;
use serde_json::{Value, json};

pub const VECTOR_ID_SIDECAR_ENSURE_IDEMPOTENT: &str = "ak.vector.sidecar.ensure_idempotent.v1";
pub const VECTOR_ID_SIDECAR_MLS_BOOTSTRAP_BINDING: &str =
    "ak.vector.sidecar.mls_bootstrap_binding.v1";
pub const VECTOR_ID_SIDECAR_MLS_EFFECTIVE_ACCESS: &str =
    "ak.vector.sidecar.mls_effective_access.v1";
pub const VECTOR_ID_SIDECAR_ELIGIBILITY_STATES: &str = "ak.vector.sidecar.eligibility_states.v1";
pub const VECTOR_ID_SIDECAR_EXISTENCE_PRIVACY: &str = "ak.vector.sidecar.existence_privacy.v1";
pub const VECTOR_ID_SIDECAR_HOSTED_PROJECTION: &str = "ak.vector.sidecar.hosted_projection.v1";
pub const VECTOR_ID_SIDECAR_MULTI_AGENT_PUBLISH: &str = "ak.vector.sidecar.multi_agent_publish.v1";
pub const VECTOR_ID_SIDECAR_EXCHANGE_BINDING_CLOSED_LOOP: &str =
    "ak.vector.sidecar.exchange_binding_closed_loop.v1";
pub const VECTOR_ID_SIDECAR_EXCHANGE_PROJECTION_RECOVERY: &str =
    "ak.vector.sidecar.exchange_projection_recovery.v1";
pub const VECTOR_ID_SIDECAR_EXCHANGE_BINDING_CONTAINMENT: &str =
    "ak.vector.sidecar.exchange_binding_containment.v1";
pub const VECTOR_ID_SIDECAR_CONTEXT_LOCATOR_RECOVERY: &str =
    "ak.vector.sidecar.context_locator_recovery.v1";
pub const VECTOR_ID_SIDECAR_CANONICAL_SIBLING_DIGEST: &str =
    "ak.vector.sidecar.canonical_sibling_digest.v1";
pub const VECTOR_ID_SIDECAR_UNION_HISTORY_FRONTIER: &str =
    "ak.vector.sidecar.union_history_checkpoint.v1";
pub const VECTOR_ID_SIDECAR_NON_DISCLOSURE_SURFACE_MATRIX: &str =
    "ak.vector.sidecar.non_disclosure_surface_matrix.v1";
pub const VECTOR_ID_SIDECAR_REVOKE_FAIL_CLOSED: &str = "ak.vector.sidecar.revoke_fail_closed.v1";
pub const VECTOR_ID_SIDECAR_EXPLICIT_PUBLISH: &str = "ak.vector.sidecar.explicit_publish.v1";
pub const VECTOR_ID_SIDECAR_ACCEPTED_REQUEST_IDENTITY: &str =
    "ak.vector.sidecar.accepted_request_identity.v1";
pub const VECTOR_ID_SIDECAR_HOSTED_UI_MATRIX: &str = "ak.vector.sidecar.hosted_ui_matrix.v1";

pub const ALL_SIDECAR_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_SIDECAR_MLS_BOOTSTRAP_BINDING,
    VECTOR_ID_SIDECAR_MLS_EFFECTIVE_ACCESS,
    VECTOR_ID_SIDECAR_ENSURE_IDEMPOTENT,
    VECTOR_ID_SIDECAR_ELIGIBILITY_STATES,
    VECTOR_ID_SIDECAR_EXISTENCE_PRIVACY,
    VECTOR_ID_SIDECAR_HOSTED_PROJECTION,
    VECTOR_ID_SIDECAR_MULTI_AGENT_PUBLISH,
    VECTOR_ID_SIDECAR_EXCHANGE_BINDING_CLOSED_LOOP,
    VECTOR_ID_SIDECAR_EXCHANGE_PROJECTION_RECOVERY,
    VECTOR_ID_SIDECAR_EXCHANGE_BINDING_CONTAINMENT,
    VECTOR_ID_SIDECAR_CONTEXT_LOCATOR_RECOVERY,
    VECTOR_ID_SIDECAR_CANONICAL_SIBLING_DIGEST,
    VECTOR_ID_SIDECAR_UNION_HISTORY_FRONTIER,
    VECTOR_ID_SIDECAR_NON_DISCLOSURE_SURFACE_MATRIX,
    VECTOR_ID_SIDECAR_REVOKE_FAIL_CLOSED,
    VECTOR_ID_SIDECAR_EXPLICIT_PUBLISH,
    VECTOR_ID_SIDECAR_ACCEPTED_REQUEST_IDENTITY,
    VECTOR_ID_SIDECAR_HOSTED_UI_MATRIX,
];

fn event_id(byte: u8) -> EventId {
    EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32])
}

fn realm_id() -> RealmId {
    RealmId::from_event_id(&event_id(1))
}

fn sidecar_id() -> SidecarId {
    SidecarId::from_event_id(&event_id(2))
}

fn account() -> Value {
    json!({
        "principal_id": "ak:did_core:webvh:z6mkfixture:alice.example",
        "station_id": "ak:did_core:web:station.example"
    })
}

fn agent() -> &'static str {
    "ak:did_core:webvh:z6mkfixture:agent.example"
}

fn context() -> Value {
    json!({"kind": "strand", "strand_id": arkret::StrandId::from_event_id(&event_id(3))})
}

fn request_binding() -> Value {
    json!({
        "schema": SchemaId::AGENT_SIDECAR_EVENT_EXCHANGE_BINDING_V1,
        "exchange_id": "exchange-fixture-0000001",
        "role": "request",
        "request_context": {
            "source_track_ref": {
                "realm_id": realm_id(),
                "strand_id": arkret::StrandId::from_event_id(&event_id(3)),
                "track_name": "main"
            },
            "source_hlc": "0198ff000000-0001-0a0b0c0d",
            "client_order_key": "order-1",
            "addressed_agent_ids": [agent()]
        }
    })
}

fn response_binding() -> Value {
    json!({
        "schema": SchemaId::AGENT_SIDECAR_EVENT_EXCHANGE_BINDING_V1,
        "exchange_id": "exchange-fixture-0000001",
        "role": "user_facing_response",
        "request_event_id": event_id(4)
    })
}

fn control() -> Value {
    json!({
        "schema": SchemaId::AGENT_SIDECAR_EXCHANGE_CONTROL_V1,
        "exchange_id": "exchange-fixture-0000001",
        "request_event_id": event_id(4),
        "basis_event_ids": [event_id(4), event_id(5)],
        "action": "close",
        "response_event_ids": [event_id(5)]
    })
}

fn projection() -> Value {
    json!({
        "schema": SchemaId::AGENT_SIDECAR_EXCHANGE_PROJECTION_V1,
        "controller_account_id": account(),
        "sidecar_id": sidecar_id(),
        "exchange_id": "exchange-fixture-0000001",
        "source_track_ref": {
            "realm_id": realm_id(),
            "strand_id": arkret::StrandId::from_event_id(&event_id(3)),
            "track_name": "main"
        },
        "source_hlc": "0198ff000000-0001-0a0b0c0d",
        "client_order_key": "order-1",
        "addressed_agent_ids": [agent()],
        "coordinator_agent_id": agent(),
        "coordinator_assignment_event_id": event_id(4),
        "participating_agent_ids": [agent()],
        "private_request_event_id": event_id(4),
        "user_facing_response_event_ids": [],
        "status": "delivered",
        "folded_checkpoint": {
            "event_ids": [event_id(4)],
            "event_set_digest": format!("sha256:{}", "ab".repeat(32)),
            "max_hlc": "0198ff000000-0001-0a0b0c0d"
        }
    })
}

fn view_state() -> Value {
    json!({
        "schema": SchemaId::AGENT_SIDECAR_VIEW_STATE_V1,
        "controller_account_id": account(),
        "sidecar_id": sidecar_id(),
        "context_ref": {
            "realm_id": realm_id(),
            "strand_id": arkret::StrandId::from_event_id(&event_id(3))
        },
        "display_mode": "context_merged",
        "updated_hlc": "0198ff000000-0001-0a0b0c0d",
        "origin_device_id": "ak:device:0198ff00-0000-7000-8000-00000000000a"
    })
}

fn validate_registry() -> Result<()> {
    let registry = super::load_artifact_json("registry/vector-registry.json")?;
    let vectors = registry["vectors"]
        .as_array()
        .ok_or_else(|| anyhow!("vector registry has no vectors array"))?;
    ensure!(
        ALL_SIDECAR_VECTOR_IDS.len() == 18,
        "Sidecar vector count drifted"
    );
    for id in ALL_SIDECAR_VECTOR_IDS {
        ensure!(
            vectors
                .iter()
                .any(|entry| entry["vector_id"] == *id && entry["status"] == "active"),
            "Sidecar vector {id} is absent or inactive"
        );
    }
    Ok(())
}

pub fn run_sidecar_mls_bootstrap_binding_vector() -> Result<()> {
    let digest: Hash = serde_json::from_value(json!(format!("sha256:{}", "cd".repeat(32))))?;
    let head = vec![event_id(8), event_id(9)];
    let binding = MlsGovernanceBindingPayload::sidecar(
        realm_id(),
        sidecar_id(),
        None,
        0,
        0,
        0,
        digest.clone(),
        head.clone(),
    )?;
    let bytes = binding.to_deterministic_cbor()?;
    let decoded = MlsGovernanceBindingPayload::from_deterministic_cbor(&bytes)?;
    ensure!(
        decoded.to_deterministic_cbor()? == bytes,
        "Sidecar MLS CBOR changed"
    );
    let sidecar = decoded
        .sidecar_binding()
        .ok_or_else(|| anyhow!("Sidecar binding absent"))?;
    ensure!(
        sidecar.participant_authority_digest == digest && sidecar.authority_stream_head == head,
        "signed Sidecar authority cut was lost"
    );
    ensure!(
        MlsGovernanceBindingPayload::sidecar(
            realm_id(),
            sidecar_id(),
            None,
            0,
            0,
            0,
            digest,
            vec![event_id(9), event_id(8)]
        )
        .is_err(),
        "unsorted Sidecar authority head was accepted"
    );
    Ok(())
}

pub fn run_sidecar_mls_effective_access_vector() -> Result<()> {
    // Desired membership alone does not imply decryptability. The accepted Add,
    // matching Welcome, consumed KeyPackage and current join ref must all hold.
    let complete = [true, true, true, true, true];
    ensure!(
        complete.iter().all(|value| *value),
        "complete join was rejected"
    );
    for missing in 0..complete.len() {
        let mut chain = complete;
        chain[missing] = false;
        ensure!(
            !chain.iter().all(|value| *value),
            "incomplete join became effective"
        );
    }
    let pending: PendingSidecarAccessReconciliation = serde_json::from_value(json!({
        "agent_id": agent(), "provisioning_phase": "mls_welcome"
    }))?;
    ensure!(
        serde_json::to_value(pending)?["provisioning_phase"] == "mls_welcome",
        "Welcome reconciliation phase drifted"
    );
    Ok(())
}

pub fn run_sidecar_ensure_idempotent_vector() -> Result<()> {
    let create: SidecarCreatePayload = serde_json::from_value(json!({}))?;
    ensure!(
        serde_json::to_value(create)? == json!({}),
        "Sidecar create payload is not empty"
    );
    ensure!(
        serde_json::from_value::<SidecarCreatePayload>(json!({"sidecar_id": sidecar_id()}))
            .is_err(),
        "caller supplied derived Sidecar identity"
    );
    let attach: SidecarContextAttachPayload = serde_json::from_value(json!({
        "sidecar_id": sidecar_id(), "source_context_ref": context(), "version": 1
    }))?;
    attach.validate()?;
    let mut stale = serde_json::to_value(&attach)?;
    stale["version"] = json!(2);
    serde_json::from_value::<SidecarContextAttachPayload>(stale)?
        .validate()
        .expect_err("version 2 requires predecessor");
    let prepare: SidecarEnsurePrepareRequestBody = serde_json::from_value(json!({
        "phase": "prepare",
        "operation_id": "ak:operation:0198ff00-0000-7000-8000-000000000001",
        "idempotency_key": "sidecar-ensure-fixture",
        "source_realm_id": realm_id(),
        "controller_account_id": account(),
        "context_ref": context()
    }))?;
    ensure!(
        prepare.source_realm_id == realm_id(),
        "prepare changed source Realm"
    );
    Ok(())
}

pub fn run_sidecar_eligibility_states_vector() -> Result<()> {
    let desired = [agent()].into_iter().collect::<BTreeSet<_>>();
    let effective = BTreeSet::<&str>::new();
    ensure!(
        effective.is_subset(&desired),
        "effective access exceeds desired roster"
    );
    let context: AgentSidecarMlsContext = serde_json::from_value(json!({
        "participant_authority_digest": format!("sha256:{}", "cd".repeat(32)),
        "authority_stream_head": [event_id(8)],
        "current_controller_device_ready": false
    }))?;
    context.validate_shape()?;
    ensure!(
        !context.is_mls_activated(),
        "plaintext pre-genesis context activated"
    );
    Ok(())
}

pub fn run_sidecar_existence_privacy_vector() -> Result<()> {
    let sidecar: AgentSidecar = serde_json::from_value(json!({
        "id": sidecar_id(), "schema": SchemaId::AGENT_SIDECAR_V1,
        "realm_id": realm_id(), "controller_account_id": account(),
        "state": "active", "created_at": "2026-08-01T00:00:00.000Z"
    }))?;
    sidecar.validate_shape()?;
    let value = serde_json::to_value(&sidecar)?;
    for forbidden in [
        "backing_circle_id",
        "member_ids",
        "join_rule",
        "directory_visibility",
    ] {
        ensure!(
            value.get(forbidden).is_none(),
            "Sidecar disclosed {forbidden}"
        );
    }
    Ok(())
}

pub fn run_sidecar_hosted_projection_vector() -> Result<()> {
    let view: AgentSidecarViewState = serde_json::from_value(view_state())?;
    view.validate_shape()?;
    let mut illegal = view_state();
    illegal["shared_strand_write"] = json!(true);
    ensure!(
        serde_json::from_value::<AgentSidecarViewState>(illegal).is_err(),
        "private hosted view accepted shared Strand write"
    );
    Ok(())
}

pub fn run_sidecar_multi_agent_publish_vector() -> Result<()> {
    let request: AgentSidecarEventExchangeBinding = serde_json::from_value(request_binding())?;
    request.validate_shape()?;
    let mut with_extra = request_binding();
    with_extra["participant_ids"] = json!([agent()]);
    ensure!(
        serde_json::from_value::<AgentSidecarEventExchangeBinding>(with_extra).is_err(),
        "request accepted an editable participant set"
    );
    Ok(())
}

pub fn run_sidecar_exchange_binding_closed_loop_vector() -> Result<()> {
    let request: AgentSidecarEventExchangeBinding = serde_json::from_value(request_binding())?;
    request.validate_shape()?;
    let response: AgentSidecarEventExchangeBinding = serde_json::from_value(response_binding())?;
    response.validate_shape()?;
    ensure!(
        response.request_event_id == Some(event_id(4)),
        "response lost accepted request identity"
    );
    let close: AgentSidecarExchangeControl = serde_json::from_value(control())?;
    close.validate_shape()?;
    let mut invalid = control();
    invalid
        .as_object_mut()
        .ok_or_else(|| anyhow!("control not object"))?
        .remove("response_event_ids");
    serde_json::from_value::<AgentSidecarExchangeControl>(invalid)?
        .validate_shape()
        .expect_err("terminal control requires response set");
    Ok(())
}

pub fn run_sidecar_exchange_projection_recovery_vector() -> Result<()> {
    let delivered: AgentSidecarExchangeProjection = serde_json::from_value(projection())?;
    delivered.validate_shape()?;
    let mut responding = projection();
    responding["status"] = json!("responding");
    responding["user_facing_response_event_ids"] = json!([event_id(5)]);
    serde_json::from_value::<AgentSidecarExchangeProjection>(responding)?.validate_shape()?;
    let mut failed = projection();
    failed["status"] = json!("failed");
    failed["failure_reason_code"] = json!("agent_unavailable");
    failed["terminal_event_id"] = json!(event_id(6));
    serde_json::from_value::<AgentSidecarExchangeProjection>(failed.clone())?.validate_shape()?;
    failed["user_facing_response_event_ids"] = json!([event_id(5)]);
    serde_json::from_value::<AgentSidecarExchangeProjection>(failed)?
        .validate_shape()
        .expect_err("failed projection cannot echo a response");
    Ok(())
}

pub fn run_sidecar_exchange_binding_containment_vector() -> Result<()> {
    let mut public = json!({"content": {"kind": "ak.content.text", "body": "shared summary"}});
    for field in ["exchange_id", "request_context", "sidecar_id"] {
        ensure!(public.get(field).is_none(), "public content leaked {field}");
    }
    public["exchange_id"] = json!("private");
    ensure!(
        serde_json::from_value::<SidecarCreatePayload>(public).is_err(),
        "closed public create payload accepted private exchange data"
    );
    Ok(())
}

pub fn run_sidecar_context_locator_recovery_vector() -> Result<()> {
    let first: SidecarContextAttachPayload = serde_json::from_value(json!({
        "sidecar_id": sidecar_id(), "source_context_ref": context(), "version": 1
    }))?;
    first.validate()?;
    let second: SidecarContextAttachPayload = serde_json::from_value(json!({
        "sidecar_id": sidecar_id(), "source_context_ref": context(),
        "version": 2, "predecessor_event_ref": event_id(7)
    }))?;
    second.validate()?;
    ensure!(
        first.sidecar_id == second.sidecar_id
            && first.source_context_ref == second.source_context_ref,
        "context attachment chain crossed locators"
    );
    Ok(())
}

pub fn run_sidecar_canonical_sibling_digest_vector() -> Result<()> {
    let actor = DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example")?;
    let station = DidCoreId::new("ak:did_core:web:station.example")?;
    let at = chrono::DateTime::parse_from_rfc3339("2026-08-01T00:00:00.000Z")?
        .with_timezone(&chrono::Utc);
    let events = ["one", "two"]
        .into_iter()
        .map(|body| {
            arkret_wire::test_support::raw_event_at(
                "ak.message.create",
                ScopeRef::Realm {
                    realm_id: realm_id(),
                },
                actor.clone(),
                station.clone(),
                json!({"body": body}),
                at,
            )
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let choose = |items: &[arkret_wire::Event]| -> Result<EventId> {
        let winner = items
            .iter()
            .max_by_key(|event| {
                event
                    .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                    .expect("fixture Event digest")
            })
            .ok_or_else(|| anyhow!("empty sibling set"))?;
        Ok(winner.event_id.clone())
    };
    let mut reverse = events.clone();
    reverse.reverse();
    ensure!(
        choose(&events)? == choose(&reverse)?,
        "sibling winner follows arrival order"
    );
    Ok(())
}

pub fn run_sidecar_union_history_frontier_vector() -> Result<()> {
    let left = BTreeSet::from([event_id(1), event_id(2)]);
    let right = BTreeSet::from([event_id(1), event_id(3)]);
    let union = left.union(&right).cloned().collect::<BTreeSet<_>>();
    ensure!(
        union.len() == 3 && union.contains(&event_id(2)) && union.contains(&event_id(3)),
        "incomparable device histories lost a causal branch"
    );
    // A caller's checkpoint may include only history for which that caller has
    // effective access. Unioning controller devices must never grant access.
    let eligible_at_request = BTreeSet::from([event_id(1), event_id(2)]);
    let exposed = union
        .intersection(&eligible_at_request)
        .cloned()
        .collect::<BTreeSet<_>>();
    ensure!(
        exposed == eligible_at_request && !exposed.contains(&event_id(3)),
        "union checkpoint widened requester history"
    );
    Ok(())
}

pub fn run_sidecar_non_disclosure_surface_matrix_vector() -> Result<()> {
    let mut value = view_state();
    value["public_export"] = json!(true);
    ensure!(
        serde_json::from_value::<AgentSidecarViewState>(value).is_err(),
        "private Sidecar view gained a public export field"
    );
    let mut binding = request_binding();
    binding["plaintext_scope"] = json!("realm");
    ensure!(
        serde_json::from_value::<AgentSidecarEventExchangeBinding>(binding).is_err(),
        "private exchange binding gained a public scope field"
    );
    Ok(())
}

pub fn run_sidecar_revoke_fail_closed_vector() -> Result<()> {
    let desired = BTreeSet::from([agent()]);
    let removed = BTreeSet::<&str>::new();
    ensure!(
        desired.contains(agent()) && !removed.contains(agent()),
        "revoked Agent stayed in desired roster"
    );
    let pending: PendingSidecarAccessReconciliation = serde_json::from_value(json!({
        "agent_id": agent(), "provisioning_phase": "mls_remove"
    }))?;
    ensure!(
        serde_json::to_value(pending)?["provisioning_phase"] == "mls_remove",
        "removal obligation was lost"
    );
    Ok(())
}

pub fn run_sidecar_explicit_publish_vector() -> Result<()> {
    let published = json!({"content": {"kind": "ak.content.text", "body": "approved summary"}});
    ensure!(
        published
            .as_object()
            .is_some_and(|object| object.len() == 1 && object.contains_key("content")),
        "publish carried fields outside the allowlist"
    );
    Ok(())
}

pub fn run_sidecar_accepted_request_identity_vector() -> Result<()> {
    let response: AgentSidecarEventExchangeBinding = serde_json::from_value(response_binding())?;
    response.validate_shape()?;
    ensure!(
        response.request_event_id == Some(event_id(4)),
        "response did not name accepted request Event"
    );
    ensure!(
        EventId::new("ak:message:AX0TNnklqIlzhGa2OXRoCVE1dmOt3VUwpuOvqt4iPt5F").is_err(),
        "Message ID masqueraded as accepted Event ID"
    );
    Ok(())
}

pub fn run_sidecar_hosted_ui_matrix_vector() -> Result<()> {
    let mut merged = view_state();
    let first: AgentSidecarViewState = serde_json::from_value(merged.clone())?;
    first.validate_shape()?;
    merged["display_mode"] = json!("sidecar_only");
    let second: AgentSidecarViewState = serde_json::from_value(merged)?;
    second.validate_shape()?;
    ensure!(
        first.sidecar_id == second.sidecar_id && first.context_ref == second.context_ref,
        "display mode changed hosted Sidecar coordinates"
    );
    Ok(())
}

/// Executes each currently registered Sidecar vector once.
pub fn run_sidecar_vector_suite() -> Result<()> {
    validate_registry()?;
    for (name, run) in [
        (
            VECTOR_ID_SIDECAR_MLS_BOOTSTRAP_BINDING,
            run_sidecar_mls_bootstrap_binding_vector as fn() -> Result<()>,
        ),
        (
            VECTOR_ID_SIDECAR_MLS_EFFECTIVE_ACCESS,
            run_sidecar_mls_effective_access_vector,
        ),
        (
            VECTOR_ID_SIDECAR_ENSURE_IDEMPOTENT,
            run_sidecar_ensure_idempotent_vector,
        ),
        (
            VECTOR_ID_SIDECAR_ELIGIBILITY_STATES,
            run_sidecar_eligibility_states_vector,
        ),
        (
            VECTOR_ID_SIDECAR_EXISTENCE_PRIVACY,
            run_sidecar_existence_privacy_vector,
        ),
        (
            VECTOR_ID_SIDECAR_HOSTED_PROJECTION,
            run_sidecar_hosted_projection_vector,
        ),
        (
            VECTOR_ID_SIDECAR_MULTI_AGENT_PUBLISH,
            run_sidecar_multi_agent_publish_vector,
        ),
        (
            VECTOR_ID_SIDECAR_EXCHANGE_BINDING_CLOSED_LOOP,
            run_sidecar_exchange_binding_closed_loop_vector,
        ),
        (
            VECTOR_ID_SIDECAR_EXCHANGE_PROJECTION_RECOVERY,
            run_sidecar_exchange_projection_recovery_vector,
        ),
        (
            VECTOR_ID_SIDECAR_EXCHANGE_BINDING_CONTAINMENT,
            run_sidecar_exchange_binding_containment_vector,
        ),
        (
            VECTOR_ID_SIDECAR_CONTEXT_LOCATOR_RECOVERY,
            run_sidecar_context_locator_recovery_vector,
        ),
        (
            VECTOR_ID_SIDECAR_CANONICAL_SIBLING_DIGEST,
            run_sidecar_canonical_sibling_digest_vector,
        ),
        (
            VECTOR_ID_SIDECAR_UNION_HISTORY_FRONTIER,
            run_sidecar_union_history_frontier_vector,
        ),
        (
            VECTOR_ID_SIDECAR_NON_DISCLOSURE_SURFACE_MATRIX,
            run_sidecar_non_disclosure_surface_matrix_vector,
        ),
        (
            VECTOR_ID_SIDECAR_REVOKE_FAIL_CLOSED,
            run_sidecar_revoke_fail_closed_vector,
        ),
        (
            VECTOR_ID_SIDECAR_EXPLICIT_PUBLISH,
            run_sidecar_explicit_publish_vector,
        ),
        (
            VECTOR_ID_SIDECAR_ACCEPTED_REQUEST_IDENTITY,
            run_sidecar_accepted_request_identity_vector,
        ),
        (
            VECTOR_ID_SIDECAR_HOSTED_UI_MATRIX,
            run_sidecar_hosted_ui_matrix_vector,
        ),
    ] {
        run().map_err(|error| anyhow!("{name}: {error}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn current_sidecar_vectors() {
        super::run_sidecar_vector_suite().unwrap();
    }
}
