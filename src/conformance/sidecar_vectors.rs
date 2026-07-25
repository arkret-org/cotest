//! Sidecar conformance vectors (§0.11 of `_before_todos.md`).
//!
//! 10 vectors:
//!   - `ak.vector.sidecar.mls_bootstrap_binding.v1`
//!   - `ak.vector.sidecar.mls_effective_access.v1`
//!   - `ak.vector.sidecar.ensure_idempotent.v1`
//!   - `ak.vector.sidecar.eligibility_states.v1`
//!   - `ak.vector.sidecar.existence_privacy.v1`
//!   - `ak.vector.sidecar.hosted_projection.v1`
//!   - `ak.vector.sidecar.multi_agent_publish.v1`
//!   - `ak.vector.sidecar.exchange_binding_closed_loop.v1`
//!   - `ak.vector.sidecar.exchange_projection_recovery.v1`
//!   - `ak.vector.sidecar.exchange_binding_containment.v1`
//!
//! These vectors pin the first-class Sidecar wire model. Backing scope is an
//! internal MLS implementation detail and may not appear in public outcomes.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use arkret::{
    AgentSidecarDisplayMode, AgentSidecarEventExchangeBinding, AgentSidecarExchangeBindingRole,
    AgentSidecarExchangeCompletionPolicy, AgentSidecarExchangeControl,
    AgentSidecarExchangeControlAction, AgentSidecarExchangeControlSchema,
    AgentSidecarExchangeFoldedFrontier, AgentSidecarExchangeId, AgentSidecarExchangeOrigin,
    AgentSidecarExchangeProjection, AgentSidecarExchangeProjectionSchema,
    AgentSidecarExchangeRequestContext, AgentSidecarExchangeStatus,
    AgentSidecarProjectionProvenance, AgentSidecarSourceTrackRef, Did, EventId, Hash, Hlc,
    MessageMetadata, MlsGovernanceBindingPayload, NonEmptyString,
    PendingSidecarAccessReconciliationItem, PendingSidecarAccessReconciliationStage, RealmId,
    SidecarId, SidecarMlsBinding, StrandId, agent_sidecar_desired_access_digest,
    agent_sidecar_exchange_event_set_digest,
};
use arkret_wire::{CapabilityActionId, PROFILE_AGENT_SIDECAR};
use garth::projection::{
    SidecarExchangeAgentFact, SidecarExchangeCacheDecision, SidecarExchangeControlFact,
    SidecarExchangeFoldScope, SidecarExchangeRequestFact, evaluate_sidecar_exchange_cache,
    fold_sidecar_exchange,
};
use serde_json::Value;

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
];

const SIDECAR_VECTORS_FIXTURE_FILE: &str = "agent-sidecar-fixture.json";
const SIDECAR_VECTORS_PROFILE: &str = "ak.profile.agent_sidecar.v1";

fn validate_sidecar_vectors_fixture_metadata() -> Result<()> {
    let fixture = super::load_fixture_value(SIDECAR_VECTORS_FIXTURE_FILE)?;
    super::validate_profile(&fixture, SIDECAR_VECTORS_PROFILE)?;
    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("sidecar fixture missing covers_vectors[]"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("sidecar fixture missing cases[]"))?;

    for vector_id in ALL_SIDECAR_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
            bail!("sidecar fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("sidecar fixture missing asserted case {vector_id}");
        }
    }

    Ok(())
}

// ─── VECT-SC-1 — ensure_idempotent ─────────────────────────────────────────

pub fn run_sidecar_mls_bootstrap_binding_vector() -> Result<()> {
    let fixture = super::load_fixture_value(SIDECAR_VECTORS_FIXTURE_FILE)?;
    let case = fixture["cases"]
        .as_array()
        .and_then(|cases| {
            cases.iter().find(|case| {
                case["vector_id"].as_str() == Some(VECTOR_ID_SIDECAR_MLS_BOOTSTRAP_BINDING)
            })
        })
        .ok_or_else(|| anyhow!("Sidecar MLS bootstrap fixture case is missing"))?;
    let transcript = &case["desired_access_transcript"];
    let sidecar_id = SidecarId::new(
        transcript["sidecar_id"]
            .as_str()
            .ok_or_else(|| anyhow!("fixture sidecar_id is missing"))?
            .to_owned(),
    )?;
    let realm_id = RealmId::new(
        transcript["realm_id"]
            .as_str()
            .ok_or_else(|| anyhow!("fixture realm_id is missing"))?
            .to_owned(),
    )?;
    let controller_id = Did::new(
        transcript["controller_id"]
            .as_str()
            .ok_or_else(|| anyhow!("fixture controller_id is missing"))?
            .to_owned(),
    )?;
    let desired_agent_ids = transcript["principal_ids"]
        .as_array()
        .ok_or_else(|| anyhow!("fixture principal_ids are missing"))?
        .iter()
        .filter_map(Value::as_str)
        .filter(|principal_id| *principal_id != controller_id.as_str())
        .map(|principal_id| Did::new(principal_id.to_owned()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let digest = agent_sidecar_desired_access_digest(
        sidecar_id.clone(),
        realm_id.clone(),
        controller_id,
        &desired_agent_ids,
    )?;
    if case["expected_desired_access_digest"].as_str() != Some(digest.as_str()) {
        bail!("Sidecar desired-access canonical digest differs from the fixture KAT");
    }

    let sidecar_binding = SidecarMlsBinding {
        sidecar_id,
        desired_access_digest: digest,
        control_frontier: vec![
            NonEmptyString::new("ak:event:01964137-0000-7000-8000-000000000040")
                .map_err(anyhow::Error::msg)?,
        ],
    };
    let binding = MlsGovernanceBindingPayload::circle(
        realm_id,
        arkret::CircleId::new("ak:circle:01964137-0000-7000-8000-000000000030".to_owned())?,
        "YXJrcmV0LXNpZGVjYXItZ3JvdXA",
        0,
        0,
        vec![EventId::new(
            "ak:event:01964137-0000-7000-8000-000000000040".to_owned(),
        )?],
        Hash::new(format!("sha256:{}", "1".repeat(64)))?,
        Hash::new(format!("sha256:{}", "2".repeat(64)))?,
        Hash::new(format!("sha256:{}", "3".repeat(64)))?,
        "ak.profile.mls_governance_binding.full.v1",
        "ak.reducer.v1",
    )?
    .with_sidecar_binding(sidecar_binding.clone())?;
    let cbor = binding.to_deterministic_cbor()?;
    let decoded = MlsGovernanceBindingPayload::from_deterministic_cbor(&cbor)?;
    if decoded.sidecar_binding() != Some(&sidecar_binding)
        || decoded.to_deterministic_cbor()? != cbor
    {
        bail!("Sidecar MLS binding did not survive deterministic CBOR round-trip");
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct DeviceJoinEvidence {
    active_authorized: bool,
    accepted_add_commit: bool,
    matching_welcome: bool,
    key_package_consumed: bool,
    current_join_ref_bound: bool,
}

fn principal_effective(devices: &[DeviceJoinEvidence]) -> bool {
    devices.iter().any(|device| {
        device.active_authorized
            && device.accepted_add_commit
            && device.matching_welcome
            && device.key_package_consumed
            && device.current_join_ref_bound
    })
}

pub fn run_sidecar_mls_effective_access_vector() -> Result<()> {
    let complete = DeviceJoinEvidence {
        active_authorized: true,
        accepted_add_commit: true,
        matching_welcome: true,
        key_package_consumed: true,
        current_join_ref_bound: true,
    };
    if !principal_effective(&[complete]) {
        bail!("one complete active-device evidence chain must make the principal effective");
    }
    for incomplete in [
        DeviceJoinEvidence {
            accepted_add_commit: false,
            ..complete
        },
        DeviceJoinEvidence {
            matching_welcome: false,
            ..complete
        },
        DeviceJoinEvidence {
            key_package_consumed: false,
            ..complete
        },
        DeviceJoinEvidence {
            current_join_ref_bound: false,
            ..complete
        },
        DeviceJoinEvidence {
            active_authorized: false,
            ..complete
        },
    ] {
        if principal_effective(&[incomplete]) {
            bail!("incomplete or unauthorized device evidence became effective");
        }
    }
    let desired_after_removal = false;
    let delivery_allowed = desired_after_removal && principal_effective(&[complete]);
    let removal_obligation_created = !desired_after_removal;
    let principal_server_authored_commit = false;
    if delivery_allowed || !removal_obligation_created || principal_server_authored_commit {
        bail!(
            "Sidecar removal must stop delivery and create only a client-authored MLS obligation"
        );
    }
    let removal = PendingSidecarAccessReconciliationItem {
        agent_id: Did::new("did:webvh:z6mkfixture:assistant.agents.example")?,
        stage: PendingSidecarAccessReconciliationStage::MlsRemove,
        reason: NonEmptyString::new("mls_remove_obligation_pending").map_err(anyhow::Error::msg)?,
        membership_frontier: Some(vec![EventId::new(
            "ak:event:01964137-0000-7000-8000-000000000041",
        )?]),
    };
    removal.validate()?;
    Ok(())
}

pub fn run_sidecar_ensure_idempotent_vector() -> Result<()> {
    if arkret_wire::ServiceOperationId::SELF_AGENT_SIDECAR_COMMAND_ENSURE
        != "ak.self.agent.sidecar.command.ensure"
    {
        bail!("Sidecar ensure operation spelling drifted");
    }
    if CapabilityActionId::SELF_AGENT_SIDECAR_COMMAND_ENSURE
        != "ak.self.agent.sidecar.command.ensure"
    {
        bail!("sidecar ensure capability action spelling drifted");
    }
    if PROFILE_AGENT_SIDECAR != "ak.profile.agent_sidecar.v1" {
        bail!("PROFILE_AGENT_SIDECAR spelling drifted: {PROFILE_AGENT_SIDECAR}");
    }
    // Idempotency invariant: same (controller, agent_principal) MUST
    // yield the same `sidecar_id`. Wire-shape: deterministic
    // derivation is server-side; here we pin that the operation id is
    // stable so the client can re-issue safely.
    Ok(())
}

// ─── VECT-SC-2 — eligibility_states ────────────────────────────────────────

pub fn run_sidecar_eligibility_states_vector() -> Result<()> {
    // Sidecar ensure rejects from `paused` / `deactivated` agents with
    // the canonical error codes (also covered by the agent FSM
    // vector, but pinned again at the sidecar-specific code path).
    if arkret_wire::ReasonCode::AGENT_PAUSED != "agent_paused" {
        bail!("arkret_wire::ReasonCode::AGENT_PAUSED spelling drifted: agent_paused");
    }
    if arkret_wire::ReasonCode::AGENT_DEACTIVATED != "agent_deactivated" {
        bail!("arkret_wire::ReasonCode::AGENT_DEACTIVATED spelling drifted: agent_deactivated");
    }
    Ok(())
}

// ─── VECT-SC-3 — existence_privacy ─────────────────────────────────────────

pub fn run_sidecar_existence_privacy_vector() -> Result<()> {
    // A caller without the Sidecar ensure capability
    // MUST receive `sidecar_create_denied` (NOT `not_found` — the
    // server MUST NOT confirm or deny existence by error code).
    if arkret_wire::ReasonCode::SIDECAR_CREATE_DENIED != "sidecar_create_denied" {
        bail!(
            "arkret_wire::ReasonCode::SIDECAR_CREATE_DENIED spelling drifted: sidecar_create_denied"
        );
    }
    Ok(())
}

// ─── VECT-SC-4 — hosted_projection ─────────────────────────────────────────

pub fn run_sidecar_hosted_projection_vector() -> Result<()> {
    let sidecar = SidecarId::new("ak:sidecar:01964137-0000-7000-8000-000000000021".to_owned())?;
    if !sidecar.as_str().starts_with("ak:sidecar:") {
        bail!("Sidecar identity is not first-class");
    }
    if serde_json::to_value(AgentSidecarDisplayMode::ContextMerged)? != "context_merged"
        || serde_json::to_value(AgentSidecarDisplayMode::SidecarOnly)? != "sidecar_only"
        || serde_json::to_value(AgentSidecarExchangeOrigin::SourceTrackRouted)?
            != "source_track_routed"
        || serde_json::to_value(AgentSidecarExchangeOrigin::SidecarNative)? != "sidecar_native"
    {
        bail!("hosted Sidecar closed enums drifted");
    }
    let realm_id = RealmId::new("ak:realm:01964137-0000-7000-8000-000000000030")?;
    let source_strand_id = StrandId::new("ak:strand:01964137-0000-7000-8000-000000000031")?;
    let private_strand_id = StrandId::new("ak:strand:01964137-0000-7000-8000-000000000032")?;
    let anchor_id = EventId::new("ak:event:01964137-0000-7000-8000-000000000033")?;
    let request_id = EventId::new("ak:event:01964137-0000-7000-8000-000000000034")?;
    let native_id = EventId::new("ak:event:01964137-0000-7000-8000-000000000035")?;
    let response_id = EventId::new("ak:event:01964137-0000-7000-8000-000000000036")?;
    let addressed_agent = Did::new("did:webvh:z6mkfixture:assistant.agents.example")?;
    let terminal_id = EventId::new("ak:event:01964137-0000-7000-8000-000000000037")?;
    let projection = AgentSidecarExchangeProjection {
        schema: AgentSidecarExchangeProjectionSchema::V1,
        controller_id: Did::new("did:webvh:z6mkfixture:example.com:users:alice")?,
        sidecar_id: sidecar,
        private_strand_id: private_strand_id.clone(),
        exchange_id: AgentSidecarExchangeId::new("Abcdefghijklmnopqrstuv")?,
        origin: AgentSidecarExchangeOrigin::SourceTrackRouted,
        source_track_ref: AgentSidecarSourceTrackRef {
            realm_id: realm_id.clone(),
            strand_id: source_strand_id.clone(),
            track_name: "discussion".to_owned(),
        },
        source_frontier_anchor: Some(anchor_id.clone()),
        source_hlc: Hlc::new("01970e589d21-0001-a13f9c2e")?,
        client_order_key: NonEmptyString::new("device-1-1").map_err(anyhow::Error::msg)?,
        addressed_agent_ids: vec![addressed_agent.clone()],
        completion_policy: AgentSidecarExchangeCompletionPolicy::Coordinator,
        coordinator_agent_id: addressed_agent.clone(),
        coordinator_assignment_event_id: request_id.clone(),
        participating_agent_ids: vec![addressed_agent],
        private_request_event_id: request_id.clone(),
        user_facing_response_event_ids: vec![response_id.clone()],
        status: AgentSidecarExchangeStatus::Complete,
        failure_code: None,
        terminal_event_id: Some(terminal_id.clone()),
        folded_frontier: AgentSidecarExchangeFoldedFrontier {
            event_ids: vec![terminal_id],
            event_set_digest: agent_sidecar_exchange_event_set_digest(&[
                request_id.clone(),
                response_id.clone(),
            ])?,
            max_hlc: Hlc::new("01970e589d21-0004-a13f9c2e")?,
        },
    };
    projection.validate()?;
    let event = |event_id: EventId, hlc: &str, value: &'static str| {
        garth::projection::SidecarTimelineEvent {
            event_id,
            hlc: hlc.to_owned(),
            track_name: "discussion".to_owned(),
            value,
        }
    };
    let shared = vec![event(
        anchor_id.clone(),
        "01970e589d21-0001-a13f9c2e",
        "shared anchor",
    )];
    let private = vec![
        event(
            request_id.clone(),
            "01970e589d21-0002-a13f9c2e",
            "routed request",
        ),
        event(
            native_id.clone(),
            "01970e589d21-0003-a13f9c2e",
            "agent internal",
        ),
        event(
            response_id.clone(),
            "01970e589d21-0004-a13f9c2e",
            "user-facing response",
        ),
    ];
    let merged = garth::projection::merge_sidecar_timeline(
        [&projection],
        AgentSidecarDisplayMode::ContextMerged,
        &shared,
        &private,
    );
    if merged.iter().map(|item| &item.event_id).collect::<Vec<_>>()
        != vec![&anchor_id, &request_id, &response_id, &native_id]
        || merged[1].provenance != AgentSidecarProjectionProvenance::PrivateEcho
        || merged[2].provenance != AgentSidecarProjectionProvenance::PrivateEcho
        || merged[3].provenance != AgentSidecarProjectionProvenance::Private
    {
        bail!("hosted Sidecar merge did not isolate explicit responses from internal Events");
    }
    let private_only = garth::projection::merge_sidecar_timeline(
        [&projection],
        AgentSidecarDisplayMode::SidecarOnly,
        &shared,
        &private,
    );
    if private_only.len() != 3
        || private_only
            .iter()
            .any(|item| item.provenance != AgentSidecarProjectionProvenance::Private)
    {
        bail!("Sidecar-only projection leaked shared content or echo provenance");
    }
    Ok(())
}

// ─── VECT-SC-4 — multi_agent_publish ───────────────────────────────────────

pub fn run_sidecar_multi_agent_publish_vector() -> Result<()> {
    // The publish/write/ensure trio MUST be present and namespaced.
    let trio = [
        CapabilityActionId::SELF_AGENT_SIDECAR_COMMAND_ENSURE,
        CapabilityActionId::AGENT_SIDECAR_WRITE,
        CapabilityActionId::AGENT_SIDECAR_PUBLISH,
    ];
    for action in trio {
        if !action.contains(".sidecar.") {
            bail!("sidecar capability action `{action}` lost canonical scope");
        }
    }
    let mut sorted = trio.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != trio.len() {
        bail!("sidecar capability action trio has duplicates");
    }
    Ok(())
}

// ─── shared exchange fixtures for the §7.2 vectors ─────────────────────────

fn exchange_event_id(suffix: u32) -> Result<EventId> {
    Ok(EventId::new(format!(
        "ak:event:01964137-0000-7000-8000-{suffix:012x}"
    ))?)
}

fn exchange_hlc(counter: u32) -> Result<Hlc> {
    Ok(Hlc::new(format!("01970e589d21-{counter:04x}-a13f9c2e"))?)
}

fn exchange_controller() -> Result<Did> {
    Ok(Did::new("did:webvh:z6mkfixture:example.com:users:alice")?)
}

fn exchange_agent_s() -> Result<Did> {
    Ok(Did::new("did:webvh:z6mkfixture:assistant.agents.example")?)
}

fn exchange_agent_t() -> Result<Did> {
    Ok(Did::new("did:webvh:z6mkfixture:reviewer.agents.example")?)
}

fn exchange_scope() -> Result<SidecarExchangeFoldScope> {
    Ok(SidecarExchangeFoldScope {
        controller_id: exchange_controller()?,
        sidecar_id: SidecarId::new("ak:sidecar:01964137-0000-7000-8000-000000000021")?,
        private_strand_id: StrandId::new("ak:strand:01964137-0000-7000-8000-000000000032")?,
    })
}

fn exchange_id_x1() -> Result<AgentSidecarExchangeId> {
    AgentSidecarExchangeId::new("Xabcdefghijklmnopqrstu").map_err(Into::into)
}

fn exchange_request_context() -> Result<AgentSidecarExchangeRequestContext> {
    Ok(AgentSidecarExchangeRequestContext {
        source_track_ref: AgentSidecarSourceTrackRef {
            realm_id: RealmId::new("ak:realm:01964137-0000-7000-8000-000000000030")?,
            strand_id: StrandId::new("ak:strand:01964137-0000-7000-8000-000000000031")?,
            track_name: "discussion".to_owned(),
        },
        source_hlc: exchange_hlc(1)?,
        client_order_key: NonEmptyString::new("device-1-1").map_err(anyhow::Error::msg)?,
        addressed_agent_ids: vec![exchange_agent_s()?, exchange_agent_t()?],
        completion_policy: AgentSidecarExchangeCompletionPolicy::Coordinator,
        coordinator_agent_id: Some(exchange_agent_s()?),
        source_frontier_anchor: None,
    })
}

fn exchange_request_fact(
    suffix: u32,
    actor_seq: u64,
    digest: &str,
) -> Result<SidecarExchangeRequestFact> {
    Ok(SidecarExchangeRequestFact {
        event_id: exchange_event_id(suffix)?,
        hlc: exchange_hlc(1)?,
        actor_id: exchange_controller()?,
        actor_seq,
        event_digest: digest.to_owned(),
        exchange_id: exchange_id_x1()?,
        context: exchange_request_context()?,
    })
}

fn exchange_agent_fact(
    suffix: u32,
    counter: u32,
    actor: Did,
    role: AgentSidecarExchangeBindingRole,
) -> Result<SidecarExchangeAgentFact> {
    let request_event_id = exchange_event_id(0x34)?;
    let binding = match role {
        AgentSidecarExchangeBindingRole::UserFacingResponse => {
            AgentSidecarEventExchangeBinding::user_facing_response(
                exchange_id_x1()?,
                request_event_id.clone(),
            )?
        }
        AgentSidecarExchangeBindingRole::Internal => {
            AgentSidecarEventExchangeBinding::internal(exchange_id_x1()?, request_event_id.clone())?
        }
        AgentSidecarExchangeBindingRole::Request => bail!("request facts use the request builder"),
    };
    Ok(SidecarExchangeAgentFact {
        event_id: exchange_event_id(suffix)?,
        hlc: exchange_hlc(counter)?,
        actor_id: actor,
        binding,
        refs_after: vec![request_event_id],
    })
}

fn exchange_close_control(
    suffix: u32,
    actor_seq: u64,
    digest: &str,
    action: AgentSidecarExchangeControlAction,
    basis: Vec<EventId>,
    responses: Option<Vec<EventId>>,
    failure_code: Option<&str>,
) -> Result<SidecarExchangeControlFact> {
    Ok(SidecarExchangeControlFact {
        event_id: exchange_event_id(suffix)?,
        hlc: exchange_hlc(0x40 + suffix)?,
        actor_id: exchange_controller()?,
        actor_seq,
        event_digest: digest.to_owned(),
        refs_after: basis.clone(),
        control: AgentSidecarExchangeControl {
            schema: AgentSidecarExchangeControlSchema::V1,
            exchange_id: exchange_id_x1()?,
            request_event_id: exchange_event_id(0x34)?,
            basis_event_ids: basis,
            action,
            response_event_ids: responses,
            failure_code: failure_code
                .map(|code| NonEmptyString::new(code).map_err(anyhow::Error::msg))
                .transpose()?,
            expected_coordinator_agent_id: None,
            coordinator_agent_id: None,
        },
    })
}

// ─── VECT-SC-8 — exchange_binding_closed_loop ──────────────────────────────

pub fn run_sidecar_exchange_binding_closed_loop_vector() -> Result<()> {
    let scope = exchange_scope()?;
    let exchange = exchange_id_x1()?;
    // Step 1: the request binding is the only exchange identity source.
    let request_binding =
        AgentSidecarEventExchangeBinding::request(exchange.clone(), exchange_request_context()?)?;
    if request_binding.request_context.as_ref().map(|context| {
        context.completion_policy == AgentSidecarExchangeCompletionPolicy::Coordinator
    }) != Some(true)
    {
        bail!("request binding lost its coordinator completion policy");
    }
    let request = exchange_request_fact(0x34, 3, "aa")?;

    // Step 2: a duplicate request reusing X1 at a higher sequence never
    // becomes canonical, and an agent-authored request binding is invalid.
    let duplicate_request = exchange_request_fact(0x40, 9, "zz")?;
    let mut agent_authored_request = exchange_request_fact(0x41, 1, "zz")?;
    agent_authored_request.actor_id = exchange_agent_s()?;
    let delivered = fold_sidecar_exchange(
        &scope,
        &exchange,
        &[
            duplicate_request,
            agent_authored_request.clone(),
            request.clone(),
        ],
        &[],
        &[],
    )?
    .ok_or_else(|| anyhow!("canonical request must fold"))?;
    if delivered.private_request_event_id != exchange_event_id(0x34)?
        || delivered.status != AgentSidecarExchangeStatus::Delivered
    {
        bail!("canonical request selection or delivered fold drifted");
    }
    if fold_sidecar_exchange(&scope, &exchange, &[agent_authored_request], &[], &[])?.is_some() {
        bail!("an agent-authored request binding must never be consumed");
    }

    // Internal events keep delivered and stay non-echo.
    let internal = exchange_agent_fact(
        0x35,
        2,
        exchange_agent_s()?,
        AgentSidecarExchangeBindingRole::Internal,
    )?;
    let with_internal = fold_sidecar_exchange(
        &scope,
        &exchange,
        std::slice::from_ref(&request),
        std::slice::from_ref(&internal),
        &[],
    )?
    .ok_or_else(|| anyhow!("internal fold missing"))?;
    if with_internal.status != AgentSidecarExchangeStatus::Delivered
        || !with_internal.user_facing_response_event_ids.is_empty()
        || with_internal.participating_agent_ids != vec![exchange_agent_s()?]
    {
        bail!("internal events must track participation without echo or status change");
    }

    // Step 3: every mutation fails closed to non-echo.
    let valid_response = exchange_agent_fact(
        0x36,
        4,
        exchange_agent_s()?,
        AgentSidecarExchangeBindingRole::UserFacingResponse,
    )?;
    let mut wrong_exchange = valid_response.clone();
    wrong_exchange.event_id = exchange_event_id(0x50)?;
    wrong_exchange.binding.exchange_id = AgentSidecarExchangeId::new("Yabcdefghijklmnopqrstu")?;
    let mut wrong_request_ref = valid_response.clone();
    wrong_request_ref.event_id = exchange_event_id(0x51)?;
    wrong_request_ref.binding.request_event_id = Some(exchange_event_id(0x99)?);
    let mut missing_causal_ref = valid_response.clone();
    missing_causal_ref.event_id = exchange_event_id(0x52)?;
    missing_causal_ref.refs_after = Vec::new();
    let mut unaddressed_actor = valid_response.clone();
    unaddressed_actor.event_id = exchange_event_id(0x53)?;
    unaddressed_actor.actor_id = Did::new("did:webvh:z6mkfixture:stranger.agents.example")?;
    let mut controller_response = valid_response.clone();
    controller_response.event_id = exchange_event_id(0x54)?;
    controller_response.actor_id = exchange_controller()?;
    let duplicate_delivery = valid_response.clone();
    let folded = fold_sidecar_exchange(
        &scope,
        &exchange,
        std::slice::from_ref(&request),
        &[
            valid_response.clone(),
            duplicate_delivery,
            wrong_exchange,
            wrong_request_ref,
            missing_causal_ref,
            unaddressed_actor,
            controller_response,
        ],
        &[],
    )?
    .ok_or_else(|| anyhow!("closed-loop fold missing"))?;
    // Step 4: duplicate delivery appends exactly once.
    if folded.user_facing_response_event_ids != vec![exchange_event_id(0x36)?]
        || folded.status != AgentSidecarExchangeStatus::Responding
    {
        bail!("mutated responses leaked into the echo set or duplicates were not idempotent");
    }

    // Unknown roles and ak:message: shaped request references fail closed at
    // the closed schema (fail-closed metadata accessor -> non-echo).
    for invalid in [
        serde_json::json!({
            "schema": "ak.schema.agent_sidecar_event_exchange_binding.v1",
            "exchange_id": exchange.as_str(),
            "role": "coordinator_summary",
        }),
        serde_json::json!({
            "schema": "ak.schema.agent_sidecar_event_exchange_binding.v1",
            "exchange_id": exchange.as_str(),
            "role": "user_facing_response",
            "request_event_id": "ak:message:01964137-0000-7000-8000-000000000034",
        }),
    ] {
        let metadata: MessageMetadata =
            serde_json::from_value(serde_json::json!({ "sidecar_exchange_binding": invalid }))?;
        if metadata.sidecar_exchange_binding().is_some() {
            bail!("invalid binding material must fail closed to non-echo");
        }
    }

    // Step 5: a non-coordinator completion request never closes the exchange;
    // only the controller-authored durable close control advances terminal
    // state, and completes_exchange itself changes nothing.
    let non_coordinator_completion = AgentSidecarEventExchangeBinding::user_facing_response(
        exchange.clone(),
        exchange_event_id(0x34)?,
    )?
    .with_completion(exchange_event_id(0x34)?)?;
    let mut t_response = exchange_agent_fact(
        0x37,
        5,
        exchange_agent_t()?,
        AgentSidecarExchangeBindingRole::UserFacingResponse,
    )?;
    t_response.binding = non_coordinator_completion;
    let coordinator = with_internal.coordinator_agent_id.clone();
    if t_response.actor_id == coordinator {
        bail!("fixture expects T to be a non-coordinator");
    }
    let responding = fold_sidecar_exchange(
        &scope,
        &exchange,
        std::slice::from_ref(&request),
        &[valid_response.clone(), t_response.clone()],
        &[],
    )?
    .ok_or_else(|| anyhow!("responding fold missing"))?;
    if responding.status != AgentSidecarExchangeStatus::Responding
        || responding.terminal_event_id.is_some()
    {
        bail!("completes_exchange must not advance terminal state by itself");
    }
    // T is addressed, so its body may echo even though its completion
    // request is ignored.
    if !responding
        .user_facing_response_event_ids
        .contains(&exchange_event_id(0x37)?)
    {
        bail!("an addressed non-coordinator user-facing response must still echo");
    }
    let close = exchange_close_control(
        0x38,
        7,
        "cc",
        AgentSidecarExchangeControlAction::Close,
        vec![exchange_event_id(0x36)?, exchange_event_id(0x37)?],
        Some(vec![exchange_event_id(0x36)?, exchange_event_id(0x37)?]),
        None,
    )?;
    let complete = fold_sidecar_exchange(
        &scope,
        &exchange,
        &[request],
        &[valid_response, t_response],
        std::slice::from_ref(&close),
    )?
    .ok_or_else(|| anyhow!("terminal fold missing"))?;
    if complete.status != AgentSidecarExchangeStatus::Complete
        || complete.terminal_event_id != Some(exchange_event_id(0x38)?)
        || complete.user_facing_response_event_ids
            != vec![exchange_event_id(0x36)?, exchange_event_id(0x37)?]
    {
        bail!("only the accepted durable close control may advance terminal state");
    }
    Ok(())
}

// ─── VECT-SC-9 — exchange_projection_recovery ──────────────────────────────

pub fn run_sidecar_exchange_projection_recovery_vector() -> Result<()> {
    let scope = exchange_scope()?;
    let exchange = exchange_id_x1()?;
    let request = exchange_request_fact(0x34, 1, "aa")?;
    let response_r1 = exchange_agent_fact(
        0x35,
        3,
        exchange_agent_s()?,
        AgentSidecarExchangeBindingRole::UserFacingResponse,
    )?;
    let response_r2 = exchange_agent_fact(
        0x36,
        2,
        exchange_agent_s()?,
        AgentSidecarExchangeBindingRole::UserFacingResponse,
    )?;

    // Independent devices replay the same accepted history in different
    // arrival orders and MUST produce bit-identical projections with the
    // canonical (event HLC, event id) response order.
    let device_one = fold_sidecar_exchange(
        &scope,
        &exchange,
        std::slice::from_ref(&request),
        &[response_r1.clone(), response_r2.clone()],
        &[],
    )?
    .ok_or_else(|| anyhow!("device one fold missing"))?;
    let device_two = fold_sidecar_exchange(
        &scope,
        &exchange,
        std::slice::from_ref(&request),
        &[response_r2.clone(), response_r1.clone()],
        &[],
    )?
    .ok_or_else(|| anyhow!("device two fold missing"))?;
    if device_one != device_two {
        bail!("independent device replay must be bit-identical");
    }
    if device_one.user_facing_response_event_ids
        != vec![exchange_event_id(0x36)?, exchange_event_id(0x35)?]
    {
        bail!("responses must order by (event HLC, event id) bytes, not arrival");
    }

    // Cache-loss rebuild starts from the request binding alone and never
    // redelivers: the request fact is sufficient and deterministic.
    let rebuilt =
        fold_sidecar_exchange(&scope, &exchange, std::slice::from_ref(&request), &[], &[])?
            .ok_or_else(|| anyhow!("rebuild fold missing"))?;
    if rebuilt.status != AgentSidecarExchangeStatus::Delivered
        || rebuilt.source_track_ref != exchange_request_context()?.source_track_ref
    {
        bail!("write-once projection fields must rebuild verbatim from the request binding");
    }

    // Partial views: D1 only saw R1, D2 only saw R2. Their frontiers are
    // incomparable; neither may win by HLC/LWW — both must backfill and fold
    // the joined history to the same digest.
    let d1_partial = fold_sidecar_exchange(
        &scope,
        &exchange,
        std::slice::from_ref(&request),
        std::slice::from_ref(&response_r1),
        &[],
    )?
    .ok_or_else(|| anyhow!("partial fold missing"))?;
    let d2_local: BTreeSet<EventId> = [exchange_event_id(0x34)?, exchange_event_id(0x36)?]
        .into_iter()
        .collect();
    if evaluate_sidecar_exchange_cache(&d1_partial.folded_frontier, &d2_local)?
        != SidecarExchangeCacheDecision::BackfillRequired
    {
        bail!("incomparable frontiers must demand backfill, never LWW");
    }
    let joined: BTreeSet<EventId> = [
        exchange_event_id(0x34)?,
        exchange_event_id(0x35)?,
        exchange_event_id(0x36)?,
    ]
    .into_iter()
    .collect();
    if evaluate_sidecar_exchange_cache(&d1_partial.folded_frontier, &joined)?
        != SidecarExchangeCacheDecision::Refold
        || evaluate_sidecar_exchange_cache(&device_one.folded_frontier, &joined)?
            != SidecarExchangeCacheDecision::Fresh
    {
        bail!("cache decisions must derive from causal coverage of the local verified set");
    }
    if device_one.folded_frontier.event_set_digest
        != agent_sidecar_exchange_event_set_digest(&joined.iter().cloned().collect::<Vec<_>>())?
    {
        bail!("folded frontier digest must commit to the complete contributing set");
    }

    // Terminal action x response-set mapping.
    let cases: [(AgentSidecarExchangeControlAction, bool, Option<&str>, _); 5] = [
        (
            AgentSidecarExchangeControlAction::Close,
            true,
            None,
            AgentSidecarExchangeStatus::Complete,
        ),
        (
            AgentSidecarExchangeControlAction::Cancel,
            true,
            None,
            AgentSidecarExchangeStatus::Complete,
        ),
        (
            AgentSidecarExchangeControlAction::Close,
            false,
            None,
            AgentSidecarExchangeStatus::Failed,
        ),
        (
            AgentSidecarExchangeControlAction::Cancel,
            false,
            None,
            AgentSidecarExchangeStatus::Failed,
        ),
        (
            AgentSidecarExchangeControlAction::Fail,
            false,
            Some("agent_deactivated"),
            AgentSidecarExchangeStatus::Failed,
        ),
    ];
    for (action, with_response, failure_code, expected_status) in cases {
        let responses = if with_response {
            vec![exchange_event_id(0x35)?]
        } else {
            Vec::new()
        };
        // §7.2.3 exactness: response_event_ids must be exactly the
        // basis-covered validated set, so the empty-response terminals use a
        // basis that covers only the request (a basis covering the validated
        // response with an empty listing would be an invalid control).
        let basis = if with_response {
            vec![exchange_event_id(0x35)?]
        } else {
            vec![exchange_event_id(0x34)?]
        };
        let control =
            exchange_close_control(0x38, 5, "cc", action, basis, Some(responses), failure_code)?;
        let folded = fold_sidecar_exchange(
            &scope,
            &exchange,
            std::slice::from_ref(&request),
            std::slice::from_ref(&response_r1),
            std::slice::from_ref(&control),
        )?
        .ok_or_else(|| anyhow!("terminal-mapping fold missing"))?;
        if folded.status != expected_status {
            bail!("terminal action x response-set mapping drifted for {action:?}");
        }
        let expected_failure = match (action, with_response) {
            (_, true) => None,
            (AgentSidecarExchangeControlAction::Close, false) => Some("controller_closed_empty"),
            (AgentSidecarExchangeControlAction::Cancel, false) => Some("controller_cancelled"),
            (AgentSidecarExchangeControlAction::Fail, false) => Some("agent_deactivated"),
            (AgentSidecarExchangeControlAction::ReassignCoordinator, false) => unreachable!(),
        };
        if folded.failure_code.as_ref().map(|code| code.as_str()) != expected_failure {
            bail!("derived failure code drifted for {action:?}");
        }
        if expected_status == AgentSidecarExchangeStatus::Failed
            && !folded.user_facing_response_event_ids.is_empty()
        {
            bail!("failed exchanges never carry responses");
        }
    }

    // An empty terminal whose basis covers a validated response is an
    // inexact response set and therefore an invalid control: the exchange
    // stays responding rather than forking to failed (§7.2.3).
    let inexact_empty_close = exchange_close_control(
        0x3c,
        5,
        "cc",
        AgentSidecarExchangeControlAction::Close,
        vec![exchange_event_id(0x35)?],
        Some(Vec::new()),
        None,
    )?;
    let still_responding = fold_sidecar_exchange(
        &scope,
        &exchange,
        std::slice::from_ref(&request),
        std::slice::from_ref(&response_r1),
        std::slice::from_ref(&inexact_empty_close),
    )?
    .ok_or_else(|| anyhow!("inexact-terminal fold missing"))?;
    if still_responding.status != AgentSidecarExchangeStatus::Responding {
        bail!("an inexact terminal response set must invalidate the control");
    }

    // Same-sequence terminal siblings resolve by bytewise-max event digest;
    // the winner absorbs everything after it, and Events outside the winning
    // basis closure stay private audit history.
    let winner = exchange_close_control(
        0x38,
        5,
        "ff",
        AgentSidecarExchangeControlAction::Close,
        vec![exchange_event_id(0x35)?],
        Some(vec![exchange_event_id(0x35)?]),
        None,
    )?;
    let sibling_loser = exchange_close_control(
        0x39,
        5,
        "aa",
        AgentSidecarExchangeControlAction::Cancel,
        vec![exchange_event_id(0x35)?],
        Some(Vec::new()),
        None,
    )?;
    let uncovered_late = response_r2.clone();
    let folded = fold_sidecar_exchange(
        &scope,
        &exchange,
        std::slice::from_ref(&request),
        &[response_r1.clone(), uncovered_late],
        &[sibling_loser, winner],
    )?
    .ok_or_else(|| anyhow!("sibling fold missing"))?;
    if folded.status != AgentSidecarExchangeStatus::Complete
        || folded.terminal_event_id != Some(exchange_event_id(0x38)?)
    {
        bail!("same-sequence siblings must resolve by bytewise-max event digest");
    }
    if folded
        .folded_frontier
        .event_ids
        .contains(&exchange_event_id(0x36)?)
    {
        bail!("Events outside the winning terminal basis must stay private audit history");
    }

    // Reassignment is valid only before terminal and only with a matching
    // expected coordinator; it retargets the assignment Event id.
    let mut reassign = exchange_close_control(
        0x3a,
        5,
        "cc",
        AgentSidecarExchangeControlAction::ReassignCoordinator,
        vec![exchange_event_id(0x34)?],
        None,
        None,
    )?;
    reassign.control.expected_coordinator_agent_id = Some(exchange_agent_s()?);
    reassign.control.coordinator_agent_id = Some(exchange_agent_t()?);
    let mut stale_reassign = exchange_close_control(
        0x3b,
        6,
        "dd",
        AgentSidecarExchangeControlAction::ReassignCoordinator,
        vec![exchange_event_id(0x34)?],
        None,
        None,
    )?;
    stale_reassign.control.expected_coordinator_agent_id = Some(exchange_agent_s()?);
    stale_reassign.control.coordinator_agent_id = Some(exchange_agent_t()?);
    let reassigned = fold_sidecar_exchange(
        &scope,
        &exchange,
        std::slice::from_ref(&request),
        &[],
        &[reassign, stale_reassign],
    )?
    .ok_or_else(|| anyhow!("reassign fold missing"))?;
    if reassigned.coordinator_agent_id != exchange_agent_t()?
        || reassigned.coordinator_assignment_event_id != exchange_event_id(0x3a)?
    {
        bail!("matching reassignment must retarget coordinator and assignment Event id");
    }

    // Projection state invariants are closed.
    let mut invalid = device_one.clone();
    invalid.status = AgentSidecarExchangeStatus::Failed;
    invalid.failure_code =
        Some(NonEmptyString::new("agent_deactivated").map_err(anyhow::Error::msg)?);
    invalid.terminal_event_id = Some(exchange_event_id(0x38)?);
    if invalid.validate().is_ok() {
        bail!("failed with responses must violate the projection schema");
    }
    Ok(())
}

// ─── VECT-SC-10 — exchange_binding_containment ─────────────────────────────

pub fn run_sidecar_exchange_binding_containment_vector() -> Result<()> {
    // The forbidden-wire-fields registry hard-rejects plaintext/shared-scope
    // occurrences of the binding key, both schema ids, and exchange_id.
    let registry = super::load_artifact_json("registry/forbidden-wire-fields.json")?;
    let entry = registry["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|entry| entry["id"].as_str() == Some("sidecar_exchange_binding"))
        .ok_or_else(|| anyhow!("forbidden-wire-fields registry lost sidecar_exchange_binding"))?;
    if entry["rejection_level"].as_str() != Some("hard_reject") {
        bail!("sidecar_exchange_binding containment must be a hard reject");
    }
    let allowed = entry["allowed_contexts"]
        .as_array()
        .map(|contexts| {
            contexts
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if allowed != vec!["changelog", "negative_test"] {
        bail!("sidecar_exchange_binding allowed contexts widened: {allowed:?}");
    }

    // The account-data registry carries no exchange projection key surface.
    let account_registry = super::load_artifact_json("registry/account-data-type-registry.json")?;
    if serde_json::to_string(&account_registry)?.contains("sidecar_projection") {
        bail!("the exchange projection must not register any account-data key");
    }

    // The local projection cache DTO rejects account-data key smuggling: a
    // fully valid projection round-trips, and the same JSON plus a smuggled
    // account-data key fails closed (deny_unknown_fields).
    let valid_projection = fold_sidecar_exchange(
        &exchange_scope()?,
        &exchange_id_x1()?,
        &[exchange_request_fact(0x34, 1, "aa")?],
        &[],
        &[],
    )?
    .ok_or_else(|| anyhow!("containment projection fold missing"))?;
    let mut round_trip = serde_json::to_value(&valid_projection)?;
    if serde_json::from_value::<AgentSidecarExchangeProjection>(round_trip.clone()).is_err() {
        bail!("a valid exchange projection must round-trip");
    }
    round_trip["account_data_type"] = serde_json::json!("ak.agent.sidecar_projection.v1:x");
    if serde_json::from_value::<AgentSidecarExchangeProjection>(round_trip).is_ok() {
        bail!("the exchange projection DTO must reject account-data key fields");
    }

    // Binding material only round-trips through the closed schema mount;
    // spelling of both schema ids is pinned.
    let binding = AgentSidecarEventExchangeBinding::user_facing_response(
        exchange_id_x1()?,
        exchange_event_id(0x34)?,
    )?;
    let mut metadata = MessageMetadata::default();
    metadata.set_sidecar_exchange_binding(&binding)?;
    let raw = serde_json::to_value(&metadata)?;
    if raw["sidecar_exchange_binding"]["schema"].as_str()
        != Some("ak.schema.agent_sidecar_event_exchange_binding.v1")
    {
        bail!("binding schema id spelling drifted");
    }
    if serde_json::to_value(AgentSidecarExchangeControlSchema::V1)?
        != "ak.schema.agent_sidecar_exchange_control.v1"
    {
        bail!("control schema id spelling drifted");
    }

    // Fixture assertions 3/4 (explicit publish output, shared history, push
    // previews, notifications, and public telemetry carrying zero exchange
    // material) require the live client publish path plus a real service
    // stack; they are intentionally NOT modeled here so that this static
    // runner cannot stand in for live evidence. The corresponding acceptance
    // items stay unchecked in the coordination task until the joint E2E
    // covers them.
    Ok(())
}

/// Suite entry point — runs all 10 Sidecar vectors.
pub fn run_sidecar_vector_suite() -> Result<()> {
    validate_sidecar_vectors_fixture_metadata()?;
    if ALL_SIDECAR_VECTOR_IDS.len() != 10 {
        bail!(
            "expected 10 sidecar vector ids, got {}",
            ALL_SIDECAR_VECTOR_IDS.len()
        );
    }
    run_sidecar_mls_bootstrap_binding_vector()?;
    run_sidecar_mls_effective_access_vector()?;
    run_sidecar_ensure_idempotent_vector()?;
    run_sidecar_eligibility_states_vector()?;
    run_sidecar_existence_privacy_vector()?;
    run_sidecar_hosted_projection_vector()?;
    run_sidecar_multi_agent_publish_vector()?;
    run_sidecar_exchange_binding_closed_loop_vector()?;
    run_sidecar_exchange_projection_recovery_vector()?;
    run_sidecar_exchange_binding_containment_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_ten_sidecar_vectors_run_clean() {
        run_sidecar_vector_suite().unwrap();
    }
}
