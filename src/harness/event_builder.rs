use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::Ordering;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use arkret::{
    DeviceId, DeviceMessageId, DeviceMessageTarget, DeviceMessagesSendRequestBody, ProtocolKind,
};
use arkret_identifiers::{
    DidCoreId, DidFullId, EventId, Hash, Hlc, MessageId, RealmId, StrandId,
    project_full_id_to_core_id,
};
use arkret_models_collaboration::events_payloads::{
    ContentBlock, MessageCreatePayload, MessageRedactPayload, MessageRevisePayload,
};
use arkret_models_collaboration::governance::invite_addressing::InviteDeliveryTarget;
use arkret_models_collaboration::governance::membership_invite::{
    InviteCreatePayload, MembershipInviteRef, MembershipPayload, MembershipPayloadState,
};
use arkret_models_collaboration::governance::moderation::{
    ModerationReportAcceptedTargetBasis, ModerationReportRequestBody,
};
use arkret_models_identity::delivery_binding::{DeliveryStatus, MemberDeliveryBinding};
use arkret_wire::{AuthContext, DidUrl, Event, ScopeRef};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::{Value, json};

use super::assertions::expect_json;
use super::client::TestActorClient;
use super::proof::refresh_typed_event_proof_with_signing_seed;
use super::server::ArkretServer;
use super::{
    NEXT_EVENT_SEQ, RealmBootstrapDraft, canonical_device_id, events_frontier_request_body,
    member_join_payload, query_method, realm_create_payload,
};

type RegisteredEventSigner = ([u8; 32], DidUrl);

static REGISTERED_EVENT_SIGNERS: LazyLock<Mutex<HashMap<String, RegisteredEventSigner>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn register_event_signing_identity(
    actor: &str,
    signing_seed: [u8; 32],
    verification_method: impl Into<String>,
) {
    let verification_method = DidUrl::new(verification_method)
        .expect("registered Event signer verification method is a DID URL");
    REGISTERED_EVENT_SIGNERS
        .lock()
        .expect("registered Event signer lock")
        .insert(actor.to_owned(), (signing_seed, verification_method));
}

pub(crate) fn event_signing_identity(actor: &str) -> ([u8; 32], DidUrl) {
    REGISTERED_EVENT_SIGNERS
        .lock()
        .expect("registered Event signer lock")
        .get(actor)
        .cloned()
        .unwrap_or_else(|| {
            let verification_method = default_event_verification_method(actor);
            let signing_seed =
                arkret::signatures::development_signing_key_seed(&verification_method);
            (signing_seed, verification_method)
        })
}

pub(crate) fn event_signing_identity_for_device(
    actor: &str,
    device_id: &str,
) -> ([u8; 32], DidUrl) {
    REGISTERED_EVENT_SIGNERS
        .lock()
        .expect("registered Event signer lock")
        .get(actor)
        .cloned()
        .unwrap_or_else(|| {
            let verification_method = DidUrl::new(format!("{actor}#{device_id}"))
                .expect("cotest client Event signer verification method is a DID URL");
            let signing_seed =
                arkret::signatures::development_signing_key_seed(&verification_method);
            (signing_seed, verification_method)
        })
}

pub fn default_event_verification_method(actor: &str) -> DidUrl {
    DidUrl::new(format!("{actor}#{}", canonical_device_id(actor)))
        .expect("cotest default Event signer verification method is a canonical device DID URL")
}

pub(crate) fn registered_event_signing_seed(
    signer: &str,
    verification_method: &DidUrl,
) -> Option<[u8; 32]> {
    REGISTERED_EVENT_SIGNERS
        .lock()
        .expect("registered Event signer lock")
        .get(signer)
        .filter(|(_, registered_method)| registered_method == verification_method)
        .map(|(seed, _)| *seed)
}

fn verification_method_for_actor(actor: &str) -> DidUrl {
    default_event_verification_method(actor)
}

pub async fn register_account(
    server: &ArkretServer,
    did: &str,
    handle: &str,
    device_id: &str,
) -> Result<String> {
    let device_id = canonical_device_id(device_id);
    let full_id = arkret_identifiers::DidFullId::new(did.to_owned())?;
    let body = arkret_models_collaboration::account_lifecycle::AccountRegisterRequestBody {
        principal_id: arkret_identifiers::project_full_id_to_core_id(&full_id)?,
        full_id,
        display_name: Some(handle.trim_start_matches('@').to_owned()),
        device_id: Some(arkret_identifiers::DeviceId::new(device_id.clone())?),
        proof: None,
        identity_creation: None,
        policy_evidence: None,
    };
    expect_json(
        server.account_registration_request().json(&body),
        StatusCode::OK,
    )
    .await?;

    dev_login(server, did, &device_id).await
}

pub async fn register_account_with_localpart(
    server: &ArkretServer,
    did: &str,
    display_handle: &str,
    localpart: &str,
    device_id: &str,
) -> Result<String> {
    let token = register_account(server, did, display_handle, device_id).await?;
    expect_json(
        server
            .account_localpart_request(did)?
            .json(&crate::harness::NonProtocolTestBody::new(json!({
                "localpart": localpart,
                "is_primary": true
            }))),
        StatusCode::OK,
    )
    .await?;
    Ok(token)
}

pub async fn dev_login(server: &ArkretServer, actor: &str, device_id: &str) -> Result<String> {
    let device_id = canonical_device_id(device_id);
    let actor_id = project_full_id_to_core_id(&DidFullId::new(actor.to_owned())?)?;
    let login = expect_json(
        server
            .http()
            .post(server.url("/_soland/gate/auth/dev-login"))
            .json(&crate::harness::NonProtocolTestBody::new(json!({
                "actor": actor_id,
                "device_id": device_id,
                "display_name": device_id
            }))),
        StatusCode::OK,
    )
    .await?;
    login["session_credential"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("login response did not include session_credential: {login}"))
}

pub fn device_message_send_request(
    recipient: &str,
    device_id: &str,
    message_id: &str,
    kind: &str,
    content: Value,
    expires_at: DateTime<Utc>,
) -> Result<DeviceMessagesSendRequestBody> {
    let content = content
        .as_object()
        .ok_or_else(|| anyhow!("device-message content must be an object"))?
        .clone()
        .into_iter()
        .collect();
    let target = DeviceMessageTarget {
        message_id: DeviceMessageId::new(message_id.to_owned())?,
        kind: ProtocolKind::new(kind.to_owned()).map_err(anyhow::Error::msg)?,
        content,
        expires_at,
    };
    let mut devices = BTreeMap::new();
    devices.insert(DeviceId::new(device_id.to_owned())?, target);
    let mut messages = BTreeMap::new();
    messages.insert(
        DidCoreId::from(project_full_id_to_core_id(&DidFullId::new(
            recipient.to_owned(),
        )?)?),
        devices,
    );
    Ok(DeviceMessagesSendRequestBody { messages })
}

pub async fn create_realm(
    server: &ArkretServer,
    token: &str,
    actor: &str,
    title: &str,
) -> Result<String> {
    let draft = realm_create_payload(
        server.service_id().as_str(),
        &json!({
            "title": title,
            "summary": title,
            "public": false,
            "plaintext_visible_services": [server.service_id()]
        }),
    )?;
    let (realm_id, events) = realm_bootstrap_event_batch(actor, draft)?;
    let events = events
        .into_iter()
        .map(arkret_wire::EventInitialSubmission::online)
        .collect();
    let request = arkret_wire::EventsSubmitBatchRequestBody { events };
    expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(token)
            .json(&request),
        StatusCode::OK,
    )
    .await?;
    Ok(realm_id)
}

/// Author the exact signed DataEvent carried by the self moderation-report
/// operation. The reporter is always the actor's core DID while Event proof
/// verification methods remain full DID URLs through `TestActorClient`.
pub async fn moderation_report_request(
    actor: &TestActorClient,
    realm_id: &str,
    target_ref: &str,
    effective_scope: ScopeRef,
) -> Result<ModerationReportRequestBody> {
    if effective_scope.realm_id_opt().map(RealmId::as_str) != Some(realm_id) {
        return Err(anyhow!(
            "moderation target scope does not belong to the requested Realm"
        ));
    }
    let reporter = project_full_id_to_core_id(&DidFullId::new(actor.actor.clone())?)?;
    let mut payload = json!({
        "realm_id": realm_id,
        "target_ref": target_ref,
        "report_reason_code": "spam",
        "reporter": reporter,
        "provenance": "self"
    });
    if matches!(effective_scope, ScopeRef::Circle { .. }) {
        payload["effective_scope"] = serde_json::to_value(&effective_scope)?;
    }
    let request = ModerationReportRequestBody {
        report_event: arkret_wire::EventInitialSubmission::online(
            actor
                .author_event(
                    realm_id,
                    arkret_wire::event_kind_str::SELF_MODERATION_REPORT,
                    payload,
                )
                .await?,
        ),
    };
    request.validate_authoring_context(
        &reporter,
        &ModerationReportAcceptedTargetBasis {
            target_ref: target_ref.to_owned(),
            effective_scope,
        },
    )?;
    Ok(request)
}

pub async fn create_realm_with_signing_seed(
    server: &ArkretServer,
    token: &str,
    actor: &str,
    title: &str,
    signing_seed: [u8; 32],
) -> Result<String> {
    let draft = realm_create_payload(
        server.service_id().as_str(),
        &json!({
            "title": title,
            "summary": title,
            "public": false,
            "plaintext_visible_services": [server.service_id()]
        }),
    )?;
    let (realm_id, events) = realm_bootstrap_event_batch_with_signing_seed(
        actor,
        draft,
        signing_seed,
        &verification_method_for_actor(actor),
    )?;
    let events = events
        .into_iter()
        .map(arkret_wire::EventInitialSubmission::online)
        .collect();
    let request = arkret_wire::EventsSubmitBatchRequestBody { events };
    expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(token)
            .json(&request),
        StatusCode::OK,
    )
    .await?;
    Ok(realm_id)
}

pub fn realm_bootstrap_event_batch(
    actor: &str,
    draft: RealmBootstrapDraft,
) -> Result<(String, Vec<arkret_wire::Event>)> {
    let (signing_seed, verification_method) = event_signing_identity(actor);
    realm_bootstrap_event_batch_with_signing_seed(actor, draft, signing_seed, &verification_method)
}

pub(crate) fn realm_bootstrap_event_batch_for_device(
    actor: &str,
    device_id: &str,
    draft: RealmBootstrapDraft,
) -> Result<(String, Vec<arkret_wire::Event>)> {
    let (signing_seed, verification_method) = event_signing_identity_for_device(actor, device_id);
    realm_bootstrap_event_batch_with_signing_seed(actor, draft, signing_seed, &verification_method)
}

/// The ordinary Realm genesis unit (`models/realm-and-space.md` section 2.5).
///
/// The `head_eq null` Control Move precondition every Realm genesis write
/// carries: each of these cells is written exactly once, at genesis.
fn head_eq_null_precondition(cell: &str) -> Result<arkret_wire::cba::Precondition> {
    Ok(arkret_wire::cba::Precondition {
        cell: arkret_wire::CellRef::new(cell.to_owned())?,
        predicate: arkret_wire::cba::Predicate {
            op: arkret_wire::cba::PredicateOp::HeadEq,
            value: Some(Value::Null),
            values: None,
            predicate_id: None,
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn realm_bootstrap_followup_event(
    actor: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    actor_seq: u64,
    predecessor: EventId,
    cell: &str,
    signing_seed: [u8; 32],
    verification_method: &DidUrl,
) -> Result<Event> {
    let mut event = event_envelope_with_chain_signing_identity_causal_refs_and_preconditions(
        actor,
        realm_id,
        kind,
        payload,
        Some(actor_seq),
        vec![predecessor],
        signing_seed,
        verification_method,
        Vec::new(),
        vec![head_eq_null_precondition(cell)?],
    );
    event.authorization_ref = Some(
        arkret_wire::AuthorizationRef::new(arkret_wire::REALM_AUTHORITY_ROOT_CELL)
            .map_err(anyhow::Error::msg)?,
    );
    refresh_typed_event_proof_with_signing_seed(&mut event, signing_seed)?;
    Ok(event)
}

/// v1 has no genesis `ak.capability.grant` slot: the creator's root authority is
/// the `ak.component.realm.authority_root.v1` cell that the `ak.realm.create`
/// reducer contract writes. Callers that need to name that authority on a later
/// Event use [`REALM_AUTHORITY_ROOT_CELL`], not a grant id.
///
/// `plaintext_visible_services` is a forbidden Realm policy field
/// (`realm.schema.json` `not.anyOf`): its only carrier is the
/// `ak.component.realm.plaintext_visible_services.v1` facet cell. Callers still
/// hand it to us on the create object because that is where it reads naturally,
/// so genesis lifts it off and emits the `ak.realm.plaintext_visible_services`
/// Event that actually writes the cell.
pub fn realm_bootstrap_event_batch_with_signing_seed(
    actor: &str,
    draft: RealmBootstrapDraft,
    signing_seed: [u8; 32],
    verification_method: &DidUrl,
) -> Result<(String, Vec<arkret_wire::Event>)> {
    let RealmBootstrapDraft {
        create,
        profile,
        policy_bundle,
        join_rule,
        history_visibility,
        history_sharing_policy,
        discovery,
        alias,
        plaintext_visible_services,
        delivery_binding_policy,
    } = draft;
    // Genesis carries no Realm id at all — the scope is `realm_genesis` and the
    // id falls out of the signed Event. The placeholder below is never read.
    let realm_event = event_envelope_with_chain_signing_identity_causal_refs_and_preconditions(
        actor,
        "ak:realm:AbJKasiJAuypE52tDrie6RY7PJds4G20xbtLIvYRInJk",
        "ak.realm.create",
        create.to_value()?,
        Some(0),
        Vec::new(),
        signing_seed,
        verification_method,
        Vec::new(),
        vec![head_eq_null_precondition(
            "ak:cell:ak.component.realm.create.v1:null",
        )?],
    );
    // The genesis carries no realm_id; the SDK resolved it from the Event, and
    // every follow-up in this batch MUST name that derived value or admission
    // reports `out_of_order_bootstrap`.
    let derived_realm_id = realm_event.realm_id.to_string();
    let mut events = vec![realm_event];
    let mut push_followup = |kind: &str, payload: Value, cell: String| -> Result<()> {
        let actor_seq = events.len() as u64;
        let predecessor = events.last().expect("Realm create exists").event_id.clone();
        events.push(realm_bootstrap_followup_event(
            actor,
            &derived_realm_id,
            kind,
            payload,
            actor_seq,
            predecessor,
            &cell,
            signing_seed,
            verification_method,
        )?);
        Ok(())
    };
    push_followup(
        arkret_wire::event_kind_str::REALM_PROFILE,
        profile.to_value()?,
        arkret_wire::null_subject_cell(arkret_wire::CellFamilyId::REALM_PROFILE_V1),
    )?;
    push_followup(
        arkret_wire::event_kind_str::REALM_POLICY_BUNDLE,
        policy_bundle.to_value()?,
        arkret_wire::null_subject_cell(arkret_wire::CellFamilyId::REALM_POLICY_BUNDLE_V1),
    )?;
    push_followup(
        arkret_wire::event_kind_str::REALM_JOIN_RULE,
        join_rule.to_value()?,
        arkret_wire::null_subject_cell(arkret_wire::CellFamilyId::REALM_JOIN_RULE_V1),
    )?;
    push_followup(
        arkret_wire::event_kind_str::REALM_HISTORY_VISIBILITY,
        history_visibility.to_value()?,
        arkret_wire::null_subject_cell(arkret_wire::CellFamilyId::REALM_HISTORY_VISIBILITY_V1),
    )?;
    if let Some(policy) = history_sharing_policy {
        push_followup(
            arkret_wire::event_kind_str::REALM_HISTORY_SHARING_POLICY,
            policy.to_value()?,
            arkret_wire::null_subject_cell(
                arkret_wire::CellFamilyId::REALM_HISTORY_SHARING_POLICY_V1,
            ),
        )?;
    }
    push_followup(
        arkret_wire::event_kind_str::REALM_DISCOVERY,
        discovery.to_value()?,
        arkret_wire::null_subject_cell(arkret_wire::CellFamilyId::REALM_DISCOVERY_V1),
    )?;
    if let Some(alias) = alias {
        push_followup(
            arkret_wire::event_kind_str::REALM_ALIAS,
            alias.to_value()?,
            arkret_wire::null_subject_cell(arkret_wire::CellFamilyId::REALM_ALIAS_V1),
        )?;
    }
    if let Some(services) = plaintext_visible_services {
        push_followup(
            arkret_wire::event_kind_str::REALM_PLAINTEXT_VISIBLE_SERVICES,
            services.to_value()?,
            arkret_wire::null_subject_cell(
                arkret_wire::CellFamilyId::REALM_PLAINTEXT_VISIBLE_SERVICES_V1,
            ),
        )?;
    };
    push_followup(
        arkret_wire::event_kind_str::REALM_DELIVERY_BINDING_POLICY,
        delivery_binding_policy.to_value()?,
        arkret_wire::null_subject_cell(arkret_wire::CellFamilyId::REALM_DELIVERY_BINDING_POLICY_V1),
    )?;
    push_followup(
        arkret_wire::event_kind_str::MEMBER_STATE,
        member_join_payload_value(&derived_realm_id, actor)?,
        format!("ak:cell:ak.component.member.state.v1:{actor}"),
    )?;
    arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&events)
        .map_err(|error| anyhow!("Realm bootstrap validation failed: {error}"))?;
    Ok((derived_realm_id, events))
}

pub async fn add_member(
    server: &ArkretServer,
    token: &str,
    actor: &str,
    realm_id: &str,
    member: &str,
) -> Result<()> {
    submit_event(
        server,
        token,
        actor,
        realm_id,
        "ak.member.state",
        member_join_payload(realm_id, member),
        StatusCode::OK,
    )
    .await?;
    Ok(())
}

pub async fn add_member_with_signing_seed(
    server: &ArkretServer,
    token: &str,
    actor: &str,
    realm_id: &str,
    member: &str,
    signing_seed: [u8; 32],
) -> Result<()> {
    submit_event_with_signing_seed(
        server,
        token,
        actor,
        realm_id,
        "ak.member.state",
        member_join_payload(realm_id, member),
        StatusCode::OK,
        signing_seed,
    )
    .await?;
    Ok(())
}

pub async fn send_message(
    server: &ArkretServer,
    token: &str,
    actor: &str,
    realm_id: &str,
    strand_id: &str,
    body: &str,
) -> Result<Value> {
    let payload = message_create_text_payload(strand_id, body)?;
    submit_event(
        server,
        token,
        actor,
        realm_id,
        "ak.message.create",
        payload,
        StatusCode::OK,
    )
    .await
}

pub async fn submit_event(
    server: &ArkretServer,
    token: &str,
    actor: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    status: StatusCode,
) -> Result<Value> {
    let (signing_seed, verification_method) = event_signing_identity(actor);
    submit_event_with_signing_seed_and_verification_method(
        server,
        token,
        actor,
        realm_id,
        kind,
        payload,
        status,
        signing_seed,
        &verification_method,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn submit_event_with_signing_seed(
    server: &ArkretServer,
    token: &str,
    actor: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    status: StatusCode,
    signing_seed: [u8; 32],
) -> Result<Value> {
    submit_event_with_signing_seed_and_verification_method(
        server,
        token,
        actor,
        realm_id,
        kind,
        payload,
        status,
        signing_seed,
        &default_event_verification_method(actor),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn submit_event_with_signing_seed_and_verification_method(
    server: &ArkretServer,
    token: &str,
    actor: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    status: StatusCode,
    signing_seed: [u8; 32],
    verification_method: &DidUrl,
) -> Result<Value> {
    let frontier = expect_json(
        server
            .http()
            .request(query_method(), server.url("/_arkret/self/events/frontier"))
            .json(&events_frontier_request_body(Some(actor), Some(realm_id))?)
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    let state: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
        serde_json::from_value(frontier.clone())?;
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmActor(frontier) =
        state.frontier
    else {
        return Err(anyhow!(
            "combined selector returned the wrong frontier variant"
        ));
    };
    frontier.validate()?;
    let expected_actor_id = project_full_id_to_core_id(&DidFullId::new(actor.to_owned())?)?;
    if frontier.realm_id.as_str() != realm_id || frontier.actor_id != expected_actor_id {
        return Err(anyhow!("combined selector returned the wrong actor scope"));
    }
    let mut event = event_envelope_with_chain_and_signing_identity(
        actor,
        realm_id,
        kind,
        payload,
        Some(frontier.next_actor_seq),
        frontier.frontier_event_ids,
        signing_seed,
        verification_method,
    );
    let descriptor = arkret_wire::EventKind::from(kind).descriptor();
    let is_control_move = descriptor
        .is_some_and(|descriptor| descriptor.reducer_input && descriptor.plane == Some("control"));
    let is_data_event = descriptor
        .is_some_and(|descriptor| descriptor.reducer_input && descriptor.plane == Some("data"));
    if is_control_move || is_data_event {
        let seal_frontier =
            realm_seal_frontier_for(server, token, realm_id, Duration::from_secs(10)).await?;
        let state: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
            serde_json::from_value(seal_frontier)?;
        let arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(frontier) =
            state.frontier
        else {
            return Err(anyhow!(
                "Realm selector returned the wrong frontier variant"
            ));
        };
        if is_control_move {
            event.seal_basis = Some(frontier.seal_basis());
            let physical_millis = chrono::Utc::now().timestamp_millis();
            event.hlc = Some(Hlc::new(format!("{physical_millis:012x}-0000-a13f9c2e"))?);
        } else {
            event.seal_ref = Some(frontier.seal_id);
            event.auth_context = Some(AuthContext {
                actor_id: DidCoreId::from(project_full_id_to_core_id(&DidFullId::new(
                    actor.to_owned(),
                )?)?),
                key_id: verification_method.to_string(),
                key_epoch: 0,
                credential_epoch: None,
            });
        }
        refresh_typed_event_proof_with_signing_seed(&mut event, signing_seed)?;
    }
    let mut body = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(token)
            .json(&crate::publication::initial_submission(event.clone(), "")?),
        status,
    )
    .await?;
    if status.is_success() {
        ensure_submit_event_id(&mut body, &event);
    }
    Ok(body)
}

async fn realm_seal_frontier_for(
    server: &ArkretServer,
    token: &str,
    realm_id: &str,
    timeout: Duration,
) -> Result<Value> {
    let deadline = Instant::now() + timeout;
    loop {
        let response = server
            .http()
            .request(query_method(), server.url("/_arkret/self/events/frontier"))
            .json(&events_frontier_request_body(None, Some(realm_id))?)
            .bearer_auth(token)
            .send()
            .await?;
        let status = response.status();
        if status == StatusCode::OK {
            return Ok(response.json().await?);
        }
        let body = response.text().await.unwrap_or_default();
        if status == StatusCode::SERVICE_UNAVAILABLE
            && body.contains("frontier_unavailable")
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        }
        return Err(anyhow!(
            "expected Realm frontier HTTP 200, got {status}: {body}"
        ));
    }
}

pub fn event_envelope(actor: &str, realm_id: &str, kind: &str, payload: Value) -> Event {
    let (signing_seed, verification_method) = event_signing_identity(actor);
    event_envelope_with_signing_seed_and_verification_method(
        actor,
        realm_id,
        kind,
        payload,
        signing_seed,
        &verification_method,
    )
}

/// A caller-signed Control Move that carries its own `head_eq` guard.
///
/// A precondition is signed content, so a surface that requires one -- the
/// policy-server writes, for instance -- can only get it from the caller. The
/// service used to read the settled value and attach the guard itself, which is
/// the co-signing `key-management.md` section 411 forbids.
pub fn event_envelope_with_preconditions(
    actor: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    preconditions: Vec<arkret_wire::cba::Precondition>,
) -> Event {
    let (signing_seed, verification_method) = event_signing_identity(actor);
    event_envelope_with_chain_signing_identity_causal_refs_and_preconditions(
        actor,
        realm_id,
        kind,
        payload,
        None,
        Vec::new(),
        signing_seed,
        &verification_method,
        Vec::new(),
        preconditions,
    )
}

/// The `head_eq` guard naming the complete settled value a Control Move
/// replaces.
pub fn head_eq_precondition(cell: &str, settled_value: Value) -> arkret_wire::cba::Precondition {
    serde_json::from_value(json!({
        "cell": cell,
        "predicate": { "op": "head_eq", "value": settled_value },
    }))
    .expect("cotest head_eq precondition")
}

pub fn event_envelope_with_signing_seed(
    actor: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    signing_seed: [u8; 32],
) -> Event {
    event_envelope_with_signing_seed_and_verification_method(
        actor,
        realm_id,
        kind,
        payload,
        signing_seed,
        &verification_method_for_actor(actor),
    )
}

pub fn event_envelope_with_signing_seed_and_verification_method(
    actor: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    signing_seed: [u8; 32],
    verification_method: &DidUrl,
) -> Event {
    event_envelope_with_chain_and_signing_identity(
        actor,
        realm_id,
        kind,
        payload,
        None,
        Vec::new(),
        signing_seed,
        verification_method,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn event_envelope_at_frontier_with_signing_seed(
    actor: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    next_actor_seq: u64,
    frontier_event_ids: Vec<EventId>,
    signing_seed: [u8; 32],
) -> Event {
    event_envelope_with_chain_and_signing_identity(
        actor,
        realm_id,
        kind,
        payload,
        Some(next_actor_seq),
        frontier_event_ids,
        signing_seed,
        &verification_method_for_actor(actor),
    )
}

#[allow(clippy::too_many_arguments)]
fn event_envelope_with_chain_and_signing_identity(
    actor: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    actor_seq: Option<u64>,
    prev_event_ids: Vec<EventId>,
    signing_seed: [u8; 32],
    verification_method: &DidUrl,
) -> Event {
    event_envelope_with_chain_and_signing_identity_and_causal_refs(
        actor,
        realm_id,
        kind,
        payload,
        actor_seq,
        prev_event_ids,
        signing_seed,
        verification_method,
        Vec::new(),
    )
}

#[allow(clippy::too_many_arguments)]
fn event_envelope_with_chain_and_signing_identity_and_causal_refs(
    actor: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    actor_seq: Option<u64>,
    prev_event_ids: Vec<EventId>,
    signing_seed: [u8; 32],
    verification_method: &DidUrl,
    causal_refs: Vec<String>,
) -> Event {
    event_envelope_with_chain_signing_identity_causal_refs_and_preconditions(
        actor,
        realm_id,
        kind,
        payload,
        actor_seq,
        prev_event_ids,
        signing_seed,
        verification_method,
        causal_refs,
        Vec::new(),
    )
}

/// Envelope `created_at` for the next Event this process builds: the platform
/// clock, never moving backward.
///
/// It has to be the real clock rather than a base stamped at process start and
/// stepped per Event. Tests share this process and run concurrently, so a test
/// that begins a minute in has its Realm bootstrap stamped by the SDK with the
/// real clock while a counter anchored at process start is still handing out
/// timestamps from a minute ago — the harness Event then lands before the
/// bootstrap Event it names in `prev_refs` and the server rejects it with
/// `created_at_before_causal_predecessor`.
///
/// The floor exists because `created_at` sits in the digest preimage: two
/// Events built inside one millisecond would otherwise tie while one names the
/// other.
fn harness_event_created_at() -> DateTime<Utc> {
    static LAST_ISSUED: Mutex<Option<DateTime<Utc>>> = Mutex::new(None);
    let mut last_issued = LAST_ISSUED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = Utc::now();
    let issued = match *last_issued {
        Some(previous) if now <= previous => previous + chrono::Duration::milliseconds(1),
        _ => now,
    };
    *last_issued = Some(issued);
    issued
}

/// Preconditions are signed content, so a Control Move that needs one has to
/// declare it here rather than have it stamped onto an already-signed envelope.
#[allow(clippy::too_many_arguments)]
fn event_envelope_with_chain_signing_identity_causal_refs_and_preconditions(
    actor: &str,
    realm_id: &str,
    kind: &str,
    mut payload: Value,
    actor_seq: Option<u64>,
    prev_event_ids: Vec<EventId>,
    signing_seed: [u8; 32],
    verification_method: &DidUrl,
    causal_refs: Vec<String>,
    preconditions: Vec<arkret_wire::cba::Precondition>,
) -> Event {
    let unique_seq = NEXT_EVENT_SEQ.fetch_add(1, Ordering::Relaxed);
    let actor_seq = actor_seq.unwrap_or(unique_seq);
    let hlc_logical = unique_seq & 0xffff;
    let suffix = format!("01999999-0000-7000-8000-{unique_seq:012x}");
    normalize_message_payload(kind, &mut payload);
    // A static timestamp cannot stay behind a causal predecessor: the Realm
    // bootstrap the SDK submits is stamped with the real clock, so any harness
    // Event pinned to a fixed past date lands before the Event it names in
    // `prev_refs` and the server rejects it with
    // `created_at_before_causal_predecessor`. Anchor on the process clock and
    // step once per built Event so successors are strictly later.
    let created_at = harness_event_created_at();
    let actor_full_id = DidFullId::new(actor.to_owned()).expect("cotest actor DID");
    let actor_id = arkret_identifiers::DidCoreId::from(
        arkret_identifiers::project_full_id_to_core_id(&actor_full_id)
            .expect("cotest actor DID projects to a core id"),
    );
    // The `suffix` is no longer an id: spec encoding.md section 4.0 derives
    // `event_id` from the Event's own content, so the harness builds with the
    // derived constructor and callers read the id back off the built Event.
    let _ = &suffix;
    let mut event = arkret_wire::test_support::raw_event_at(
        kind,
        // A Realm genesis carries the closed genesis scope and no realm_id;
        // the Realm's id is derived from the Event (spec realm-and-space.md
        // section 2.5.0).
        if kind == "ak.realm.create" {
            ScopeRef::RealmGenesis
        } else {
            ScopeRef::Realm {
                realm_id: RealmId::new(realm_id.to_owned()).expect("cotest Realm id"),
            }
        },
        actor_id.clone(),
        actor_seq,
        arkret_identifiers::Hlc::new(format!("01970e589d21-{hlc_logical:04x}-a13f9c2e"))
            .expect("cotest HLC"),
        payload,
        created_at,
    )
    .expect("SDK Event builder accepts cotest envelope");
    event.prev_refs = prev_event_ids;
    event.preconditions = preconditions;
    event.causal_refs = causal_refs
        .into_iter()
        .map(|value| arkret_identifiers::Hash::new(value).expect("cotest causal ref digest"))
        .collect();
    // No cell writes are stamped here. The v1 Event wire has no producer
    // `effects[]`: reducer writes are derived from `kind + payload` through the
    // contract registry, so a client that tried to declare them would be
    // asserting something the wire cannot carry.
    event.unsigned.insert(
        "local_operation_idempotency_alias".to_owned(),
        json!(format!("ak:operation:{suffix}")),
    );
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        signing_seed,
        actor_full_id,
        verification_method.to_owned(),
    );
    arkret::signatures::sign_event(
        &mut event,
        &signer,
        verification_method,
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .expect("SDK Event signer accepts cotest envelope");
    event
}

pub(crate) fn event_envelope_with_chain(
    actor: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    actor_seq: u64,
    prev_event_id: Option<&str>,
) -> Event {
    let (signing_seed, verification_method) = event_signing_identity(actor);
    event_envelope_with_chain_and_signing_identity(
        actor,
        realm_id,
        kind,
        payload,
        Some(actor_seq),
        prev_event_id
            .map(|value| EventId::new(value.to_owned()).expect("accepted actor frontier Event id"))
            .into_iter()
            .collect(),
        signing_seed,
        &verification_method,
    )
}

pub(crate) fn event_envelope_with_chain_for_device(
    actor: &str,
    device_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    actor_seq: u64,
    prev_event_id: Option<&str>,
) -> Event {
    let (signing_seed, verification_method) = event_signing_identity_for_device(actor, device_id);
    event_envelope_with_chain_and_signing_identity(
        actor,
        realm_id,
        kind,
        payload,
        Some(actor_seq),
        prev_event_id
            .map(|value| EventId::new(value.to_owned()).expect("accepted actor frontier Event id"))
            .into_iter()
            .collect(),
        signing_seed,
        &verification_method,
    )
}

fn normalize_message_payload(kind: &str, payload: &mut Value) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };

    match kind {
        "ak.message.create" => {
            object
                .entry("track_name".to_owned())
                .or_insert_with(|| Value::String("discussion".to_owned()));
            object.remove("thread_id");
            normalize_message_content(object);
        }
        "ak.message.revise" => {
            if let Some(target_event_id) = object.remove("target_event_id")
                && !object.contains_key("target_ref")
                && !object.contains_key("message_id")
                && !object.contains_key("revision_of")
            {
                object.insert(
                    "target_ref".to_owned(),
                    message_ref_from_event_ref(target_event_id),
                );
            }
            object.remove("thread_id");
            normalize_message_content(object);
        }
        "ak.message.redact" => {
            if !object.contains_key("target_event_id") {
                if let Some(event_id) = object.get("event_id").cloned() {
                    object.insert("target_event_id".to_owned(), event_id);
                } else if let Some(target_ref) = object.get("target_ref").and_then(Value::as_str) {
                    if target_ref.starts_with("ak:event:") {
                        object.insert(
                            "target_event_id".to_owned(),
                            Value::String(target_ref.to_owned()),
                        );
                    } else if let Ok(message_id) = MessageId::new(target_ref.to_owned()) {
                        object.insert(
                            "target_event_id".to_owned(),
                            Value::String(message_id.event_id().to_string()),
                        );
                    }
                }
            }
            object.remove("thread_id");
        }
        _ => {}
    }
}

pub(crate) fn ensure_submit_event_id(body: &mut Value, event: &Event) {
    let Some(object) = body.as_object_mut() else {
        return;
    };
    if object.contains_key("event_id") {
        return;
    }
    let accepted_id = object
        .get("accepted")
        .and_then(Value::as_array)
        .and_then(|accepted| accepted.first())
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let event_id = accepted_id.or_else(|| Some(event.event_id.to_string()));
    if let Some(event_id) = event_id {
        object.insert("event_id".to_owned(), Value::String(event_id));
    }
}

fn normalize_message_content(object: &mut serde_json::Map<String, Value>) {
    let body = object.remove("body");
    if !object.contains_key("content")
        && let Some(body) = body
    {
        object.insert(
            "content".to_owned(),
            json!({
                "kind": "ak.content.text",
                "body": body,
            }),
        );
    }
    if let Some(content) = object.get_mut("content").and_then(Value::as_object_mut)
        && content.get("kind").is_none()
        && content.get("body").is_some()
    {
        content.insert(
            "kind".to_owned(),
            Value::String("ak.content.text".to_owned()),
        );
    }
}

fn message_ref_from_event_ref(value: Value) -> Value {
    if let Some(event_id) = value.as_str()
        && let Ok(event_id) = EventId::new(event_id.to_owned())
    {
        return Value::String(MessageId::from_event_id(&event_id).to_string());
    }
    value
}

pub(crate) fn message_create_text_payload(strand_id: &str, body: &str) -> Result<Value> {
    message_create_text_payload_for_strand(parse_strand_id(strand_id)?, body)
}

pub(crate) fn message_create_text_payload_for_strand(
    strand_id: StrandId,
    body: &str,
) -> Result<Value> {
    let content = ContentBlock::text(body);
    MessageCreatePayload::with_content(strand_id, "discussion", content)
        .to_value()
        .map_err(|err| anyhow!("message create payload serialize: {err}"))
}

pub(crate) fn parse_strand_id(strand_id: &str) -> Result<StrandId> {
    StrandId::new(strand_id.to_owned()).map_err(|err| anyhow!("invalid strand_id: {err}"))
}

pub(crate) fn message_revise_text_payload(target_event_id: &str, body: &str) -> Result<Value> {
    serialize_payload(
        &MessageRevisePayload {
            message_id: Some(message_id_from_event_id(target_event_id)?),
            target_ref: None,
            revision_of: None,
            track_name: None,
            content: Some(ContentBlock::text(body)),
            encrypted_content: None,
            metadata: None,
            encrypted_metadata: None,
            reason: None,
        },
        "message revise payload",
    )
}

pub(crate) fn message_redact_payload(target_event_id: &str, reason: Option<&str>) -> Result<Value> {
    serialize_payload(
        &MessageRedactPayload {
            message_id: Some(message_id_from_event_id(target_event_id)?),
            target_ref: None,
            event_id: None,
            target_event_id: Some(
                EventId::new(target_event_id.to_owned())
                    .map_err(|err| anyhow!("invalid message target event_id: {err}"))?,
            ),
            track_name: None,
            reason: reason.map(ToOwned::to_owned),
            preserve: None,
        },
        "message redact payload",
    )
}

pub(crate) fn member_join_payload_value(realm_id: &str, actor_id: &str) -> Result<Value> {
    member_payload(
        realm_id,
        actor_id,
        MembershipPayloadState::Join,
        Some(DeliveryStatus::Unroutable),
        None,
        None,
        None,
    )
}

pub(crate) fn member_transition_payload(
    realm_id: &str,
    actor_id: &str,
    membership: MembershipPayloadState,
    reason: Option<&str>,
) -> Result<Value> {
    member_payload(
        realm_id,
        actor_id,
        membership,
        None,
        None,
        None,
        reason.map(ToOwned::to_owned),
    )
}

pub(crate) fn invite_create_payload(
    invitee: &str,
    recipient_service_id: &str,
    introduction_evidence_digest: impl Into<String>,
    expires_at: DateTime<Utc>,
) -> Result<Value> {
    let invitee_full_id = DidFullId::new(invitee.to_owned())
        .map_err(|err| anyhow!("invalid invitee full id: {err}"))?;
    let recipient_service_id = arkret_identifiers::DidCoreId::new(recipient_service_id.to_owned())
        .map_err(|err| anyhow!("invalid recipient service core id: {err}"))?;
    let current_record_url = format!(
        "https://cotest.invalid{}",
        arkret_models_identity::canonical_service_current_record_path(&recipient_service_id)
    );
    InviteCreatePayload::new(
        arkret_identifiers::project_full_id_to_core_id(&invitee_full_id)?,
        InviteDeliveryTarget::principal_server(
            recipient_service_id,
            arkret_models_identity::ServiceResolutionCarrier::CurrentRecordUrl {
                current_record_url,
                pinned_record_digest: None,
            },
        ),
        Hash::new(introduction_evidence_digest.into())
            .map_err(|err| anyhow!("invalid introduction_evidence_digest: {err}"))?,
        expires_at,
    )
    .to_value()
    .map_err(|err| anyhow!("invite create payload serialize: {err}"))
}

fn member_payload(
    realm_id: &str,
    actor_id: &str,
    membership: MembershipPayloadState,
    delivery_status: Option<DeliveryStatus>,
    delivery_binding: Option<Value>,
    invite_ref: Option<String>,
    reason: Option<String>,
) -> Result<Value> {
    let delivery_binding = delivery_binding
        .map(serde_json::from_value::<MemberDeliveryBinding>)
        .transpose()
        .map_err(|error| anyhow!("invalid member delivery binding: {error}"))?;
    let invite_ref = invite_ref
        .map(|value| serde_json::from_value::<MembershipInviteRef>(Value::String(value)))
        .transpose()
        .map_err(|error| anyhow!("invalid membership invite ref: {error}"))?;
    MembershipPayload {
        membership,
        strand_id: None,
        realm_id: Some(RealmId::new(realm_id.to_owned()).map_err(|err| anyhow!("{err}"))?),
        actor_id: Some(arkret_identifiers::DidCoreId::from(
            arkret_identifiers::project_full_id_to_core_id(
                &DidFullId::new(actor_id.to_owned()).map_err(|err| anyhow!("{err}"))?,
            )?,
        )),
        principal_authority_instance: None,
        delivery_status,
        delivery_binding,
        gate_proofs: Vec::new(),
        via_service_ids: Vec::new(),
        reason,
        invite_ref,
    }
    .to_value()
    .map_err(|err| anyhow!("member state payload serialize: {err}"))
}

fn message_id_from_event_id(event_id: &str) -> Result<MessageId> {
    let event_id = EventId::new(event_id.to_owned())
        .map_err(|err| anyhow!("invalid message target event_id: {err}"))?;
    Ok(MessageId::from_event_id(&event_id))
}

fn serialize_payload<T: Serialize>(payload: &T, context: &str) -> Result<Value> {
    serde_json::to_value(payload).map_err(|err| anyhow!("{context} serialize: {err}"))
}

pub fn encrypted_envelope(content_type: &str, ciphertext: &str) -> Value {
    json!({
        "scheme": "mls_rfc9420",
        "version": 1,
        "group_id": "ak:mls:test",
        "epoch": 1,
        "content_type": content_type,
        "ciphertext": ciphertext,
        "authentication_tag": "opaque-tag",
        "aad": {"suite": "test"},
        "key_ref": {"kid": "did:webvh:z6mkfixture:alice.example#device"},
        "digests": {
            "ciphertext": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    })
}

/// Builds a signed envelope that additionally carries semantic causal edges.
///
/// RSVP needs this: the entry's schedule basis MUST be a subset of
/// `causal_refs`, and those same edges decide which earlier heads a response
/// dominates. Two responses that omit each other's digest are concurrent by
/// construction, which is exactly what the convergence scenario exercises.
pub(crate) fn event_envelope_with_causal_refs(
    actor: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    actor_seq: Option<u64>,
    prev_event_ids: Vec<EventId>,
    causal_refs: Vec<String>,
) -> Event {
    let (signing_seed, verification_method) = event_signing_identity(actor);
    event_envelope_with_chain_and_signing_identity_and_causal_refs(
        actor,
        realm_id,
        kind,
        payload,
        actor_seq,
        prev_event_ids,
        signing_seed,
        &verification_method,
        causal_refs,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn event_envelope_with_causal_refs_for_device(
    actor: &str,
    device_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    actor_seq: Option<u64>,
    prev_event_ids: Vec<EventId>,
    causal_refs: Vec<String>,
) -> Event {
    let (signing_seed, verification_method) = event_signing_identity_for_device(actor, device_id);
    event_envelope_with_chain_and_signing_identity_and_causal_refs(
        actor,
        realm_id,
        kind,
        payload,
        actor_seq,
        prev_event_ids,
        signing_seed,
        &verification_method,
        causal_refs,
    )
}

#[cfg(test)]
mod realm_bootstrap_tests {
    use super::*;

    const ACTOR: &str = "did:webvh:z6mkfixture:alice.soland.local";
    const ACTOR_CORE: &str = "ak:did_core:webvh:z6mkfixture";
    const SERVICE: &str = "ak:did_core:web:service.soland.local";
    const SERVICE_FULL: &str = "did:web:service.soland.local";
    const SALT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn draft(extra: Value) -> RealmBootstrapDraft {
        let mut input = json!({
            "title": "Bootstrap Realm",
            "summary": "Complete atomic bootstrap",
            "genesis_salt": SALT,
            "plaintext_visible_services": []
        });
        input
            .as_object_mut()
            .expect("fixture object")
            .extend(extra.as_object().expect("extra object").clone());
        realm_create_payload(SERVICE, &input).expect("valid Realm bootstrap draft")
    }

    fn build(draft: RealmBootstrapDraft) -> (String, Vec<Event>) {
        realm_bootstrap_event_batch_with_signing_seed(
            ACTOR,
            draft,
            [7; 32],
            &DidUrl::new(format!("{ACTOR}#device-1")).expect("valid verification method"),
        )
        .expect("valid Realm bootstrap unit")
    }

    #[test]
    fn ordinary_bootstrap_uses_the_registered_order_and_explicit_creator_member() {
        let (_, events) = build(draft(json!({
            "alias": "general:service.soland.local",
            "alias_authority_service_full_id": SERVICE_FULL
        })));
        let kinds: Vec<_> = events.iter().map(|event| event.kind.as_str()).collect();
        assert_eq!(
            kinds,
            [
                arkret_wire::event_kind_str::REALM_CREATE,
                arkret_wire::event_kind_str::REALM_PROFILE,
                arkret_wire::event_kind_str::REALM_POLICY_BUNDLE,
                arkret_wire::event_kind_str::REALM_JOIN_RULE,
                arkret_wire::event_kind_str::REALM_HISTORY_VISIBILITY,
                arkret_wire::event_kind_str::REALM_DISCOVERY,
                arkret_wire::event_kind_str::REALM_ALIAS,
                arkret_wire::event_kind_str::REALM_DELIVERY_BINDING_POLICY,
                arkret_wire::event_kind_str::MEMBER_STATE,
            ]
        );
        assert_eq!(
            events
                .last()
                .and_then(|event| event.payload.get("actor_id")),
            Some(&json!(ACTOR_CORE))
        );
    }

    #[test]
    fn bootstrap_rejects_missing_or_reordered_required_facets() {
        let (_, events) = build(draft(json!({})));
        let mut missing_profile = events.clone();
        missing_profile.remove(1);
        assert!(
            arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&missing_profile)
                .is_err()
        );

        let mut reordered = events;
        reordered.swap(1, 2);
        assert!(arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&reordered).is_err());
    }

    #[test]
    fn exact_retry_reuses_prepared_signed_bytes() {
        let (_, prepared) = build(draft(json!({})));
        let retry = prepared.clone();
        assert_eq!(
            serde_json::to_vec(&prepared).expect("serialize prepared unit"),
            serde_json::to_vec(&retry).expect("serialize retry unit")
        );
    }
}
