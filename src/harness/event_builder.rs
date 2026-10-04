use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::Ordering;
use std::sync::{LazyLock, Mutex};

use anyhow::{Result, anyhow};
use arkret::{
    DeviceId, DeviceMessageId, DeviceMessageTarget, DeviceMessagesSendRequestBody, ProtocolKind,
};
use arkret_identifiers::{
    Did, DidCoreId, EventId, Hash, MessageId, RealmId, StrandId, project_did_to_core_id,
};
use arkret_models_collaboration::events_payloads::{
    ContentBlock, MessageCreatePayload, MessageRedactPayload, MessageRevisePayload,
};
use arkret_models_collaboration::governance::membership_invite::{
    InviteCreatePayload, MembershipInviteRef, MembershipPayload, MembershipPayloadState,
};
use arkret_models_collaboration::governance::moderation::{
    ModerationReportAcceptedTargetBasis, ModerationReportRequestBody,
};
use arkret_wire::{AccountId, ActorId, DidUrl, Event, ScopeRef};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::{Value, json};

use super::assertions::expect_json;
use super::client::TestActorClient;
use super::server::ArkretServer;
use super::{
    NEXT_EVENT_SEQ, RealmBootstrapDraft, canonical_device_id, member_join_payload,
    realm_create_payload_for_station,
};

type RegisteredEventSigner = ([u8; 32], DidUrl, DidCoreId);

static REGISTERED_EVENT_SIGNERS: LazyLock<Mutex<HashMap<String, Vec<RegisteredEventSigner>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn register_event_signing_identity(
    actor: &str,
    signing_seed: [u8; 32],
    verification_method: impl Into<String>,
    station_id: DidCoreId,
) {
    let verification_method = DidUrl::new(verification_method)
        .expect("registered Event signer verification method is a DID URL");
    let mut signers = REGISTERED_EVENT_SIGNERS
        .lock()
        .expect("registered Event signer lock");
    let actor_signers = signers.entry(actor.to_owned()).or_default();
    actor_signers.retain(|(_, registered_method, _)| registered_method != &verification_method);
    actor_signers.push((signing_seed, verification_method, station_id));
}

pub(crate) fn event_signing_identity(actor: &str) -> ([u8; 32], DidUrl) {
    REGISTERED_EVENT_SIGNERS
        .lock()
        .expect("registered Event signer lock")
        .get(actor)
        .and_then(|signers| signers.last())
        .cloned()
        .map(|(seed, method, _)| (seed, method))
        .unwrap_or_else(|| {
            let verification_method = default_event_verification_method(actor);
            let signing_seed =
                arkret::signatures::development_signing_key_seed(&verification_method);
            (signing_seed, verification_method)
        })
}

fn event_station_id(actor: &str) -> DidCoreId {
    REGISTERED_EVENT_SIGNERS
        .lock()
        .expect("registered Event signer lock")
        .get(actor)
        .and_then(|signers| signers.last())
        .map(|(_, _, station_id)| station_id.clone())
        .unwrap_or_else(|| {
            DidCoreId::new("ak:did_core:web:principal.example").expect("cotest default Station id")
        })
}

pub(crate) fn event_signing_identity_for_device(
    actor: &str,
    device_id: &str,
) -> ([u8; 32], DidUrl) {
    let verification_method = DidUrl::new(format!("{actor}#{}", canonical_device_id(device_id)))
        .expect("cotest client Event signer verification method is a DID URL");
    REGISTERED_EVENT_SIGNERS
        .lock()
        .expect("registered Event signer lock")
        .get(actor)
        .and_then(|signers| {
            signers
                .iter()
                .find(|(_, registered_method, _)| registered_method == &verification_method)
        })
        .cloned()
        .map(|(seed, method, _)| (seed, method))
        .unwrap_or_else(|| {
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
        .and_then(|signers| {
            signers
                .iter()
                .find(|(_, registered_method, _)| registered_method == verification_method)
        })
        .map(|(seed, ..)| *seed)
}

fn verification_method_for_actor(actor: &str) -> DidUrl {
    default_event_verification_method(actor)
}

/// Project a Station account and take a development session for it.
///
/// **This is not the canonical chain.** It posts a
/// [`NonProtocolTestBody`](crate::harness::NonProtocolTestBody) to the
/// deployment-private registration endpoint and then calls [`dev_login`], so
/// nothing here exercises account authorization, the OAuth handoff, PCR
/// genesis, or identity binding. The account it produces has no DID document it
/// controls and no verified binding.
///
/// Use it where the test needs a principal to *exist* and is not about how one
/// comes to exist. A scenario that claims to be services-live canonical must
/// not reach for it: the canonical chain lives in
/// `cotest_test_support::provisioning` and is the same code the TypeScript
/// suite reaches through `cotest-provision`.
pub async fn register_account_via_dev_login(
    server: &ArkretServer,
    did: &str,
    handle: &str,
    device_id: &str,
) -> Result<String> {
    let device_id = canonical_device_id(device_id);
    let did = arkret_identifiers::Did::new(did.to_owned())?;
    let requested_localpart = handle.trim().trim_start_matches('@');
    let localpart = arkret_wire::string_profiles::prepare_handle_localpart(requested_localpart)
        .unwrap_or_else(|_| {
            format!(
                "cotest-{}",
                device_id.rsplit(':').next().unwrap_or("account")
            )
        });
    let body = crate::harness::NonProtocolTestBody::new(serde_json::json!({
        "did": did,
        "handle": localpart,
        "display_name": handle.trim_start_matches('@'),
        "device_id": arkret_identifiers::DeviceId::new(device_id.clone())?,
    }));
    expect_json(
        server.account_registration_request().json(&body),
        StatusCode::OK,
    )
    .await?;

    dev_login(server, did.as_str(), &device_id).await
}

/// [`register_account_via_dev_login`] plus a primary localpart claim.
///
/// Carries the same caveat: development seam, not the canonical chain.
pub async fn register_account_with_localpart_via_dev_login(
    server: &ArkretServer,
    did: &str,
    display_handle: &str,
    localpart: &str,
    device_id: &str,
) -> Result<String> {
    let token = register_account_via_dev_login(server, did, display_handle, device_id).await?;
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

/// Take a session straight from the deployment-private dev-login endpoint.
///
/// No account authorization, no grant issuance, no DPoP binding — a token the
/// Station will accept because it is configured to in test builds. Scenarios
/// that assert anything about how a session is obtained must use the canonical
/// chain instead; `conformance/inkson_client.rs` already fails a conformance
/// path that is caught using this.
pub async fn dev_login(server: &ArkretServer, actor: &str, device_id: &str) -> Result<String> {
    let device_id = canonical_device_id(device_id);
    let actor_id = project_did_to_core_id(&Did::new(actor.to_owned())?)?;
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
    let token = login["session_credential"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("login response did not include session_credential: {login}"))?;
    let verification_method = default_event_verification_method(actor);
    register_event_signing_identity(
        actor,
        arkret::signatures::development_signing_key_seed(&verification_method),
        verification_method.as_str().to_owned(),
        server.service_id().clone(),
    );
    Ok(token)
}

pub fn device_message_send_request(
    recipient: &str,
    device_id: &str,
    device_message_id: &str,
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
        device_message_id: DeviceMessageId::new(device_message_id.to_owned())?,
        kind: ProtocolKind::new(kind.to_owned()).map_err(anyhow::Error::msg)?,
        content,
        expires_at,
    };
    let mut devices = BTreeMap::new();
    devices.insert(DeviceId::new(device_id.to_owned())?, target);
    let mut messages = BTreeMap::new();
    messages.insert(
        project_did_to_core_id(&Did::new(recipient.to_owned())?)?,
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
    let draft = realm_create_payload_for_station(
        server.service_id().as_str(),
        &json!({
            "title": title,
            "summary": title,
            "public": false,
            "plaintext_visible_services": [server.service_id()]
        }),
    )?;
    let (realm_id, events) = realm_bootstrap_event_batch(actor, draft)?;
    let request = ordinary_realm_bootstrap_submission(events)?;
    request.validate()?;
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

/// Author the exact signed ordinary Event carried by the self moderation-report
/// operation. The reporter is always the actor's core DID while Event proof
/// verification methods remain DID URLs through `TestActorClient`.
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
    let reporter_id = project_did_to_core_id(&Did::new(actor.actor.clone())?)?;
    let reporter_account_id = AccountId::new(
        reporter_id.clone(),
        DidCoreId::new(actor.service_id.clone())?,
    );
    let mut payload = json!({
        "realm_id": realm_id,
        "target_ref": target_ref,
        "report_reason_code": "spam",
        "reporter_id": reporter_id,
        "provenance": "self"
    });
    if matches!(effective_scope, ScopeRef::Circle { .. }) {
        payload["effective_scope"] = serde_json::to_value(&effective_scope)?;
    }
    let request = ModerationReportRequestBody {
        report_event: arkret_wire::EventAdmissionSubmission::new(
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
        &reporter_account_id,
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
    let draft = realm_create_payload_for_station(
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
    let request = ordinary_realm_bootstrap_submission(events)?;
    request.validate()?;
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
    station_id: &DidCoreId,
    draft: RealmBootstrapDraft,
) -> Result<(String, Vec<arkret_wire::Event>)> {
    let (signing_seed, verification_method) = event_signing_identity_for_device(actor, device_id);
    realm_bootstrap_event_batch_with_signing_identity(
        actor,
        draft,
        signing_seed,
        &verification_method,
        Some(station_id),
    )
}

#[allow(clippy::too_many_arguments)]
fn realm_bootstrap_followup_event(
    actor: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    signing_seed: [u8; 32],
    verification_method: &DidUrl,
    station_id: Option<&DidCoreId>,
) -> Result<Event> {
    let event = event_envelope_with_chain_signing_identity_causal_refs_and_preconditions(
        actor,
        realm_id,
        kind,
        payload,
        None,
        Vec::new(),
        signing_seed,
        verification_method,
        station_id,
        Vec::new(),
    );
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
    realm_bootstrap_event_batch_with_signing_identity(
        actor,
        draft,
        signing_seed,
        verification_method,
        None,
    )
}

pub(crate) fn ordinary_realm_bootstrap_submission(
    events: Vec<Event>,
) -> Result<arkret_models_collaboration::authority_commit::OrdinaryRealmBootstrapUnitSubmission> {
    let millis = u64::try_from(Utc::now().timestamp_millis())?;
    let sequence = NEXT_EVENT_SEQ.fetch_add(1, Ordering::Relaxed);
    let key = format!(
        "{:08x}-{:04x}-7000-8000-{:012x}",
        millis >> 16,
        millis & 0xffff,
        sequence
    );
    Ok(arkret_models_collaboration::authority_commit::OrdinaryRealmBootstrapUnitSubmission {
        unit_kind: arkret_models_collaboration::authority_commit::OrdinaryRealmBootstrapUnitKind::OrdinaryRealmBootstrap,
        idempotency_key: arkret_wire::UuidV7::new(key.parse()?)?,
        events: events.into_iter().map(arkret_wire::EventAdmissionSubmission::new).collect(),
    })
}

fn realm_bootstrap_event_batch_with_signing_identity(
    actor: &str,
    draft: RealmBootstrapDraft,
    signing_seed: [u8; 32],
    verification_method: &DidUrl,
    station_id: Option<&DidCoreId>,
) -> Result<(String, Vec<arkret_wire::Event>)> {
    let RealmBootstrapDraft {
        create,
        profile,
        policy_bundle,
        join_rule,
        history_access,
        discovery,
        alias,
        plaintext_visible_services,
    } = draft;
    // Genesis carries no Realm id at all — the scope is `realm_genesis` and the
    // id falls out of the signed Event. The placeholder below is never read.
    let realm_event = event_envelope_with_chain_signing_identity_causal_refs_and_preconditions(
        actor,
        "ak:realm:AbJKasiJAuypE52tDrie6RY7PJds4G20xbtLIvYRInJk",
        "ak.realm.create",
        create.to_value()?,
        None,
        Vec::new(),
        signing_seed,
        verification_method,
        station_id,
        Vec::new(),
    );
    // The genesis carries no realm_id; the SDK resolved it from the Event, and
    // every follow-up in this batch MUST name that derived value or admission
    // reports `out_of_order_bootstrap`.
    let derived_realm_id = realm_event.realm_id.to_string();
    let mut events = vec![realm_event];
    let mut push_followup = |kind: &str, payload: Value| -> Result<EventId> {
        let event = realm_bootstrap_followup_event(
            actor,
            &derived_realm_id,
            kind,
            payload,
            signing_seed,
            verification_method,
            station_id,
        )?;
        let event_id = event.event_id.clone();
        events.push(event);
        Ok(event_id)
    };
    push_followup(
        arkret_wire::event_kind_str::REALM_PROFILE,
        profile.to_value()?,
    )?;
    push_followup(
        arkret_wire::event_kind_str::REALM_POLICY_BUNDLE,
        policy_bundle.to_value()?,
    )?;
    push_followup(
        arkret_wire::event_kind_str::REALM_JOIN_RULE,
        join_rule.to_value()?,
    )?;
    push_followup(
        arkret_wire::event_kind_str::REALM_HISTORY_ACCESS,
        history_access.to_value()?,
    )?;
    push_followup(
        arkret_wire::event_kind_str::REALM_DISCOVERY,
        discovery.to_value()?,
    )?;
    if let Some(alias) = alias {
        push_followup(arkret_wire::event_kind_str::REALM_ALIAS, alias.to_value()?)?;
    }
    if let Some(services) = plaintext_visible_services {
        push_followup(
            arkret_wire::event_kind_str::REALM_PLAINTEXT_VISIBLE_SERVICES,
            services.to_value()?,
        )?;
    };
    let creator_core_id = project_did_to_core_id(&Did::new(actor.to_owned())?)?;
    let creator_station_id = station_id
        .cloned()
        .unwrap_or_else(|| event_station_id(actor));
    let _creator_actor_id = ActorId::account(AccountId::new(creator_core_id, creator_station_id));
    push_followup(
        arkret_wire::event_kind_str::MEMBER_STATE,
        creator_member_join_payload_value(&derived_realm_id, actor, station_id)?,
    )?;
    ordinary_realm_bootstrap_submission(events.clone())?.validate()?;
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
    let event = prepare_event_submission_with_signing_identity(
        server,
        token,
        actor,
        realm_id,
        kind,
        payload,
        signing_seed,
        verification_method,
    )
    .await?;
    let body = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(token)
            .json(&crate::publication::initial_submission(event.clone(), "")?),
        status,
    )
    .await?;
    Ok(body)
}

/// Build the exact signed Event a submit helper would POST, bound to the live
/// actor frontier. A Control Move carries the current Seal basis; an ordinary
/// Event carries signer authority references from the verified authority
/// frontier, which production clients may retain for offline authoring.
/// Callers that relay the Event through another admission surface — the
/// device-pairing gate, for instance — wrap the result in
/// `publication::initial_submission` themselves.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn prepare_event_submission_with_signing_identity(
    server: &ArkretServer,
    _token: &str,
    actor: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    signing_seed: [u8; 32],
    verification_method: &DidUrl,
) -> Result<Event> {
    let event = event_envelope_with_chain_and_signing_identity(
        actor,
        realm_id,
        kind,
        payload,
        None,
        Vec::new(),
        signing_seed,
        verification_method,
        Some(server.service_id()),
    );
    Ok(event)
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
        None,
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
        None,
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
    station_id: Option<&DidCoreId>,
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
        station_id,
        Vec::new(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn event_envelope_with_chain_and_signing_identity_and_causal_refs(
    actor: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    actor_seq: Option<u64>,
    prev_event_ids: Vec<EventId>,
    signing_seed: [u8; 32],
    verification_method: &DidUrl,
    station_id: Option<&DidCoreId>,
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
        station_id,
        causal_refs,
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
    static CLOCK: std::sync::LazyLock<arkret_test_kit::FixtureClock> =
        std::sync::LazyLock::new(|| Box::new(arkret_test_kit::monotonic_floor_clock()));
    CLOCK()
}

#[allow(clippy::too_many_arguments)]
fn event_envelope_with_chain_signing_identity_causal_refs_and_preconditions(
    actor: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    actor_seq: Option<u64>,
    prev_event_ids: Vec<EventId>,
    signing_seed: [u8; 32],
    verification_method: &DidUrl,
    station_id: Option<&DidCoreId>,
    causal_refs: Vec<String>,
) -> Event {
    assert!(
        actor_seq.is_none() && prev_event_ids.is_empty() && causal_refs.is_empty(),
        "actor frontier and causal references belong to committed RealmCommit ordering, not producer Events"
    );
    // A static timestamp cannot stay behind a causal predecessor: the Realm
    // bootstrap the SDK submits is stamped with the real clock, so any harness
    // Event pinned to a fixed past date lands before the Event it names in
    // `prev_refs` and the server rejects it with
    // `created_at_before_causal_predecessor`. Anchor on the process clock and
    // step once per built Event so successors are strictly later.
    let created_at = harness_event_created_at();
    let actor_did = Did::new(actor.to_owned()).expect("cotest actor DID");
    let actor_id = arkret_identifiers::project_did_to_core_id(&actor_did)
        .expect("cotest actor DID projects to a core id");
    let station_id = station_id
        .cloned()
        .unwrap_or_else(|| event_station_id(actor));
    let event = arkret_wire::test_support::raw_event_at(
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
        station_id,
        payload,
        created_at,
    )
    .expect("SDK Event builder accepts cotest envelope");
    let signer = arkret_test_kit::seeded_signer_for_seed(
        signing_seed,
        actor_did,
        verification_method.to_owned(),
    );
    arkret_test_kit::sign_verifiable_event(event, &signer, arkret::canonical::DigestSuite::Sha256)
        .expect("SDK Event signer accepts cotest envelope")
        .expect_verifiable()
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
        None,
    )
}

pub(crate) fn event_envelope_with_chain_for_device(
    actor: &str,
    device_id: &str,
    station_id: &DidCoreId,
    realm_id: &str,
    kind: &str,
    payload: Value,
    actor_seq: u64,
) -> Event {
    let (signing_seed, verification_method) = event_signing_identity_for_device(actor, device_id);
    event_envelope_with_chain_and_signing_identity(
        actor,
        realm_id,
        kind,
        payload,
        Some(actor_seq),
        Vec::new(),
        signing_seed,
        &verification_method,
        Some(station_id),
    )
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
            message_id: message_id_from_event_id(target_event_id)?,
            track_name: None,
            content: Some(ContentBlock::text(body)),
            encrypted_content: None,
            metadata: None,
            encrypted_metadata: None,
            reason: None,
            mimi_provenance: None,
        },
        "message revise payload",
    )
}

pub(crate) fn message_redact_payload(target_event_id: &str, reason: Option<&str>) -> Result<Value> {
    serialize_payload(
        &MessageRedactPayload {
            message_id: message_id_from_event_id(target_event_id)?,
            track_name: None,
            reason: reason.map(ToOwned::to_owned),
            preserve: None,
            mimi_provenance: None,
        },
        "message redact payload",
    )
}

pub(crate) fn member_join_payload_value(realm_id: &str, actor_id: &str) -> Result<Value> {
    member_payload(realm_id, actor_id, MembershipPayloadState::Join, None, None)
}

fn creator_member_join_payload_value(
    realm_id: &str,
    actor_id: &str,
    station_id: Option<&DidCoreId>,
) -> Result<Value> {
    let station_id = station_id
        .cloned()
        .unwrap_or_else(|| event_station_id(actor_id));
    member_payload_at_station(
        realm_id,
        actor_id,
        station_id,
        MembershipPayloadState::Join,
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
        reason.map(ToOwned::to_owned),
    )
}

pub(crate) fn invite_create_payload(
    invitee: &str,
    account_station_id: &str,
    introduction_evidence_digest: impl Into<String>,
    expires_at: DateTime<Utc>,
) -> Result<Value> {
    let invitee_did =
        Did::new(invitee.to_owned()).map_err(|err| anyhow!("invalid invitee DID: {err}"))?;
    let station_id = arkret_identifiers::DidCoreId::new(account_station_id.to_owned())
        .map_err(|err| anyhow!("invalid account Station core id: {err}"))?;
    InviteCreatePayload::new(
        AccountId::new(
            arkret_identifiers::project_did_to_core_id(&invitee_did)?,
            station_id,
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
    invite_ref: Option<String>,
    reason: Option<String>,
) -> Result<Value> {
    member_payload_at_station(
        realm_id,
        actor_id,
        event_station_id(actor_id),
        membership,
        invite_ref,
        reason,
    )
}

fn member_payload_at_station(
    realm_id: &str,
    actor_id: &str,
    station_id: DidCoreId,
    membership: MembershipPayloadState,
    invite_ref: Option<String>,
    reason: Option<String>,
) -> Result<Value> {
    let invite_ref = invite_ref
        .map(|value| serde_json::from_value::<MembershipInviteRef>(Value::String(value)))
        .transpose()
        .map_err(|error| anyhow!("invalid membership invite ref: {error}"))?;
    MembershipPayload {
        membership,
        strand_id: None,
        realm_id: Some(RealmId::new(realm_id.to_owned()).map_err(|err| anyhow!("{err}"))?),
        member_id: ActorId::account(AccountId::new(
            arkret_identifiers::project_did_to_core_id(
                &Did::new(actor_id.to_owned()).map_err(|err| anyhow!("{err}"))?,
            )?,
            station_id,
        )),
        gate_proofs: Vec::new(),
        reason,
        invite_ref,
        membership_cause: None,
        agent_controller_binding: None,
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn event_envelope_with_causal_refs_for_device(
    actor: &str,
    device_id: &str,
    station_id: &DidCoreId,
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
        Some(station_id),
        causal_refs,
    )
}

#[cfg(test)]
mod realm_bootstrap_tests {
    use super::*;

    const ACTOR: &str = "did:webvh:z6mkfixture:alice.soland.local";
    const ACTOR_CORE: &str = "ak:did_core:webvh:z6mkfixture";
    const SERVICE: &str = "ak:did_core:web:service.soland.local";
    const DEFAULT_STATION: &str = "ak:did_core:web:principal.example";
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
        crate::harness::realm_create_payload(SERVICE, &input).expect("valid Realm bootstrap draft")
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

    fn build_for_device(draft: RealmBootstrapDraft) -> (String, Vec<Event>) {
        let station_id = DidCoreId::new(SERVICE.to_owned()).expect("valid service id");
        realm_bootstrap_event_batch_with_signing_identity(
            ACTOR,
            draft,
            [7; 32],
            &DidUrl::new(format!("{ACTOR}#device-1")).expect("valid verification method"),
            Some(&station_id),
        )
        .expect("valid device/account Realm bootstrap unit")
    }

    #[test]
    fn registered_event_signers_are_scoped_by_actor_and_device() {
        const MULTI_DEVICE_ACTOR: &str = "did:webvh:z6mkmultidevice:alice.soland.local";
        const DEVICE_ONE: &str = "ak:device:01904100-0000-7000-8000-0000000000d1";
        const DEVICE_TWO: &str = "ak:device:01904100-0000-7000-8000-0000000000d2";
        let service = DidCoreId::new(SERVICE.to_owned()).expect("valid service id");
        register_event_signing_identity(
            MULTI_DEVICE_ACTOR,
            [31; 32],
            format!("{MULTI_DEVICE_ACTOR}#{DEVICE_ONE}"),
            service.clone(),
        );
        register_event_signing_identity(
            MULTI_DEVICE_ACTOR,
            [32; 32],
            format!("{MULTI_DEVICE_ACTOR}#{DEVICE_TWO}"),
            service,
        );

        let (first_seed, first_method) =
            event_signing_identity_for_device(MULTI_DEVICE_ACTOR, DEVICE_ONE);
        let (second_seed, second_method) =
            event_signing_identity_for_device(MULTI_DEVICE_ACTOR, DEVICE_TWO);
        assert_eq!(first_seed, [31; 32]);
        assert_eq!(second_seed, [32; 32]);
        assert_eq!(
            first_method.as_str(),
            format!("{MULTI_DEVICE_ACTOR}#{DEVICE_ONE}")
        );
        assert_eq!(
            second_method.as_str(),
            format!("{MULTI_DEVICE_ACTOR}#{DEVICE_TWO}")
        );
    }

    #[test]
    fn ordinary_bootstrap_uses_the_registered_order_and_explicit_creator_member() {
        let (_, events) = build(draft(json!({
            "alias": "general:service.soland.local",
            "alias_authority_service_did": SERVICE_FULL
        })));
        let kinds: Vec<_> = events.iter().map(|event| event.kind.as_str()).collect();
        assert_eq!(
            kinds,
            [
                arkret_wire::event_kind_str::REALM_CREATE,
                arkret_wire::event_kind_str::REALM_PROFILE,
                arkret_wire::event_kind_str::REALM_POLICY_BUNDLE,
                arkret_wire::event_kind_str::REALM_JOIN_RULE,
                arkret_wire::event_kind_str::REALM_HISTORY_ACCESS,
                arkret_wire::event_kind_str::REALM_DISCOVERY,
                arkret_wire::event_kind_str::REALM_ALIAS,
                arkret_wire::event_kind_str::MEMBER_STATE,
            ]
        );
        // `models/realm-and-space.md` section 2.7: the creator membership comes
        // only from this last standalone `ak.member.state{membership="join"}`,
        // and `ak.realm.create` MUST NOT write membership implicitly.
        let membership = events.last().expect("creator membership slot");
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind.as_str() == arkret_wire::event_kind_str::MEMBER_STATE)
                .count(),
            1
        );
        assert_eq!(
            membership.payload.get("member_id"),
            Some(&json!({
                "kind": "account",
                "account_id": {
                    "principal_id": ACTOR_CORE,
                    "station_id": DEFAULT_STATION,
                }
            })),
            "the membership subject is the creator's exact Station account"
        );
        assert_eq!(
            membership.payload.get("membership"),
            Some(&json!("join")),
            "the bootstrap membership slot is a join"
        );
        ordinary_realm_bootstrap_submission(events.clone())
            .expect("typed submission")
            .validate()
            .expect("registered atomic unit accepts creator member slot");
        assert!(!membership.payload.contains_key("delivery_status"));
        assert!(!membership.payload.contains_key("delivery_binding"));
    }

    #[test]
    fn device_bootstrap_carries_the_creator_station_in_the_actor_id() {
        let (_, events) = build_for_device(draft(json!({})));
        let membership = events.last().expect("creator membership slot");
        assert_eq!(
            membership.payload.get("member_id"),
            Some(&json!({
                "kind": "account",
                "account_id": {
                    "principal_id": ACTOR_CORE,
                    "station_id": SERVICE,
                }
            }))
        );
        assert!(!membership.payload.contains_key("delivery_status"));
        assert!(!membership.payload.contains_key("delivery_binding"));
    }

    #[test]
    fn bootstrap_rejects_missing_or_reordered_required_facets() {
        let (_, events) = build(draft(json!({})));
        let mut missing_profile = events.clone();
        missing_profile.remove(1);
        assert!(
            ordinary_realm_bootstrap_submission(missing_profile)
                .expect("typed submission")
                .validate()
                .is_err()
        );

        let mut reordered = events;
        reordered.swap(1, 2);
        assert!(
            ordinary_realm_bootstrap_submission(reordered)
                .expect("typed submission")
                .validate()
                .is_err()
        );
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
