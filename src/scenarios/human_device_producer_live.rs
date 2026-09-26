//! Live checks of the single human-device producer rule
//! (`device-lifecycle.md` §8.2.2, decision 0107) on a Realm with a second
//! member.
//!
//! * Same Station: Carol enters Alice's public Realm by her own `ak.member.state{join}`; Alice's
//!   human device then signs a Control Event (removing Carol) and a Data Event through the one
//!   producer proof path. The governing Station resolves every signer from its own PCR and no
//!   submission carries device evidence.
//! * Cross Station: the Account lives on Station A and the Realm is governed by Station B. Alice
//!   prepares her join on A (the verified current authority becomes A's forwarding target), signs
//!   her own `join` and submits it to A, which forwards it to B through `authority_forward` with
//!   freshly signed `producer_device_evidence`; B commits it and replicates the committed join back
//!   to A. With a Message grant from the Realm controller, Alice's forwarded Data Event is
//!   committed by B and replicated to A. A ciphertext Message into the Realm, which has no accepted
//!   MLS group, is refused by B's shared send gate with its registered identity and relayed by A.
//!   After A revokes one of Alice's devices, an Event signed by that device is refused by A with
//!   `device_revoked` and B never commits it; Alice finally leaves by a forwarded Control Event.
//!
//! Both Stations use standard DPoP SessionGrants from one Account Authority,
//! and the cross-Station leg revokes a device through the live
//! SecurityRotation path, so Station A carries the same two accepted devices B
//! and C, admitted through its accepted-device unit, as
//! `security_rotation_live`.

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use arkret_models_collaboration::governance::membership_invite::{
    MembershipPayload, MembershipPayloadState,
};
use arkret_models_collaboration::governance::realm_join_intake::{
    AuthorityLocatorSource, RealmJoinCandidate, RealmJoinCandidateServiceKind, RealmJoinIntent,
    RealmJoinTarget, SelfRealmJoinPrepareOutcome, SelfRealmJoinPrepareRequestBody,
};
use arkret_models_crypto::{
    EncryptedEnvelope, EncryptedEnvelopeEncryptionContext, SecurityRotationRevokeCommandResult,
    SecurityTransaction,
};
use arkret_wire::{
    AccountId, ActorId, AuthorityCommitStatus, AuthoritySubmitOutcome, CommitStreamRef,
    CommittedEventView, DidCoreId, DidUrl, ErrorCode, Event, EventId, EventKind, RealmCommit,
    RealmId, RequestId,
};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    ArkretServer, TestActorClient, TestServerGroup,
    event_envelope_with_chain_and_signing_identity_and_causal_refs, expect_api_error, expect_json,
    message_create_text_payload,
};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::coauth_bootstrap::{EphemeralPg, spawn_ephemeral_postgres_for};
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::bridge_contracts::session_grant::mock_session_grant_jwt;
use crate::scenarios::identity_test_support::{
    HARNESS_INTERNAL_AUTHORITY_SECRET, actor_did_for_service_did,
};
use crate::scenarios::security_rotation_live::{
    DEVICE_A, DEVICE_C, DEVICE_C_SEED, RotationFixture, create, refused, rotation_fixture,
    rotation_station_env,
};

const SAME_STATION_GROUP: &str = "human-producer-same-station";
const FORWARD_GROUP: &str = "authority-forward-producer";
const SAME_STATION_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002101";
const GOVERNANCE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002102";
const SECOND_MEMBER_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002103";
const EVIDENCE_MEMBER: &str = "producer_device_evidence";

/// A self-submitting client on `server` whose session is a standard DPoP
/// SessionGrant for its founding device, and the complete Account it acts as.
pub(crate) async fn standard_client(
    server: &ArkretServer,
    coauth: &MockCoauthIntrospectionServer,
    label: &str,
    device: &str,
) -> Result<(TestActorClient, AccountId)> {
    let actor = actor_did_for_service_did(server.service_did(), label)?;
    let demo = server.demo_client(&actor, device).await?;
    let principal = demo
        .principal
        .as_ref()
        .context("the client carries its provisioned principal")?;
    let grant = mock_session_grant_jwt(
        principal.core_id.as_str(),
        principal.device_id.as_str(),
        server.service_id().as_str(),
    );
    coauth.bind_founding_device_grant(
        &grant,
        principal.core_id.as_str(),
        principal.device_id.as_str(),
        principal.founding_authorize_event_id.as_str(),
        &principal.device_signing_key.verifying_key(),
    )?;
    let account = AccountId::new(principal.core_id.clone(), server.service_id().clone());
    Ok((
        server.client_with_founding_device_grant(principal, grant)?,
        account,
    ))
}

pub(crate) fn station_env(
    database_url: &str,
    coauth: &MockCoauthIntrospectionServer,
) -> Vec<(String, String)> {
    let mut env = vec![
        ("DATABASE_URL".to_owned(), database_url.to_owned()),
        ("SOLAND_FEDERATION_OUTBOUND".to_owned(), "1".to_owned()),
    ];
    env.extend(rotation_station_env(coauth));
    env
}

/// One Station governs a public Realm its own Account created. Carol enters
/// by her own join; Alice's single device then signs a Control Event and a
/// Data Event, both committed from the Station's local PCR.
pub async fn run_same_station_human_control_event_live() -> Result<()> {
    let Some(database) = database(SAME_STATION_GROUP)? else {
        return Ok(());
    };
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        SAME_STATION_GROUP,
        &[station_env(&database.connect_url, &coauth)],
    )
    .await?
    else {
        return skip_or_fail(SAME_STATION_GROUP, "prebuilt Soland unavailable");
    };
    let station = group.server(0);
    let (alice, alice_account) =
        standard_client(station, &coauth, "producer-alice", SAME_STATION_DEVICE).await?;
    let (carol, carol_account) =
        standard_client(station, &coauth, "producer-carol", SECOND_MEMBER_DEVICE).await?;
    let realm_id = create_public_realm(&alice, "Human device producer", &[station]).await?;
    let strand_id = alice.default_strand_id(&realm_id)?;

    // Carol's own Control Event is her entry into the public Realm.
    let carol_join = carol
        .author_event(
            &realm_id,
            EventKind::MemberState.as_str(),
            membership_payload(
                &realm_id,
                carol_account.clone(),
                MembershipPayloadState::Join,
                "same-Station second member",
            )?,
        )
        .await?;
    let join_commit =
        submit_and_expect_commit(&carol, &carol_account, SECOND_MEMBER_DEVICE, &carol_join).await?;
    ensure_commit_signed_by(&join_commit, station)?;

    // Alice's device signs a Control Event on another member ...
    let control = alice
        .author_event(
            &realm_id,
            EventKind::MemberState.as_str(),
            membership_payload(
                &realm_id,
                carol_account.clone(),
                MembershipPayloadState::Leave,
                "same-Station human Control Event",
            )?,
        )
        .await?;
    let control_commit =
        submit_and_expect_commit(&alice, &alice_account, SAME_STATION_DEVICE, &control).await?;
    ensure_commit_signed_by(&control_commit, station)?;

    // ... and a Data Event, under the same producer rule.
    let data = alice
        .author_event(
            &realm_id,
            EventKind::MessageCreate.as_str(),
            message_create_text_payload(&strand_id, "same producer rule")?,
        )
        .await?;
    let data_commit =
        submit_and_expect_commit(&alice, &alice_account, SAME_STATION_DEVICE, &data).await?;
    ensure_commit_signed_by(&data_commit, station)?;
    ensure!(
        join_commit.stream_position < control_commit.stream_position
            && control_commit.stream_position < data_commit.stream_position,
        "the join, Control and Data Events were not committed in submission order"
    );
    drop(coauth);
    Ok(())
}

/// The Account lives on Station A and the Realm is governed by Station B.
pub async fn run_cross_station_authority_forward_live() -> Result<()> {
    let Some(account_database) = database(FORWARD_GROUP)? else {
        return Ok(());
    };
    let Some(governance_database) = database(FORWARD_GROUP)? else {
        return Ok(());
    };
    ensure!(
        account_database.connect_url != governance_database.connect_url,
        "the account and governance Stations must use separate databases"
    );
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        FORWARD_GROUP,
        &[
            station_env(&account_database.connect_url, &coauth),
            station_env(&governance_database.connect_url, &coauth),
        ],
    )
    .await?
    else {
        return skip_or_fail(FORWARD_GROUP, "prebuilt Soland unavailable");
    };
    let account_station = group.server(0);
    let governance_station = group.server(1);

    // Alice on A: founding device A plus accepted devices B and C.
    let RotationFixture {
        client_a,
        client_c,
        events_a,
        principal,
        signer,
        seed_a,
        old,
        selected,
        ..
    } = rotation_fixture(account_station, &coauth, "forward-alice").await?;
    let alice_account = AccountId::new(
        principal.core_id.clone(),
        account_station.service_id().clone(),
    );

    // Bob on B creates a public Realm whose plaintext Message bodies both
    // Stations may hold.
    let (bob, _) = standard_client(
        governance_station,
        &coauth,
        "forward-bob",
        GOVERNANCE_DEVICE,
    )
    .await?;
    let realm_id = create_public_realm(
        &bob,
        "Authority forward",
        &[governance_station, account_station],
    )
    .await?;
    let strand_id = bob.default_strand_id(&realm_id)?;

    // 1. Alice prepares on A: the verified current authority is the only place her Station will
    //    forward to.
    prepare_join(
        &events_a,
        &realm_id,
        governance_station,
        "ak:request:019b0000-0000-7000-8000-000000002104",
        RealmJoinIntent::MemberJoin,
    )
    .await?;

    // 2. Alice's own join Control Event, submitted to A and forwarded to B.
    let join = events_a
        .author_event(
            &realm_id,
            EventKind::MemberState.as_str(),
            membership_payload(
                &realm_id,
                alice_account.clone(),
                MembershipPayloadState::Join,
                "cross-Station member",
            )?,
        )
        .await?;
    let join_commit = submit_and_expect_commit(&events_a, &alice_account, DEVICE_A, &join).await?;
    ensure_commit_signed_by(&join_commit, governance_station)?;
    ensure_same_commit(
        &join_commit,
        &wait_for_committed(&bob, &join.event_id).await?,
    )?;
    // B replicates the committed join to A, which opens A's held Realm stream.
    ensure_same_commit(
        &join_commit,
        &wait_for_committed(&events_a, &join.event_id).await?,
    )?;

    // 3. Joining grants no writing: the controller grants Alice Messages.
    grant_message_create(&bob, governance_station, &realm_id, &alice_account).await?;

    // 4. Data Event by device A, submitted to A and forwarded to B, then replicated back to A.
    let data = events_a
        .author_event(
            &realm_id,
            EventKind::MessageCreate.as_str(),
            message_create_text_payload(&strand_id, "forwarded human Data Event")?,
        )
        .await?;
    let data_commit = submit_and_expect_commit(&events_a, &alice_account, DEVICE_A, &data).await?;
    ensure_commit_signed_by(&data_commit, governance_station)?;
    ensure_same_commit(
        &data_commit,
        &wait_for_committed(&bob, &data.event_id).await?,
    )?;
    ensure_same_commit(
        &data_commit,
        &wait_for_committed(&events_a, &data.event_id).await?,
    )?;

    // 5. A ciphertext Message into a Realm scope with no accepted MLS group is refused by B's
    //    shared send gate as `failed_precondition` and relayed by A unchanged.
    let ciphertext = events_a
        .author_event(
            &realm_id,
            EventKind::MessageCreate.as_str(),
            ciphertext_message_payload(&strand_id, &join.event_id)?,
        )
        .await?;
    let refusal = expect_api_error(
        events_a
            .post("/_arkret/self/events")
            .json(&crate::publication::initial_submission(
                ciphertext.clone(),
                "",
            )?),
        StatusCode::CONFLICT,
        ErrorCode::FailedPrecondition.as_str(),
    )
    .await
    .context("the forwarded ciphertext Message was not refused by the send gate")?;
    ensure!(
        !refusal.extensions.contains_key("reason_code"),
        "the send gate refusal carries a reason: {refusal:?}"
    );
    ensure_never_committed(&bob, &ciphertext.event_id, Duration::from_secs(2)).await?;

    // 6. Control Event by device A: Alice leaves the B-governed Realm.
    let leave = events_a
        .author_event(
            &realm_id,
            EventKind::MemberState.as_str(),
            membership_payload(
                &realm_id,
                alice_account.clone(),
                MembershipPayloadState::Leave,
                "cross-Station human Control Event",
            )?,
        )
        .await?;
    let leave_commit =
        submit_and_expect_commit(&events_a, &alice_account, DEVICE_A, &leave).await?;
    ensure_commit_signed_by(&leave_commit, governance_station)?;
    ensure_same_commit(
        &leave_commit,
        &wait_for_committed(&bob, &leave.event_id).await?,
    )?;
    // 7. A revokes device C through the live SecurityRotation path.
    let (rotation, _) = signer.rotation(
        "fa01",
        DEVICE_C,
        seed_a,
        seed_a,
        &old,
        &selected.active_series.authority_commit_id,
    )?;
    let created = create(&client_a, &rotation).await?;
    wait_for_accepted_revoke(&client_a, &created).await?;
    ensure!(
        refused(&client_c).await?,
        "the revoked device C still authenticates at its account Station"
    );

    // 8. An Event device C signed is refused by A's live gate with device_revoked, and B never
    //    commits it.
    let station_a_id = DidCoreId::new(account_station.service_id().as_str().to_owned())?;
    let revoked_method =
        DidUrl::new(format!("{}#{DEVICE_C}", principal.did)).map_err(|error| anyhow!("{error}"))?;
    let revoked_event = event_envelope_with_chain_and_signing_identity_and_causal_refs(
        principal.did.as_str(),
        &realm_id,
        EventKind::MessageCreate.as_str(),
        message_create_text_payload(&strand_id, "signed by a revoked device")?,
        None,
        Vec::new(),
        DEVICE_C_SEED,
        &revoked_method,
        Some(&station_a_id),
        Vec::new(),
    );
    ensure_human_producer(&revoked_event, &alice_account, DEVICE_C)?;
    let refusal = expect_api_error(
        events_a
            .post("/_arkret/self/events")
            .json(&crate::publication::initial_submission(
                revoked_event.clone(),
                "",
            )?),
        StatusCode::CONFLICT,
        ErrorCode::DeviceRevoked.as_str(),
    )
    .await
    .context("the account Station did not refuse the revoked device's Event with device_revoked")?;
    let _ = refusal;
    ensure_never_committed(&bob, &revoked_event.event_id, Duration::from_secs(10)).await?;
    ensure_absent_from_stream(&bob, &realm_id, &revoked_event.event_id).await?;

    drop(coauth);
    Ok(())
}

/// A public Realm created by `creator`, whose plaintext Message bodies every
/// Station in `plaintext_stations` may hold.
async fn create_public_realm(
    creator: &TestActorClient,
    title: &str,
    plaintext_stations: &[&ArkretServer],
) -> Result<String> {
    create_realm_with_join_rule(creator, title, "public", plaintext_stations).await
}

/// A Realm created by `creator` under `join_rule`, whose plaintext Message
/// bodies every Station in `plaintext_stations` may hold.
pub(crate) async fn create_realm_with_join_rule(
    creator: &TestActorClient,
    title: &str,
    join_rule: &str,
    plaintext_stations: &[&ArkretServer],
) -> Result<String> {
    let created = creator
        .create_realm_with(json!({
            "title": title,
            "summary": title,
            "public": false,
            "join_rule": join_rule,
            "plaintext_visible_services": plaintext_stations
                .iter()
                .map(|station| station.service_id().to_string())
                .collect::<Vec<_>>(),
        }))
        .await?;
    created["realm_id"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("create Realm response did not include realm_id: {created}"))
}

/// `ak.self.realm_join.command.prepare.v1` on the applicant's own Station,
/// naming the governance Station only as an untrusted locator.
pub(crate) async fn prepare_join(
    client: &TestActorClient,
    realm_id: &str,
    governance: &ArkretServer,
    request_id: &str,
    intent: RealmJoinIntent,
) -> Result<()> {
    let invite_id = match &intent {
        RealmJoinIntent::InviteAccept { invite_id } => Some(invite_id.clone()),
        RealmJoinIntent::MemberJoin | RealmJoinIntent::Knock => None,
    };
    let body = SelfRealmJoinPrepareRequestBody {
        request_id: RequestId::new(request_id.to_owned())?,
        target: RealmJoinTarget {
            realm_id: RealmId::new(realm_id.to_owned())?,
            invite_id,
            authority_locator_hints: vec![RealmJoinCandidate {
                service_kind: RealmJoinCandidateServiceKind::Station,
                service_id: governance.service_id().clone(),
                endpoint_url: None,
                source: AuthorityLocatorSource::Directory,
            }],
        },
        intent,
    };
    body.validate()?;
    let outcome: SelfRealmJoinPrepareOutcome = serde_json::from_value(
        expect_json(
            client.post("/_arkret/self/realm-joins/prepare").json(&body),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        outcome.authority_bundle.current_service_id == *governance.service_id(),
        "the prepared join does not name the governance Station"
    );
    Ok(())
}

/// The Realm controller grants `member` the Realm-wide Message action.
pub(crate) async fn grant_message_create(
    controller: &TestActorClient,
    controller_station: &ArkretServer,
    realm_id: &str,
    member: &AccountId,
) -> Result<()> {
    grant_realm_actions(
        controller,
        controller_station,
        realm_id,
        member,
        &[arkret_wire::CapabilityActionId::MESSAGE_CREATE],
    )
    .await?;
    Ok(())
}

/// The Realm controller grants `member` the Realm-wide `actions`; returns the
/// grant's Commit.
pub(crate) async fn grant_realm_actions(
    controller: &TestActorClient,
    controller_station: &ArkretServer,
    realm_id: &str,
    member: &AccountId,
    actions: &[&str],
) -> Result<RealmCommit> {
    let realm = RealmId::new(realm_id.to_owned())?;
    let issuer = ActorId::account(AccountId::new(
        controller
            .principal
            .as_ref()
            .context("the controller carries its provisioned principal")?
            .core_id
            .clone(),
        controller_station.service_id().clone(),
    ));
    let grant = arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody {
        schema: "ak.schema.capability.v1".to_owned(),
        realm_id: Some(realm.clone()),
        issuer_id: issuer,
        subject:
            arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(
                ActorId::account(member.clone()),
            ),
        actions: actions.iter().map(|action| (*action).to_owned()).collect(),
        resources: vec![serde_json::from_value(json!({
            "kind": "realm",
            "realm_id": realm_id,
            "match_scope": "realm_wide"
        }))?],
        constraints: Vec::new(),
        issuer_authority_refs: vec![arkret::IssuerAuthorityRef::RealmRoot {
            realm_id: realm.clone(),
            authority_event_ref: realm.event_id(),
            authority_generation: 0,
        }],
        issued_at: chrono::Utc::now(),
    };
    let payload = arkret_models_collaboration::events_payloads::CapabilityGrantPayload { grant };
    let outcome: AuthoritySubmitOutcome = serde_json::from_value(
        controller
            .submit_event(
                realm_id,
                EventKind::CapabilityGrant.as_str(),
                serde_json::to_value(payload)?,
            )
            .await?,
    )?;
    match outcome {
        AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Committed,
            commit,
        } => Ok(commit),
        other => bail!("the grant of {actions:?} was not committed: {other:?}"),
    }
}

/// A discussion Message carrying only an RFC 9420 ciphertext envelope.
fn ciphertext_message_payload(strand_id: &str, group_state_ref: &EventId) -> Result<Value> {
    let envelope = EncryptedEnvelope {
        version: "1.0".to_owned(),
        content_type: "application/vnd.arkret.message+json".to_owned(),
        encryption_context: EncryptedEnvelopeEncryptionContext::standard(
            0,
            group_state_ref.clone(),
        ),
        ciphertext: "Y2lwaGVydGV4dA".to_owned(),
    };
    let payload = json!({
        "strand_id": strand_id,
        "track_name": "discussion",
        "encrypted_content": envelope,
    });
    // The envelope serializes in struct order; the submitted payload must be
    // canonical JSON.
    Ok(serde_json::from_slice(
        &arkret_canonical::canonical_json_bytes(&payload)?,
    )?)
}

pub(crate) fn database(scenario: &str) -> Result<Option<EphemeralPg>> {
    let database = spawn_ephemeral_postgres_for("COTEST_SOLAND_DATABASE_URL")?;
    if database.is_none() {
        skip_or_fail(scenario, "PostgreSQL unavailable")?;
    }
    Ok(database)
}

pub(crate) fn membership_payload(
    realm_id: &str,
    member: AccountId,
    membership: MembershipPayloadState,
    reason: &str,
) -> Result<Value> {
    let realm_id = RealmId::new(realm_id.to_owned())?;
    let member = ActorId::account(member);
    let payload = if membership == MembershipPayloadState::Join {
        MembershipPayload::join(realm_id, member, reason).to_value()?
    } else {
        MembershipPayload::transition(membership, member, reason)
            .with_realm_id(realm_id)
            .to_value()?
    };
    arkret_schema_conformance::event_payload_validator_catalog()?
        .validate_payload(EventKind::MemberState.as_str(), &payload)?;
    Ok(payload)
}

fn ensure_human_producer(event: &Event, account: &AccountId, device: &str) -> Result<()> {
    let producer = event
        .human_device_producer()?
        .context("the harness Event is not signed by a human Account device")?;
    ensure!(
        &producer.account_id == account && producer.device_id.as_str() == device,
        "the Event's actual signer is not {device} of the expected Account"
    );
    Ok(())
}

/// Submit through the self surface and require the committed outcome. The
/// self submission is the bare Event: it never carries device evidence, whether
/// the Realm is governed here or forwarded elsewhere.
pub(crate) async fn submit_and_expect_commit(
    client: &TestActorClient,
    account: &AccountId,
    device: &str,
    event: &Event,
) -> Result<RealmCommit> {
    ensure_human_producer(event, account, device)?;
    let submission = crate::publication::initial_submission(event.clone(), "")?;
    ensure!(
        serde_json::to_value(&submission)?
            .get(EVIDENCE_MEMBER)
            .is_none(),
        "a self submission carries producer device evidence"
    );
    let outcome: AuthoritySubmitOutcome = serde_json::from_value(
        expect_json(
            client.post("/_arkret/self/events").json(&submission),
            StatusCode::OK,
        )
        .await?,
    )?;
    let AuthoritySubmitOutcome::Accepted { status, commit } = outcome else {
        bail!("{} was not accepted: {outcome:?}", event.kind.as_str());
    };
    ensure!(
        status == AuthorityCommitStatus::Committed && commit.event_ref == event.event_id,
        "{} was not committed as submitted",
        event.kind.as_str()
    );
    commit.validate_shape()?;
    Ok(commit)
}

/// The RealmCommit is the governance Station's own signature.
pub(crate) fn ensure_commit_signed_by(
    commit: &RealmCommit,
    governance: &ArkretServer,
) -> Result<()> {
    let signer = commit
        .signature
        .verification_method
        .as_str()
        .split_once('#')
        .map(|(did, _)| did)
        .context("RealmCommit signature method has no fragment")?;
    ensure!(
        signer == governance.service_did().as_str(),
        "RealmCommit for {} was signed by {signer}, not the governance Station",
        commit.event_ref
    );
    Ok(())
}

pub(crate) fn ensure_same_commit(
    submitted: &RealmCommit,
    observed: &CommittedEventView,
) -> Result<()> {
    ensure!(
        observed.commit() == submitted,
        "the governance Station holds a different RealmCommit for {}",
        submitted.event_ref
    );
    Ok(())
}

pub(crate) async fn wait_for_committed(
    client: &TestActorClient,
    event_id: &EventId,
) -> Result<CommittedEventView> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Ok(view) = client.sdk().committed_event_get(event_id).await {
            view.validate_shape()?;
            ensure!(view.commit().event_ref == *event_id);
            return Ok(view);
        }
        if Instant::now() >= deadline {
            bail!("committed Event {event_id} did not reach the Station");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

pub(crate) async fn ensure_never_committed(
    client: &TestActorClient,
    event_id: &EventId,
    window: Duration,
) -> Result<()> {
    let deadline = Instant::now() + window;
    while Instant::now() < deadline {
        ensure!(
            client.sdk().committed_event_get(event_id).await.is_err(),
            "the governance Station committed {event_id} after the account Station refused it"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Ok(())
}

async fn ensure_absent_from_stream(
    client: &TestActorClient,
    realm_id: &str,
    event_id: &EventId,
) -> Result<()> {
    let realm_id = RealmId::new(realm_id.to_owned())?;
    let outcome = client
        .sdk()
        .scan_commit_stream_to_head(
            realm_id.clone(),
            CommitStreamRef::Realm { realm_id },
            None,
            1000,
        )
        .await?;
    ensure!(
        outcome
            .committed_events
            .iter()
            .all(|item| item.commit().event_ref != *event_id),
        "the governance Realm stream contains the refused Event {event_id}"
    );
    Ok(())
}

async fn wait_for_accepted_revoke(
    client: &TestActorClient,
    created: &SecurityTransaction,
) -> Result<()> {
    let path = format!(
        "/_arkret/self/security-transactions/{}",
        created.transaction_id
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut current = created.clone();
    loop {
        if let Some(outcome) = &current.revoke_command_outcome {
            ensure!(
                outcome.result == SecurityRotationRevokeCommandResult::Accepted,
                "the device revoke was not accepted: {current:?}"
            );
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("the device revoke was never decided: {current:?}");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        current = serde_json::from_value(expect_json(client.get(&path), StatusCode::OK).await?)?;
    }
}
