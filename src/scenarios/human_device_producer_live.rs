//! Live checks of the single human-device producer rule
//! (`device-lifecycle.md` §8.2.2, decision 0107).
//!
//! * Same Station: a human device signs a Control Event (`ak.member.state`) and a Data Event
//!   through the one producer proof path; the governing Station resolves the signer from its own
//!   PCR and the submission carries no device evidence.
//! * Cross Station: the Account lives on Station A and the Realm is governed by Station B. A Data
//!   Event and a Control Event signed by the Account's human device are submitted to A, which
//!   forwards them to B through `authority_forward` with freshly signed `producer_device_evidence`;
//!   B commits both. After A revokes one of the Account's devices, an Event signed by that device
//!   is refused by A with `device_revoked` and B never commits it.
//!
//! The cross-Station leg revokes a device through the live SecurityRotation
//! path, so Station A carries the same two accepted devices B and C, admitted
//! through its accepted-device unit, as `security_rotation_live`.

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use arkret_models_collaboration::governance::membership_invite::{
    MembershipPayload, MembershipPayloadState,
};
use arkret_models_crypto::{SecurityRotationRevokeCommandResult, SecurityTransaction};
use arkret_wire::{
    AccountId, ActorId, AuthorityCommitStatus, AuthoritySubmitOutcome, CommitStreamRef,
    CommittedEventView, Did, DidCoreId, DidUrl, ErrorCode, Event, EventId, EventKind, RealmCommit,
    RealmId,
};
use reqwest::StatusCode;
use serde_json::Value;

use crate::harness::{
    ArkretServer, TestActorClient, TestServerGroup,
    event_envelope_with_chain_and_signing_identity_and_causal_refs, expect_json,
    message_create_text_payload,
};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::coauth_bootstrap::{EphemeralPg, spawn_ephemeral_postgres_for};
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::identity_test_support::{
    HARNESS_ACCOUNT_AUTHORITY_ORIGIN, HARNESS_INTERNAL_AUTHORITY_SECRET, actor_did_for_service_did,
};
use crate::scenarios::security_rotation_live::{
    DEVICE_A, DEVICE_C, DEVICE_C_SEED, RotationFixture, create, refused, rotation_fixture,
    rotation_station_env,
};

const SAME_STATION_GROUP: &str = "human-producer-same-station";
const FORWARD_GROUP: &str = "authority-forward-producer";
const SAME_STATION_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002101";
const GOVERNANCE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002102";
const EVIDENCE_MEMBER: &str = "producer_device_evidence";

/// One Station governs a Realm its own Account created. The same device signs
/// a Control and a Data Event, both through the ordinary self submit, and both
/// are committed from the Station's local PCR.
pub async fn run_same_station_human_control_event_live() -> Result<()> {
    let Some(database) = database(SAME_STATION_GROUP)? else {
        return Ok(());
    };
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        SAME_STATION_GROUP,
        &[node_env(
            &database.connect_url,
            HARNESS_ACCOUNT_AUTHORITY_ORIGIN,
        )],
    )
    .await?
    else {
        return skip_or_fail(SAME_STATION_GROUP, "prebuilt Soland unavailable");
    };
    let station = group.server(0);
    let alice_did = actor_did_for_service_did(station.service_did(), "producer-alice")?;
    let alice = station
        .register_client(&alice_did, "producer-alice", SAME_STATION_DEVICE)
        .await?;
    let principal = alice
        .principal
        .as_ref()
        .context("same-Station Account PCR bootstrap")?;
    let account = AccountId::new(principal.core_id.clone(), station.service_id().clone());
    let realm_id = alice.create_realm("Human device producer").await?;
    let strand_id = alice.default_strand_id(&realm_id)?;

    let carol_join = membership_payload(
        &realm_id,
        AccountId::new(
            arkret_wire::project_did_to_core_id(&Did::new("did:web:producer-carol.example")?)?,
            station.service_id().clone(),
        ),
        MembershipPayloadState::Join,
        "same-Station human Control Event",
    )?;
    let control = alice
        .author_event(&realm_id, EventKind::MemberState.as_str(), carol_join)
        .await?;
    let control_commit =
        submit_and_expect_commit(&alice, &account, SAME_STATION_DEVICE, &control).await?;
    ensure_commit_signed_by(&control_commit, station)?;

    let data = alice
        .author_event(
            &realm_id,
            EventKind::MessageCreate.as_str(),
            message_create_text_payload(&strand_id, "same producer rule")?,
        )
        .await?;
    let data_commit =
        submit_and_expect_commit(&alice, &account, SAME_STATION_DEVICE, &data).await?;
    ensure_commit_signed_by(&data_commit, station)?;
    ensure!(
        data_commit.stream_position > control_commit.stream_position,
        "the Data Event was not committed after the Control Event in the Realm stream"
    );
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
    let mut account_env = vec![
        (
            "DATABASE_URL".to_owned(),
            account_database.connect_url.clone(),
        ),
        ("SOLAND_FEDERATION_OUTBOUND".to_owned(), "1".to_owned()),
    ];
    account_env.extend(rotation_station_env(&coauth));
    let governance_env = node_env(
        &governance_database.connect_url,
        HARNESS_ACCOUNT_AUTHORITY_ORIGIN,
    );
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        FORWARD_GROUP,
        &[account_env, governance_env],
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

    // Bob on B creates the Realm and admits Alice's A-hosted Account.
    let bob_did = actor_did_for_service_did(governance_station.service_did(), "forward-bob")?;
    let bob = governance_station
        .register_client(&bob_did, "forward-bob", GOVERNANCE_DEVICE)
        .await?;
    let realm_id = bob.create_realm("Authority forward").await?;
    let strand_id = bob.default_strand_id(&realm_id)?;
    let join = bob
        .submit_event(
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
    let join_id = crate::harness::submitted_event_id(&join)?;
    wait_for_committed(&events_a, &join_id).await?;

    // 1. Data Event by device A, submitted to A and forwarded to B.
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

    // 2. A revokes device C through the live SecurityRotation path.
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

    // 3. An Event device C signed is refused by A's live gate with device_revoked, and B never
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
    let refusal = events_a
        .post("/_arkret/self/events")
        .json(&crate::publication::initial_submission(
            revoked_event.clone(),
            "",
        )?)
        .send()
        .await?;
    let status = refusal.status();
    let problem: Value = refusal.json().await?;
    ensure!(
        status == StatusCode::CONFLICT
            && problem["type"]
                == format!(
                    "https://arkret.org/problems/{}",
                    ErrorCode::DeviceRevoked.as_str()
                ),
        "the account Station did not refuse the revoked device's Event with device_revoked: {status} {problem}"
    );
    ensure_never_committed(&bob, &revoked_event.event_id, Duration::from_secs(10)).await?;
    ensure_absent_from_stream(&bob, &realm_id, &revoked_event.event_id).await?;

    // 4. Control Event by device A: Alice leaves the B-governed Realm.
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
    drop(coauth);
    Ok(())
}

fn database(scenario: &str) -> Result<Option<EphemeralPg>> {
    let database = spawn_ephemeral_postgres_for("COTEST_SOLAND_DATABASE_URL")?;
    if database.is_none() {
        skip_or_fail(scenario, "PostgreSQL unavailable")?;
    }
    Ok(database)
}

fn node_env(database_url: &str, account_authority: &str) -> Vec<(String, String)> {
    vec![
        ("DATABASE_URL".to_owned(), database_url.to_owned()),
        ("SOLAND_FEDERATION_OUTBOUND".to_owned(), "1".to_owned()),
        (
            "SOLAND_ACCOUNT_AUTHORITY_URL".to_owned(),
            account_authority.to_owned(),
        ),
    ]
}

fn membership_payload(
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
async fn submit_and_expect_commit(
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
fn ensure_commit_signed_by(commit: &RealmCommit, governance: &ArkretServer) -> Result<()> {
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

fn ensure_same_commit(submitted: &RealmCommit, observed: &CommittedEventView) -> Result<()> {
    ensure!(
        observed.commit() == submitted,
        "the governance Station holds a different RealmCommit for {}",
        submitted.event_ref
    );
    Ok(())
}

async fn wait_for_committed(
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

async fn ensure_never_committed(
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
