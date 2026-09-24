//! Two-Station live checks against committed Event replication and current
//! signer resolution. The wire authority is Event + RealmCommit throughout.

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use arkret_models_collaboration::governance::membership_invite::{
    MembershipPayload, MembershipPayloadState,
};
use arkret_models_identity::{
    CurrentSignerKeyQuerySender, SignerKeyQueryResult, SignerKeyQuerySelector,
    SignerKeysQueryRequestBody,
};
use arkret_wire::{
    AccountId, ActorId, CommitStreamRef, CommittedEventView, Did, DidCoreId, DidUrl, EventId,
    EventKind, RealmId, RequestId,
};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{TestActorClient, TestServerGroup};
use crate::scenarios::identity_test_support::{
    HARNESS_ACCOUNT_AUTHORITY_ORIGIN, actor_did_for_service_did,
};

const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002002";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002003";

/// Stop the recipient after it has accepted the member's committed join,
/// commit another Control Event at the authority, restart both processes,
/// and require the exact source Commit to appear once at the recipient.
pub async fn run_fanout_route_miss_live() -> Result<()> {
    let source_ephemeral = match std::env::var("COTEST_FANOUT_SOURCE_DATABASE_URL") {
        Ok(_) => None,
        Err(_) => crate::scenarios::_helpers::coauth_bootstrap::spawn_ephemeral_postgres()?,
    };
    let target_ephemeral = match std::env::var("COTEST_FANOUT_TARGET_DATABASE_URL") {
        Ok(_) => None,
        Err(_) => crate::scenarios::_helpers::coauth_bootstrap::spawn_ephemeral_postgres()?,
    };
    let source_database_url = std::env::var("COTEST_FANOUT_SOURCE_DATABASE_URL")
        .ok()
        .or_else(|| {
            source_ephemeral
                .as_ref()
                .map(|database| database.connect_url.clone())
        });
    let target_database_url = std::env::var("COTEST_FANOUT_TARGET_DATABASE_URL")
        .ok()
        .or_else(|| {
            target_ephemeral
                .as_ref()
                .map(|database| database.connect_url.clone())
        });
    let (Some(source_database_url), Some(target_database_url)) =
        (source_database_url, target_database_url)
    else {
        ensure!(
            std::env::var("COTEST_REQUIRE_LIVE").as_deref() != Ok("1"),
            "required live federation needs two PostgreSQL databases"
        );
        eprintln!("skipping fanout route-miss live E2E: two PostgreSQL databases unavailable");
        return Ok(());
    };
    ensure!(
        source_database_url != target_database_url,
        "source and recipient must use separate PostgreSQL databases"
    );
    let node_envs = vec![
        federation_node_env(source_database_url),
        federation_node_env(target_database_url),
    ];
    let Some(mut group) =
        TestServerGroup::try_multi_external_with_node_envs("fanout-route-miss", &node_envs).await?
    else {
        ensure!(
            std::env::var("COTEST_REQUIRE_LIVE").as_deref() != Ok("1"),
            "required live federation needs a prebuilt Soland"
        );
        eprintln!("skipping fanout route-miss live E2E: prebuilt Soland unavailable");
        return Ok(());
    };
    group.server(0).assert_tls_trust_boundaries().await?;
    group.server(1).assert_tls_trust_boundaries().await?;

    let alice_did = actor_did_for_service_did(group.server(0).service_did(), "fanout-alice")?;
    // Equal DID cores on distinct Stations must keep separate account and PCR authority.
    let bob_did = alice_did.clone();
    let alice = group
        .server(0)
        .register_client(&alice_did, "fanout-alice", ALICE_DEVICE)
        .await?;
    let bob = group
        .server(1)
        .register_client(&bob_did, "fanout-bob", BOB_DEVICE)
        .await?;
    let alice_principal = alice.principal.as_ref().context("source PCR bootstrap")?;
    let bob_principal = bob.principal.as_ref().context("recipient PCR bootstrap")?;
    ensure!(alice_principal.core_id == bob_principal.core_id);
    ensure!(alice_principal.pcr_realm_id != bob_principal.pcr_realm_id);
    let wrong_station_session = group.server(1).client_with_token(
        &alice_did,
        ALICE_DEVICE,
        alice.expect_dev_bearer().to_owned(),
    )?;
    let cross_session = wrong_station_session
        .get("/_arkret/self/account/viewer")
        .send()
        .await?;
    ensure!(
        matches!(
            cross_session.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ),
        "source Station session was accepted by recipient Station"
    );

    let realm_id = create_realm(&alice, "Fanout route miss").await?;
    let bob_join = member_payload(
        &realm_id,
        &bob_did,
        group.server(1).service_id().clone(),
        MembershipPayloadState::Join,
    )?;
    let bob_join_id = submit_and_settle_member_transition(&alice, &realm_id, bob_join).await?;
    let bob_join_source = wait_for_committed(&alice, &bob_join_id).await?;
    let bob_join_recipient = wait_for_committed(&bob, &bob_join_id).await?;
    assert_same_commit(&bob_join_source, &bob_join_recipient)?;

    group.server_mut(1).stop_external_process().await?;
    let missed_payload = member_payload(
        &realm_id,
        "did:web:fanout-carol.example",
        group.server(0).service_id().clone(),
        MembershipPayloadState::Join,
    )?;
    let missed_response = alice
        .submit_event(&realm_id, EventKind::MemberState.as_str(), missed_payload)
        .await?;
    // The self submit receipt cannot disclose private peer topology.
    ensure!(
        missed_response.get("targets").is_none() && missed_response.get("service_id").is_none(),
        "self submit leaked a federation target: {missed_response}"
    );
    let missed_id = crate::harness::submitted_event_id(&missed_response)?;
    let source_committed = wait_for_committed(&alice, &missed_id).await?;
    ensure!(source_committed.commit().event_ref == missed_id);

    // The accepted source Commit survives authority restart while the target
    // is still offline; a later recipient read must return that exact Commit.
    group.server_mut(0).restart_external_process().await?;
    let alice = group
        .server(0)
        .demo_client(&alice_did, ALICE_DEVICE)
        .await?;
    let restored_source = wait_for_committed(&alice, &missed_id).await?;
    assert_same_commit(&source_committed, &restored_source)?;
    group.server_mut(1).start_external_process().await?;
    let bob = group.server(1).demo_client(&bob_did, BOB_DEVICE).await?;
    let recipient_committed = wait_for_committed(&bob, &missed_id).await?;
    assert_same_commit(&source_committed, &recipient_committed)?;
    assert_one_stream_position(&bob, &realm_id, &missed_id).await?;

    // A second authority restart must not append another recipient Commit.
    group.server_mut(0).restart_external_process().await?;
    assert_one_stream_position(&bob, &realm_id, &missed_id).await?;
    Ok(())
}

/// `ak.self.signer_keys.read.resolve.v1`: a recipient without Alice's signer
/// cache asks its own Station for the `current_admission` signing key bound to
/// the accepted cross-Station membership history.
pub async fn run_signer_keys_query_live() -> Result<()> {
    let source_ephemeral = match std::env::var("COTEST_SIGNER_KEYS_SOURCE_DATABASE_URL") {
        Ok(_) => None,
        Err(_) => crate::scenarios::_helpers::coauth_bootstrap::spawn_ephemeral_postgres()?,
    };
    let target_ephemeral = match std::env::var("COTEST_SIGNER_KEYS_TARGET_DATABASE_URL") {
        Ok(_) => None,
        Err(_) => crate::scenarios::_helpers::coauth_bootstrap::spawn_ephemeral_postgres()?,
    };
    let source_database_url = std::env::var("COTEST_SIGNER_KEYS_SOURCE_DATABASE_URL")
        .ok()
        .or_else(|| {
            source_ephemeral
                .as_ref()
                .map(|database| database.connect_url.clone())
        });
    let target_database_url = std::env::var("COTEST_SIGNER_KEYS_TARGET_DATABASE_URL")
        .ok()
        .or_else(|| {
            target_ephemeral
                .as_ref()
                .map(|database| database.connect_url.clone())
        });
    let (Some(source_database_url), Some(target_database_url)) =
        (source_database_url, target_database_url)
    else {
        ensure!(
            std::env::var("COTEST_REQUIRE_LIVE").as_deref() != Ok("1"),
            "required live signer-keys query needs two PostgreSQL databases"
        );
        eprintln!("skipping signer-keys query live E2E: databases unavailable");
        return Ok(());
    };
    ensure!(source_database_url != target_database_url);
    let node_envs = vec![
        federation_node_env(source_database_url),
        federation_node_env(target_database_url),
    ];
    let Some(mut group) =
        TestServerGroup::try_multi_external_with_node_envs("signer-keys-query", &node_envs).await?
    else {
        ensure!(
            std::env::var("COTEST_REQUIRE_LIVE").as_deref() != Ok("1"),
            "required live signer-keys query needs a prebuilt Soland"
        );
        eprintln!("skipping signer-keys query live E2E: prebuilt Soland unavailable");
        return Ok(());
    };
    let alice_did = actor_did_for_service_did(group.server(0).service_did(), "signer-keys-alice")?;
    let bob_did = actor_did_for_service_did(group.server(1).service_did(), "signer-keys-bob")?;
    let alice = group
        .server(0)
        .register_client(&alice_did, "signer-keys-alice", ALICE_DEVICE)
        .await?;
    let bob = group
        .server(1)
        .register_client(&bob_did, "signer-keys-bob", BOB_DEVICE)
        .await?;
    let alice_principal = alice.principal.as_ref().context("source PCR bootstrap")?;
    let bob_principal = bob.principal.as_ref().context("recipient PCR bootstrap")?;
    let alice_account = AccountId::new(
        alice_principal.core_id.clone(),
        group.server(0).service_id().clone(),
    );
    let bob_account = AccountId::new(
        bob_principal.core_id.clone(),
        group.server(1).service_id().clone(),
    );
    let realm_id = create_realm(&alice, "Signer keys query").await?;
    let bob_join = member_payload(
        &realm_id,
        &bob_did,
        group.server(1).service_id().clone(),
        MembershipPayloadState::Join,
    )?;
    let bob_join_id = submit_and_settle_member_transition(&alice, &realm_id, bob_join).await?;
    group.server_mut(0).restart_external_process().await?;
    let bob = group.server(1).demo_client(&bob_did, BOB_DEVICE).await?;
    wait_for_committed(&bob, &bob_join_id).await?;

    let verification_method = DidUrl::new(format!(
        "{}#{}",
        alice_principal.did, alice_principal.device_id
    ))
    .map_err(anyhow::Error::msg)?;
    let request = SignerKeysQueryRequestBody {
        request_id: RequestId::new("ak:request:019b0000-0000-7000-8000-000000000101")?,
        realm_id: RealmId::new(realm_id)?,
        recipient_account_id: bob_account.clone(),
        queries: vec![SignerKeyQuerySelector::CurrentAdmission {
            sender: CurrentSignerKeyQuerySender::AccountDevice {
                actor: ActorId::account(alice_account),
                device_id: alice_principal.device_id.clone(),
                verification_method,
            },
        }],
    };
    request.validate()?;
    let outcome = bob.sdk().signer_keys_query(&request).await?;
    outcome.validate_for_request(&request)?;
    let [SignerKeyQueryResult::CurrentResolved { selector, key }] = outcome.results.as_slice()
    else {
        bail!("recipient Station did not resolve the current admitted sender");
    };
    ensure!(selector == &request.queries[0]);
    key.validate()?;

    let mut wrong_station = request.clone();
    wrong_station.request_id = RequestId::new("ak:request:019b0000-0000-7000-8000-000000000102")?;
    let SignerKeyQuerySelector::CurrentAdmission {
        sender: CurrentSignerKeyQuerySender::AccountDevice { actor, .. },
    } = &mut wrong_station.queries[0]
    else {
        bail!("current signer request changed selector kind");
    };
    let ActorId::Account { account_id } = actor else {
        bail!("current signer selector lost account Actor");
    };
    account_id.station_id = group.server(1).service_id().clone();
    let wrong = bob.sdk().signer_keys_query(&wrong_station).await?;
    wrong.validate_for_request(&wrong_station)?;
    ensure!(matches!(
        wrong.results.as_slice(),
        [SignerKeyQueryResult::Unavailable { .. }]
    ));
    let mut misbound = outcome;
    let SignerKeyQueryResult::CurrentResolved {
        selector:
            SignerKeyQuerySelector::CurrentAdmission {
                sender: CurrentSignerKeyQuerySender::AccountDevice { actor, .. },
            },
        ..
    } = &mut misbound.results[0]
    else {
        bail!("current signer outcome changed shape");
    };
    *actor = ActorId::account(bob_account);
    ensure!(misbound.validate_for_request(&request).is_err());
    Ok(())
}

fn federation_node_env(database_url: String) -> Vec<(String, String)> {
    vec![
        ("DATABASE_URL".to_owned(), database_url),
        ("SOLAND_FEDERATION_OUTBOUND".to_owned(), "1".to_owned()),
        (
            "SOLAND_ACCOUNT_AUTHORITY_URL".to_owned(),
            HARNESS_ACCOUNT_AUTHORITY_ORIGIN.to_owned(),
        ),
    ]
}

async fn create_realm(client: &TestActorClient, title: &str) -> Result<String> {
    let bootstrap = client
        .create_realm_bootstrap_with(json!({
            "title": title,
            "summary": title,
            "public": false,
            "plaintext_visible_services": [client.service_id()]
        }))
        .await?;
    let realm_id = bootstrap["realm_id"]
        .as_str()
        .context("ordinary Realm bootstrap omitted realm_id")?;
    RealmId::new(realm_id.to_owned())?;
    Ok(realm_id.to_owned())
}

fn member_payload(
    realm_id: &str,
    member: &str,
    member_service: DidCoreId,
    membership: MembershipPayloadState,
) -> Result<Value> {
    let realm_id = RealmId::new(realm_id.to_owned())?;
    let member = arkret_wire::project_did_to_core_id(&Did::new(member.to_owned())?)?;
    let member = ActorId::account(AccountId::new(member, member_service));
    let payload = if membership == MembershipPayloadState::Join {
        MembershipPayload::join(realm_id, member, "fanout route-miss fixture").to_value()?
    } else {
        MembershipPayload::transition(membership, member, "fanout authority ended")
            .with_realm_id(realm_id)
            .to_value()?
    };
    arkret_schema_conformance::event_payload_validator_catalog()?
        .validate_payload(EventKind::MemberState.as_str(), &payload)?;
    Ok(payload)
}

async fn submit_and_settle_member_transition(
    client: &TestActorClient,
    realm_id: &str,
    payload: Value,
) -> Result<EventId> {
    let response = client
        .submit_event(realm_id, EventKind::MemberState.as_str(), payload)
        .await?;
    let event_id = crate::harness::submitted_event_id(&response)?;
    client
        .await_event_seal_coverage(realm_id, &event_id)
        .await?;
    Ok(event_id)
}

async fn wait_for_committed(
    client: &TestActorClient,
    event_id: &EventId,
) -> Result<CommittedEventView> {
    let deadline = Instant::now() + Duration::from_secs(360);
    loop {
        if let Ok(view) = client.sdk().committed_event_get(event_id).await {
            view.validate_shape()?;
            ensure!(view.commit().event_ref == *event_id);
            return Ok(view);
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "committed Event {event_id} did not reach the Station"
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn assert_same_commit(source: &CommittedEventView, recipient: &CommittedEventView) -> Result<()> {
    ensure!(
        source.commit() == recipient.commit(),
        "recipient did not retain the exact source RealmCommit"
    );
    Ok(())
}

async fn assert_one_stream_position(
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
    let count = outcome
        .committed_events
        .iter()
        .filter(|item| item.commit().event_ref == *event_id)
        .count();
    ensure!(
        count == 1,
        "recipient stream contained {count} copies of Event {event_id}"
    );
    Ok(())
}
