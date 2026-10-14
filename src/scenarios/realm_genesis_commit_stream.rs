//! API-only Realm founding, exact replay, and same-stream continuation.

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::authority_commit::{
    OrdinaryRealmBootstrapUnitSubmission, SelfAuthoritySubmitRequest,
};
use arkret_wire::{CommitStreamRef, RealmId, StreamScanOutcome};
use serde_json::{Value, json};

use crate::harness::TestActorClient;
use crate::scenarios::identity_test_support::{
    actor_did_for_service_did, spawn_with_harness_account_authority,
};

async fn scan(client: &TestActorClient, realm_id: &RealmId) -> Result<StreamScanOutcome> {
    let result = client
        .sdk()
        .scan_commit_stream_tail(
            realm_id.clone(),
            CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            None,
            1000,
        )
        .await?;
    ensure!(!result.truncated, "founding stream unexpectedly truncated");
    Ok(result)
}

fn assert_chain(scan: &StreamScanOutcome, realm_id: &RealmId) -> Result<()> {
    ensure!(!scan.committed_events.is_empty(), "empty founding stream");
    for (index, item) in scan.committed_events.iter().enumerate() {
        item.validate_shape()?;
        let commit = item.commit();
        let event = item
            .reducer_input()
            .context("creator's own Event was withheld")?;
        ensure!(
            commit.stream_ref
                == CommitStreamRef::Realm {
                    realm_id: realm_id.clone()
                },
            "founding Commit left its Realm stream"
        );
        ensure!(
            commit.stream_position == index as u64 && commit.event_ref == event.event_id,
            "Commit position/Event mismatch"
        );
        ensure!(
            commit.previous_commit_ref.as_ref()
                == index
                    .checked_sub(1)
                    .map(|i| &scan.committed_events[i].commit().commit_id),
            "Commit predecessor mismatch"
        );
        let value = serde_json::to_value(event)?;
        for field in [
            "actor_seq",
            "prev_refs",
            "preconditions",
            "hlc",
            "seal_ref",
            "cell_writes",
            "basis",
        ] {
            ensure!(
                value.get(field).is_none(),
                "retired producer member {field}"
            );
        }
    }
    Ok(())
}

pub async fn realm_genesis_commit_stream_preserves_founding_replay_and_continuation() -> Result<()>
{
    let server = spawn_with_harness_account_authority("genesis-api-migration", &[]).await?;
    let did = actor_did_for_service_did(server.service_did(), "genesis-api-owner")?;
    let client = server
        .standard_client(&did, "ak:device:01904100-0000-7000-8000-00000000e601")
        .await?;
    realm_genesis_with_client(&client).await
}

pub async fn realm_genesis_with_client(client: &TestActorClient) -> Result<()> {
    let bootstrap = client
        .create_realm_bootstrap_with(json!({ "title": "API migration genesis" }))
        .await?;
    let realm = RealmId::new(bootstrap["realm_id"].as_str().context("bootstrap Realm")?)?;
    let before = scan(&client, &realm).await?;
    assert_chain(&before, &realm)?;
    let events = before
        .committed_events
        .iter()
        .map(|item| item.reducer_input().context("founding Event withheld"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        events
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>()
            == [
                "ak.realm.create",
                "ak.realm.profile",
                "ak.realm.policy_bundle",
                "ak.realm.join_rule",
                "ak.realm.history_access",
                "ak.realm.discovery",
                "ak.realm.plaintext_visible_services",
                "ak.member.state",
            ],
        "founding unit differs from the registered Event set"
    );
    let object = &events[0].payload["object"];
    for field in ["title", "summary", "plaintext_visible_services"] {
        ensure!(
            object.get(field).is_none(),
            "display facet leaked into genesis: {field}"
        );
    }
    ensure!(
        object["governance_station_id"] == client.service_id(),
        "genesis governance Station mismatch"
    );
    let salt = object["genesis_salt"].as_str().context("genesis salt")?;
    ensure!(
        arkret_canonical::base64url_decode(salt)?.len() == 32,
        "genesis salt length"
    );
    let membership = events.last().unwrap();
    ensure!(
        serde_json::to_value(&membership.actor_id)? == membership.payload["member_id"]
            && membership.payload["membership"] == "join",
        "founding membership is not the creator's join"
    );

    let request: OrdinaryRealmBootstrapUnitSubmission =
        serde_json::from_value(bootstrap["submission"].clone())?;
    let retry = client
        .sdk()
        .submit_to_realm_authority(
            &SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(request),
            &Default::default(),
        )
        .await?;
    let retry = serde_json::to_value(retry)?;
    ensure!(
        retry["unit_kind"] == "ordinary_realm_bootstrap" && retry["status"] == "duplicate",
        "bootstrap retry is not duplicate"
    );
    ensure!(
        retry["commits"] == bootstrap["event_response"]["commits"],
        "bootstrap retry changed exact Commits"
    );
    ensure!(
        scan(&client, &realm).await? == before,
        "bootstrap replay changed the stream"
    );

    let strand = client.create_default_strand(realm.as_str()).await?;
    client
        .send_message(realm.as_str(), &strand, "owner write after genesis")
        .await?;
    let after = scan(&client, &realm).await?;
    assert_chain(&after, &realm)?;
    ensure!(
        after.committed_events[..before.committed_events.len()] == before.committed_events,
        "ordinary write changed founding prefix"
    );
    let suffix = &after.committed_events[before.committed_events.len()..];
    let kinds = suffix
        .iter()
        .map(|item| item.reducer_input().map(|event| event.kind.as_str()))
        .collect::<Vec<_>>();
    ensure!(
        kinds
            == [
                Some("ak.strand.create"),
                Some("ak.realm.set_default_strand"),
                Some("ak.message.create")
            ],
        "ordinary writes did not continue the Realm stream"
    );
    // One transcript records all three migrated phases on the same live SUT.
    let transcript: Value = json!({"phase": "realm_genesis_commit_stream", "founding_count": before.committed_events.len(),
        "continuation_count": suffix.len(), "duplicate": true});
    println!("{transcript}");
    Ok(())
}

pub async fn canonical_realm_genesis_api_migration() -> Result<()> {
    let fixture = super::_helpers::canonical_api::fixture("genesis").await?;
    realm_genesis_with_client(&fixture.client).await
}
