//! A two-Station Contact request and normal response over the durable peer
//! carrier. Both directions must converge on the same accepted round.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use arkret::contact_operations::{
    ContactPeer, ContactPreparePhase, ContactState, ContactTombstonePrepareRequestBody,
};
use arkret_models_collaboration::contact_operations::RequestAcceptanceReceipt;
use arkret_models_collaboration::direct_conversation::{
    DirectConversationResolveOutcome, DirectConversationResolveRequestBody,
};
use arkret_models_collaboration::governance::invite_addressing::{
    InviteLocatorIssueRequestBody, InviteLocatorResolveRequestBody, PrincipalLocator,
};
use arkret_models_collaboration::governance::peer_contact::ContactIntroductionEvidence;
use arkret_models_collaboration::objects::direct_conversation::DirectConversationFoundingAuthorityEvidence;
use arkret_signatures::webvh::validate_webvh_history_at;
use arkret_wire::{ActorId, Did, DidUrl};
use reqwest::StatusCode;

use crate::harness::{TestActorClient, TestServerGroup, expect_json, test_service_signing_key};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::human_device_producer_live::{database, standard_client, station_env};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;

const GROUP: &str = "contact-federation-live";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002141";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002142";
const CAROL_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002143";

async fn service_webvh_history(
    server: &crate::harness::ArkretServer,
) -> Result<Vec<serde_json::Value>> {
    let body = server
        .http()
        .get(server.url("/webvh/service/did.jsonl"))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(anyhow::Error::from))
        .collect()
}

fn receipt_key_at(
    did: &Did,
    history: &[serde_json::Value],
    receipt: &RequestAcceptanceReceipt,
) -> Result<ed25519_dalek::VerifyingKey> {
    let point = validate_webvh_history_at(did, history, receipt.core.accepted_at)?;
    let method_id = receipt.signature.verification_method.as_str();
    ensure!(
        point.document["assertionMethod"]
            .as_array()
            .is_some_and(|methods| methods
                .iter()
                .any(|method| method.as_str() == Some(method_id))),
        "receipt signer is absent from the historical assertionMethod"
    );
    let method = point.document["verificationMethod"]
        .as_array()
        .and_then(|methods| methods.iter().find(|method| method["id"] == method_id))
        .context("receipt signer has no historical verification method")?;
    let public = method["publicKeyMultibase"]
        .as_str()
        .context("historical receipt method has no public key")?;
    Ok(ed25519_dalek::VerifyingKey::from_bytes(
        &arkret_canonical::decode_ed25519_multibase(public)?,
    )?)
}

async fn issued_locator(holder: &TestActorClient) -> Result<PrincipalLocator> {
    issued_locator_with_ttl(holder, 900).await
}

async fn issued_locator_with_ttl(
    holder: &TestActorClient,
    ttl_seconds: u32,
) -> Result<PrincipalLocator> {
    let issued = expect_json(
        holder
            .post("/_arkret/self/invite-locators")
            .json(&InviteLocatorIssueRequestBody {
                ttl_seconds: Some(ttl_seconds),
                ..Default::default()
            }),
        StatusCode::OK,
    )
    .await?;
    let token = issued["locator_token"]
        .as_str()
        .context("locator issue omitted locator_token")?;
    let resolved = expect_json(
        holder
            .post("/_arkret/open/invite-locators/resolve")
            .json(&InviteLocatorResolveRequestBody::new(token)),
        StatusCode::OK,
    )
    .await?;
    Ok(serde_json::from_value(resolved)?)
}

async fn wait_contact(
    holder: &TestActorClient,
    peer: &ActorId,
    state: ContactState,
) -> Result<arkret::contact_operations::ContactListRow> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last_row = None;
    loop {
        if let Some(row) = holder
            .sdk()
            .contacts_list()
            .await?
            .contacts
            .into_iter()
            .find(|row| row.peer.contact_actor_id() == *peer)
        {
            if row.state == state {
                return Ok(row);
            }
            last_row = Some(row);
        }
        if Instant::now() >= deadline {
            bail!(
                "Contact at {} did not reach {state:?} for {peer}; last row: {last_row:?}",
                holder.service_id(),
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn tombstone_contact(
    holder: &TestActorClient,
    row: &arkret::contact_operations::ContactListRow,
) -> Result<()> {
    use arkret::contact_operations::{
        ContactCommitPhase, ContactCommitRequestBody, ContactOperationOutcome,
        ContactPreparedOutcome,
    };
    let next = row
        .next_prepare_input
        .as_ref()
        .context("accepted Contact has no next prepare input")?;
    let operation_id = arkret::ProtocolOperationId::new(crate::harness::next_typed_id("operation"))
        .map_err(anyhow::Error::msg)?;
    let idempotency_key = arkret::IdempotencyKey::new(crate::harness::next_typed_id("idempotency"))
        .map_err(anyhow::Error::msg)?;
    let path = "/_arkret/self/contacts/tombstone";
    let prepared: ContactOperationOutcome = serde_json::from_value(
        expect_json(
            holder.post(path).json(&ContactTombstonePrepareRequestBody {
                phase: ContactPreparePhase::Prepare,
                operation_id: operation_id.clone(),
                idempotency_key: idempotency_key.clone(),
                peer: row.peer.clone(),
                contact_round_id: next.contact_round_id.clone(),
                version: next.version,
                predecessor_event_ref: next.predecessor_event_ref.clone(),
                block_peer: false,
            }),
            StatusCode::OK,
        )
        .await?,
    )?;
    let ContactOperationOutcome::Prepared {
        outcome:
            ContactPreparedOutcome::Tombstone {
                reservation_handle,
                event_draft,
                ..
            },
    } = prepared
    else {
        bail!("cross-Station tombstone did not prepare: {prepared:?}");
    };
    let committed: ContactOperationOutcome = serde_json::from_value(
        expect_json(
            holder.post(path).json(&ContactCommitRequestBody {
                phase: ContactCommitPhase::Commit,
                operation_id,
                idempotency_key,
                reservation_handle,
                signed_event: holder.sign_prepared_contact_event(
                    &event_draft,
                    arkret_wire::event_kind_str::CONTACT_TOMBSTONE,
                )?,
            }),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        matches!(committed, ContactOperationOutcome::Accepted { .. }),
        "cross-Station tombstone was not accepted: {committed:?}"
    );
    Ok(())
}

pub async fn normal_round_crosses_two_stations() -> Result<()> {
    let Some(alice_database) = database(GROUP)? else {
        return Ok(());
    };
    let Some(bob_database) = database(GROUP)? else {
        return Ok(());
    };
    ensure!(
        alice_database.connect_url != bob_database.connect_url,
        "Contact Stations need distinct databases"
    );
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let station = |url: &str| {
        let mut env = station_env(url, &coauth);
        env.push(("COLAND_FEDERATION_OUTBOUND".to_owned(), "1".to_owned()));
        env
    };
    let Some(mut group) = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[
            station(&alice_database.connect_url),
            station(&bob_database.connect_url),
        ],
    )
    .await?
    else {
        return skip_or_fail(GROUP, "prebuilt Coland unavailable");
    };
    let (alice, alice_account) =
        standard_client(group.server(0), &coauth, "contact-alice", ALICE_DEVICE).await?;
    let (bob, bob_account) =
        standard_client(group.server(1), &coauth, "contact-bob", BOB_DEVICE).await?;
    let locator = issued_locator(&bob).await?;
    ensure!(
        locator.account_id == bob_account,
        "locator names another holder"
    );
    let receipt = alice
        .request_contact_with_peer(
            ContactPeer::Human {
                account_id: bob_account.clone(),
            },
            ContactIntroductionEvidence::LocatorRef {
                principal_locator: locator,
            },
        )
        .await?;
    let alice_actor = ActorId::account(alice_account);
    let incoming = wait_contact(&bob, &alice_actor, ContactState::PendingIncoming).await?;
    ensure!(
        incoming.request_event_ref.as_ref() == Some(&receipt.core.request_event_ref),
        "peer mirror changed the exact request Event ref"
    );
    bob.accept_contact(&alice).await?;
    let bob_actor = ActorId::account(bob_account);
    let alice_row = wait_contact(&alice, &bob_actor, ContactState::Accepted).await?;
    let bob_row = wait_contact(&bob, &alice_actor, ContactState::Accepted).await?;
    let alice_round = alice_row
        .next_prepare_input
        .context("requester has no confirmed round input")?;
    let bob_round = bob_row
        .next_prepare_input
        .context("responder has no confirmed round input")?;
    ensure!(
        alice_round.contact_round_id == bob_round.contact_round_id,
        "both Stations installed different Contact rounds"
    );

    // Reopen both service processes before they reissue DC authority. The
    // historical assertion-key cache is empty after restart, so the founder
    // must resolve and verify the durable bilateral Contact evidence again.
    group.server_mut(0).restart_external_process().await?;
    group.server_mut(1).restart_external_process().await?;
    let alice_after_restart = wait_contact(&alice, &bob_actor, ContactState::Accepted).await?;
    let bob_after_restart = wait_contact(&bob, &alice_actor, ContactState::Accepted).await?;
    ensure!(
        alice_after_restart
            .next_prepare_input
            .as_ref()
            .context("restarted requester has no confirmed round input")?
            .contact_round_id
            == alice_round.contact_round_id
            && bob_after_restart
                .next_prepare_input
                .as_ref()
                .context("restarted responder has no confirmed round input")?
                .contact_round_id
                == alice_round.contact_round_id,
        "restart changed the accepted Contact round"
    );
    let alice_resolve = alice
        .sdk()
        .direct_conversation_resolve(&DirectConversationResolveRequestBody {
            peer: ContactPeer::Human {
                account_id: bob_actor
                    .as_account_id()
                    .context("Bob is not an Account")?
                    .clone(),
            },
        })
        .await?;
    let bob_resolve = bob
        .sdk()
        .direct_conversation_resolve(&DirectConversationResolveRequestBody {
            peer: ContactPeer::Human {
                account_id: alice_actor
                    .as_account_id()
                    .context("Alice is not an Account")?
                    .clone(),
            },
        })
        .await?;
    let founder_material = match (&alice_resolve, &bob_resolve) {
        (
            DirectConversationResolveOutcome::CreationRequired {
                next_founding_input,
            },
            DirectConversationResolveOutcome::AwaitingFounder { .. },
        )
        | (
            DirectConversationResolveOutcome::AwaitingFounder { .. },
            DirectConversationResolveOutcome::CreationRequired {
                next_founding_input,
            },
        ) => next_founding_input,
        _ => bail!(
            "restarted normal Contact did not identify one DC founder: Alice {alice_resolve:?}; Bob {bob_resolve:?}"
        ),
    };
    let DirectConversationFoundingAuthorityEvidence::Human {
        contact_round_evidence,
        ..
    } = &founder_material.founding_authority_evidence
    else {
        bail!("restarted founder received non-Contact DC authority");
    };
    ensure!(
        contact_round_evidence.contact_round_id == alice_round.contact_round_id,
        "restarted DC material names another Contact round"
    );
    Ok(())
}

/// Production signer rotation is exercised through the existing Contact
/// request receipt carrier on both sides of a real WebVH successor.
pub async fn old_and_new_contact_signatures_survive_cold_peer_restart() -> Result<()> {
    const ROTATION_GROUP: &str = "contact-signer-rotation-live";
    let Some(alice_database) = database(ROTATION_GROUP)? else {
        return Ok(());
    };
    let Some(bob_database) = database(ROTATION_GROUP)? else {
        return Ok(());
    };
    ensure!(
        alice_database.connect_url != bob_database.connect_url,
        "Stations need separate databases"
    );
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let station = |url: &str| station_env(url, &coauth);
    let Some(mut group) = TestServerGroup::try_multi_external_with_node_envs(
        ROTATION_GROUP,
        &[
            station(&alice_database.connect_url),
            station(&bob_database.connect_url),
        ],
    )
    .await?
    else {
        return skip_or_fail(ROTATION_GROUP, "prebuilt Coland unavailable");
    };
    let (alice, alice_account) =
        standard_client(group.server(0), &coauth, "rotation-alice", ALICE_DEVICE).await?;
    let (bob, bob_account) =
        standard_client(group.server(1), &coauth, "rotation-bob", BOB_DEVICE).await?;
    let alice_actor = ActorId::account(alice_account.clone());
    let bob_actor = ActorId::account(bob_account.clone());
    let old_receipt = alice
        .request_contact_with_peer(
            ContactPeer::Human {
                account_id: bob_account.clone(),
            },
            ContactIntroductionEvidence::LocatorRef {
                principal_locator: issued_locator(&bob).await?,
            },
        )
        .await?;
    wait_contact(&bob, &alice_actor, ContactState::PendingIncoming)
        .await
        .context("old-signer Contact request did not arrive at Bob")?;
    bob.accept_contact(&alice).await?;
    wait_contact(&alice, &bob_actor, ContactState::Accepted).await?;
    wait_contact(&bob, &alice_actor, ContactState::Accepted).await?;

    let (new_seed_base64, _) = test_service_signing_key("contact-signer-rotation-new");
    group
        .server_mut(0)
        .restart_external_process_with_notary_signing_key(&new_seed_base64)
        .await?;
    let history = service_webvh_history(group.server(0)).await?;
    ensure!(
        history.len() == 2,
        "signer rotation must add exactly one WebVH successor"
    );
    let version_time = history[1]["versionTime"]
        .as_str()
        .context("rotation omitted versionTime")?
        .parse::<chrono::DateTime<chrono::Utc>>()?;
    group.server_mut(1).restart_external_process().await?;
    wait_contact(&bob, &alice_actor, ContactState::Accepted).await?;

    let (carol, carol_account) =
        standard_client(group.server(1), &coauth, "rotation-carol", CAROL_DEVICE).await?;
    let new_receipt = alice
        .request_contact_with_peer(
            ContactPeer::Human {
                account_id: carol_account.clone(),
            },
            ContactIntroductionEvidence::LocatorRef {
                principal_locator: issued_locator(&carol).await?,
            },
        )
        .await?;
    ensure!(
        new_receipt.core.accepted_at >= version_time,
        "new Contact evidence precedes the signer successor's effective time"
    );
    wait_contact(&carol, &alice_actor, ContactState::PendingIncoming)
        .await
        .context("new-signer Contact request did not arrive at Carol")?;
    carol.accept_contact(&alice).await?;
    group.server_mut(1).restart_external_process().await?;
    wait_contact(&bob, &alice_actor, ContactState::Accepted).await?;
    wait_contact(&carol, &alice_actor, ContactState::Accepted).await?;

    let did = group.server(0).service_did();
    let old_key = receipt_key_at(did, &history, &old_receipt)?;
    let new_key = receipt_key_at(did, &history, &new_receipt)?;
    ensure!(
        old_key != new_key,
        "Contact signer did not change after the real successor"
    );
    arkret_signatures::contact_receipt::verify_contact_request_acceptance_receipt(
        &old_receipt,
        &old_receipt.core.request_event_ref,
        &old_key,
    )?;
    arkret_signatures::contact_receipt::verify_contact_request_acceptance_receipt(
        &new_receipt,
        &new_receipt.core.request_event_ref,
        &new_key,
    )?;
    ensure!(
        arkret_signatures::contact_receipt::verify_contact_request_acceptance_receipt(
            &old_receipt,
            &old_receipt.core.request_event_ref,
            &new_key,
        )
        .is_err(),
        "old Contact evidence validated with the new assertion key"
    );
    ensure!(
        arkret_signatures::contact_receipt::verify_contact_request_acceptance_receipt(
            &new_receipt,
            &new_receipt.core.request_event_ref,
            &old_key,
        )
        .is_err(),
        "new Contact evidence validated with the old assertion key"
    );
    ensure!(
        validate_webvh_history_at(did, &history[1..], old_receipt.core.accepted_at).is_err(),
        "a partial history was accepted as old signer evidence"
    );
    let mut wrong_method = new_receipt.clone();
    wrong_method.signature.verification_method =
        DidUrl::new(format!("{did}#missing")).map_err(anyhow::Error::msg)?;
    ensure!(
        receipt_key_at(did, &history, &wrong_method).is_err(),
        "an unregistered Contact verification method was selected"
    );
    let mut tampered = new_receipt.clone();
    tampered.signature.jws.push('x');
    ensure!(
        arkret_signatures::contact_receipt::verify_contact_request_acceptance_receipt(
            &tampered,
            &tampered.core.request_event_ref,
            &new_key,
        )
        .is_err(),
        "tampered Contact receipt signature was accepted"
    );
    Ok(())
}

pub async fn concurrent_requests_complete_glare_round() -> Result<()> {
    let Some(alice_database) = database("contact-glare-live")? else {
        return Ok(());
    };
    let Some(bob_database) = database("contact-glare-live")? else {
        return Ok(());
    };
    ensure!(
        alice_database.connect_url != bob_database.connect_url,
        "glare Stations need distinct databases"
    );
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let station = |url: &str| {
        let mut env = station_env(url, &coauth);
        env.push(("COLAND_FEDERATION_OUTBOUND".to_owned(), "1".to_owned()));
        env
    };
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        "contact-glare-live",
        &[
            station(&alice_database.connect_url),
            station(&bob_database.connect_url),
        ],
    )
    .await?
    else {
        return skip_or_fail("contact-glare-live", "prebuilt Coland unavailable");
    };
    let (alice, alice_account) =
        standard_client(group.server(0), &coauth, "glare-alice", ALICE_DEVICE).await?;
    let (bob, bob_account) =
        standard_client(group.server(1), &coauth, "glare-bob", BOB_DEVICE).await?;
    let alice_locator = issued_locator(&alice).await?;
    let bob_locator = issued_locator(&bob).await?;
    ensure!(
        alice_locator.account_id == alice_account && bob_locator.account_id == bob_account,
        "glare locators changed participant Accounts"
    );
    let (alice_result, bob_result) = tokio::join!(
        alice.request_contact_with_peer(
            ContactPeer::Human {
                account_id: bob_account.clone(),
            },
            ContactIntroductionEvidence::LocatorRef {
                principal_locator: bob_locator,
            },
        ),
        bob.request_contact_with_peer(
            ContactPeer::Human {
                account_id: alice_account.clone(),
            },
            ContactIntroductionEvidence::LocatorRef {
                principal_locator: alice_locator,
            },
        )
    );
    let alice_receipt = alice_result?;
    let bob_receipt = bob_result?;
    ensure!(
        alice_receipt.core.request_event_ref != bob_receipt.core.request_event_ref,
        "glare requests have the same Event ref"
    );
    let alice_row = wait_contact(
        &alice,
        &ActorId::account(bob_account.clone()),
        ContactState::Accepted,
    )
    .await?;
    let bob_row = wait_contact(
        &bob,
        &ActorId::account(alice_account.clone()),
        ContactState::Accepted,
    )
    .await?;
    let alice_round = alice_row
        .next_prepare_input
        .as_ref()
        .context("glare initiator has no confirmed round input")?;
    let bob_round = bob_row
        .next_prepare_input
        .as_ref()
        .context("glare receiver has no confirmed round input")?;
    ensure!(
        alice_round.contact_round_id == bob_round.contact_round_id,
        "glare Stations installed different Contact rounds"
    );
    let alice_resolve = alice
        .sdk()
        .direct_conversation_resolve(&DirectConversationResolveRequestBody {
            peer: ContactPeer::Human {
                account_id: bob_account.clone(),
            },
        })
        .await?;
    let bob_resolve = bob
        .sdk()
        .direct_conversation_resolve(&DirectConversationResolveRequestBody {
            peer: ContactPeer::Human {
                account_id: alice_account.clone(),
            },
        })
        .await?;
    let founder_material = match (&alice_resolve, &bob_resolve) {
        (
            DirectConversationResolveOutcome::CreationRequired {
                next_founding_input,
            },
            DirectConversationResolveOutcome::AwaitingFounder { .. },
        )
        | (
            DirectConversationResolveOutcome::AwaitingFounder { .. },
            DirectConversationResolveOutcome::CreationRequired {
                next_founding_input,
            },
        ) => next_founding_input,
        _ => bail!(
            "glare did not identify one DC founder: Alice {alice_resolve:?}; Bob {bob_resolve:?}"
        ),
    };
    let DirectConversationFoundingAuthorityEvidence::Human {
        contact_round_evidence,
        ..
    } = &founder_material.founding_authority_evidence
    else {
        bail!("glare founder received non-Contact DC authority");
    };
    ensure!(
        contact_round_evidence.contact_round_id == alice_round.contact_round_id,
        "glare DC founding input names another Contact round"
    );
    tombstone_contact(&alice, &alice_row).await?;
    wait_contact(
        &alice,
        &ActorId::account(bob_account.clone()),
        ContactState::Tombstoned,
    )
    .await?;
    wait_contact(
        &bob,
        &ActorId::account(alice_account.clone()),
        ContactState::Tombstoned,
    )
    .await?;
    Ok(())
}

async fn checkpoint_fault(url: &str, install: bool) -> Result<()> {
    let url = url.to_owned();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut client=postgres::Client::connect(&url,postgres::NoTls)?;
        if install {
            client.batch_execute(r#"
                CREATE FUNCTION reject_checkpoint_result() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN IF NEW.operation_id='ak.self.contact.command.checkpoint' AND NEW.idempotency_key LIKE 'contact-checkpoint-result:%' THEN RAISE EXCEPTION 'injected checkpoint result failure'; END IF; RETURN NEW; END $$;
                CREATE TRIGGER reject_checkpoint_result BEFORE INSERT ON idempotency_keys FOR EACH ROW EXECUTE FUNCTION reject_checkpoint_result();
            "#)?;
        } else { client.batch_execute("DROP TRIGGER reject_checkpoint_result ON idempotency_keys; DROP FUNCTION reject_checkpoint_result();")?; }
        Ok(())
    }).await??;
    Ok(())
}

async fn prune_completed_checkpoint_plan(url: &str, key: &str) -> Result<()> {
    let (url, key) = (url.to_owned(), format!("contact-checkpoint:{key}"));
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut client=postgres::Client::connect(&url,postgres::NoTls)?;
        client.execute("DELETE FROM idempotency_keys WHERE operation_id='coland://internal/contact-checkpoint-plan' AND idempotency_key=$1",&[&key])?;
        Ok(())
    }).await??;
    Ok(())
}

async fn frozen_checkpoint_plan(url: &str, key: &str) -> Result<serde_json::Value> {
    let (url, key) = (url.to_owned(), format!("contact-checkpoint:{key}"));
    let body=tokio::task::spawn_blocking(move || -> Result<String> {
        let mut client=postgres::Client::connect(&url,postgres::NoTls)?;
        Ok(client.query_one("SELECT response_body::text FROM idempotency_keys WHERE operation_id='coland://internal/contact-checkpoint-plan' AND idempotency_key=$1",&[&key])?.get(0))
    }).await??;
    Ok(serde_json::from_str(&body)?)
}

// Read the actual stored tail, before the export view strips carrier metadata.
// A second checkpoint must leave the same accepted row usable for authoring.
async fn assert_stored_checkpoint_tail(url: &str, digest: &arkret::Hash) -> Result<()> {
    let url = url.to_owned();
    let (current, history) = tokio::task::spawn_blocking(move || -> Result<(String, String)> {
        let mut client = postgres::Client::connect(&url, postgres::NoTls)?;
        let rows = client.query("SELECT contact_round_evidence::text,contact_round_evidence_history::text FROM contacts", &[])?;
        ensure!(rows.len() == 1, "checkpoint fixture must have exactly one durable Contact");
        Ok((rows[0].get::<_, Option<String>>(0).context("committed current missing")?, rows[0].get(1)))
    }).await??;
    let current: arkret::contact_operations::ContactRoundEvidenceBundle =
        serde_json::from_str(&current)?;
    let history: Vec<arkret::contact_operations::ContactRoundEvidenceBundle> =
        serde_json::from_str(&history)?;
    ensure!(
        current
            .continuity_checkpoint
            .as_ref()
            .is_some_and(|checkpoint| &checkpoint.checkpoint_digest == digest),
        "durable current did not install the committed checkpoint"
    );
    arkret::contact_operations::validate_recontact_continuity(&current, &history)
        .context("stored checkpoint tail no longer supports Contact authoring")?;
    ensure!(
        history
            .iter()
            .all(|bundle| bundle.continuity_checkpoint.is_none()),
        "retained tail kept superseded checkpoint carrier metadata"
    );
    Ok(())
}

/// Real authoring/PG/HTTP and native process restart; no synthetic Contact history.
pub async fn checkpoint_replay_and_long_history(cross_station: bool) -> Result<()> {
    use arkret::contact_operations::{
        ContactContinuityCheckpointRequestBody, ContactContinuityCheckpointStatus,
    };
    let name = if cross_station {
        "contact-checkpoint-cross-live"
    } else {
        "contact-checkpoint-local-live"
    };
    let alice_database = database(name)?.context("checkpoint requires PostgreSQL")?;
    let bob_database = database(name)?.context("checkpoint requires PostgreSQL")?;
    if cross_station {
        ensure!(
            alice_database.connect_url != bob_database.connect_url,
            "checkpoint Stations require independent databases"
        );
    }
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let mut envs = vec![station_env(&alice_database.connect_url, &coauth)];
    if cross_station {
        envs.push(station_env(&bob_database.connect_url, &coauth));
    }
    let mut group = TestServerGroup::try_multi_external_with_node_envs(name, &envs)
        .await?
        .context("checkpoint requires native Coland")?;
    let (mut alice, alice_account) =
        standard_client(group.server(0), &coauth, "checkpoint-alice", ALICE_DEVICE).await?;
    let (mut bob, bob_account) = standard_client(
        group.server(usize::from(cross_station)),
        &coauth,
        "checkpoint-bob",
        BOB_DEVICE,
    )
    .await?;
    let alice_actor = ActorId::account(alice_account.clone());
    let bob_actor = ActorId::account(bob_account.clone());
    let peer = ContactPeer::Human {
        account_id: bob_account.clone(),
    };
    let total = if cross_station { 66 } else { 3 };
    // A locator is reusable until expiry or explicit revocation. The live
    // outbox cadence makes 66 rounds exceed the default 15-minute lifetime;
    // request the existing v1 one-hour maximum for this long fixture.
    let locator = issued_locator_with_ttl(&bob, 3600).await?;
    // Freeze an uncommitted first-request draft. After a real accepted round
    // becomes terminal, retrying it must replay, not select new server history.
    let frozen_prepare = if !cross_station {
        let request = alice.contact_request_prepare_with_peer(
            peer.clone(),
            ContactIntroductionEvidence::LocatorRef {
                principal_locator: locator.clone(),
            },
        )?;
        let prepared = alice
            .sdk()
            .contacts_request(&alice.verify_publication(request.clone())?)
            .await?;
        ensure!(
            matches!(
                prepared,
                arkret::contact_operations::ContactOperationOutcome::Prepared { .. }
            ),
            "initial replay fixture did not prepare"
        );
        Some((request, prepared))
    } else {
        None
    };
    let mut last_checkpoint = None;
    let mut authenticated_at = Instant::now();
    for round in 0..total {
        // Reauthenticate the long fixture through the existing mock issuer
        // ledger. Never extend the predecessor grant or production expiry.
        if authenticated_at.elapsed() >= Duration::from_secs(240) {
            alice = group
                .server(0)
                .reissue_mock_native_host_session(&alice, &coauth)
                .await?;
            bob = group
                .server(usize::from(cross_station))
                .reissue_mock_native_host_session(&bob, &coauth)
                .await?;
            authenticated_at = Instant::now();
            eprintln!("checkpoint live: reauthenticated the same accepted Account/Device");
        }
        if round > 0 {
            let current = wait_contact(&alice, &bob_actor, ContactState::Accepted).await?;
            tombstone_contact(&alice, &current).await?;
            wait_contact(&bob, &alice_actor, ContactState::Tombstoned).await?;
            if round == 1
                && let Some((request, original)) = &frozen_prepare
            {
                let replay = alice
                    .sdk()
                    .contacts_request(&alice.verify_publication(request.clone())?)
                    .await?;
                ensure!(
                    serde_json::to_value(original)? == serde_json::to_value(replay)?,
                    "prepare retry reselected mutable server continuity"
                );
                let mut changed = request.clone();
                let arkret::contact_operations::ContactOperationRequestBody::Prepare(body) =
                    &mut changed
                else {
                    unreachable!()
                };
                body.message = Some("different retry bytes".to_owned());
                ensure!(
                    matches!(
                        alice
                            .sdk()
                            .contacts_request(&alice.verify_publication(changed)?)
                            .await,
                        Err(arkret_http_client::Error::Api { status: 409, .. })
                    ),
                    "changed caller bytes reused a frozen prepare identity"
                );
            }
        }
        ensure!(
            chrono::Utc::now() < locator.expires_at,
            "fixture locator expired before live round {round}"
        );
        alice
            .request_contact_with_peer(
                peer.clone(),
                ContactIntroductionEvidence::LocatorRef {
                    principal_locator: locator.clone(),
                },
            )
            .await?;
        wait_contact(&bob, &alice_actor, ContactState::PendingIncoming).await?;
        bob.accept_contact(&alice).await?;
        wait_contact(&alice, &bob_actor, ContactState::Accepted).await?;
        wait_contact(&bob, &alice_actor, ContactState::Accepted).await?;
        if round == 1 || (cross_station && (round == 32 || round == 64)) {
            let request = ContactContinuityCheckpointRequestBody {
                idempotency_key: arkret::IdempotencyKey::new(format!("checkpoint-{round}"))
                    .map_err(anyhow::Error::msg)?,
                peer: peer.clone(),
            };
            if round == 1 {
                checkpoint_fault(&alice_database.connect_url, true).await?;
            }
            // Deliberately discard the response before reconstructing the client request.
            let first = alice
                .sdk()
                .contacts_checkpoint(&alice_account, &request)
                .await;
            if round == 1 {
                if !cross_station {
                    ensure!(
                        first.is_err(),
                        "injected local result failure must refuse acceptance"
                    );
                }
                let frozen = frozen_checkpoint_plan(
                    &alice_database.connect_url,
                    request.idempotency_key.as_str(),
                )
                .await?;
                let before = alice.sdk().contacts_list_with_continuity().await?;
                ensure!(
                    before
                        .contacts
                        .iter()
                        .find(|row| row.peer.contact_actor_id() == bob_actor)
                        .context("contact disappeared")?
                        .continuity_evidence
                        .is_none(),
                    "failed result transaction installed a checkpoint"
                );
                group.server_mut(0).restart_external_process().await?;
                ensure!(
                    frozen
                        == frozen_checkpoint_plan(
                            &alice_database.connect_url,
                            request.idempotency_key.as_str()
                        )
                        .await?,
                    "restart rewrote frozen proposal"
                );
                checkpoint_fault(&alice_database.connect_url, false).await?;
            } else {
                first?;
            }
            let deadline = Instant::now() + Duration::from_secs(90);
            let accepted = loop {
                let outcome = alice
                    .sdk()
                    .contacts_checkpoint(&alice_account, &request)
                    .await?;
                if outcome.status == ContactContinuityCheckpointStatus::Committed {
                    break outcome;
                }
                ensure!(Instant::now() < deadline, "checkpoint never committed");
                tokio::time::sleep(Duration::from_millis(250)).await;
            };
            assert_stored_checkpoint_tail(&alice_database.connect_url, &accepted.checkpoint_digest)
                .await?;
            if cross_station {
                assert_stored_checkpoint_tail(
                    &bob_database.connect_url,
                    &accepted.checkpoint_digest,
                )
                .await?;
            }
            let frozen = frozen_checkpoint_plan(
                &alice_database.connect_url,
                request.idempotency_key.as_str(),
            )
            .await?;
            ensure!(
                frozen["proposal"]["checkpoint_digest"]
                    == serde_json::to_value(&accepted.checkpoint_digest)?,
                "retry replaced the frozen checkpoint"
            );
            let replay = alice
                .sdk()
                .contacts_checkpoint(&alice_account, &request)
                .await?;
            ensure!(
                serde_json::to_value(&accepted)? == serde_json::to_value(replay)?,
                "completed retry changed response bytes"
            );
            let evidence = accepted
                .continuity_evidence
                .as_ref()
                .context("committed without evidence")?;
            ensure!(
                evidence.uncompressed_tail_entries.len() <= 64
                    && evidence.checkpoint.signatures[0].signer
                        != evidence.checkpoint.signatures[1].signer,
                "checkpoint has no bounded bilateral evidence"
            );
            let exported = bob.sdk().contacts_list_with_continuity().await?;
            ensure!(
                exported
                    .contacts
                    .iter()
                    .find(|row| row.peer.contact_actor_id() == alice_actor)
                    .and_then(|row| row.continuity_evidence.as_ref())
                    .is_some_and(|e| e.checkpoint.checkpoint_digest == accepted.checkpoint_digest),
                "peer did not commit same checkpoint"
            );
            let mut wrong = request.clone();
            wrong.peer = ContactPeer::Human {
                account_id: arkret::AccountId::new(
                    bob_account.principal_id.clone(),
                    alice_account.station_id.clone(),
                ),
            };
            if cross_station {
                ensure!(
                    accepted
                        .validate_for_request(&alice_account, &wrong)
                        .is_err(),
                    "same principal at another Station matched checkpoint"
                );
            }
            wrong.peer = ContactPeer::Human {
                account_id: arkret::AccountId::new(
                    bob_account.principal_id.clone(),
                    arkret::DidCoreId::new("ak:did_core:web:unrelated.example")?,
                ),
            };
            ensure!(
                matches!(
                    alice
                        .sdk()
                        .contacts_checkpoint(&alice_account, &wrong)
                        .await,
                    Err(arkret_http_client::Error::Api { status: 409, .. })
                ),
                "changed peer reused checkpoint identity"
            );
            let mut altered = accepted.clone();
            altered.checkpoint_digest = arkret::Hash::new(format!("sha256:{}", "f".repeat(64)))?;
            ensure!(
                altered
                    .validate_for_request(&alice_account, &request)
                    .is_err(),
                "changed digest accepted"
            );
            let mut altered = accepted.clone();
            altered
                .continuity_evidence
                .as_mut()
                .unwrap()
                .uncompressed_tail_entries
                .clear();
            ensure!(
                altered
                    .validate_for_request(&alice_account, &request)
                    .is_err(),
                "missing tail accepted"
            );
            if round == 1 {
                group.server_mut(0).restart_external_process().await?;
                if cross_station {
                    group.server_mut(1).restart_external_process().await?;
                }
                ensure!(
                    serde_json::to_value(&accepted)?
                        == serde_json::to_value(
                            alice
                                .sdk()
                                .contacts_checkpoint(&alice_account, &request)
                                .await?
                        )?,
                    "cold completed replay changed"
                );
            }
            if round == 1 {
                prune_completed_checkpoint_plan(
                    &alice_database.connect_url,
                    request.idempotency_key.as_str(),
                )
                .await?;
                ensure!(
                    serde_json::to_value(&accepted)?
                        == serde_json::to_value(
                            alice
                                .sdk()
                                .contacts_checkpoint(&alice_account, &request)
                                .await?
                        )?,
                    "completed replay depended on an expired pending plan"
                );
            }
            last_checkpoint = Some(accepted);
        }
        eprintln!(
            "checkpoint live cross_station={cross_station}: completed round {}/{total}",
            round + 1
        );
    }
    let last = last_checkpoint.context("checkpoint never executed")?;
    let evidence = last
        .continuity_evidence
        .context("last checkpoint missing evidence")?;
    if cross_station {
        ensure!(
            evidence.checkpoint.core.covered_prefix_count > 32,
            "long live history was not compacted"
        );
    }
    Ok(())
}
