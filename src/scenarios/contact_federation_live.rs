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
    let issued = expect_json(
        holder
            .post("/_arkret/self/invite-locators")
            .json(&InviteLocatorIssueRequestBody {
                ttl_seconds: Some(900),
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
        env.push(("SOLAND_FEDERATION_OUTBOUND".to_owned(), "1".to_owned()));
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
        return skip_or_fail(GROUP, "prebuilt Soland unavailable");
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
        return skip_or_fail(ROTATION_GROUP, "prebuilt Soland unavailable");
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
        env.push(("SOLAND_FEDERATION_OUTBOUND".to_owned(), "1".to_owned()));
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
        return skip_or_fail("contact-glare-live", "prebuilt Soland unavailable");
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
