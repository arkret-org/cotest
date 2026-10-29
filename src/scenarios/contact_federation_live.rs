//! A two-Station Contact request and normal response over the durable peer
//! carrier. Both directions must converge on the same accepted round.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use arkret::contact_operations::{
    ContactPeer, ContactPreparePhase, ContactState, ContactTombstonePrepareRequestBody,
};
use arkret_models_collaboration::contact_operations::RequestAcceptanceReceipt;
use arkret_models_collaboration::direct_conversation::{
    DirectConversationResolveRequestBody, DirectConversationResolveResponseBody,
};
use arkret_models_collaboration::governance::invite_addressing::{
    InviteLocatorIssueRequestBody, InviteLocatorResolveRequestBody, PrincipalLocator,
};
use arkret_models_collaboration::governance::peer_contact::{
    ContactIntroductionEvidence, PeerContactAddress,
};
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

pub(crate) async fn issued_locator(holder: &TestActorClient) -> Result<PrincipalLocator> {
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

pub(crate) async fn wait_contact(
    holder: &TestActorClient,
    peer: &ActorId,
    state: ContactState,
) -> Result<arkret::contact_operations::ContactView> {
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
    row: &arkret::contact_operations::ContactView,
) -> Result<()> {
    use arkret::contact_operations::{
        ContactCommitPhase, ContactCommitRequestBody, ContactOperationResponseBody,
        ContactPreparedResponseBody,
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
    let prepared: ContactOperationResponseBody = serde_json::from_value(
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
    let ContactOperationResponseBody::Prepared {
        outcome:
            ContactPreparedResponseBody::Tombstone {
                reservation_handle,
                event_draft,
                ..
            },
    } = prepared
    else {
        bail!("cross-Station tombstone did not prepare: {prepared:?}");
    };
    let committed: ContactOperationResponseBody = serde_json::from_value(
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
        matches!(committed, ContactOperationResponseBody::Accepted { .. }),
        "cross-Station tombstone was not accepted: {committed:?}"
    );
    Ok(())
}

async fn scope_update_contact(
    holder: &TestActorClient,
    row: &arkret::contact_operations::ContactView,
    scopes: Vec<arkret::contact_operations::ContactScope>,
) -> Result<arkret::contact_operations::ContactAcceptedResponseBody> {
    use arkret::contact_operations::*;
    let next = row
        .next_prepare_input
        .as_ref()
        .context("accepted Contact cursor missing")?;
    let operation_id = arkret::ProtocolOperationId::new(crate::harness::next_typed_id("operation"))
        .map_err(anyhow::Error::msg)?;
    let idempotency_key = arkret::IdempotencyKey::new(crate::harness::next_typed_id("idempotency"))
        .map_err(anyhow::Error::msg)?;
    let path = "/_arkret/self/contacts/scope-update";
    let prepared: ContactOperationResponseBody = serde_json::from_value(
        expect_json(
            holder
                .post(path)
                .json(&ContactScopeUpdatePrepareRequestBody {
                    phase: ContactPreparePhase::Prepare,
                    operation_id: operation_id.clone(),
                    idempotency_key: idempotency_key.clone(),
                    peer: row.peer.clone(),
                    contact_round_id: next.contact_round_id.clone(),
                    version: next.version,
                    predecessor_event_ref: next.predecessor_event_ref.clone(),
                    granted_to_peer_scopes: scopes,
                }),
            StatusCode::OK,
        )
        .await?,
    )?;
    let ContactOperationResponseBody::Prepared {
        outcome:
            ContactPreparedResponseBody::ScopeUpdate {
                reservation_handle,
                event_draft,
                ..
            },
    } = prepared
    else {
        bail!("scope update did not prepare: {prepared:?}");
    };
    let body = ContactCommitRequestBody {
        phase: ContactCommitPhase::Commit,
        operation_id,
        idempotency_key,
        reservation_handle,
        signed_event: holder.sign_prepared_contact_event(
            &event_draft,
            arkret_wire::event_kind_str::CONTACT_SCOPE_UPDATE,
        )?,
    };
    let outcome: ContactOperationResponseBody =
        serde_json::from_value(expect_json(holder.post(path).json(&body), StatusCode::OK).await?)?;
    let replay: ContactOperationResponseBody =
        serde_json::from_value(expect_json(holder.post(path).json(&body), StatusCode::OK).await?)?;
    ensure!(
        serde_json::to_value(&outcome)? == serde_json::to_value(&replay)?,
        "scope commit retry changed its frozen source result"
    );
    let ContactOperationResponseBody::Accepted { outcome } = outcome else {
        bail!("scope update did not commit: {outcome:?}");
    };
    Ok(outcome)
}

struct NativeContactHistory(Vec<arkret_models_identity::IdentityLogListResponseBody>);
impl arkret_identity::AuthorityDidHistoryResolver for NativeContactHistory {
    fn resolve_complete_history(
        &self,
        did: &Did,
    ) -> std::result::Result<
        arkret_models_identity::IdentityLogListResponseBody,
        arkret_identity::AuthorityHistoryUnavailable,
    > {
        self.0
            .iter()
            .find(|h| &h.did == did)
            .cloned()
            .ok_or_else(|| arkret_identity::AuthorityHistoryUnavailable {
                message: "unrecognized live service DID".into(),
            })
    }
}
async fn native_contact_history(group: &TestServerGroup) -> Result<NativeContactHistory> {
    let mut histories = Vec::new();
    for index in [0, 1] {
        let server = group.server(index);
        histories.push(arkret_models_identity::IdentityLogListResponseBody {
            did: server.service_did().clone(),
            method: arkret_models_identity::DidMethodUri::Webvh,
            native_history: Some(true),
            entries: service_webvh_history(server).await?,
            next_cursor: None,
            has_more: false,
        });
    }
    Ok(NativeContactHistory(histories))
}
async fn submit_current_control(
    group: &TestServerGroup,
    request: &arkret::contact_operations::PeerContactSubmitRequestBody,
) -> Result<arkret::contact_operations::PeerContactSubmitResponseBody> {
    let (status, body) = group
        .server(1)
        .signed_peer_post(
            group.server(0),
            "/_arkret/peer/contacts",
            &arkret_canonical::canonical_json_bytes(request)?,
            group.server(1).service_id(),
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "native current control failed: {status} {}",
        String::from_utf8_lossy(&body)
    );
    Ok(serde_json::from_slice(&body)?)
}
async fn exercise_native_scope_aba_and_frozen_current(
    group: &TestServerGroup,
    alice: &TestActorClient,
    bob: &TestActorClient,
    alice_actor: &ActorId,
    bob_actor: &ActorId,
    bob_database: &str,
    alice_database: &str,
) -> Result<()> {
    use arkret::contact_operations::*;
    let before = bounded_contact_snapshot(bob_database).await?;
    let original: ContactPrivateState = serde_json::from_value(before)?;
    let direction = original
        .direction_actor(bob_actor)
        .context("Bob current direction missing")?;
    let old_grant = direction
        .scope_instances
        .iter()
        .find(|i| i.contact_scope == ContactScope::DirectMessage)
        .context("original DM grant missing")?
        .grant_event_ref
        .clone();
    let row = wait_contact(bob, alice_actor, ContactState::Accepted).await?;
    let removed = scope_update_contact(bob, &row, vec![]).await?;
    let ContactAcceptedResponseBody::ScopeUpdate {
        lineage: removed_lineage,
        current_proof: removed_proof,
        ..
    } = &removed
    else {
        bail!("scope result kind");
    };
    let peer = ContactPeer::Human {
        account_id: bob_actor.as_account_id().context("Bob is Human")?.clone(),
    };
    let requester = ContactPeer::Human {
        account_id: alice_actor
            .as_account_id()
            .context("Alice is Human")?
            .clone(),
    };
    let request = PeerContactSubmitRequestBody::CurrentRefresh {
        idempotency_key: arkret::IdempotencyKey::new(crate::harness::next_typed_id("idempotency"))
            .map_err(anyhow::Error::msg)?,
        requester,
        trust_domain_id: group.server(1).trust_domain().clone(),
        initial_contact_round_id: original
            .initial_identity
            .as_ref()
            .map(|i| i.round.contact_round_id.clone()),
        known_version: removed_proof.version,
        grant_event_refs: vec![old_grant.clone()],
        contact_address: PeerContactAddress::for_recipient(
            peer,
            arkret_models_identity::ServiceResolutionCarrier::ResolutionUrl {
                resolution_url: group.server(1).url(
                    &arkret_models_identity::canonical_service_resolution_path(
                        group.server(1).service_id(),
                    ),
                ),
            },
        ),
    };
    ensure!(
        serde_json::to_value(&request)?
            .get("prior_mirror_receipt")
            .is_none(),
        "current depended on a mirror"
    );
    let frozen = submit_current_control(group, &request).await?;
    let histories = native_contact_history(group).await?;
    arkret::contact_authorization::verify_contact_current_refresh_response(
        &request,
        &frozen,
        arkret_canonical::DigestSuite::Sha256,
        chrono::Utc::now(),
        &histories,
    )?;
    let PeerContactSubmitResponseBody::Control(
        PeerContactControlSubmitResponseBody::CurrentRefresh { material, .. },
    ) = &frozen
    else {
        bail!("current returned no material");
    };
    ensure!(
        material
            .current_proof
            .scope_instances
            .iter()
            .all(|i| i.contact_scope != ContactScope::DirectMessage),
        "removed scope stayed current"
    );
    let interval = material
        .historical_intervals
        .iter()
        .find(|i| {
            i.contact_scope == ContactScope::DirectMessage && i.grant.event().event_id == old_grant
        })
        .context("exact removed interval absent")?;
    ensure!(
        interval
            .closed_by
            .as_ref()
            .is_some_and(|op| op.event().event_id == removed_lineage.event_ref),
        "source did not certify the first actual close"
    );
    let row = wait_contact(bob, alice_actor, ContactState::Accepted).await?;
    let added = scope_update_contact(bob, &row, vec![ContactScope::DirectMessage]).await?;
    let ContactAcceptedResponseBody::ScopeUpdate {
        lineage: added_lineage,
        current_proof: added_proof,
        ..
    } = added
    else {
        bail!("readd scope kind");
    };
    let dm = added_proof
        .scope_instances
        .iter()
        .find(|i| i.contact_scope == ContactScope::DirectMessage)
        .context("readded DM missing")?;
    ensure!(
        dm.grant_event_ref == added_lineage.event_ref && dm.grant_event_ref != old_grant,
        "scope ABA reused its removed grant"
    );
    let replay = submit_current_control(group, &request).await?;
    ensure!(
        serde_json::to_value(&frozen)? == serde_json::to_value(&replay)?,
        "same current key renewed or reselected its source cut"
    );
    let mut tampered = frozen.clone();
    if let PeerContactSubmitResponseBody::Control(
        PeerContactControlSubmitResponseBody::CurrentRefresh { material, .. },
    ) = &mut tampered
    {
        material
            .historical_intervals
            .iter_mut()
            .find(|i| i.closed_by.is_some())
            .context("native first-close interval missing")?
            .closed_by = None;
    }
    ensure!(
        arkret::contact_authorization::verify_contact_current_refresh_response(
            &request,
            &tampered,
            arkret_canonical::DigestSuite::Sha256,
            chrono::Utc::now(),
            &histories
        )
        .is_err(),
        "signed control did not cover the exact historical boundary"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let row = wait_contact(alice, bob_actor, ContactState::Accepted).await?;
        let peer_current: ContactPrivateState =
            serde_json::from_value(bounded_contact_snapshot(alice_database).await?)?;
        if row
            .bidirectional_scopes
            .contains(&ContactScope::DirectMessage)
            && peer_current.direction_actor(bob_actor).is_some_and(|d| {
                d.head_operation.version() >= added_proof.version
                    && d.scope_instances.iter().any(|i| {
                        i.contact_scope == ContactScope::DirectMessage
                            && i.grant_event_ref == added_lineage.event_ref
                    })
            })
        {
            break;
        }
        ensure!(Instant::now() < deadline, "readded scope did not converge");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
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
            DirectConversationResolveResponseBody::CreationRequired {
                next_founding_input,
            },
            DirectConversationResolveResponseBody::AwaitingFounder { .. },
        )
        | (
            DirectConversationResolveResponseBody::AwaitingFounder { .. },
            DirectConversationResolveResponseBody::CreationRequired {
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
    exercise_native_scope_aba_and_frozen_current(
        &group,
        &alice,
        &bob,
        &alice_actor,
        &bob_actor,
        &bob_database.connect_url,
        &alice_database.connect_url,
    )
    .await?;
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
    let version_created_at = history[1]["versionTime"]
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
        new_receipt.core.accepted_at >= version_created_at,
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
    use DirectConversationResolveResponseBody::{
        AwaitingFounder, CreationRequired, TemporarilyUnavailable,
    };

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
    // Accepted Contact can precede both verified current proofs. Wait only for
    // unresolved authoring material; deterministic outcomes keep the assertions below.
    let deadline = Instant::now() + Duration::from_secs(30);
    let (alice_resolve, bob_resolve) = loop {
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
        let pending_material = matches!(
            (&alice_resolve, &bob_resolve),
            (
                TemporarilyUnavailable { .. },
                AwaitingFounder { .. } | CreationRequired { .. } | TemporarilyUnavailable { .. }
            ) | (
                AwaitingFounder { .. } | CreationRequired { .. },
                TemporarilyUnavailable { .. }
            )
        );
        if !pending_material {
            break (alice_resolve, bob_resolve);
        }
        ensure!(
            Instant::now() < deadline,
            "glare founding material remained unavailable: Alice {alice_resolve:?}; Bob {bob_resolve:?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    let founder_material = match (&alice_resolve, &bob_resolve) {
        (
            DirectConversationResolveResponseBody::CreationRequired {
                next_founding_input,
            },
            DirectConversationResolveResponseBody::AwaitingFounder { .. },
        )
        | (
            DirectConversationResolveResponseBody::AwaitingFounder { .. },
            DirectConversationResolveResponseBody::CreationRequired {
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

// Inspect the actual bounded PG row; this is not a synthetic history fixture.
async fn bounded_contact_snapshot(url: &str) -> Result<serde_json::Value> {
    let url = url.to_owned();
    tokio::task::spawn_blocking(move || -> Result<serde_json::Value> {
        let mut client = postgres::Client::connect(&url, postgres::NoTls)?;
        let row = client.query_one("SELECT current_state::text FROM contacts", &[])?;
        let current: serde_json::Value = serde_json::from_str(&row.get::<_, String>(0))?;
        let directions = current["directions"]
            .as_array()
            .context("current directions missing")?;
        ensure!(
            directions.len() == 2,
            "both current directions are required"
        );
        for direction in directions {
            ensure!(
                direction["scope_instances"]
                    .as_array()
                    .context("scope instances absent")?
                    .len()
                    <= 5
                    && direction["scope_grants"]
                        .as_array()
                        .context("scope origins absent")?
                        .len()
                        <= 5,
                "current material grew with history"
            );
        }
        ensure!(
            serde_json::to_vec(&current)?.len() <= 2 * 1024 * 1024,
            "current exceeds wire hard limit"
        );
        Ok(current)
    })
    .await?
}
async fn clear_verified_contact_cache(url: &str, local: &ActorId) -> Result<()> {
    let (url, local) = (url.to_owned(), serde_json::to_string(local)?);
    tokio::task::spawn_blocking(move ||->Result<()>{
        let mut client=postgres::Client::connect(&url,postgres::NoTls)?;
        client.batch_execute("DELETE FROM contact_verified_mirrors")?;
        // Drop only foreign leases. Immutable original heads and durable
        // observation floors remain, as after loss of a verified mirror cache.
        client.execute("UPDATE contacts SET current_state=jsonb_set(current_state,'{directions}',(SELECT jsonb_agg(CASE WHEN d#>'{head_operation,signed_event,actor_id}'=$1::text::jsonb THEN d ELSE d-'current_proof' END) FROM jsonb_array_elements(current_state->'directions') d)),contact_round_evidence=NULL",&[&local])?;
        Ok(())
    }).await?
}

pub async fn current_recovery_and_long_history(cross_station: bool) -> Result<()> {
    let name = if cross_station {
        "contact-current-cross-live"
    } else {
        "contact-current-local-live"
    };
    let alice_database = database(name)?.context("current requires PostgreSQL")?;
    let bob_database = database(name)?.context("current requires PostgreSQL")?;
    if cross_station {
        ensure!(
            alice_database.connect_url != bob_database.connect_url,
            "current Stations require independent databases"
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
        .context("current requires native Coland")?;
    let (mut alice, alice_account) =
        standard_client(group.server(0), &coauth, "current-alice", ALICE_DEVICE).await?;
    let (mut bob, bob_account) = standard_client(
        group.server(usize::from(cross_station)),
        &coauth,
        "current-bob",
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
                arkret::contact_operations::ContactOperationResponseBody::Prepared { .. }
            ),
            "initial replay fixture did not prepare"
        );
        Some((request, prepared))
    } else {
        None
    };
    let mut initial_identity = None;
    let mut previous_versions = std::collections::BTreeMap::new();
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
            eprintln!("current live: reauthenticated the same accepted Account/Device");
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
                    "prepare retry reselected mutable server state"
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
        if !cross_station && round == 0 {
            let alice_locator = issued_locator(&alice).await?;
            // Both requests remain unconsumed. The distinct-Station case
            // separately exercises simultaneous HTTP writers; here the same
            // pair row may legitimately refuse a stale row revision.
            alice
                .request_contact_with_peer(
                    peer.clone(),
                    ContactIntroductionEvidence::LocatorRef {
                        principal_locator: locator.clone(),
                    },
                )
                .await?;
            bob.request_contact_with_peer(
                ContactPeer::Human {
                    account_id: alice_account.clone(),
                },
                ContactIntroductionEvidence::LocatorRef {
                    principal_locator: alice_locator,
                },
            )
            .await?;
        } else {
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
        }
        wait_contact(&alice, &bob_actor, ContactState::Accepted).await?;
        wait_contact(&bob, &alice_actor, ContactState::Accepted).await?;
        let current = bounded_contact_snapshot(&alice_database.connect_url).await?;
        let identity = current["initial_identity"].clone();
        if let Some(initial) = &initial_identity {
            ensure!(
                initial == &identity,
                "recontact changed the fixed first identity"
            );
        } else {
            initial_identity = Some(identity);
        }
        for direction in current["directions"]
            .as_array()
            .context("directions absent")?
        {
            let op = &direction["head_operation"];
            let holder = op["signed_event"]["actor_id"].to_string();
            let version = op["signed_event"]["payload"]["version"]
                .as_u64()
                .context("lifetime version absent")?;
            if let Some(previous) = previous_versions.insert(holder, version) {
                ensure!(
                    version > previous,
                    "operation version reset across recontact"
                );
            }
        }
        if round == 1 || (cross_station && (round == 32 || round == 64)) {
            clear_verified_contact_cache(&alice_database.connect_url, &alice_actor).await?;
            group.server_mut(0).restart_external_process().await?;
            if cross_station {
                group.server_mut(1).restart_external_process().await?;
            }
            let deadline = Instant::now() + Duration::from_secs(90);
            loop {
                let result = alice
                    .sdk()
                    .direct_conversation_resolve(&DirectConversationResolveRequestBody {
                        peer: peer.clone(),
                    })
                    .await;
                if matches!(
                    result,
                    Ok(DirectConversationResolveResponseBody::CreationRequired { .. })
                        | Ok(DirectConversationResolveResponseBody::AwaitingFounder { .. })
                ) {
                    break;
                }
                ensure!(
                    Instant::now() < deadline,
                    "bounded current did not recover after a cold start without mirror: {result:?}"
                );
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            let recovered = bounded_contact_snapshot(&alice_database.connect_url).await?;
            ensure!(
                Some(&recovered["initial_identity"]) == initial_identity.as_ref(),
                "recovery replaced fixed founding identity"
            );
        }
        eprintln!(
            "current live cross_station={cross_station}: completed round {}/{total}",
            round + 1
        );
    }
    Ok(())
}
