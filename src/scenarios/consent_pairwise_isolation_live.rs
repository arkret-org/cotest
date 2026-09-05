//! Live consent isolation between a Realm-local ephemeral pairwise actor and
//! an ordinary root Account (scenario `identity/consent-grant` E1.4).
//!
//! Spec `zh/identity/consent-model.md` section 3.2 and section 6.1 query step
//! 1: `consent_peer` has two disjoint branches. An ordinary Account is matched
//! on its complete `ActorId`; the Realm-local ephemeral pairwise actor of a
//! `ak.profile.mls.minimal_metadata_realm.v1` Realm is matched on the whole
//! `(realm_id, principal_id)` pair. The branches never match each other, and
//! the same pairwise key under another Realm is a different peer.
//!
//! The pairwise actor here is real: a `did:key` principal whose
//! `ak:did_core:key:` projection is admitted into a minimal-metadata Realm
//! through an accepted `ak.member.state` join, which is the v1 binding — there
//! is no separate "pairwise binding Event". It has no account, no Principal
//! Control Realm and no session; the authenticated human session is transport
//! authority only. Nothing here substitutes a `did:peer` value or a second
//! registered Account for it, which is what the earlier E1.4 had to do while
//! the pairwise branch carried no Realm.

use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};
use arkret_identifiers::ConsentId;
use arkret_models_collaboration::account_lifecycle::{
    ConsentCellView, ConsentGrantRequestBody, ConsentPeer,
};
use arkret_models_collaboration::events_payloads::ConsentGrantPayload;
use arkret_models_collaboration::governance::membership_invite::MembershipPayload;
use arkret_wire::{
    AccountId, ActorId, ConsentScope, DidCoreId, EventInitialSubmission, EventKind, RealmId,
};
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{ArkretServer, TestActorClient, expect_json, next_typed_id};
use crate::scenarios::_helpers::external_binary::{SOLAND_SPEC, locate_external_binary};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

const HOLDER_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002401";
const ROOT_PEER_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002402";
/// Seed of the Realm-local pairwise endpoint incarnation.
const PAIRWISE_SEED: [u8; 32] = [0x51; 32];

/// A real Realm-local ephemeral pairwise principal: a `did:key` whose
/// `ak:did_core:key:` projection is the actor id, exactly as
/// `ak.profile.ephemeral_pairwise_principal.v1` defines it.
struct PairwisePrincipal {
    actor_id: DidCoreId,
}

impl PairwisePrincipal {
    fn from_seed(seed: [u8; 32]) -> Result<Self> {
        let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&public_key);
        Ok(Self {
            actor_id: DidCoreId::new(format!("ak:did_core:key:{multibase}"))?,
        })
    }
}

/// Prove that a pairwise consent cell and a root-Account consent cell are
/// mutually invisible, and that a pairwise cell is bound to exactly one Realm.
pub async fn run_consent_pairwise_isolation_live() -> Result<()> {
    if locate_external_binary(&SOLAND_SPEC).is_none() {
        eprintln!(
            "skipping consent pairwise isolation live scenario: pre-built Soland is unavailable"
        );
        return Ok(());
    }

    let server = ArkretServer::spawn("consent-pairwise-isolation").await?;
    let holder_did = actor_did_for_service_did(server.service_did(), "consent-pairwise-holder")?;
    let holder = server
        .register_client(&holder_did, "consent-pairwise-holder", HOLDER_DEVICE)
        .await?;
    let root_peer_did = actor_did_for_service_did(server.service_did(), "consent-pairwise-root")?;
    let root_peer = server
        .register_client(&root_peer_did, "consent-pairwise-root", ROOT_PEER_DEVICE)
        .await?;

    let holder_core_id = holder
        .principal
        .as_ref()
        .context("holder was not provisioned")?
        .core_id
        .clone();
    let root_peer_core_id = root_peer
        .principal
        .as_ref()
        .context("root peer was not provisioned")?
        .core_id
        .clone();

    let pairwise = PairwisePrincipal::from_seed(PAIRWISE_SEED)?;
    ensure!(
        holder_core_id != pairwise.actor_id && root_peer_core_id != pairwise.actor_id,
        "the pairwise actor must not be an authenticated account of this deployment"
    );

    // Two minimal-metadata Realms. The pairwise actor is admitted to the first
    // one only, so the second is the "same key, wrong Realm" control.
    let bound_realm_id = create_minimal_metadata_realm(&holder, "Consent pairwise bound").await?;
    let other_realm_id = create_minimal_metadata_realm(&holder, "Consent pairwise other").await?;
    install_pairwise_membership(&holder, &bound_realm_id, &pairwise).await?;

    let bound_realm_id = RealmId::new(bound_realm_id)?;
    let other_realm_id = RealmId::new(other_realm_id)?;
    let station_id = DidCoreId::new(holder.service_id().to_owned())?;

    let pairwise_peer =
        ConsentPeer::realm_local_pairwise(bound_realm_id.clone(), pairwise.actor_id.clone())?;
    // Same principal core, other Realm: a different peer by the isolation key.
    let cross_realm_peer =
        ConsentPeer::realm_local_pairwise(other_realm_id, pairwise.actor_id.clone())?;
    // Same principal core dressed up as an ordinary Account of this Station.
    let impersonating_actor_peer = ConsentPeer::Actor {
        actor_id: ActorId::account(AccountId::new(
            pairwise.actor_id.clone(),
            station_id.clone(),
        )),
    };
    let root_peer_peer = ConsentPeer::Actor {
        actor_id: ActorId::account(AccountId::new(
            root_peer_core_id.clone(),
            station_id.clone(),
        )),
    };

    // ── Grant to the Realm-local pairwise actor ─────────────────────────────
    let granted = grant_consent(&holder, &pairwise_peer, ConsentScope::DirectMessage).await?;
    ensure!(
        granted.peer == pairwise_peer,
        "consent projection rewrote the pairwise peer: {:?}",
        granted.peer
    );
    ensure!(
        !granted.active_grant_dots.is_empty(),
        "pairwise consent grant produced no active dot: {granted:?}"
    );

    expect_consent_cell(&holder, &pairwise_peer, "direct_message").await?;
    // Cross kind: the same key as an ordinary Account never reaches the cell.
    expect_no_consent_cell(&holder, &impersonating_actor_peer, "direct_message").await?;
    // Cross Realm: `(realm_id, principal_id)` is the isolation key.
    expect_no_consent_cell(&holder, &cross_realm_peer, "direct_message").await?;
    // The root Account has no consent of its own yet.
    expect_no_consent_cell(&holder, &root_peer_peer, "direct_message").await?;

    // ── Grant to the ordinary root Account ──────────────────────────────────
    let root_granted = grant_consent(&holder, &root_peer_peer, ConsentScope::DirectMessage).await?;
    ensure!(
        root_granted.peer == root_peer_peer,
        "consent projection rewrote the root Account peer: {:?}",
        root_granted.peer
    );
    ensure!(
        root_granted.cell_id != granted.cell_id,
        "the pairwise peer and the root Account peer shared one consent cell"
    );

    // Both cells now exist and stay separate.
    expect_consent_cell(&holder, &pairwise_peer, "direct_message").await?;
    expect_consent_cell(&holder, &root_peer_peer, "direct_message").await?;
    // The root Account's grant does not leak into the pairwise lane, and a
    // root peer on another Station is a different peer entirely.
    expect_no_consent_cell(
        &holder,
        &ConsentPeer::realm_local_pairwise(
            bound_realm_id.clone(),
            DidCoreId::new(format!(
                "ak:did_core:key:{}",
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    &SigningKey::from_bytes(&[0x52; 32])
                        .verifying_key()
                        .to_bytes()
                )
            ))?,
        )?,
        "direct_message",
    )
    .await?;
    expect_no_consent_cell(
        &holder,
        &ConsentPeer::Actor {
            actor_id: ActorId::account(AccountId::new(
                root_peer_core_id,
                DidCoreId::new("ak:did_core:web:other-station.invalid".to_owned())?,
            )),
        },
        "direct_message",
    )
    .await?;

    Ok(())
}

/// Author, sign and submit one `ak.consent.grant` Control Move in the holder's
/// Principal Control Realm, and return the projected cell.
async fn grant_consent(
    holder: &TestActorClient,
    peer: &ConsentPeer,
    consent_scope: ConsentScope,
) -> Result<ConsentCellView> {
    let principal = holder
        .principal
        .as_ref()
        .context("holder was not provisioned with a Principal Control Realm")?;
    let payload = ConsentGrantPayload {
        consent_id: ConsentId::new(next_typed_id("consent"))?,
        peer: peer.clone(),
        consent_scope,
        not_before: None,
        expires_at: None,
        constraints: None,
        evidence_ref: None,
        reason: Some("cotest_consent_pairwise_isolation".to_owned()),
    };
    let event = holder
        .author_event(
            principal.pcr_realm_id.as_str(),
            EventKind::ConsentGrant.as_str(),
            serde_json::to_value(payload)?,
        )
        .await?;
    let granted = expect_json(
        holder
            .post("/_arkret/self/consent/cells/grant")
            .json(&ConsentGrantRequestBody {
                grant_event: crate::publication::initial_submission(event, "")?,
            }),
        StatusCode::OK,
    )
    .await?;
    serde_json::from_value(granted).context("consent grant response is not a ConsentCellView")
}

/// The cell is addressed by the exact wire `consent_peer`, so a request that
/// names the wrong kind, Station or Realm is a request for a different cell.
fn consent_cell_request(
    holder: &TestActorClient,
    peer: &ConsentPeer,
    consent_scope: &str,
) -> Result<reqwest::RequestBuilder> {
    Ok(holder.get("/_arkret/self/consent/cell").query(&[
        ("peer", serde_json::to_string(peer)?.as_str()),
        ("consent_scope", consent_scope),
    ]))
}

async fn expect_consent_cell(
    holder: &TestActorClient,
    peer: &ConsentPeer,
    consent_scope: &str,
) -> Result<ConsentCellView> {
    let value = expect_json(
        consent_cell_request(holder, peer, consent_scope)?,
        StatusCode::OK,
    )
    .await?;
    let cell: ConsentCellView =
        serde_json::from_value(value).context("consent cell response is not a ConsentCellView")?;
    ensure!(
        &cell.peer == peer,
        "consent cell answered with a different peer than it was addressed by: {:?}",
        cell.peer
    );
    Ok(cell)
}

async fn expect_no_consent_cell(
    holder: &TestActorClient,
    peer: &ConsentPeer,
    consent_scope: &str,
) -> Result<()> {
    let response = consent_cell_request(holder, peer, consent_scope)?
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    ensure!(
        status == StatusCode::NOT_FOUND,
        "peer {} reached a consent cell it must never match: {status} {body}",
        serde_json::to_string(peer)?,
    );
    Ok(())
}

/// Bootstrap a Realm that declares `ak.profile.mls.minimal_metadata_realm.v1`,
/// the only Realm kind a Realm-local ephemeral pairwise actor exists in.
async fn create_minimal_metadata_realm(client: &TestActorClient, title: &str) -> Result<String> {
    let bootstrap = client
        .create_realm_bootstrap_with(json!({
            "title": title,
            "summary": title,
            "public": false,
            "schema_refs": [
                arkret_wire::SchemaId::REALM_V1,
                arkret_wire::ProfileId::MLS_MINIMAL_METADATA_REALM_V1,
            ],
            "encryption_profile": "mls_rfc9420",
            "plaintext_visible_services": [client.service_id()]
        }))
        .await?;
    let realm_id = bootstrap["realm_id"]
        .as_str()
        .context("minimal-metadata Realm bootstrap omitted realm_id")?
        .to_owned();
    wait_for_bootstrap_seal(client, &realm_id).await?;
    Ok(realm_id)
}

/// Admit the pairwise actor into the Realm through an accepted
/// `ak.member.state` join. That accepted membership *is* the v1 binding the
/// consent match condition refers to; there is no separate binding Event.
async fn install_pairwise_membership(
    client: &TestActorClient,
    realm_id: &str,
    pairwise: &PairwisePrincipal,
) -> Result<()> {
    let payload = MembershipPayload::join(
        RealmId::new(realm_id.to_owned())?,
        ActorId::account(AccountId::new(
            pairwise.actor_id.clone(),
            DidCoreId::new(client.service_id().to_owned())?,
        )),
        "consent pairwise isolation live fixture",
    )
    .to_value()?;
    submit_and_settle_control_event(client, realm_id, EventKind::MemberState.as_str(), payload)
        .await?;
    Ok(())
}

async fn submit_and_settle_control_event(
    client: &TestActorClient,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Result<()> {
    let before = client.realm_seal_frontier(realm_id).await?;
    let before = before["frontier"]["seal_basis"]["leaves"][0]
        .as_str()
        .context("control transition predecessor Seal")?;
    let event = client.author_event(realm_id, kind, payload).await?;
    let submission: EventInitialSubmission = crate::publication::initial_submission(event, "")?;
    let response = expect_json(
        client.post("/_arkret/self/events").json(&submission),
        StatusCode::OK,
    )
    .await?;
    let proposal_digest = response["control_proposal_acks"][0]["proposal_digest"]
        .as_str()
        .context("control transition Control Proposal Ack")?;
    client
        .await_control_proposal_settled(realm_id, proposal_digest, before)
        .await?;
    Ok(())
}

async fn wait_for_bootstrap_seal(client: &TestActorClient, realm_id: &str) -> Result<()> {
    const EMPTY_ROOT: &str =
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    loop {
        match client.realm_seal_frontier(realm_id).await {
            Ok(frontier)
                if frontier["frontier"]["control_event_set_root"].as_str() != Some(EMPTY_ROOT) =>
            {
                return Ok(());
            }
            Ok(_) | Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(frontier) => bail!("minimal-metadata Realm bootstrap Seal stayed empty: {frontier}"),
            Err(error) => {
                return Err(error).context("minimal-metadata Realm bootstrap Seal unavailable");
            }
        }
    }
}
