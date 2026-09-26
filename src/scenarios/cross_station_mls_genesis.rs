//! A Station Y member activates MLS in a Station X Realm: the forwarded
//! `ak.mls.genesis` carries its two public Blobs
//! (`zh/crypto-media/encryption-and-audit.md` §5.1.2, `zh/sync/federation.md`
//! §4.1, `ak.vector.federation.authority_forward_genesis_material.v1`).
//!
//! Against two live Solands with separate PostgreSQL databases:
//!
//! 1. Alice on X creates an invite-only Realm; Bob, whose Account lives on Y, accepts her directed
//!    Invite through Y and is granted `ak.mls.genesis`.
//! 2. Bob's Genesis naming Blobs Y does not hold is refused by Y itself with a bare
//!    `failed_precondition`; X never commits it. Y answers Bob's read of the later grant from its
//!    own typed current, while Alice's Invite before his join and every read by Eve, a Y Account
//!    outside the Realm, are not found.
//! 3. Bob uploads the epoch-0 GroupInfo and ratchet tree to Y bound to the Realm (Eve's Realm-bound
//!    upload is `capability_denied`) and submits his Genesis there. Y forwards it with
//!    `mls_genesis_material`, X verifies the content addresses and the RFC 9420 public state,
//!    commits it under its own signature and replicates the Commit back to Y.
//! 4. X serves the exact two Blobs through `ak.peer.mls.read.group_state_material.v1` to Y, and the
//!    byte-identical Genesis submitted again returns the original Commit.

use anyhow::{Context, Result, anyhow, ensure};
use arkret::{ArkretMlsIdentity, ArkretMlsSigner, MlsGovernanceBindingPayload};
use arkret_models_collaboration::governance::membership_invite::{
    InviteAcceptPayload, InvitePreviousState,
};
use arkret_models_collaboration::governance::realm_join_intake::RealmJoinIntent;
use arkret_models_collaboration::mls_group_state_material::{
    MlsGroupStateMaterialOutcome, MlsGroupStateMaterialRequestBody,
};
use arkret_wire::{
    ActorId, AuthorityCommitStatus, AuthoritySubmitOutcome, EventId, EventKind, InviteId, RealmId,
    ScopeRef,
};
use chrono::{Duration as ChronoDuration, Utc};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    CanonicalJsonBody, TestActorClient, TestServerGroup, invite_create_payload, submitted_event_id,
};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::delivery_media::blob_upload_form;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, ensure_commit_signed_by, ensure_never_committed,
    ensure_same_commit, grant_realm_actions, prepare_join, standard_client, station_env,
    submit_and_expect_commit, wait_for_committed,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
use crate::scenarios::mls_lifecycle_live::upload_public_blob;

const GROUP: &str = "cross-station-mls-genesis";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002501";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002502";
const EVE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002503";
const ACTIVE_SUITE: &str = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
const GROUP_STATE_MATERIAL: &str = "/_arkret/peer/mls/group-state-material";

fn canonical(value: Value) -> Result<Value> {
    Ok(serde_json::from_slice(
        &arkret_canonical::canonical_json_bytes(&value)?,
    )?)
}

fn blob_ref(bytes: &[u8]) -> String {
    format!("ak:blob:{}", arkret_canonical::sha256_digest(bytes))
}

/// Submit `event` through the member's own Station and return the raw
/// answer.
async fn submit_raw(
    client: &TestActorClient,
    event: &arkret_wire::Event,
) -> Result<(StatusCode, Value)> {
    let response = client
        .post("/_arkret/self/events")
        .canonical_json(&crate::publication::initial_submission(event.clone(), "")?)?
        .send()
        .await?;
    let status = response.status();
    let body = response.json::<Value>().await.unwrap_or(Value::Null);
    Ok((status, body))
}

/// Upload `bytes` as one of the member's own content-addressed Blobs on its
/// Account Station (`ak.self.blob.*`), the store the forwarding Station reads
/// the Genesis material from.
/// Upload `bytes` bound to `realm_id` and return the status and problem or
/// outcome body.
async fn realm_bound_upload(
    client: &TestActorClient,
    realm_id: &RealmId,
    bytes: &[u8],
) -> Result<(StatusCode, Value)> {
    let response = client
        .post("/_arkret/self/blob/upload")
        .header("x-arkret-realm-id", realm_id.as_str())
        .multipart(blob_upload_form(bytes, "application/octet-stream")?)
        .send()
        .await?;
    let status = response.status();
    Ok((status, response.json().await?))
}

/// `client`'s Station answers a read of `event_id` as not found.
async fn ensure_not_found(client: &TestActorClient, event_id: &EventId) -> Result<()> {
    let response = client
        .get(&format!(
            "/_arkret/self/committed-events/{}",
            event_id.as_str()
        ))
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::NOT_FOUND,
        "a read of {event_id} outside the caller's interval was {}",
        response.status()
    );
    Ok(())
}

/// The Genesis payload naming `group_info_ref` and `ratchet_tree_ref`.
fn genesis_payload(
    group_info_ref: &str,
    ratchet_tree_ref: &str,
    binding: &MlsGovernanceBindingPayload,
) -> Result<Value> {
    canonical(json!({
        "cipher_suite": ACTIVE_SUITE,
        "group_info_ref": group_info_ref,
        "ratchet_tree_ref": ratchet_tree_ref,
        "governance_binding": binding,
        "created_at": arkret_canonical::format_timestamp_canonical(Utc::now()),
    }))
}

pub async fn cross_station_mls_genesis_run() -> Result<()> {
    let Some(governance_database) = database(GROUP)? else {
        return Ok(());
    };
    let Some(member_database) = database(GROUP)? else {
        return Ok(());
    };
    ensure!(
        governance_database.connect_url != member_database.connect_url,
        "the governance and member Stations must use separate databases"
    );
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[
            station_env(&governance_database.connect_url, &coauth),
            station_env(&member_database.connect_url, &coauth),
        ],
    )
    .await?
    else {
        return skip_or_fail(GROUP, "prebuilt Soland unavailable");
    };
    let governance = group.server(0);
    let member_station = group.server(1);

    // (1) Bob on Y joins Alice's invite-only Realm on X and may activate MLS.
    let (alice, _) = standard_client(governance, &coauth, "xgenesis-alice", ALICE_DEVICE).await?;
    let (bob, bob_account) =
        standard_client(member_station, &coauth, "xgenesis-bob", BOB_DEVICE).await?;
    let realm = create_realm_with_join_rule(
        &alice,
        "Cross-Station Genesis",
        "invite",
        &[governance, member_station],
    )
    .await?;
    let realm_id = RealmId::new(realm.clone())?;
    let created = alice
        .submit_event(
            &realm,
            EventKind::InviteCreate.as_str(),
            invite_create_payload(
                &bob.actor,
                bob.service_id(),
                format!("sha256:{}", "e".repeat(64)),
                Utc::now() + ChronoDuration::days(7),
            )?,
        )
        .await
        .context("commit the directed Invite to Bob's Station Y Account")?;
    let invite_id = InviteId::from_event_id(&submitted_event_id(&created)?);
    prepare_join(
        &bob,
        &realm,
        governance,
        "ak:request:019b0000-0000-7000-8000-000000002503",
        RealmJoinIntent::InviteAccept {
            invite_id: invite_id.clone(),
        },
    )
    .await?;
    let accept = bob
        .author_event(
            &realm,
            EventKind::InviteAccept.as_str(),
            serde_json::to_value(InviteAcceptPayload::directed(
                invite_id,
                bob_account.clone(),
                InvitePreviousState::Pending,
            ))?,
        )
        .await?;
    let accept_commit = submit_and_expect_commit(&bob, &bob_account, BOB_DEVICE, &accept).await?;
    ensure_same_commit(
        &accept_commit,
        &wait_for_committed(&bob, &accept.event_id).await?,
    )?;
    let grant_commit = grant_realm_actions(
        &alice,
        governance,
        &realm,
        &bob_account,
        &[arkret_wire::CapabilityActionId::MLS_GENESIS],
    )
    .await?;
    // Y answers Bob's read of Alice's later grant from its own typed current;
    // Alice's Invite before his join and every read by Eve, who is not a
    // member, stay not found.
    ensure_same_commit(
        &grant_commit,
        &wait_for_committed(&bob, &grant_commit.event_ref).await?,
    )?;
    let invite_event = submitted_event_id(&created)?;
    let (eve, _) = standard_client(member_station, &coauth, "xgenesis-eve", EVE_DEVICE).await?;
    for (reader, event_id) in [
        (&bob, &invite_event),
        (&eve, &invite_event),
        (&eve, &grant_commit.event_ref),
    ] {
        ensure_not_found(reader, event_id).await?;
    }

    // Bob's epoch-0 group with his own device leaf only.
    let principal = bob
        .principal
        .clone()
        .context("Bob's client carries its provisioned principal")?;
    let identity = ArkretMlsIdentity::new_human_device(
        ActorId::account(bob_account.clone()),
        principal.device_id.clone(),
        ArkretMlsSigner::from_ed25519_signing_key(principal.device_signing_key.clone()),
    )?;
    let scope = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let binding = MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
    let mls_group = identity.create_group_with_governance_binding(&scope, &binding)?;
    let (group_info, tree) = mls_group.public_group_state_bytes()?;

    // (2) A Genesis naming Blobs Y does not hold stops at Y.
    let unheld = bob
        .author_event(
            &realm,
            EventKind::MlsGenesis.as_str(),
            genesis_payload(&blob_ref(&group_info), &blob_ref(&tree), &binding)?,
        )
        .await?;
    let (status, body) = submit_raw(&bob, &unheld).await?;
    ensure!(
        status == StatusCode::CONFLICT
            && body["type"]
                .as_str()
                .is_some_and(|kind| kind.ends_with("/failed_precondition"))
            && body.get("reason_code").is_none(),
        "a Genesis whose Blobs Y does not hold was not a bare failed_precondition: {status} {body}"
    );
    ensure_never_committed(&alice, &unheld.event_id, std::time::Duration::from_secs(2)).await?;

    // (3) Bob uploads both Blobs to Y bound to the Realm, which Y admits
    //     from his joined membership in its typed current; Eve's upload bound
    //     to the same Realm is refused. The forwarded Genesis carries them.
    let (status, refused) = realm_bound_upload(&eve, &realm_id, &group_info).await?;
    ensure!(
        status == StatusCode::FORBIDDEN
            && refused["type"]
                .as_str()
                .is_some_and(|kind| kind.ends_with("/capability_denied")),
        "a non-member's Realm-bound upload on Y was not capability_denied: {status} {refused}"
    );
    let group_info_ref = upload_public_blob(&bob, &realm_id, &group_info).await?;
    let tree_ref = upload_public_blob(&bob, &realm_id, &tree).await?;
    ensure!(
        group_info_ref == blob_ref(&group_info) && tree_ref == blob_ref(&tree),
        "the uploaded Blob refs are not the content addresses"
    );
    let genesis = bob
        .author_event(
            &realm,
            EventKind::MlsGenesis.as_str(),
            genesis_payload(&group_info_ref, &tree_ref, &binding)?,
        )
        .await?;
    let genesis_commit = submit_and_expect_commit(&bob, &bob_account, BOB_DEVICE, &genesis).await?;
    ensure_commit_signed_by(&genesis_commit, governance)?;
    ensure_same_commit(
        &genesis_commit,
        &wait_for_committed(&alice, &genesis.event_id).await?,
    )?;
    ensure_same_commit(
        &genesis_commit,
        &wait_for_committed(&bob, &genesis.event_id).await?,
    )?;

    // (4) X serves the carried Blobs byte for byte to the member Station,
    //     whose replication right covers the Genesis Commit.
    let request = MlsGroupStateMaterialRequestBody {
        realm_id: realm_id.clone(),
        effective_scope: scope.clone(),
        mls_group_id: scope.canonical_mls_group_id()?,
        epoch: 0u64.try_into().map_err(|error| anyhow!("{error:?}"))?,
        group_state_event_id: genesis.event_id.clone(),
        group_info_ref: arkret_wire::BlobRef::new(group_info_ref.clone())?,
        ratchet_tree_ref: arkret_wire::BlobRef::new(tree_ref.clone())?,
        max_response_bytes: None,
    };
    let (status, served) = governance
        .signed_peer_post(
            member_station,
            GROUP_STATE_MATERIAL,
            &arkret_canonical::canonical_json_bytes(&request)?,
            governance.service_id(),
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "X did not serve the Genesis material: {status} {}",
        String::from_utf8_lossy(&served)
    );
    let served: MlsGroupStateMaterialOutcome = serde_json::from_slice(&served)?;
    let validated = served.validate_for_request(&request)?;
    ensure!(
        validated.group_info_bytes == group_info && validated.ratchet_tree_bytes == tree,
        "X served other bytes than the forwarded Genesis carried"
    );

    // The byte-identical Genesis again returns its original Commit.
    let (status, replay) = submit_raw(&bob, &genesis).await?;
    ensure!(
        status == StatusCode::OK,
        "the exact Genesis replay was refused: {status} {replay}"
    );
    let replay: AuthoritySubmitOutcome = serde_json::from_value(replay)?;
    ensure!(
        matches!(
            &replay,
            AuthoritySubmitOutcome::Accepted {
                status: AuthorityCommitStatus::Duplicate,
                commit,
            } if *commit == genesis_commit
        ),
        "the exact Genesis replay did not return its original Commit: {replay:?}"
    );
    drop(coauth);
    Ok(())
}
