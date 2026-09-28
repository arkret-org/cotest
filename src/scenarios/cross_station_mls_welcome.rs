//! Cross-Station MLS Welcomes (`zh/crypto-media/encryption-and-audit.md` §2.2
//! "跨站 recipient", `zh/crypto-media/device-lifecycle.md` §9.2.3,
//! `ak.vector.mls.cross_station_welcome_replication.v1`).
//!
//! Against two live Solands with separate PostgreSQL databases, Alice's Realm
//! is governed by Station X and Bob, Carol and Dave live on Station Y:
//!
//! 1. They accept Alice's directed Invites through Y; Bob activates the scope through Y.
//! 2. Bob claims Carol's KeyPackage on Y, the claim destination, and submits his inline Add Commit
//!    with Carol's Welcome to Y, which forwards it to X. X verifies everything but the claim of the
//!    Welcome and writes it into the Commit's committed-replication intent to Y; Y re-verifies the
//!    claim against its own ledger and queues the Welcome in the replica transaction. Carol reads
//!    her claim on Y, joins from the Welcome, ACKs it and consumes the claim against the Welcome
//!    binding Y recorded.
//! 3. Carol, now a member, adds Dave the same way: X signs her forwarded Commit, Y holds its exact
//!    bytes and queues Dave's Welcome, and Dave joins at epoch 2. Carol and Dave read the Commits
//!    they join from on Y, from Y's own typed current, although Bob and Carol authored them; the
//!    Genesis Blobs are uploaded to Y bound to the Realm.
//! 4. Alice on X claims one of Dave's KeyPackages at Y through X's durable relay: Y executes the
//!    claim as its destination, X answers the stored outcome and replays it exactly, Dave reads it
//!    on Y, Y replays the exact peer command and answers its query, another digest under the same
//!    identity is `duplicate_conflict` at both Stations, Y's privacy failures share one opaque
//!    `claim_failed` view, and X closes a relayed failure as `claim_failed`.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use arkret::{ArkretMlsGroup, MlsCommitPayload, MlsEndpointIdentity, MlsGovernanceBindingPayload};
use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
use arkret_models_collaboration::device_messages::DeviceMessagesAckRequestBody;
use arkret_models_collaboration::events_payloads::MlsGenesisCreatorLeafAuthority;
use arkret_models_collaboration::governance::membership_invite::{
    InviteAcceptPayload, InvitePreviousState,
};
use arkret_models_collaboration::governance::realm_join_intake::RealmJoinIntent;
use arkret_models_collaboration::mls_roster_authority::{
    MlsAddAuthorityAttestation, MlsAttestAddOutcome, MlsAttestAddRequestBody, MlsAttestAddStatus,
    MlsRosterAuthorityReadOutcome, MlsRosterAuthorityReadRequestBody, MlsRosterRecord,
};
use arkret_models_collaboration::sync_frames::demand_sync::RealmListMembership;
use arkret_models_crypto::{
    KeyPackagesClaimOutcome, KeyPackagesClaimQueryRequestBody, KeyPackagesClaimRequestBody,
    KeyPackagesUploadOutcome, PeerKeyPackagesClaimOutcome, PeerKeyPackagesClaimQueryOutcome,
    PeerKeyPackagesClaimQueryRequestBody, PeerKeyPackagesClaimQueryState,
};
use arkret_wire::{
    AuthorityCommitStatus, AuthoritySubmitOutcome, EventKind, InviteId, MlsCommitSubmission,
    MlsWelcomeDelivery, MlsWelcomeRecipientEndpoint, RealmId, ScopeRef,
};
use chrono::{Duration as ChronoDuration, Utc};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    ArkretServer, TestServerGroup, expect_json, invite_create_payload, test_service_signing_key,
};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, ensure_commit_signed_by, grant_realm_actions,
    prepare_join, station_env, submit_and_expect_commit, wait_for_committed,
};
use crate::scenarios::identity_test_support::{
    HARNESS_INTERNAL_AUTHORITY_SECRET, create_human_actor_profile,
};
use crate::scenarios::mls_lifecycle_live::{
    ACTIVE_SUITE, Member, accepted_full_view, canonical, claim_request_between, claim_request_to,
    claimed_keypackage_record, fresh_uuid_v7, json_equal, post_bytes_at, post_claim, post_json,
    post_json_at, problem_type, recipient_welcomes, signed_welcome, upload_public_blob,
};
use crate::scenarios::protocol_payloads::account_summary::{account_frames, listed_row};

const GROUP: &str = "cross-station-mls-welcome";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002601";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002602";
const CAROL_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002603";
const DAVE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002607";
const EVE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002608";
const CLAIM_QUERY: &str = "/_arkret/self/keys/keypackages/claims/query";
const PEER_ATTEST_ADD: &str = "/_arkret/peer/mls/add-authority-attestations";

fn genesis_creator_leaf_authority(
    group: &mut ArkretMlsGroup,
    creator: &Member,
) -> Result<MlsGenesisCreatorLeafAuthority> {
    group.install_local_creator_binding(
        creator.actor.clone(),
        Some(creator.authorize_event_id.clone()),
    )?;
    let bindings = group.verified_leaf_bindings()?;
    let [leaf] = bindings.as_slice() else {
        bail!("Genesis requires exactly one verified creator leaf");
    };
    ensure!(leaf.leaf_index == 0 && leaf.actor_id == creator.actor);
    let endpoint = match &leaf.endpoint {
        MlsEndpointIdentity::HumanDevice { device_id, .. } if device_id == &creator.device => {
            MlsWelcomeRecipientEndpoint::Device {
                device_id: device_id.clone(),
            }
        }
        _ => bail!("Genesis creator leaf is not the accepted device endpoint"),
    };
    let authority = MlsGenesisCreatorLeafAuthority {
        leaf_signature_key_b64u: leaf.signature_key.clone(),
        endpoint,
        authorization_event_ref: leaf
            .device_authorize_event_id
            .clone()
            .context("Genesis creator leaf lacks DeviceAuthorize Event")?,
    };
    authority.validate()?;
    Ok(authority)
}

/// `member` on Y accepts Alice's directed Invite through its own Station.
pub(crate) async fn join_through_invite(
    alice: &Member,
    governance: &ArkretServer,
    member: &Member,
    realm: &str,
    request_id: &str,
    invite_digest: char,
) -> Result<()> {
    let created = alice
        .client
        .submit_event(
            realm,
            EventKind::InviteCreate.as_str(),
            invite_create_payload(
                &member.client.actor,
                member.client.service_id(),
                format!("sha256:{}", invite_digest.to_string().repeat(64)),
                Utc::now() + ChronoDuration::days(7),
            )?,
        )
        .await
        .context("commit the directed Invite")?;
    let invite_id = InviteId::from_event_id(&crate::harness::submitted_event_id(&created)?);
    prepare_join(
        &member.client,
        realm,
        governance,
        request_id,
        RealmJoinIntent::InviteAccept {
            invite_id: invite_id.clone(),
        },
    )
    .await?;
    let accept = member
        .client
        .author_event(
            realm,
            EventKind::InviteAccept.as_str(),
            serde_json::to_value(InviteAcceptPayload::directed(
                invite_id,
                member.account.clone(),
                InvitePreviousState::Pending,
            ))?,
        )
        .await?;
    submit_and_expect_commit(
        &member.client,
        &member.account,
        member.device.as_str(),
        &accept,
    )
    .await?;
    wait_for_committed(&member.client, &accept.event_id).await?;
    wait_for_joined_row(member, realm).await
}

/// Wait until `member`'s realm list on its own Station names `realm` as
/// joined: the member Station holds the anchored replica of the Realm.
async fn wait_for_joined_row(member: &Member, realm: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let frames = account_frames(&member.client, None).await?;
        if listed_row(&frames, realm).is_ok_and(|row| row.membership == RealmListMembership::Join) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("the member Station never listed the joined Realm");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Publish one fresh KeyPackage of `member` on its own Station and return
/// the identity that holds its private state.
pub(crate) async fn publish_one(member: &Member) -> Result<arkret::ArkretMlsIdentity> {
    let identity = member.mls_identity()?;
    let record = identity.key_package_record()?;
    let upload =
        identity.signed_key_packages_upload_request(&[record], member.method.as_str(), None)?;
    let uploaded: KeyPackagesUploadOutcome = serde_json::from_value(
        expect_json(
            member
                .client
                .post("/_arkret/self/keys/keypackages/upload")
                .json(&upload),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        uploaded.accepted == 1,
        "the KeyPackage was not published: {uploaded:?}"
    );
    Ok(identity)
}

/// Claim one of `target`'s KeyPackages for `requester` until its outcome is
/// available on the requester's Station: a claim relayed to another Station
/// answers `failed_precondition` until the relay has stored the outcome, and
/// a claim the destination cannot serve yet is retried under a new id.
pub(crate) async fn claim_for(
    requester: &Member,
    source: &ArkretServer,
    destination: &ArkretServer,
    target: &Member,
    realm_id: &RealmId,
    group_id: &str,
    seed: u8,
) -> Result<(
    KeyPackagesClaimOutcome,
    Vec<u8>,
    KeyPackagesClaimRequestBody,
)> {
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut attempt = 0u8;
    loop {
        let request = claim_request_between(
            requester,
            source,
            destination,
            target,
            realm_id,
            group_id,
            [seed.wrapping_add(attempt); 16],
            ChronoDuration::minutes(5),
        )?;
        loop {
            let (status, bytes) = post_claim(&requester.client, &request).await?;
            if status == StatusCode::OK {
                let outcome: KeyPackagesClaimOutcome = serde_json::from_slice(&bytes)?;
                outcome
                    .validate_shape()
                    .map_err(|error| anyhow::anyhow!("claim outcome shape: {error:?}"))?;
                return Ok((outcome, bytes, request));
            }
            let kind = problem_type(&bytes)?;
            if Instant::now() >= deadline {
                bail!(
                    "the claim never completed: {status} {}",
                    String::from_utf8_lossy(&bytes)
                );
            }
            if kind == "claim_failed" {
                tokio::time::sleep(Duration::from_secs(2)).await;
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            ensure!(
                kind == "failed_precondition",
                "the claim was refused: {status} {}",
                String::from_utf8_lossy(&bytes)
            );
        }
        attempt += 1;
    }
}

/// The Welcomes in `member`'s recipient queue once `expected` arrived.
pub(crate) async fn wait_for_welcome(
    member: &Member,
    expected: &MlsWelcomeDelivery,
) -> Result<(Vec<MlsWelcomeDelivery>, String)> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let (queued, token) = recipient_welcomes(&member.client).await?;
        if queued.contains(expected) {
            return Ok((queued, token));
        }
        if Instant::now() >= deadline {
            bail!("the replicated Welcome never reached the recipient queue: {queued:?}");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn submit_mls_commit(
    member: &Member,
    commit_event: &arkret_wire::Event,
    welcome: &MlsWelcomeDelivery,
) -> Result<arkret_wire::RealmCommit> {
    let submission = SelfAuthoritySubmitRequest::MlsCommit(MlsCommitSubmission {
        commit_event: commit_event.clone(),
        welcomes: vec![welcome.clone()],
        idempotency_key: arkret_wire::UuidV7::new(fresh_uuid_v7().parse()?)?,
    });
    submission.validate()?;
    let (status, outcome) = post_json(&member.client, &submission).await?;
    ensure!(
        status == StatusCode::OK,
        "the Add Commit with its Welcome was not admitted: {status} {outcome}"
    );
    let outcome: AuthoritySubmitOutcome = serde_json::from_value(outcome)?;
    match outcome {
        AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Committed,
            commit,
        } if commit.event_ref == commit_event.event_id => Ok(commit),
        other => bail!("the Add Commit was not committed: {other:?}"),
    }
}

/// `adder` on Y claims one of `added`'s KeyPackages on their shared Station
/// and submits the inline Add Commit with its Welcome to Y, which forwards it
/// to X; returns the Commit Event, its Welcome, the claim outcome bytes and
/// the Commit X signed.
#[allow(clippy::too_many_arguments)]
async fn forwarded_add(
    y: &ArkretServer,
    adder: &Member,
    adder_group: &mut ArkretMlsGroup,
    added: &Member,
    realm: &str,
    scope: &ScopeRef,
    base: &arkret_wire::EventId,
    base_epoch: u64,
    seed: u8,
) -> Result<(
    arkret_wire::Event,
    MlsWelcomeDelivery,
    KeyPackagesClaimOutcome,
    Vec<u8>,
    arkret_wire::RealmCommit,
)> {
    let realm_id = RealmId::new(realm.to_owned())?;
    let group_id = scope.canonical_mls_group_id()?;
    let (outcome, bytes, _) =
        claim_for(adder, y, y, added, &realm_id, group_id.as_str(), seed).await?;
    ensure!(
        outcome.claims.len() == 1 && outcome.claims[0].actor_id == added.actor,
        "the claim did not select the added member's KeyPackage: {outcome:?}"
    );
    let binding = MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(base.clone()),
        base_epoch,
        base_epoch + 1,
        0,
    )?;
    let add = adder_group.add_member_with_governance_binding(
        &claimed_keypackage_record(&outcome.claims[0], added)?,
        &binding,
    )?;
    let payload = MlsCommitPayload::new(base.clone(), 0, &add.commit, binding)?;
    let commit_event = adder
        .client
        .author_event(
            realm,
            EventKind::MlsCommit.as_str(),
            canonical(serde_json::to_value(&payload)?)?,
        )
        .await?;
    let welcome = signed_welcome(adder, &commit_event, added, &add.welcome)?;
    let commit = submit_mls_commit(adder, &commit_event, &welcome).await?;
    Ok((commit_event, welcome, outcome, bytes, commit))
}

pub async fn cross_station_mls_welcome_run() -> Result<()> {
    cross_station_mls_welcome_original_run().await
}

pub async fn cross_station_mls_attest_add_run() -> Result<()> {
    cross_station_mls_attest_add_direct_run().await
}

async fn cross_station_mls_welcome_original_run() -> Result<()> {
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
    let x = group.server(0);
    let y = group.server(1);

    // (1) Bob, Carol and Dave on Y join Alice's Realm on X; Bob activates
    //     MLS through Y with the forwarded Genesis material.
    let alice = Member::provision(x, &coauth, "xwelcome-alice", ALICE_DEVICE).await?;
    let bob = Member::provision(y, &coauth, "xwelcome-bob", BOB_DEVICE).await?;
    let carol = Member::provision(y, &coauth, "xwelcome-carol", CAROL_DEVICE).await?;
    create_human_actor_profile(&bob.client, "Bob Welcome").await?;
    create_human_actor_profile(&carol.client, "Carol Welcome").await?;
    let dave = Member::provision(y, &coauth, "xwelcome-dave", DAVE_DEVICE).await?;
    let realm =
        create_realm_with_join_rule(&alice.client, "Cross-Station Welcome", "invite", &[x, y])
            .await?;
    let realm_id = RealmId::new(realm.clone())?;
    for (member, request_id, digest) in [
        (&bob, "ak:request:019b0000-0000-7000-8000-000000002604", 'a'),
        (
            &carol,
            "ak:request:019b0000-0000-7000-8000-000000002605",
            'b',
        ),
        (
            &dave,
            "ak:request:019b0000-0000-7000-8000-000000002606",
            'c',
        ),
    ] {
        join_through_invite(&alice, x, member, &realm, request_id, digest).await?;
    }
    grant_realm_actions(
        &alice.client,
        x,
        &realm,
        &bob.account,
        &[
            arkret_wire::CapabilityActionId::MLS_GENESIS,
            arkret_wire::CapabilityActionId::MLS_COMMIT,
        ],
    )
    .await?;
    grant_realm_actions(
        &alice.client,
        x,
        &realm,
        &carol.account,
        &[arkret_wire::CapabilityActionId::MLS_COMMIT],
    )
    .await?;
    let scope = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let group_id = scope.canonical_mls_group_id()?;
    let genesis_binding = MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
    let mut bob_group = bob
        .mls_identity()?
        .create_group_with_governance_binding(&scope, &genesis_binding)?;
    let creator_leaf_authority = genesis_creator_leaf_authority(&mut bob_group, &bob)?;
    let (group_info, tree) = bob_group.public_group_state_bytes()?;
    let group_info_ref = upload_public_blob(&bob.client, &realm_id, &group_info).await?;
    let tree_ref = upload_public_blob(&bob.client, &realm_id, &tree).await?;
    let genesis = bob
        .client
        .author_event(
            &realm,
            EventKind::MlsGenesis.as_str(),
            canonical(json!({
                "cipher_suite": ACTIVE_SUITE,
                "group_info_ref": group_info_ref,
                "ratchet_tree_ref": tree_ref,
                "governance_binding": genesis_binding,
                "creator_leaf_authority": creator_leaf_authority,
                "created_at": arkret_canonical::format_timestamp_canonical(Utc::now()),
            }))?,
        )
        .await?;
    let genesis_commit =
        submit_and_expect_commit(&bob.client, &bob.account, BOB_DEVICE, &genesis).await?;
    ensure_commit_signed_by(&genesis_commit, x)?;
    wait_for_committed(&bob.client, &genesis.event_id).await?;

    // (2) Bob adds Carol through Y. X verifies Carol's Welcome but for its
    //     claim and writes it into the Commit's replication intent to Y,
    //     which re-verifies the claim against its own ledger and queues it.
    let carol_identity = publish_one(&carol).await?;
    let dave_identity = publish_one(&dave).await?;
    let (first_event, carol_welcome, carol_claim, carol_claim_bytes, first_commit) = forwarded_add(
        y,
        &bob,
        &mut bob_group,
        &carol,
        &realm,
        &scope,
        &genesis.event_id,
        0,
        0x41,
    )
    .await?;
    ensure_commit_signed_by(&first_commit, x)?;
    let first_accepted = accepted_full_view(&alice.client, &first_event.event_id).await?;
    let (queued, ack_token) = wait_for_welcome(&carol, &carol_welcome).await?;
    ensure!(
        queued == vec![carol_welcome.clone()],
        "Carol's queue on Y does not hold exactly the replicated Welcome: {queued:?}"
    );
    ensure!(
        accepted_full_view(&carol.client, &first_event.event_id).await? == first_accepted,
        "Carol does not read the exact bytes of Bob's forwarded Commit on Y"
    );
    let claim = carol_claim.claims[0].clone();
    let (status, read) = post_bytes_at(
        &carol.client,
        CLAIM_QUERY,
        &KeyPackagesClaimQueryRequestBody {
            claim_id: arkret_wire::KeypackageClaimId::new(claim.claim_id.clone())?,
        },
    )
    .await?;
    ensure!(
        status == StatusCode::OK && json_equal(&read, &carol_claim_bytes)?,
        "Carol could not read the original claim outcome on Y: {status}"
    );
    let mut carol_group = ArkretMlsGroup::join_from_verified_welcome_delivery(
        carol_identity,
        &carol_welcome,
        &first_accepted,
    )?;
    ensure!(carol_group.epoch() == 1, "Carol did not join at epoch 1");
    carol
        .client
        .post("/_arkret/self/device_messages/ack")
        .json(&DeviceMessagesAckRequestBody { ack_token })
        .send()
        .await?
        .error_for_status()?;
    let receipt = arkret_models_crypto::RecipientMlsDurableReceipt {
        domain: arkret_wire::NonEmptyString::new(
            arkret_wire::DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1.to_owned(),
        )
        .map_err(anyhow::Error::msg)?,
        claim_request_id: carol_claim.claim_request_id.clone(),
        key_package_ref: arkret_wire::NonEmptyString::new(claim.keypackage_ref.clone())
            .map_err(anyhow::Error::msg)?,
        recipient: arkret_models_crypto::RecipientMlsDurableSigner::Device {
            recipient_account_id: carol.account.clone(),
            recipient_device_id: carol.device.clone(),
            device_verification_method: carol.method.clone(),
        },
        recipient_id: y.service_id().clone(),
        realm_id: realm_id.clone(),
        mls_group_id: group_id.clone(),
        mls_epoch: 1,
        welcome_ref: carol_welcome.welcome_id.clone(),
        welcome_digest: carol_welcome.durable_receipt_digest()?,
        durable_at: Utc::now(),
        signature: arkret_models_crypto::KeyOperationSignature {
            kid: arkret_wire::NonEmptyString::new(carol.method.to_string())
                .map_err(anyhow::Error::msg)?,
            signature_algorithm: None,
            sig: arkret_wire::Base64UrlString::new("AA".to_owned()).map_err(anyhow::Error::msg)?,
        },
    };
    let signer = carol.mls_identity()?;
    let consume = signer.signed_key_packages_consume_request(
        arkret_wire::KeypackageClaimId::new(claim.claim_id.clone())?,
        signer.sign_recipient_mls_durable_receipt(receipt)?,
    )?;
    let (status, consumed) = post_json_at(
        &carol.client,
        "/_arkret/self/keys/keypackages/consume",
        &consume,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "Carol could not consume her claim against Y's Welcome binding: {status} {consumed}"
    );

    // (3) Carol, now a member, adds Dave through Y: her forwarded Commit is
    //     signed by X, held by Y byte for byte, and Dave joins at epoch 2.
    let (second_event, dave_welcome, _, _, second_commit) = forwarded_add(
        y,
        &carol,
        &mut carol_group,
        &dave,
        &realm,
        &scope,
        &first_event.event_id,
        1,
        0x51,
    )
    .await?;
    ensure_commit_signed_by(&second_commit, x)?;
    let second_accepted = accepted_full_view(&alice.client, &second_event.event_id).await?;
    wait_for_welcome(&dave, &dave_welcome).await?;
    ensure!(
        accepted_full_view(&dave.client, &second_event.event_id).await? == second_accepted,
        "Dave does not read the exact bytes of Carol's forwarded Commit on Y"
    );
    let dave_group = ArkretMlsGroup::join_from_verified_welcome_delivery(
        dave_identity,
        &dave_welcome,
        &second_accepted,
    )?;
    ensure!(dave_group.epoch() == 2, "Dave did not join at epoch 2");

    // (4) Alice on X claims one of Dave's KeyPackages at Y, Dave's own
    //     Station: X durably relays her self claim, Y executes it as the
    //     claim destination, and X answers the stored outcome.
    publish_one(&dave).await?;
    let (relayed, relayed_bytes, relayed_request) =
        claim_for(&alice, x, y, &dave, &realm_id, group_id.as_str(), 0x61).await?;
    ensure!(
        relayed.claims.len() == 1 && relayed.claims[0].actor_id == dave.actor,
        "the relayed claim did not select Dave's KeyPackage: {relayed:?}"
    );
    let eve = Member::provision(y, &coauth, "xwelcome-eve", EVE_DEVICE).await?;
    peer_claim_at_destination(
        x,
        y,
        &alice,
        &dave,
        &eve,
        &realm_id,
        group_id.as_str(),
        &relayed_request,
        &relayed_bytes,
    )
    .await?;
    drop(coauth);
    Ok(())
}

/// Governance X's founder adds a real member on Y. The requester's existing
/// Realm root authority avoids the separate 2161 cross-Station Grant witness
/// gap while every recipient claim, remote Welcome and peer proof stays live.
async fn cross_station_mls_attest_add_direct_run() -> Result<()> {
    let Some(governance_database) = database(GROUP)? else {
        bail!("MLS attest_add live requires an isolated governance PostgreSQL database");
    };
    let Some(member_database) = database(GROUP)? else {
        bail!("MLS attest_add live requires an isolated recipient PostgreSQL database");
    };
    ensure!(
        governance_database.connect_url != member_database.connect_url,
        "MLS attest_add must use two isolated PostgreSQL databases"
    );
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let group = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[
            station_env(&governance_database.connect_url, &coauth),
            station_env(&member_database.connect_url, &coauth),
        ],
    )
    .await?
    .context("MLS attest_add live requires a prebuilt real Soland binary")?;
    let x = group.server(0);
    let y = group.server(1);
    let alice = Member::provision(x, &coauth, "xroster-alice", ALICE_DEVICE).await?;
    let carol = Member::provision(y, &coauth, "xroster-carol", CAROL_DEVICE).await?;
    create_human_actor_profile(&carol.client, "Carol Roster").await?;
    let realm =
        create_realm_with_join_rule(&alice.client, "Cross-Station MLS Roster", "invite", &[x, y])
            .await?;
    join_through_invite(
        &alice,
        x,
        &carol,
        &realm,
        "ak:request:019b0000-0000-7000-8000-000000002609",
        'd',
    )
    .await?;
    let realm_id = RealmId::new(realm.clone())?;
    let scope = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let group_id = scope.canonical_mls_group_id()?;
    let genesis_binding = MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
    let mut alice_group = alice
        .mls_identity()?
        .create_group_with_governance_binding(&scope, &genesis_binding)?;
    let creator_leaf_authority = genesis_creator_leaf_authority(&mut alice_group, &alice)?;
    let (group_info, tree) = alice_group.public_group_state_bytes()?;
    let group_info_ref = upload_public_blob(&alice.client, &realm_id, &group_info).await?;
    let tree_ref = upload_public_blob(&alice.client, &realm_id, &tree).await?;
    let genesis = alice
        .client
        .author_event(
            &realm,
            EventKind::MlsGenesis.as_str(),
            canonical(json!({
                "cipher_suite": ACTIVE_SUITE,
                "group_info_ref": group_info_ref,
                "ratchet_tree_ref": tree_ref,
                "governance_binding": genesis_binding,
                "creator_leaf_authority": creator_leaf_authority,
                "created_at": arkret_canonical::format_timestamp_canonical(Utc::now()),
            }))?,
        )
        .await?;
    let genesis_commit =
        submit_and_expect_commit(&alice.client, &alice.account, ALICE_DEVICE, &genesis).await?;
    ensure_commit_signed_by(&genesis_commit, x)?;
    let _ = publish_one(&carol).await?;
    let (claim, ..) = claim_for(&alice, x, y, &carol, &realm_id, group_id.as_str(), 0x71).await?;
    ensure!(claim.claims.len() == 1 && claim.claims[0].actor_id == carol.actor);
    let binding =
        MlsGovernanceBindingPayload::new(scope.clone(), Some(genesis.event_id.clone()), 0, 1, 0)?;
    let add = alice_group.add_member_with_governance_binding(
        &claimed_keypackage_record(&claim.claims[0], &carol)?,
        &binding,
    )?;
    let payload = MlsCommitPayload::new(genesis.event_id.clone(), 0, &add.commit, binding)?;
    let commit_event = alice
        .client
        .author_event(
            &realm,
            EventKind::MlsCommit.as_str(),
            canonical(serde_json::to_value(&payload)?)?,
        )
        .await?;
    let welcome = signed_welcome(&alice, &commit_event, &carol, &add.welcome)?;
    let commit = submit_mls_commit(&alice, &commit_event, &welcome).await?;
    ensure_commit_signed_by(&commit, x)?;
    wait_for_welcome(&carol, &welcome).await?;
    attest_add_http_round_trip(
        x,
        y,
        &scope,
        &genesis.event_id,
        &commit_event,
        &commit,
        &welcome,
        &claim,
        &carol,
    )
    .await?;
    roster_authority_http_round_trip(x, y, &scope, &genesis.event_id, &commit_event, &carol).await
}

async fn roster_authority_http_round_trip(
    governance: &ArkretServer,
    recipient_station: &ArkretServer,
    scope: &ScopeRef,
    genesis_ref: &arkret_wire::EventId,
    commit_event: &arkret_wire::Event,
    recipient: &Member,
) -> Result<()> {
    let request = MlsRosterAuthorityReadRequestBody {
        realm_id: scope
            .realm_id_opt()
            .context("roster scope has a Realm")?
            .clone(),
        effective_scope: scope.clone(),
        mls_group_id: scope.canonical_mls_group_id()?,
        genesis_event_ref: genesis_ref.clone(),
        target_commit_event_ref: commit_event.event_id.clone(),
        target_epoch: 1,
        caller_actor_id: recipient.actor.clone(),
        cursor: None,
    };
    let (status, body) = post_json_at(
        &recipient.client,
        arkret_wire::PATH_SELF_MLS_ROSTER_AUTHORITY,
        &request,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "member roster self read failed: {status} {body}"
    );
    let self_page: MlsRosterAuthorityReadOutcome = serde_json::from_value(body)?;
    let (status, bytes) = governance
        .signed_peer_post(
            recipient_station,
            arkret_wire::PATH_PEER_MLS_ROSTER_AUTHORITY,
            &arkret_canonical::canonical_json_bytes(&request)?,
            governance.service_id(),
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "member roster peer read failed: {status} {}",
        String::from_utf8_lossy(&bytes)
    );
    let peer_page: MlsRosterAuthorityReadOutcome = serde_json::from_slice(&bytes)?;
    ensure!(
        arkret_canonical::canonical_json_bytes(&self_page.records)?
            == arkret_canonical::canonical_json_bytes(&peer_page.records)?,
        "self and peer reads returned different accepted roster records"
    );
    ensure!(
        self_page.manifest.records_digest == peer_page.manifest.records_digest
            && self_page.manifest.authority_head_commit_event_ref
                == peer_page.manifest.authority_head_commit_event_ref,
        "self and peer reads signed different roster cuts"
    );
    ensure!(
        self_page.page_index == 0
            && self_page.next_cursor.is_none()
            && self_page.manifest.total_records == 2
            && self_page.manifest.page_count == 1
            && self_page.records.len() == 2,
        "complete Genesis+Add roster was not returned"
    );
    ensure!(
        self_page.manifest.records_digest.as_str()
            == arkret_canonical::canonical_sha256(&self_page.records)?,
        "governance roster digest differs from exact records"
    );
    let (_, governance_seed) = test_service_signing_key(&format!("{GROUP}-0"));
    let governance_key = ed25519_dalek::SigningKey::from_bytes(&governance_seed);
    let method = format!("{}#notary-key", governance.service_did());
    for page in [&self_page, &peer_page] {
        page.manifest.validate_for_request(&request)?;
        arkret_signatures::keypackages::verify_keypackage_signing_input(
            &governance_key.verifying_key().to_bytes(),
            &method,
            &page.manifest.signing_bytes()?,
            &page.manifest.signature,
        )?;
    }
    ensure!(
        matches!(&self_page.records[0], MlsRosterRecord::Genesis { genesis_event_ref, .. } if genesis_event_ref == genesis_ref),
        "roster Genesis does not match accepted group"
    );
    let MlsRosterRecord::Add {
        commit_event_ref,
        proposal_wire_b64u,
        attestation,
        ..
    } = &self_page.records[1]
    else {
        bail!("roster lacks the accepted Add record");
    };
    ensure!(commit_event_ref == &commit_event.event_id && attestation.actor_id == recipient.actor);
    let proposal = arkret_mls::verify_add_proposal_leaf(
        &arkret_canonical::base64url::base64url_decode(proposal_wire_b64u.as_str())?,
    )?;
    ensure!(
        proposal.actor_id == recipient.actor
            && proposal.leaf_signature_key == attestation.leaf_signature_key_b64u
    );

    let mut wrong_caller = request.clone();
    wrong_caller.caller_actor_id = arkret_wire::ActorId::service(governance.service_id().clone());
    let (status, _) = post_json_at(
        &recipient.client,
        arkret_wire::PATH_SELF_MLS_ROSTER_AUTHORITY,
        &wrong_caller,
    )
    .await?;
    ensure!(
        status == StatusCode::NOT_FOUND,
        "wrong self Actor escaped roster gate: {status}"
    );
    let (status, _) = governance
        .signed_peer_post(
            governance,
            arkret_wire::PATH_PEER_MLS_ROSTER_AUTHORITY,
            &arkret_canonical::canonical_json_bytes(&request)?,
            governance.service_id(),
        )
        .await?;
    ensure!(
        status == StatusCode::NOT_FOUND,
        "wrong peer source escaped roster gate: {status}"
    );
    let mut invalid_cursor = request;
    invalid_cursor.cursor = Some("!".to_owned());
    let (status, body) = post_json_at(
        &recipient.client,
        arkret_wire::PATH_SELF_MLS_ROSTER_AUTHORITY,
        &invalid_cursor,
    )
    .await?;
    ensure!(
        status == StatusCode::BAD_REQUEST && body.to_string().contains("cursor_invalid"),
        "malformed cursor was not rejected as cursor_invalid: {status} {body}"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn attest_add_http_round_trip(
    governance: &ArkretServer,
    recipient_station: &ArkretServer,
    scope: &ScopeRef,
    genesis_ref: &arkret_wire::EventId,
    commit_event: &arkret_wire::Event,
    accepted_commit: &arkret_wire::RealmCommit,
    welcome: &MlsWelcomeDelivery,
    claim: &KeyPackagesClaimOutcome,
    recipient: &Member,
) -> Result<()> {
    let source_outcome = PeerKeyPackagesClaimOutcome {
        claim_request_id: claim.claim_request_id.clone(),
        claims: claim.claims.clone(),
        claim_receipt: claim.claim_receipt.clone(),
    };
    source_outcome
        .validate_shape()
        .map_err(|error| anyhow::anyhow!("historical claim outcome invalid: {error:?}"))?;
    let did_method = format!("{}#notary-key", recipient_station.service_did());
    let (_, station_seed) = test_service_signing_key(&format!("{GROUP}-1"));
    let mut attestation = MlsAddAuthorityAttestation {
        attestor_station_id: recipient_station.service_id().clone(),
        realm_id: welcome.realm_id.clone(),
        effective_scope: scope.clone(),
        mls_group_id: scope.canonical_mls_group_id()?,
        genesis_event_ref: genesis_ref.clone(),
        commit_event_ref: commit_event.event_id.clone(),
        commit_stream_position: accepted_commit.stream_position,
        epoch: 1,
        welcome_id: welcome.welcome_id.clone(),
        claim_id: welcome.keypackage_claim_ref.clone(),
        actor_id: recipient.actor.clone(),
        endpoint: welcome.recipient_endpoint.clone(),
        authorization_event_ref: recipient.authorize_event_id.clone(),
        leaf_signature_key_b64u: arkret_wire::Base64UrlString::new(
            arkret_canonical::base64url_encode(recipient.key.verifying_key().as_bytes()),
        )
        .map_err(anyhow::Error::msg)?,
        claim_record_digest: arkret_wire::Hash::new(arkret_canonical::canonical_sha256(
            &source_outcome.claims[0],
        )?)?,
        claim_receipt: source_outcome.claim_receipt.clone(),
        attested_at: Utc::now(),
        signature: source_outcome.claim_receipt.signature.clone(),
    };
    attestation.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &station_seed,
        &did_method,
        &attestation.signing_bytes()?,
    )?;
    let request = MlsAttestAddRequestBody {
        attestation,
        claim_outcome: source_outcome,
    };
    request.validate_claim_binding()?;
    // Both copies of the receipt stay byte identical, so the typed shape
    // remains valid; the historical recipient-Station signature must fail.
    let mut wrong_receipt = request.clone();
    let bad_sig = arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([7; 64]))
        .map_err(anyhow::Error::msg)?;
    wrong_receipt.attestation.claim_receipt.signature.sig = bad_sig.clone();
    wrong_receipt.claim_outcome.claim_receipt.signature.sig = bad_sig;
    wrong_receipt.attestation.signature =
        arkret_signatures::keypackages::sign_keypackage_signing_input(
            &station_seed,
            &did_method,
            &wrong_receipt.attestation.signing_bytes()?,
        )?;
    wrong_receipt.validate_claim_binding()?;
    let (status, body) = post_attest_add(governance, recipient_station, &wrong_receipt).await?;
    ensure!(
        status != StatusCode::OK && String::from_utf8_lossy(&body).contains("signature_invalid"),
        "bad historical claim signature escaped ingress: {status} {}",
        String::from_utf8_lossy(&body)
    );

    // A fresh valid signature over a false accepted-cut selector passes the
    // serving-layer signatures and is refused by governance's atomic PG gate.
    let mut wrong_cut = request.clone();
    wrong_cut.attestation.commit_stream_position += 1;
    wrong_cut.attestation.signature =
        arkret_signatures::keypackages::sign_keypackage_signing_input(
            &station_seed,
            &did_method,
            &wrong_cut.attestation.signing_bytes()?,
        )?;
    wrong_cut.validate_claim_binding()?;
    let (status, body) = post_attest_add(governance, recipient_station, &wrong_cut).await?;
    ensure!(
        status == StatusCode::CONFLICT,
        "false accepted MLS cut was not refused: {status} {}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = post_attest_add(governance, recipient_station, &request).await?;
    ensure!(
        status == StatusCode::OK,
        "signed MLS Add attestation was not installed: {status} {}",
        String::from_utf8_lossy(&body)
    );
    let installed: MlsAttestAddOutcome = serde_json::from_slice(&body)?;
    ensure!(
        matches!(
            installed.status,
            MlsAttestAddStatus::Installed | MlsAttestAddStatus::Duplicate
        ),
        "attest_add returned no installed authority"
    );
    let (status, body) = post_attest_add(governance, recipient_station, &request).await?;
    ensure!(status == StatusCode::OK, "exact replay failed: {status}");
    let replay: MlsAttestAddOutcome = serde_json::from_slice(&body)?;
    ensure!(
        replay.status == MlsAttestAddStatus::Duplicate
            && replay.attestation_digest == installed.attestation_digest,
        "exact replay changed the signed MLS Add authority outcome"
    );
    Ok(())
}

async fn post_attest_add(
    governance: &ArkretServer,
    recipient_station: &ArkretServer,
    body: &MlsAttestAddRequestBody,
) -> Result<(StatusCode, Vec<u8>)> {
    governance
        .signed_peer_post(
            recipient_station,
            PEER_ATTEST_ADD,
            &arkret_canonical::canonical_json_bytes(body)?,
            governance.service_id(),
        )
        .await
}

const PEER_CLAIM: &str = "/_arkret/peer/keys/keypackages/claim";
const PEER_CLAIM_QUERY: &str = "/_arkret/peer/keys/keypackages/claims/query";

/// POST `body` to `receiver` as the peer command `source` signs, under the
/// claim's `Idempotency-Key`.
async fn peer_post(
    receiver: &ArkretServer,
    source: &ArkretServer,
    path: &str,
    body: &impl serde::Serialize,
    claim_request_id: &str,
) -> Result<(StatusCode, Vec<u8>)> {
    receiver
        .signed_peer_post_with_idempotency_key(
            source,
            path,
            &arkret_canonical::canonical_json_bytes(body)?,
            receiver.service_id(),
            Some(claim_request_id),
        )
        .await
}

/// The peer command view `bytes` carries, with its state.
fn peer_view(bytes: &[u8]) -> Result<PeerKeyPackagesClaimQueryOutcome> {
    let view: PeerKeyPackagesClaimQueryOutcome = serde_json::from_slice(bytes)?;
    view.validate_shape()
        .map_err(|error| anyhow::anyhow!("peer claim view shape: {error:?}"))?;
    Ok(view)
}

/// The outward shape of one claim failure: status, the view's closed field
/// names, its state and error code.
fn failure_shape(status: StatusCode, bytes: &[u8]) -> Result<(StatusCode, Vec<String>, Value)> {
    let value: Value = serde_json::from_slice(bytes)?;
    let fields = value
        .as_object()
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default();
    Ok((
        status,
        fields,
        json!([value.get("state"), value.get("error_code")]),
    ))
}

/// The destination side of a claim relayed from X (`device-lifecycle.md`
/// §9.2.3): X's exact replay answers the stored outcome, Dave reads it on Y,
/// Y replays the exact peer command and answers its query with the same
/// outcome, refuses another digest under the same identity with
/// `duplicate_conflict` at both Stations, and every privacy failure is the
/// same opaque `claim_failed` view, which X's relay closes for its caller.
#[allow(clippy::too_many_arguments)]
async fn peer_claim_at_destination(
    x: &ArkretServer,
    y: &ArkretServer,
    requester: &Member,
    target: &Member,
    outsider: &Member,
    realm_id: &RealmId,
    group_id: &str,
    request: &KeyPackagesClaimRequestBody,
    outcome_bytes: &[u8],
) -> Result<()> {
    let (status, replay) = post_claim(&requester.client, request).await?;
    ensure!(
        status == StatusCode::OK && json_equal(&replay, outcome_bytes)?,
        "X's exact replay of the relayed claim did not answer its stored outcome: {status}"
    );
    let outcome: Value = serde_json::from_slice(outcome_bytes)?;
    let claim_id = outcome["claims"][0]["claim_id"]
        .as_str()
        .context("the relayed outcome names no claim")?
        .to_owned();
    let (status, read) = post_bytes_at(
        &target.client,
        CLAIM_QUERY,
        &KeyPackagesClaimQueryRequestBody {
            claim_id: arkret_wire::KeypackageClaimId::new(claim_id)?,
        },
    )
    .await?;
    ensure!(
        status == StatusCode::OK && json_equal(&read, outcome_bytes)?,
        "Dave could not read the relayed claim on Y: {status}"
    );

    // Y: the exact peer command replays its stored outcome, and the query
    // under the exact digest answers the same view.
    let (status, replayed) =
        peer_post(y, x, PEER_CLAIM, request, request.claim_request_id.as_str()).await?;
    ensure!(
        status == StatusCode::OK,
        "Y refused the exact peer replay: {status} {}",
        String::from_utf8_lossy(&replayed)
    );
    let replayed = peer_view(&replayed)?;
    ensure!(
        replayed.state == PeerKeyPackagesClaimQueryState::Claimed
            && serde_json::to_value(&replayed.claim_outcome)? == outcome,
        "Y's exact peer replay is not the stored claimed outcome: {replayed:?}"
    );
    let digest = arkret_wire::Hash::new(arkret_canonical::canonical_sha256(request)?)?;
    let (status, queried) = peer_post(
        y,
        x,
        PEER_CLAIM_QUERY,
        &PeerKeyPackagesClaimQueryRequestBody {
            claim_request_id: request.claim_request_id.clone(),
            request_digest: digest,
        },
        request.claim_request_id.as_str(),
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "Y refused the claim query: {status}"
    );
    let queried = peer_view(&queried)?;
    ensure!(
        queried.state == PeerKeyPackagesClaimQueryState::Claimed
            && serde_json::to_value(&queried.claim_outcome)? == outcome,
        "Y's claim query is not the stored claimed outcome: {queried:?}"
    );

    // The same identity under another digest is duplicate_conflict at X and
    // at Y, and changes nothing.
    let seed: [u8; 16] = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        request.claim_request_id.as_str(),
    )?
    .try_into()
    .map_err(|_| anyhow::anyhow!("the claim request id is not 16 bytes"))?;
    let altered = claim_request_between(
        requester,
        x,
        y,
        target,
        realm_id,
        group_id,
        seed,
        ChronoDuration::minutes(4),
    )?;
    ensure!(
        altered.claim_request_id == request.claim_request_id
            && arkret_canonical::canonical_json_bytes(&altered)?
                != arkret_canonical::canonical_json_bytes(request)?,
        "the altered claim does not reuse the identity with another body"
    );
    for (station, (status, body)) in [
        ("X", post_claim(&requester.client, &altered).await?),
        (
            "Y",
            peer_post(
                y,
                x,
                PEER_CLAIM,
                &altered,
                altered.claim_request_id.as_str(),
            )
            .await?,
        ),
    ] {
        ensure!(
            problem_type(&body)? == "duplicate_conflict",
            "{station} answered another digest under the same claim identity with {status} {}",
            String::from_utf8_lossy(&body)
        );
    }
    let (_, still) = post_claim(&requester.client, request).await?;
    ensure!(
        json_equal(&still, outcome_bytes)?,
        "the conflicting claim changed X's stored outcome"
    );

    // Privacy failures at Y share one opaque view: a target outside the
    // Realm, an unknown target device, an exhausted target and an unknown
    // Realm.
    let unknown_device =
        arkret_wire::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000026ff".to_owned())?;
    let unknown_realm = RealmId::new(format!("ak:realm:A{}", "Q".repeat(43)))?;
    let failures = [
        ((&outsider.account, &outsider.device), realm_id, 0x71u8),
        ((&target.account, &unknown_device), realm_id, 0x72),
        ((&target.account, &target.device), realm_id, 0x73),
        ((&target.account, &target.device), &unknown_realm, 0x74),
    ];
    let mut shapes = Vec::new();
    for (target_endpoint, realm, id) in failures {
        let failing = claim_request_to(
            requester,
            x,
            y,
            target_endpoint,
            realm,
            group_id,
            [id; 16],
            ChronoDuration::minutes(5),
        )?;
        let (status, body) = peer_post(
            y,
            x,
            PEER_CLAIM,
            &failing,
            failing.claim_request_id.as_str(),
        )
        .await?;
        shapes.push(failure_shape(status, &body)?);
    }
    ensure!(
        shapes.windows(2).all(|pair| pair[0] == pair[1])
            && shapes[0].0 == StatusCode::OK
            && shapes[0].2 == json!(["claim_failed", "claim_failed"]),
        "Y's privacy failures are not one opaque claim_failed view: {shapes:?}"
    );

    // Through X's relay the exhausted target closes as claim_failed.
    let relayed_failure = claim_request_between(
        requester,
        x,
        y,
        target,
        realm_id,
        group_id,
        [0x75; 16],
        ChronoDuration::minutes(5),
    )?;
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let (status, body) = post_claim(&requester.client, &relayed_failure).await?;
        let kind = problem_type(&body)?;
        if kind == "claim_failed" {
            break;
        }
        ensure!(
            kind == "failed_precondition" && Instant::now() < deadline,
            "X did not close the relayed failure as claim_failed: {status} {}",
            String::from_utf8_lossy(&body)
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Ok(())
}
