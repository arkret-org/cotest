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
//!    bytes and queues Dave's Welcome, and Dave joins at epoch 2.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use arkret::{ArkretMlsGroup, MlsCommitPayload, MlsGovernanceBindingPayload};
use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
use arkret_models_collaboration::device_messages::DeviceMessagesAckRequestBody;
use arkret_models_collaboration::governance::membership_invite::{
    InviteAcceptPayload, InvitePreviousState,
};
use arkret_models_collaboration::governance::realm_join_intake::RealmJoinIntent;
use arkret_models_collaboration::sync_frames::demand_sync::RealmListMembership;
use arkret_models_crypto::{
    KeyPackagesClaimOutcome, KeyPackagesClaimQueryRequestBody, KeyPackagesUploadOutcome,
};
use arkret_wire::{
    AuthorityCommitStatus, AuthoritySubmitOutcome, EventKind, InviteId, MlsCommitSubmission,
    MlsWelcomeDelivery, RealmId, ScopeRef,
};
use chrono::{Duration as ChronoDuration, Utc};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ArkretServer, TestServerGroup, expect_json, invite_create_payload};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, ensure_commit_signed_by, grant_realm_actions,
    prepare_join, station_env, submit_and_expect_commit, wait_for_committed,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
use crate::scenarios::mls_lifecycle_live::{
    ACTIVE_SUITE, Member, accepted_full_view, canonical, claim_request_between,
    claimed_keypackage_record, fresh_uuid_v7, json_equal, post_bytes_at, post_claim, post_json,
    post_json_at, problem_type, recipient_welcomes, signed_welcome, upload_public_blob,
};
use crate::scenarios::protocol_payloads::account_summary::{account_frames, listed_row};

const GROUP: &str = "cross-station-mls-welcome";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002601";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002602";
const CAROL_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002603";
const DAVE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002607";
const CLAIM_QUERY: &str = "/_arkret/self/keys/keypackages/claims/query";

/// `member` on Y accepts Alice's directed Invite through its own Station.
async fn join_through_invite(
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
async fn publish_one(member: &Member) -> Result<arkret::ArkretMlsIdentity> {
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
async fn claim_for(
    requester: &Member,
    source: &ArkretServer,
    destination: &ArkretServer,
    target: &Member,
    realm_id: &RealmId,
    group_id: &str,
    seed: u8,
) -> Result<(KeyPackagesClaimOutcome, Vec<u8>)> {
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
                return Ok((outcome, bytes));
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
async fn wait_for_welcome(
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

/// Upload `bytes` as one of the member's own content-addressed Blobs.
async fn upload_own_blob(member: &Member, bytes: &[u8]) -> Result<String> {
    let uploaded = expect_json(
        member.client.post("/_arkret/self/blob/upload").multipart(
            crate::scenarios::delivery_media::blob_upload_form(bytes, "application/octet-stream")?,
        ),
        StatusCode::OK,
    )
    .await?;
    uploaded["blob_ref"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow::anyhow!("Blob upload returned no blob_ref: {uploaded}"))
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
    let (outcome, bytes) =
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
    let (group_info, tree) = bob_group.public_group_state_bytes()?;
    let group_info_ref = upload_own_blob(&bob, &group_info).await?;
    let tree_ref = upload_own_blob(&bob, &tree).await?;
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
        accepted_full_view(&bob.client, &first_event.event_id).await? == first_accepted,
        "Y does not hold the exact bytes of Bob's forwarded Commit"
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
        accepted_full_view(&carol.client, &second_event.event_id).await? == second_accepted,
        "Y does not hold the exact bytes of Carol's forwarded Commit"
    );
    let dave_group = ArkretMlsGroup::join_from_verified_welcome_delivery(
        dave_identity,
        &dave_welcome,
        &second_accepted,
    )?;
    ensure!(dave_group.epoch() == 2, "Dave did not join at epoch 2");
    drop(coauth);
    Ok(())
}
