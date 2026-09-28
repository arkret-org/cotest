//! Live MLS KeyPackage lifecycle on one governing Station
//! (`ak.suite.crypto.keypackage_lifecycle.v1`, encryption-and-audit §2,
//! device-lifecycle §9).
//!
//! Alice founds a public Realm, Bob joins it by his own `ak.member.state`,
//! then the whole same-Station lifecycle runs against the real Soland over
//! its registered surfaces:
//!
//! * Bob publishes KeyPackages whose LeafNode carries the complete ActorId under his device key; an
//!   entry naming a suite other than the one its bytes declare is refused with
//!   `unsupported_ciphersuite` and stores nothing.
//! * Alice's self claim linearizes the `published -> claimed` CAS with its ledger: the exact replay
//!   returns the byte-identical outcome, the same `claim_request_id` with another canonical digest
//!   is `duplicate_conflict` and claims nothing, and a genuinely new attempt under a new id still
//!   finds Bob's other package.
//! * Alice activates the scope with `ak.mls.genesis`, then adds Bob with one inline Add
//!   `ak.mls.commit` whose Welcome names the claim; Bob reads the Welcome from his own recipient
//!   queue, joins from it against the accepted Commit and decrypts Alice's next message. Plaintext
//!   into the activated scope is `mls_activation_required`.
//! * Bob reads the claim through `ak.self.keys.keypackages.read.claim.v1` and gets the original
//!   outcome bytes; Alice and an unknown claim id both get `keypackage_unknown`.
//! * After the durable group state and the ACK, Bob consumes the claim against the Welcome binding
//!   the Station recorded when it queued the Welcome (decision 0121): a receipt naming another
//!   `welcome_digest` or `mls_epoch` is `conflict`, the exact receipt consumes and replays
//!   byte-identically.
//! * After a Station restart the claim ledger replays byte-identically and the ACKed Welcome is not
//!   delivered again.
//!
//! Cross-Station Welcome delivery needs a second Station and is not exercised here.

use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use arkret::{
    ArkretMlsGroup, ArkretMlsIdentity, ArkretMlsSigner, MlsCommitPayload, MlsEndpointIdentity,
    MlsGovernanceBindingPayload, MlsKeyPackageRecord,
};
use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
use arkret_models_collaboration::device_messages::{
    DeviceMessagesAckRequestBody, DeviceMessagesGetOutcome, RecipientDelivery,
};
use arkret_models_collaboration::events_payloads::MlsGenesisCreatorLeafAuthority;
use arkret_models_collaboration::governance::membership_invite::MembershipPayloadState;
use arkret_models_crypto::{
    KeyPackagesClaimOutcome, KeyPackagesClaimQueryRequestBody, KeyPackagesClaimRequestBody,
    KeyPackagesUploadOutcome, mls_key_package_record_upload_entry,
};
use arkret_wire::{
    AccountId, ActorId, AuthorityCommitStatus, AuthoritySubmitOutcome, CommittedEventFullView,
    CommittedEventView, DeviceId, DidUrl, Event, EventId, EventKind, MlsCommitSubmission,
    MlsWelcomeDelivery, MlsWelcomeRecipientEndpoint, RealmId, ScopeRef,
};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{ArkretServer, TestActorClient, TestServerGroup, expect_json};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::delivery_media::blob_upload_form;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, membership_payload, standard_client, station_env,
    submit_and_expect_commit,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;

const GROUP: &str = "mls-keypackage-lifecycle";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002201";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002202";
pub(crate) const ACTIVE_SUITE: &str = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
const RESERVED_SUITE: &str = "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519";
pub(crate) const CONTENT_CAPABILITY: &str = "ak.content.v1";

/// One Account with its standard-grant client and the founding device key
/// every signature of this scenario is made with.
pub(crate) struct Member {
    pub(crate) client: TestActorClient,
    pub(crate) account: AccountId,
    pub(crate) actor: ActorId,
    pub(crate) device: DeviceId,
    pub(crate) method: DidUrl,
    pub(crate) key: SigningKey,
    pub(crate) authorize_event_id: EventId,
}

impl Member {
    pub(crate) async fn provision(
        station: &ArkretServer,
        coauth: &MockCoauthIntrospectionServer,
        label: &str,
        device: &str,
    ) -> Result<Self> {
        let (client, account) = standard_client(station, coauth, label, device).await?;
        let principal = client
            .principal
            .clone()
            .context("the standard client carries its provisioned principal")?;
        let method = DidUrl::new(format!(
            "{}#{}",
            principal.did.as_str(),
            principal.device_id.as_str()
        ))
        .map_err(anyhow::Error::msg)?;
        Ok(Self {
            actor: ActorId::account(account.clone()),
            account,
            device: principal.device_id.clone(),
            method,
            key: principal.device_signing_key.clone(),
            authorize_event_id: principal.founding_authorize_event_id.clone(),
            client,
        })
    }

    /// The MLS endpoint of the founding device: its LeafNode key is the
    /// authorized device key and its BasicCredential the complete ActorId.
    pub(crate) fn mls_identity(&self) -> Result<ArkretMlsIdentity> {
        Ok(ArkretMlsIdentity::new_human_device(
            self.actor.clone(),
            self.device.clone(),
            ArkretMlsSigner::from_ed25519_signing_key(self.key.clone()),
        )?)
    }
}

pub async fn run_same_station_mls_keypackage_lifecycle_live() -> Result<()> {
    run_with_blocklist_observer(false, false).await
}

pub async fn run_blocklist_call_invite_live() -> Result<()> {
    run_with_blocklist_observer(true, false).await
}

pub async fn run_blocklist_automatic_receipt_live() -> Result<()> {
    run_with_blocklist_observer(true, true).await
}

async fn run_with_blocklist_observer(observe_blocklist: bool, observe_receipt: bool) -> Result<()> {
    let Some(database) = database(GROUP)? else {
        if observe_blocklist {
            bail!("blocklist Call evidence requires an isolated PostgreSQL database");
        }
        return Ok(());
    };
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(mut group) = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[station_env(&database.connect_url, &coauth)],
    )
    .await?
    else {
        if observe_blocklist {
            bail!("blocklist Call evidence requires a prebuilt real Soland binary");
        }
        return skip_or_fail(GROUP, "prebuilt Soland unavailable");
    };
    let station = group.server(0);
    let alice = Member::provision(station, &coauth, "mls-alice", ALICE_DEVICE).await?;
    let bob = Member::provision(station, &coauth, "mls-bob", BOB_DEVICE).await?;
    let realm_id = RealmId::new(
        create_realm_with_join_rule(&alice.client, "MLS lifecycle", "public", &[station]).await?,
    )?;
    let strand_id = alice.client.default_strand_id(realm_id.as_str())?;
    let join = bob
        .client
        .author_event(
            realm_id.as_str(),
            EventKind::MemberState.as_str(),
            membership_payload(
                realm_id.as_str(),
                bob.account.clone(),
                MembershipPayloadState::Join,
                "MLS lifecycle member",
            )?,
        )
        .await?;
    submit_and_expect_commit(&bob.client, &bob.account, BOB_DEVICE, &join).await?;

    // Publish: two KeyPackages under the active suite, one whose outer label
    // names a suite its bytes do not declare.
    let bob_identity = bob.mls_identity()?;
    let first = bob_identity.key_package_record()?;
    let second = bob_identity.key_package_record()?;
    let mut mislabeled = bob_identity.key_package_record()?;
    mislabeled.cipher_suites = vec![RESERVED_SUITE.to_owned()];
    let valid_upload = bob_identity.signed_key_packages_upload_request(
        &[first.clone(), second.clone()],
        bob.method.as_str(),
        None,
    )?;
    let mut unsigned = valid_upload.unsigned();
    unsigned
        .keypackages
        .push(mls_key_package_record_upload_entry(&mislabeled).map_err(anyhow::Error::msg)?);
    let signature = arkret_signatures::keypackages::sign_keypackages_upload_request(
        &unsigned,
        bob.method.as_str(),
        &bob.key.to_bytes(),
    )?;
    let upload = unsigned.into_signed(signature);
    let uploaded: KeyPackagesUploadOutcome = serde_json::from_value(
        expect_json(
            bob.client
                .post("/_arkret/self/keys/keypackages/upload")
                .json(&upload),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        uploaded.accepted == 2,
        "the two active-suite KeyPackages were not both published: {uploaded:?}"
    );
    ensure!(
        uploaded.rejections.len() == 1
            && uploaded.rejections[0].reason_code.as_str() == "unsupported_ciphersuite",
        "the mislabeled suite was not refused as unsupported_ciphersuite: {uploaded:?}"
    );
    let published = [
        first.keypackage_ref.to_string(),
        second.keypackage_ref.to_string(),
    ];
    ensure!(
        uploaded
            .key_package_refs
            .iter()
            .all(|reference| published.contains(reference))
            && !uploaded
                .key_package_refs
                .contains(&mislabeled.keypackage_ref.to_string()),
        "the Station stored a KeyPackage outside the active-suite pair: {uploaded:?}"
    );

    // Claim: the self claim, its exact replay, a conflicting reuse of the
    // same identity, and a genuinely new attempt.
    let scope = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let group_id = scope.canonical_mls_group_id()?;
    let first_request = claim_request(
        &alice,
        station,
        &bob,
        &realm_id,
        group_id.as_str(),
        [0x31; 16],
        chrono::Duration::minutes(4),
    )?;
    let (status, first_bytes) = post_claim(&alice.client, &first_request).await?;
    ensure!(
        status == StatusCode::OK,
        "the self claim was not admitted: {status} {}",
        String::from_utf8_lossy(&first_bytes)
    );
    let claimed: KeyPackagesClaimOutcome = serde_json::from_slice(&first_bytes)?;
    claimed
        .validate_shape()
        .map_err(|error| anyhow!("claim outcome shape: {error:?}"))?;
    ensure!(
        claimed.claims.len() == 1 && published.contains(&claimed.claims[0].keypackage_ref),
        "the claim did not select exactly one published KeyPackage: {claimed:?}"
    );
    let claim = claimed.claims[0].clone();
    ensure!(
        claim.actor_id == bob.actor
            && claim.device_id.as_ref() == Some(&bob.device)
            && claim.device_authorize_event_id.as_ref() == Some(&bob.authorize_event_id)
            && claim.agent_key_authorize_event_id.is_none(),
        "the claim record does not carry the exact device-branch owner: {claim:?}"
    );

    let (status, replay_bytes) = post_claim(&alice.client, &first_request).await?;
    ensure!(
        status == StatusCode::OK && json_equal(&replay_bytes, &first_bytes)?,
        "the exact claim replay did not return the stored outcome: {status}"
    );

    // Claim read (device-lifecycle §9 `claims/query`): only the claimed
    // endpoint reads the original outcome; the requester sees the same
    // `keypackage_unknown` as for an unknown id.
    let query = KeyPackagesClaimQueryRequestBody {
        claim_id: arkret_wire::KeypackageClaimId::new(claim.claim_id.clone())?,
    };
    let (status, read_bytes) = post_bytes_at(
        &bob.client,
        "/_arkret/self/keys/keypackages/claims/query",
        &query,
    )
    .await?;
    ensure!(
        status == StatusCode::OK && json_equal(&read_bytes, &first_bytes)?,
        "the claimed endpoint did not read the original claim outcome: {status}"
    );
    for (reader, body) in [
        (&alice, query.clone()),
        (
            &bob,
            KeyPackagesClaimQueryRequestBody {
                claim_id: arkret_wire::KeypackageClaimId::new(
                    "ak:keypackage_claim:01904100-0000-7000-8000-00000000c1a1".to_owned(),
                )?,
            },
        ),
    ] {
        let (status, refused) = post_bytes_at(
            &reader.client,
            "/_arkret/self/keys/keypackages/claims/query",
            &body,
        )
        .await?;
        ensure!(
            status == StatusCode::NOT_FOUND && problem_type(&refused)? == "keypackage_unknown",
            "a claim read outside the claimed endpoint was not keypackage_unknown: {status}"
        );
    }

    let conflicting = claim_request(
        &alice,
        station,
        &bob,
        &realm_id,
        group_id.as_str(),
        [0x31; 16],
        chrono::Duration::minutes(3),
    )?;
    let (status, conflict_bytes) = post_claim(&alice.client, &conflicting).await?;
    ensure!(
        status == StatusCode::CONFLICT && problem_type(&conflict_bytes)? == "duplicate_conflict",
        "reusing claim_request_id with another digest was not duplicate_conflict: {status} {}",
        String::from_utf8_lossy(&conflict_bytes)
    );
    let fresh = claim_request(
        &alice,
        station,
        &bob,
        &realm_id,
        group_id.as_str(),
        [0x32; 16],
        chrono::Duration::minutes(4),
    )?;
    let (status, fresh_bytes) = post_claim(&alice.client, &fresh).await?;
    ensure!(
        status == StatusCode::OK,
        "a new claim attempt found no KeyPackage after the refused conflict: {status} {}",
        String::from_utf8_lossy(&fresh_bytes)
    );
    let fresh_claim: KeyPackagesClaimOutcome = serde_json::from_slice(&fresh_bytes)?;
    ensure!(
        fresh_claim.claims.len() == 1
            && fresh_claim.claims[0].keypackage_ref != claim.keypackage_ref
            && published.contains(&fresh_claim.claims[0].keypackage_ref),
        "the refused conflict claimed a second KeyPackage: {fresh_claim:?}"
    );

    // Genesis: Alice activates the Realm scope with herself as its only leaf.
    let alice_identity = alice.mls_identity()?;
    let genesis_binding = MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
    let mut alice_group =
        alice_identity.create_group_with_governance_binding(&scope, &genesis_binding)?;
    alice_group.install_local_creator_binding(
        alice.actor.clone(),
        Some(alice.authorize_event_id.clone()),
    )?;
    let verified = alice_group.verified_leaf_bindings()?;
    let [creator] = verified.as_slice() else {
        bail!("Genesis requires Alice's sole verified MLS leaf");
    };
    ensure!(
        creator.leaf_index == 0 && creator.actor_id == alice.actor,
        "Genesis creator leaf does not belong to Alice"
    );
    let endpoint = match &creator.endpoint {
        MlsEndpointIdentity::HumanDevice { device_id, .. } => {
            ensure!(*device_id == alice.device);
            MlsWelcomeRecipientEndpoint::Device {
                device_id: device_id.clone(),
            }
        }
        _ => bail!("Genesis creator leaf is not Alice's device"),
    };
    let creator_leaf_authority = MlsGenesisCreatorLeafAuthority {
        leaf_signature_key_b64u: creator.signature_key.clone(),
        endpoint,
        authorization_event_ref: creator
            .device_authorize_event_id
            .clone()
            .context("Alice's MLS creator leaf lacks accepted DeviceAuthorize Event")?,
    };
    creator_leaf_authority.validate()?;
    let (group_info, tree) = alice_group.public_group_state_bytes()?;
    let group_info_ref = upload_public_blob(&alice.client, &realm_id, &group_info).await?;
    let tree_ref = upload_public_blob(&alice.client, &realm_id, &tree).await?;
    let genesis = alice
        .client
        .author_event(
            realm_id.as_str(),
            EventKind::MlsGenesis.as_str(),
            canonical(json!({
                "cipher_suite": ACTIVE_SUITE,
                "group_info_ref": group_info_ref,
                "ratchet_tree_ref": tree_ref,
                "governance_binding": genesis_binding,
                "creator_leaf_authority": creator_leaf_authority,
                "created_at": arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
            }))?,
        )
        .await?;
    submit_and_expect_commit(&alice.client, &alice.account, ALICE_DEVICE, &genesis).await?;
    crate::scenarios::message_mls_cross_station_live::install_bindings(&mut alice_group, &[&alice])
        .await?;

    // Plaintext into the activated scope is refused by the shared send gate.
    let plaintext = alice
        .client
        .author_event(
            realm_id.as_str(),
            EventKind::MessageCreate.as_str(),
            crate::harness::message_create_text_payload(&strand_id, "plaintext after Genesis")?,
        )
        .await?;
    let refused = post_json(
        &alice.client,
        &crate::publication::initial_submission(plaintext, "")?,
    )
    .await?;
    ensure!(
        refused.0 == StatusCode::CONFLICT
            && refused.1["reason_code"].as_str() == Some("mls_activation_required"),
        "plaintext after Genesis was not mls_activation_required: {:?}",
        refused
    );

    // Add Bob: one inline Add Commit carrying the Welcome that names the claim.
    let add_binding =
        MlsGovernanceBindingPayload::new(scope.clone(), Some(genesis.event_id.clone()), 0, 1, 0)?;
    let claimed_record = claimed_keypackage_record(&claim, &bob)?;
    let add = alice_group.add_member_with_governance_binding(&claimed_record, &add_binding)?;
    let commit_payload =
        MlsCommitPayload::new(genesis.event_id.clone(), 0, &add.commit, add_binding)?;
    let commit_event = alice
        .client
        .author_event(
            realm_id.as_str(),
            EventKind::MlsCommit.as_str(),
            canonical(serde_json::to_value(&commit_payload)?)?,
        )
        .await?;
    let welcome = signed_welcome(&alice, &commit_event, &bob, &add.welcome)?;
    let submission = SelfAuthoritySubmitRequest::MlsCommit(MlsCommitSubmission {
        commit_event: commit_event.clone(),
        welcomes: vec![welcome.clone()],
        idempotency_key: arkret_wire::UuidV7::new(fresh_uuid_v7().parse()?)?,
    });
    submission.validate()?;
    let (status, outcome) = post_json(&alice.client, &submission).await?;
    ensure!(
        status == StatusCode::OK,
        "the Add Commit with its Welcome was not admitted: {status} {outcome}"
    );
    let outcome: AuthoritySubmitOutcome = serde_json::from_value(outcome)?;
    ensure!(
        matches!(
            &outcome,
            AuthoritySubmitOutcome::Accepted {
                status: AuthorityCommitStatus::Committed,
                commit,
            } if commit.event_ref == commit_event.event_id
        ),
        "the Add Commit was not committed: {outcome:?}"
    );
    let accepted_commit = accepted_full_view(&alice.client, &commit_event.event_id).await?;
    let base = arkret_wire::MlsGroupCurrent {
        effective_scope: scope.clone(),
        genesis_event_ref: genesis.event_id.clone(),
        current_mls_commit_event_ref: genesis.event_id.clone(),
        epoch: 0,
        current_key_access_revision: 0,
        covered_key_access_revision: 0,
        public_tree_ref: arkret_wire::BlobRef::new(tree_ref.clone())?,
    };
    ensure!(
        alice_group.install_accepted_commit(&accepted_commit, &base)? == 1,
        "Alice did not install her accepted Add Commit"
    );

    // Bob reads the Welcome from his own recipient queue and joins from it.
    let (queued, ack_token) = recipient_welcomes(&bob.client).await?;
    ensure!(
        queued == vec![welcome.clone()],
        "Bob's recipient queue does not hold exactly the admitted Welcome: {queued:?}"
    );
    let mut bob_group = ArkretMlsGroup::join_from_verified_welcome_delivery(
        bob_identity,
        &welcome,
        &accepted_commit,
    )?;
    ensure!(bob_group.epoch() == 1, "Bob did not join at epoch 1");
    crate::scenarios::message_mls_cross_station_live::install_bindings(
        &mut alice_group,
        &[&alice, &bob],
    )
    .await?;
    crate::scenarios::message_mls_cross_station_live::install_bindings(
        &mut bob_group,
        &[&alice, &bob],
    )
    .await?;

    bob.client
        .post("/_arkret/self/device_messages/ack")
        .json(&DeviceMessagesAckRequestBody { ack_token })
        .send()
        .await?
        .error_for_status()?;

    // Consume after the durable group state and the ACK (decision 0121: the
    // Station compares the receipt with the claim's Welcome binding, never
    // the queue row). Another digest or epoch is `conflict`; the exact
    // receipt consumes and replays byte-identically.
    let bob_signer = bob.mls_identity()?;
    let consume = |welcome_digest: arkret_wire::Hash, mls_epoch: u64| -> Result<_> {
        let receipt = arkret_models_crypto::RecipientMlsDurableReceipt {
            domain: arkret_wire::NonEmptyString::new(
                arkret_wire::DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1.to_owned(),
            )
            .map_err(anyhow::Error::msg)?,
            claim_request_id: first_request.claim_request_id.clone(),
            key_package_ref: arkret_wire::NonEmptyString::new(claim.keypackage_ref.clone())
                .map_err(anyhow::Error::msg)?,
            recipient: arkret_models_crypto::RecipientMlsDurableSigner::Device {
                recipient_account_id: bob.account.clone(),
                recipient_device_id: bob.device.clone(),
                device_verification_method: bob.method.clone(),
            },
            recipient_id: station.service_id().clone(),
            realm_id: realm_id.clone(),
            mls_group_id: group_id.clone(),
            mls_epoch,
            welcome_ref: welcome.welcome_id.clone(),
            welcome_digest,
            durable_at: chrono::Utc::now(),
            signature: arkret_models_crypto::KeyOperationSignature {
                kid: arkret_wire::NonEmptyString::new(bob.method.to_string())
                    .map_err(anyhow::Error::msg)?,
                signature_algorithm: None,
                sig: arkret_wire::Base64UrlString::new("AA".to_owned())
                    .map_err(anyhow::Error::msg)?,
            },
        };
        let receipt = bob_signer.sign_recipient_mls_durable_receipt(receipt)?;
        Ok(bob_signer.signed_key_packages_consume_request(
            arkret_wire::KeypackageClaimId::new(claim.claim_id.clone())?,
            receipt,
        )?)
    };
    let digest = welcome.durable_receipt_digest()?;
    for (name, tampered) in [
        (
            "welcome_digest",
            consume(
                arkret_wire::Hash::new(format!("sha256:{}", "7".repeat(64)))?,
                1,
            )?,
        ),
        ("mls_epoch", consume(digest.clone(), 2)?),
    ] {
        let (status, refusal) = post_json_at(
            &bob.client,
            "/_arkret/self/keys/keypackages/consume",
            &tampered,
        )
        .await?;
        ensure!(
            status == StatusCode::CONFLICT
                && refusal["type"]
                    .as_str()
                    .is_some_and(|value| value.ends_with("/conflict")),
            "a consume with a tampered {name} was not conflict: {status} {refusal}"
        );
    }
    let exact = consume(digest, 1)?;
    let (status, consumed) = post_bytes_at(
        &bob.client,
        "/_arkret/self/keys/keypackages/consume",
        &exact,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "the exact consume was not admitted: {status} {}",
        String::from_utf8_lossy(&consumed)
    );
    let outcome: arkret_models_crypto::KeyPackagesConsumeOutcome =
        serde_json::from_slice(&consumed)?;
    ensure!(
        outcome.consume_receipt.claim_id.as_str() == claim.claim_id,
        "the consume receipt names another claim"
    );
    let (status, replayed) = post_bytes_at(
        &bob.client,
        "/_arkret/self/keys/keypackages/consume",
        &exact,
    )
    .await?;
    ensure!(
        status == StatusCode::OK && replayed == consumed,
        "the exact consume replay did not return the first receipt: {status}"
    );

    // Encrypted application content at the accepted epoch reaches Bob.
    let header = arkret::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/vnd.arkret.message+json",
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        scope.clone(),
        EventKind::MessageCreate.as_str(),
        1,
        commit_event.event_id.clone(),
        alice_group.local_content_sender_domain()?,
        arkret::EventContentRoutingContext::None,
    )?;
    let sealed = arkret::MessageCrypto::encrypt(
        &mut alice_group,
        "mls-lifecycle-message",
        header,
        b"after Add",
    )?;
    ensure!(
        arkret::MessageCrypto::decrypt(&mut bob_group, &sealed)? == b"after Add",
        "Bob could not decrypt Alice's message at the accepted epoch"
    );

    if observe_blocklist {
        crate::conformance::account_blocklist_projection::observe_ordinary_call_invite(
            &alice,
            &bob,
            station,
            &realm_id,
            &commit_event.event_id,
            &mut alice_group,
            &bob_group,
            observe_receipt,
        )
        .await?;
    }

    // Restart: the claim ledger replays byte-identically and the ACKed
    // Welcome is gone.
    group.server_mut(0).restart_external_process().await?;
    let (status, restarted_replay) = post_claim(&alice.client, &first_request).await?;
    ensure!(
        status == StatusCode::OK && json_equal(&restarted_replay, &first_bytes)?,
        "the claim ledger did not replay its stored outcome after restart: {status}"
    );
    let (after_restart, _) = recipient_welcomes(&bob.client).await?;
    ensure!(
        after_restart.is_empty(),
        "the ACKed Welcome was delivered again after restart: {after_restart:?}"
    );
    drop(coauth);
    Ok(())
}

/// A self claim for one of `target`'s device KeyPackages, signed by the
/// requester's device over the exact request and service binding.
fn claim_request(
    requester: &Member,
    station: &ArkretServer,
    target: &Member,
    realm_id: &RealmId,
    mls_group_id: &str,
    claim_request_id: [u8; 16],
    lifetime: chrono::Duration,
) -> Result<KeyPackagesClaimRequestBody> {
    claim_request_between(
        requester,
        station,
        station,
        target,
        realm_id,
        mls_group_id,
        claim_request_id,
        lifetime,
    )
}

/// A self claim at the requester's `source` Station for one of `target`'s
/// device KeyPackages held by `destination`, the target's own Station.
#[allow(clippy::too_many_arguments)]
pub(crate) fn claim_request_between(
    requester: &Member,
    source: &ArkretServer,
    destination: &ArkretServer,
    target: &Member,
    realm_id: &RealmId,
    mls_group_id: &str,
    claim_request_id: [u8; 16],
    lifetime: chrono::Duration,
) -> Result<KeyPackagesClaimRequestBody> {
    claim_request_to(
        requester,
        source,
        destination,
        (&target.account, &target.device),
        realm_id,
        mls_group_id,
        claim_request_id,
        lifetime,
    )
}

/// [`claim_request_between`] for an exact `(AccountId, device)` target that
/// need not be a provisioned member.
#[allow(clippy::too_many_arguments)]
pub(crate) fn claim_request_to(
    requester: &Member,
    source: &ArkretServer,
    destination: &ArkretServer,
    (target_account, target_device): (&AccountId, &DeviceId),
    realm_id: &RealmId,
    mls_group_id: &str,
    claim_request_id: [u8; 16],
    lifetime: chrono::Duration,
) -> Result<KeyPackagesClaimRequestBody> {
    let signed_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut body: KeyPackagesClaimRequestBody = serde_json::from_value(json!({
        "claim_request_id": base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(claim_request_id),
        "target_account_id": target_account,
        "target_device_ids": [target_device],
        "requester_account_id": requester.account,
        "intended_realm_id": realm_id,
        "mls_group_id": mls_group_id,
        "claim_purpose": "realm_membership",
        "required_capabilities": [CONTENT_CAPABILITY],
        "expires_at": arkret_canonical::format_timestamp_canonical(signed_at + lifetime),
        "timeout_ms": null,
        "service_binding": {
            "source_id": source.service_id(),
            "destination_id": destination.service_id(),
        },
        "requester_authorization": {
            "kind": "device",
            "verification_method": requester.method,
            "requester_device_id": requester.device,
            "device_authorize_event_id": requester.authorize_event_id,
            "signed_at": arkret_canonical::format_timestamp_canonical(signed_at),
            "signature": {
                "kid": requester.method,
                "signature_algorithm": "Ed25519",
                "sig": "AA",
            },
        },
    }))?;
    let bytes = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &body.unsigned_request(),
        &body.service_binding,
        &body.requester_authorization,
    )?;
    let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device { signature, .. } =
        &mut body.requester_authorization
    else {
        unreachable!("the scenario builds the device branch");
    };
    signature.sig = arkret_wire::Base64UrlString::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(requester.key.sign(&bytes).to_bytes()),
    )
    .map_err(anyhow::Error::msg)?;
    Ok(body)
}

/// POST one claim with `Idempotency-Key = claim_request_id` and return the
/// raw response body.
pub(crate) async fn post_claim(
    client: &TestActorClient,
    body: &KeyPackagesClaimRequestBody,
) -> Result<(StatusCode, Vec<u8>)> {
    let response = client
        .post("/_arkret/self/keys/keypackages/claim")
        .header("idempotency-key", body.claim_request_id.as_str())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(arkret_canonical::canonical_json_bytes(body)?)
        .send()
        .await?;
    let status = response.status();
    Ok((status, response.bytes().await?.to_vec()))
}

pub(crate) async fn post_bytes_at(
    client: &TestActorClient,
    path: &str,
    body: &impl serde::Serialize,
) -> Result<(StatusCode, Vec<u8>)> {
    let response = client
        .post(path)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(arkret_canonical::canonical_json_bytes(body)?)
        .send()
        .await?;
    let status = response.status();
    Ok((status, response.bytes().await?.to_vec()))
}

pub(crate) async fn post_json(
    client: &TestActorClient,
    body: &impl serde::Serialize,
) -> Result<(StatusCode, Value)> {
    post_json_at(client, "/_arkret/self/events", body).await
}

pub(crate) async fn post_json_at(
    client: &TestActorClient,
    path: &str,
    body: &impl serde::Serialize,
) -> Result<(StatusCode, Value)> {
    let response = client
        .post(path)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(arkret_canonical::canonical_json_bytes(body)?)
        .send()
        .await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    Ok((
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned())),
    ))
}

pub(crate) fn problem_type(bytes: &[u8]) -> Result<String> {
    let body: Value = serde_json::from_slice(bytes)?;
    Ok(body["type"]
        .as_str()
        .and_then(|value| value.rsplit('/').next())
        .unwrap_or_default()
        .to_owned())
}

pub(crate) fn json_equal(left: &[u8], right: &[u8]) -> Result<bool> {
    Ok(serde_json::from_slice::<Value>(left)? == serde_json::from_slice::<Value>(right)?)
}

pub(crate) fn canonical(value: Value) -> Result<Value> {
    Ok(serde_json::from_slice(
        &arkret_canonical::canonical_json_bytes(&value)?,
    )?)
}

/// Upload one public MLS state Blob and return its content-addressed ref.
pub(crate) async fn upload_public_blob(
    client: &TestActorClient,
    realm_id: &RealmId,
    bytes: &[u8],
) -> Result<String> {
    let uploaded = expect_json(
        client
            .post("/_arkret/self/blob/upload")
            .header("x-arkret-realm-id", realm_id.as_str())
            .multipart(blob_upload_form(bytes, "application/octet-stream")?),
        StatusCode::OK,
    )
    .await?;
    uploaded["blob_ref"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("Blob upload returned no blob_ref: {uploaded}"))
}

/// The claimed KeyPackage as the adder installs it from the claim record.
pub(crate) fn claimed_keypackage_record(
    claim: &arkret_models_crypto::KeyPackageClaimRecord,
    owner: &Member,
) -> Result<MlsKeyPackageRecord> {
    Ok(MlsKeyPackageRecord {
        keypackage_id: format!("ak:mls:kp:{}", fresh_uuid_v7()),
        actor_id: claim.actor_id.clone(),
        endpoint: arkret_models_crypto::MlsEndpointIdentity::human_device(
            owner.account.principal_id.clone(),
            owner.device.clone(),
        ),
        keypackage: claim.keypackage.clone(),
        keypackage_ref: arkret_wire::Hash::new(claim.keypackage_ref.clone())?,
        cipher_suites: vec![ACTIVE_SUITE.to_owned()],
        capabilities: claim.capabilities.clone(),
        state: arkret_models_crypto::MlsKeyPackageState::Claimed,
        claim_id: Some(claim.claim_id.clone()),
        created_at: chrono::Utc::now(),
        expires_at: Some(claim.expires_at),
        last_resort: false,
    })
}

/// Seal the Welcome for `recipient` under the method that signed the Commit.
pub(crate) fn signed_welcome(
    producer: &Member,
    commit_event: &Event,
    recipient: &Member,
    draft: &arkret::MlsWelcomeDraft,
) -> Result<MlsWelcomeDelivery> {
    let method = commit_event
        .producer_proof
        .as_ref()
        .context("the Commit Event carries its producer proof")?
        .verification_method
        .clone();
    ensure!(
        method == producer.method,
        "the Commit was not signed by the producer device method"
    );
    let mut delivery = MlsWelcomeDelivery {
        welcome_id: arkret_wire::MlsWelcomeDeliveryId::new_v7_at(now_ms()),
        realm_id: commit_event.realm_id.clone(),
        effective_scope: commit_event.scope_ref.clone(),
        commit_event_ref: commit_event.event_id.clone(),
        recipient_actor_id: recipient.actor.clone(),
        recipient_endpoint: MlsWelcomeRecipientEndpoint::Device {
            device_id: recipient.device.clone(),
        },
        keypackage_claim_ref: draft.keypackage_claim_ref.clone(),
        ciphertext_b64: draft.ciphertext_b64.clone(),
        producer_proof: arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: method.clone(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            created_at: chrono::Utc::now(),
            sig: arkret_wire::Base64UrlString::new("AA".to_owned()).map_err(anyhow::Error::msg)?,
        },
    };
    let mut unsigned = serde_json::to_value(&delivery)?;
    unsigned
        .as_object_mut()
        .context("a Welcome delivery is a JSON object")?
        .remove("producer_proof");
    delivery.producer_proof = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
        method,
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        &producer.key,
    )?;
    delivery.validate_shape()?;
    Ok(delivery)
}

/// The accepted Commit Event with its RealmCommit, as the Station serves it.
pub(crate) async fn accepted_full_view(
    client: &TestActorClient,
    event_id: &EventId,
) -> Result<CommittedEventFullView> {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        match client.sdk().committed_event_get(event_id).await {
            Ok(CommittedEventView::Full(view)) => {
                view.validate_shape()?;
                return Ok(view);
            }
            Ok(CommittedEventView::Withheld(_)) => {
                bail!("the accepted Commit {event_id} is withheld from its reader")
            }
            Err(error) if std::time::Instant::now() >= deadline => {
                bail!("the accepted Commit {event_id} is not readable: {error}")
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
}

/// Every Welcome in the caller's recipient queue and the ACK token of the
/// page.
pub(crate) async fn recipient_welcomes(
    client: &TestActorClient,
) -> Result<(Vec<MlsWelcomeDelivery>, String)> {
    let polled = expect_json(client.get("/_arkret/self/device_messages"), StatusCode::OK).await?;
    let outcome: DeviceMessagesGetOutcome = serde_json::from_value(polled.clone())
        .with_context(|| format!("recipient queue page is not closed SDK wire data: {polled}"))?;
    let welcomes = outcome
        .deliveries
        .iter()
        .filter_map(|delivery| match delivery {
            RecipientDelivery::MlsWelcome { mls_welcome } => Some(mls_welcome.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let token = match (&outcome.ack_token, welcomes.is_empty()) {
        (Some(token), _) => token.clone(),
        (None, true) => String::new(),
        (None, false) => bail!("a non-empty recipient page omitted its ack_token"),
    };
    Ok((welcomes, token))
}

fn now_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or_default()
}

/// A fresh RFC 9562 UUIDv7 in its hyphenated text form.
pub(crate) fn fresh_uuid_v7() -> String {
    arkret_wire::MlsWelcomeDeliveryId::new_v7_at(now_ms())
        .as_str()
        .rsplit(':')
        .next()
        .unwrap_or_default()
        .to_owned()
}
