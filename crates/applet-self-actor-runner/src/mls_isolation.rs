//! Real MLS isolation only. The accepted carriers below are authority stubs.
//! This verifies no native DID, device delegation, capability or Station admission.

use anyhow::{Result, ensure};
use arkret_mls::{ArkretMlsGroup, ArkretMlsIdentity, MlsAddMemberResult};
use arkret_models_crypto::{MlsCommitPayload, MlsGovernanceBindingPayload, MlsKeyPackageState};
use arkret_wire::{
    AccountId, ActorId, CommitStreamRef, CommittedEventFullView, DetachedObjectSignature,
    DetachedSignatureAlgorithm, DetachedSignatureContext, DeviceId, DidCoreId, DidUrl, Event,
    EventId, EventKind, Hash, KeypackageClaimId, MlsWelcomeDelivery, MlsWelcomeDeliveryId,
    MlsWelcomeRecipientEndpoint, RealmCommit, RealmCommitAuthorityRef, RealmCommitId, RealmId,
    ScopeRef,
};

const REALM: &str = "ak:realm:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT";

fn actor(label: &str) -> ActorId {
    ActorId::account(AccountId::new(
        DidCoreId::new(format!("ak:did_core:web:{label}.example")).unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ))
}

fn device(seed: u8) -> DeviceId {
    DeviceId::new(format!(
        "ak:device:01904100-0000-7000-8000-0000000000{seed:02x}"
    ))
    .unwrap()
}

/// Ordinary Device MLS credential fixture; no delegation authority is inferred.
fn identity(actor: &ActorId, seed: u8) -> ArkretMlsIdentity {
    ArkretMlsIdentity::new_test_human_device(actor.clone(), device(seed)).unwrap()
}

fn scope() -> ScopeRef {
    ScopeRef::Circle {
        realm_id: RealmId::new(REALM).unwrap(),
        circle_id: arkret_wire::CircleId::new(
            "ak:circle:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT",
        )
        .unwrap(),
    }
}

fn signature(context: DetachedSignatureContext) -> DetachedObjectSignature {
    DetachedObjectSignature {
        context,
        signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
        verification_method: DidUrl::new("did:web:station.example#authority").unwrap(),
        signed_digest: Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap(),
        created_at: chrono::Utc::now(),
        sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
    }
}

/// The accepted `ak.mls.commit` carrying `add`, over `base` at `position`.
fn accepted(
    committer: &ActorId,
    base: &EventId,
    add: &MlsAddMemberResult,
    binding: MlsGovernanceBindingPayload,
    position: u64,
) -> CommittedEventFullView {
    let payload = MlsCommitPayload::new(base.clone(), 0, &add.commit, binding).unwrap();
    let serde_json::Value::Object(payload) = serde_json::to_value(payload).unwrap() else {
        unreachable!("an MLS Commit payload is an object")
    };
    let event = Event {
        event_id: EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [position as u8; 32]),
        kind: EventKind::MlsCommit,
        realm_id: RealmId::new(REALM).unwrap(),
        scope_ref: scope(),
        actor_id: committer.clone(),
        executed_by: None,
        authorization_ref: None,
        applet_id: None,
        external_ref: None,
        created_at: chrono::Utc::now(),
        semantic_refs: Vec::new(),
        payload: payload.into_iter().collect(),
        producer_proof: None,
    };
    let commit = RealmCommit {
        commit_id: RealmCommitId::from_digest([position as u8; 32]),
        realm_id: RealmId::new(REALM).unwrap(),
        stream_ref: match scope() {
            ScopeRef::Circle {
                realm_id,
                circle_id,
            } => CommitStreamRef::Circle {
                realm_id,
                circle_id,
            },
            _ => unreachable!(),
        },
        stream_position: position,
        previous_commit_ref: Some(RealmCommitId::from_digest([0x70; 32])),
        event_ref: event.event_id.clone(),
        governance_generation: 0,
        authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x71; 32],
        )),
        committed_at: chrono::Utc::now(),
        producer_signer_fact_digest: None,
        signature: signature(DetachedSignatureContext::RealmCommit),
    };
    CommittedEventFullView { commit, event }
}

fn delivery(
    view: &CommittedEventFullView,
    recipient: &ActorId,
    endpoint: &DeviceId,
    add: &MlsAddMemberResult,
) -> MlsWelcomeDelivery {
    MlsWelcomeDelivery {
        welcome_id: MlsWelcomeDeliveryId::new(
            "ak:mls_welcome_delivery:01904100-0000-7000-8000-000000000091".to_owned(),
        )
        .unwrap(),
        realm_id: RealmId::new(REALM).unwrap(),
        effective_scope: scope(),
        commit_event_ref: view.event.event_id.clone(),
        recipient_actor_id: recipient.clone(),
        recipient_endpoint: MlsWelcomeRecipientEndpoint::Device {
            device_id: endpoint.clone(),
        },
        keypackage_claim_ref: add.welcome.keypackage_claim_ref.clone(),
        ciphertext_b64: add.welcome.ciphertext_b64.clone(),
        producer_proof: signature(DetachedSignatureContext::MlsWelcomeDelivery),
    }
}

fn claimed(identity: &ArkretMlsIdentity, claim: u8) -> arkret_models_crypto::MlsKeyPackageRecord {
    let mut record = identity.key_package_record().unwrap();
    record.state = MlsKeyPackageState::Claimed;
    record.claim_id = Some(
        KeypackageClaimId::new(format!(
            "ak:keypackage_claim:01904100-0000-7000-8000-0000000000{claim:02x}"
        ))
        .unwrap()
        .as_str()
        .to_owned(),
    );
    record
}

fn encrypt(
    group: &mut ArkretMlsGroup,
    scope: ScopeRef,
    plaintext: &[u8],
    seed: u8,
) -> arkret_models_crypto::EncryptedPayload {
    let header = arkret_models_crypto::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/vnd.arkret.message+json",
        arkret_wire::EncryptedPayloadScheme::MlsRfc9420,
        scope,
        "ak.message.create",
        group.epoch(),
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32]),
        &group.local_content_sender_domain().unwrap(),
        arkret_models_crypto::EventContentRoutingContext::None,
    )
    .unwrap();
    group.encrypt_payload(header, plaintext).unwrap()
}

pub fn verify() -> Result<()> {
    let invoker = actor("alice");
    let applet = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:webvh:z6mkfixtureapplet").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ));
    let source_scope = ScopeRef::Realm {
        realm_id: RealmId::new(REALM).unwrap(),
    };
    let mut source = identity(&invoker, 3).create_group_with_governance_binding(
        &source_scope,
        &MlsGovernanceBindingPayload::new(source_scope.clone(), None, 0, 0, 0)?,
    )?;
    let original = encrypt(&mut source, source_scope, b"unselected private history", 9);
    let mut sender = identity(&invoker, 1).create_group_with_governance_binding(
        &scope(),
        &MlsGovernanceBindingPayload::new(scope(), None, 0, 0, 0)?,
    )?;
    let applet_identity = identity(&applet, 2);
    let endpoints = vec![
        sender.identity().endpoint_identity(),
        applet_identity.endpoint_identity(),
    ];
    let base = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x72; 32]);
    let binding = MlsGovernanceBindingPayload::new(scope(), Some(base.clone()), 0, 1, 0)?;
    let added =
        sender.add_member_with_governance_binding(&claimed(&applet_identity, 0x81), &binding)?;
    let view = accepted(&invoker, &base, &added, binding, 1);
    sender.install_recovered_own_commit(&view, &base)?;
    sender.install_test_leaf_bindings(endpoints.clone())?;
    let mut receiver = ArkretMlsGroup::join_from_verified_welcome_delivery(
        applet_identity,
        &delivery(&view, &applet, &device(2), &added),
        &view,
    )?;
    receiver.install_test_leaf_bindings(endpoints)?;
    ensure!(
        source.group_id() != receiver.group_id(),
        "invocation reused original group"
    );
    let before = receiver.export_state_record()?.serialized_state;
    ensure!(
        receiver.decrypt_payload(&original).is_err(),
        "Applet decrypted unselected source history"
    );
    ensure!(
        before == receiver.export_state_record()?.serialized_state,
        "wrong-group rejection changed receiver state"
    );
    let selected = encrypt(&mut sender, scope(), b"approved selected context", 10);
    ensure!(receiver.decrypt_payload(&selected)? == b"approved selected context");
    let mut restored = ArkretMlsGroup::restore_from_state_record(&receiver.export_state_record()?)?;
    let next = encrypt(&mut sender, scope(), b"next approved context", 11);
    ensure!(restored.decrypt_payload(&next)? == b"next approved context");
    Ok(())
}
