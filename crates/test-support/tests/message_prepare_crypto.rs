use arkret_canonical::DigestSuite;
use arkret_mls::{
    ArkretMlsGroup, ArkretMlsIdentity, encrypted_envelope_from_payload,
    encrypted_envelope_to_payload_with_verified_header,
};
use arkret_models_collaboration::events_payloads::message::MessageTrackName;
use arkret_models_collaboration::message_authoring::{
    MessageAuthoringContent, MessageAuthoringIntent, MessageEncryptionContext,
    MessageSubmitRequestBody,
};
use arkret_models_crypto::{
    EventContentPreEncryptionHeader, EventContentRoutingContext, MlsCommitPayload,
    MlsGovernanceBindingPayload, MlsKeyPackageState,
};
use arkret_wire::{
    AccountId, ActorId, Base64UrlString, BlobRef, CommitStreamRef, CommittedEventFullView,
    DetachedObjectSignature, DetachedSignatureAlgorithm, DetachedSignatureContext, DeviceId,
    DidCoreId, DidUrl, EncryptedPayloadScheme, EventAdmissionSubmission, EventId, Hash,
    MlsGroupCurrent, MlsWelcomeDelivery, MlsWelcomeDeliveryId, MlsWelcomeRecipientEndpoint,
    RealmCommit, RealmCommitAuthorityRef, RealmCommitId, RealmId, ScopeRef, StrandId,
};

const STATION: &str = "ak:did_core:web:station.example";
const REALM: &str = "ak:realm:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT";

/// The authority's detached object signature over a committed object.
///
/// `CommittedEventFullView` and `MlsWelcomeDelivery` validate the signature *shape* and its
/// domain context; the cryptographic check belongs to the accepting service and
/// is exercised live, so this composition test carries a well-formed carrier.
fn detached(context: DetachedSignatureContext) -> DetachedObjectSignature {
    DetachedObjectSignature {
        context,
        signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
        verification_method: DidUrl::new(format!("did:web:station.example#{STATION}")).unwrap(),
        signed_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
        created_at: "2026-09-12T00:00:00.000Z".parse().unwrap(),
        sig: Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
    }
}

/// Real MLS ciphertext survives Event authoring and an exact reauthoring, and
/// still decrypts at the other MLS member after the Commit that carried its
/// epoch is accepted. This is a crypto/authoring composition test; network
/// governance is tested live.
#[test]
fn authored_message_decrypts_at_the_other_mls_member_without_reencrypting() {
    let alice_id = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
    let device = DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap();
    let alice = ArkretMlsIdentity::new_test_human_device(
        ActorId::account(AccountId::new(
            alice_id.clone(),
            DidCoreId::new(STATION).unwrap(),
        )),
        device.clone(),
    )
    .unwrap();
    let bob = ArkretMlsIdentity::new_test_human_device(
        ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            DidCoreId::new(STATION).unwrap(),
        )),
        DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
    )
    .unwrap();
    let bob_endpoint = bob.endpoint_identity();
    let endpoints = vec![alice.endpoint_identity(), bob_endpoint.clone()];
    let realm = RealmId::new(REALM).unwrap();
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };

    // The MLS group id is derived from the canonical scope, so the group state
    // the Commit Event names and the group Alice actually holds are the same
    // group by construction rather than by agreement.
    let genesis_binding = MlsGovernanceBindingPayload::realm(realm.clone(), None, 0, 0, 0).unwrap();
    let mut sender = alice
        .create_group_with_governance_binding(&scope, &genesis_binding)
        .unwrap();

    // Adding Bob is one accepted transition: epoch 0 -> 1, bound to the Event
    // that carried the group's genesis state.
    let base_group_state_ref = EventId::from_digest(DigestSuite::Sha256, [3; 32]);
    let transition_binding = MlsGovernanceBindingPayload::realm(
        realm.clone(),
        Some(base_group_state_ref.clone()),
        0,
        1,
        0,
    )
    .unwrap();
    // An MLS Add consumes a KeyPackage the authority has already claimed, so
    // the record carries the claim the Welcome will name.
    let mut bob_keypackage = bob.key_package_record().unwrap();
    bob_keypackage.state = MlsKeyPackageState::Claimed;
    bob_keypackage.claim_id =
        Some("ak:keypackage_claim:01904100-0000-7000-8000-0000000000c1".to_owned());
    let added = sender
        .add_member_with_governance_binding(&bob_keypackage, &transition_binding)
        .unwrap();

    // The Commit Event, as the governance Station accepted it into the Realm's
    // own linear stream. One RealmCommit covers exactly one Event.
    let commit_payload = MlsCommitPayload::new(
        base_group_state_ref.clone(),
        0,
        &added.commit,
        transition_binding.clone(),
    )
    .unwrap();
    let commit_event_id = EventId::from_digest(DigestSuite::Sha256, [11; 32]);
    let accepted_commit = CommittedEventFullView {
        commit: RealmCommit {
            commit_id: RealmCommitId::from_digest([19; 32]),
            realm_id: realm.clone(),
            stream_ref: CommitStreamRef::Realm {
                realm_id: realm.clone(),
            },
            stream_position: 0,
            previous_commit_ref: None,
            event_ref: commit_event_id.clone(),
            governance_generation: 0,
            authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(commit_event_id.clone()),
            committed_at: "2026-09-12T00:00:00.000Z".parse().unwrap(),
            signature: detached(DetachedSignatureContext::RealmCommit),
        },
        event: mls_commit_event(&realm, &scope, &commit_event_id, &commit_payload),
    };
    accepted_commit.validate_shape().unwrap();

    // The producer installs its own transition only once the authority has
    // committed the Event that carried it, so the sender's epoch and the
    // Welcome's epoch cannot diverge.
    let base_current = MlsGroupCurrent {
        effective_scope: scope.clone(),
        genesis_event_ref: base_group_state_ref.clone(),
        cipher_suite: arkret_wire::NonEmptyString::new(
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        )
        .unwrap(),
        current_mls_commit_event_ref: base_group_state_ref,
        epoch: 0,
        current_key_access_revision: 0,
        covered_key_access_revision: 0,
        public_tree_ref: BlobRef::new(format!("ak:blob:sha256:{}", "55".repeat(32))).unwrap(),
    };
    assert_eq!(
        sender
            .install_accepted_commit(&accepted_commit, &base_current)
            .unwrap(),
        1
    );
    sender.install_test_leaf_bindings(endpoints).unwrap();

    let delivery = MlsWelcomeDelivery {
        welcome_id: MlsWelcomeDeliveryId::new(
            "ak:mls_welcome_delivery:01904100-0000-7000-8000-0000000000f1",
        )
        .unwrap(),
        realm_id: realm.clone(),
        effective_scope: scope.clone(),
        commit_event_ref: commit_event_id,
        recipient_actor_id: ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            DidCoreId::new(STATION).unwrap(),
        )),
        recipient_endpoint: MlsWelcomeRecipientEndpoint::Device {
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        },
        keypackage_claim_ref: added.welcome.keypackage_claim_ref.clone(),
        ciphertext_b64: added.welcome.ciphertext_b64.clone(),
        producer_proof: detached(DetachedSignatureContext::MlsWelcomeDelivery),
    };
    let mut recipient =
        ArkretMlsGroup::join_from_verified_welcome_delivery(bob, &delivery, &accepted_commit)
            .unwrap();

    let scheme = EncryptedPayloadScheme::MlsRfc9420;
    let sender_domain = sender.local_content_sender_domain().unwrap();
    let header = EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/vnd.arkret.message+json",
        scheme.clone(),
        scope.clone(),
        "ak.message.create",
        sender.epoch(),
        EventId::from_digest(DigestSuite::Sha256, [7; 32]),
        &sender_domain,
        EventContentRoutingContext::None,
    )
    .unwrap();
    let plaintext = br#"{"kind":"ak.content.text","body":"first confidential message"}"#;
    let encrypted = sender.encrypt_payload(header.clone(), plaintext).unwrap();
    let envelope = encrypted_envelope_from_payload(&encrypted).unwrap();
    let sender_after_encrypt: serde_json::Value =
        serde_json::from_slice(&sender.export_state_record().unwrap().serialized_state).unwrap();

    let intent = MessageAuthoringIntent {
        strand_id: StrandId::new("ak:strand:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT").unwrap(),
        track_name: MessageTrackName::Discussion,
        content: MessageAuthoringContent::Mls {
            encrypted_content: envelope.clone(),
            encrypted_metadata: None,
            encryption_context: MessageEncryptionContext {
                scheme: scheme.clone(),
                effective_scope: scope.clone(),
                sender_domain: sender_domain.clone(),
            },
        },
        blob_refs: vec![],
        reply_to_id: None,
    };

    // Authoring is a pure projection of the intent: doing it twice is
    // byte-identical, and it never touches the sender's ratchet state.
    let first = intent.payload();
    let retry = intent.payload();
    assert_eq!(
        arkret_canonical::canonical_json_string(&first).unwrap(),
        arkret_canonical::canonical_json_string(&retry).unwrap()
    );
    assert_eq!(
        sender_after_encrypt,
        serde_json::from_slice::<serde_json::Value>(
            &sender.export_state_record().unwrap().serialized_state,
        )
        .unwrap()
    );

    // The plaintext never reaches the wire, and the envelope the Station will
    // carry is the exact one MLS produced.
    let online = arkret_canonical::canonical_json_string(&first).unwrap();
    assert!(!online.contains("first confidential message"));
    let returned = first.encrypted_content.clone().unwrap();
    assert_eq!(
        serde_json::to_value(&returned).unwrap(),
        serde_json::to_value(&envelope).unwrap()
    );

    let reconstructed = returned
        .reconstruct_pre_encryption_header(
            scheme,
            scope.clone(),
            "ak.message.create",
            &sender_domain,
            None,
        )
        .unwrap();
    let received =
        encrypted_envelope_to_payload_with_verified_header(&returned, reconstructed).unwrap();

    assert_eq!(recipient.decrypt_payload(&received).unwrap(), plaintext);
    assert!(recipient.decrypt_payload(&received).is_err());

    // The claimed sender domain is sealed into the header the ciphertext was
    // encrypted under, so a second message that renames its sender does not
    // open even though its ciphertext is untouched.
    let second = sender
        .encrypt_payload(
            header,
            br#"{"kind":"ak.content.text","body":"second confidential message"}"#,
        )
        .unwrap();
    let second_envelope = encrypted_envelope_from_payload(&second).unwrap();
    let tampered_header = second_envelope
        .reconstruct_pre_encryption_header(
            EncryptedPayloadScheme::MlsRfc9420,
            scope,
            "ak.message.create",
            "ak:device:01904100-0000-7000-8000-00000000000e",
            None,
        )
        .unwrap();
    let tampered =
        encrypted_envelope_to_payload_with_verified_header(&second_envelope, tampered_header)
            .unwrap();
    assert!(recipient.decrypt_payload(&tampered).is_err());
}

/// Message submission carries exactly one producer Event and refuses anything
/// that is not `ak.message.create`.
#[test]
fn message_submission_admits_only_the_message_create_kind() {
    let realm = RealmId::new(REALM).unwrap();
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let event_id = EventId::from_digest(DigestSuite::Sha256, [23; 32]);
    let binding = MlsGovernanceBindingPayload::realm(realm.clone(), None, 0, 0, 0).unwrap();
    let wrong_kind = MessageSubmitRequestBody {
        submission: EventAdmissionSubmission::new(mls_commit_like_event(
            &realm, &scope, &event_id, &binding,
        )),
    };
    assert!(wrong_kind.validate().is_err());
}

fn mls_commit_event(
    realm: &RealmId,
    scope: &ScopeRef,
    event_id: &EventId,
    payload: &MlsCommitPayload,
) -> arkret_wire::Event {
    event_with_payload(
        realm,
        scope,
        event_id,
        arkret_wire::EventKind::MlsCommit,
        serde_json::to_value(payload).unwrap(),
    )
}

fn mls_commit_like_event(
    realm: &RealmId,
    scope: &ScopeRef,
    event_id: &EventId,
    binding: &MlsGovernanceBindingPayload,
) -> arkret_wire::Event {
    event_with_payload(
        realm,
        scope,
        event_id,
        arkret_wire::EventKind::MlsGenesis,
        serde_json::json!({ "mls_governance_binding": binding }),
    )
}

fn event_with_payload(
    realm: &RealmId,
    scope: &ScopeRef,
    event_id: &EventId,
    kind: arkret_wire::EventKind,
    payload: serde_json::Value,
) -> arkret_wire::Event {
    serde_json::from_value(serde_json::json!({
        "event_id": event_id,
        "realm_id": realm,
        "scope_ref": scope,
        "kind": kind,
        "actor_id": ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new(STATION).unwrap(),
        )),
        "created_at": "2026-09-12T00:00:00.000Z",
        "payload": payload,
    }))
    .unwrap()
}
