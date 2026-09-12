use arkret_canonical::DigestSuite;
use arkret_mls::{
    ArkretMlsGroup, ArkretMlsIdentity, encrypted_envelope_from_payload,
    encrypted_envelope_to_payload_with_verified_header,
};
use arkret_models_collaboration::event_sync::RealmActorFrontierView;
use arkret_models_collaboration::events_payloads::message::MessageTrackName;
use arkret_models_collaboration::message_authoring::{
    MessageAuthoringContent, MessageAuthoringIntent, MessageEncryptionContext,
    MessagePrepareOutcome, MessagePrepareRequestBody,
};
use arkret_models_crypto::{EventContentPreEncryptionHeader, EventContentRoutingContext};
use arkret_wire::{
    AccountId, ActorId, AuthContext, DeviceId, DidCoreId, EncryptedPayloadScheme, EventId,
    OpaqueLocalId, RealmId, RequestId, ScopeRef, SealId, StrandId,
};

fn seal(hex: &str) -> SealId {
    SealId::new(format!("ak:seal:sha256:{}", hex.repeat(64))).unwrap()
}

/// Real MLS ciphertext survives prepare verification and an exact retry. This
/// is a crypto/authoring composition test; network governance is tested live.
#[test]
fn prepared_message_decrypts_at_the_other_mls_member_without_reencrypting() {
    let alice_id = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
    let device = DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap();
    let alice = ArkretMlsIdentity::new_test_human_device(alice_id.clone(), device.clone()).unwrap();
    let bob = ArkretMlsIdentity::new_test_human_device(
        DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
        DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
    )
    .unwrap();
    let endpoints = vec![alice.endpoint_identity(), bob.endpoint_identity()];
    let realm = RealmId::new("ak:realm:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT").unwrap();
    let mut sender = alice.create_group(realm.as_str().as_bytes()).unwrap();
    let added = sender
        .add_member(&bob.key_package_record().unwrap())
        .unwrap();
    sender.install_test_leaf_bindings(endpoints).unwrap();
    let mut recipient = ArkretMlsGroup::join_from_welcome(bob, &added.welcome).unwrap();
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let scheme = EncryptedPayloadScheme::MlsRfc9420;
    let header = EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/vnd.arkret.message+json",
        scheme.clone(),
        scope.clone(),
        "ak.message.create",
        sender.epoch(),
        EventId::from_digest(DigestSuite::Sha256, [7; 32]),
        device.as_str(),
        None,
        EventContentRoutingContext::None,
    )
    .unwrap();
    let plaintext = br#"{"kind":"ak.content.text","body":"first confidential message"}"#;
    let encrypted = sender.encrypt_payload(header.clone(), plaintext).unwrap();
    let envelope = encrypted_envelope_from_payload(&encrypted).unwrap();
    let sender_after_encrypt: serde_json::Value =
        serde_json::from_slice(&sender.export_state_record().unwrap().serialized_state).unwrap();
    let account = AccountId::new(
        alice_id,
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    );
    let request = MessagePrepareRequestBody {
        request_id: RequestId::new_v7_at(1_789_171_200_000),
        account_id: account.clone(),
        realm_id: realm.clone(),
        intent: MessageAuthoringIntent {
            strand_id: StrandId::new("ak:strand:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT")
                .unwrap(),
            track_name: MessageTrackName::Discussion,
            content: MessageAuthoringContent::Mls {
                encrypted_content: envelope.clone(),
                encrypted_metadata: None,
                encryption_context: MessageEncryptionContext {
                    scheme: scheme.clone(),
                    effective_scope: scope.clone(),
                    sender_domain: device.to_string(),
                },
            },
            blob_refs: vec![],
            reply_to_id: None,
        },
        created_at: "2026-09-12T00:00:00.000Z".parse().unwrap(),
        hlc: None,
    };
    let auth = AuthContext {
        key_id: OpaqueLocalId::new(device.as_str().strip_prefix("ak:").unwrap()).unwrap(),
        key_epoch: 0,
        credential_epoch: None,
        authority_refs: vec![seal("a")],
    };
    let frontier = RealmActorFrontierView::new(
        realm,
        ActorId::account(account),
        0,
        vec![],
        DigestSuite::Sha256,
    )
    .unwrap();
    let outcome = MessagePrepareOutcome::prepare(
        &request,
        frontier,
        scope.clone(),
        auth.clone(),
        None,
        None,
        DigestSuite::Sha256,
        request.created_at,
    )
    .unwrap();
    let first = outcome
        .verify_for_signing(&request, &scope, &auth, None, None, request.created_at)
        .unwrap();
    let retry = outcome
        .verify_for_signing(&request, &scope, &auth, None, None, request.created_at)
        .unwrap();
    assert_eq!(
        first.event().digest_payload().unwrap(),
        retry.event().digest_payload().unwrap()
    );
    assert_eq!(
        sender_after_encrypt,
        serde_json::from_slice::<serde_json::Value>(
            &sender.export_state_record().unwrap().serialized_state,
        )
        .unwrap()
    );
    let online = arkret_canonical::canonical_json_string(&request).unwrap();
    assert!(!online.contains("first confidential message"));
    let returned: arkret_models_crypto::EncryptedEnvelope =
        serde_json::from_value(first.event().payload["encrypted_content"].clone()).unwrap();
    assert_eq!(
        serde_json::to_value(&returned).unwrap(),
        serde_json::to_value(&envelope).unwrap()
    );
    let reconstructed = returned
        .reconstruct_pre_encryption_header(
            scheme,
            scope.clone(),
            "ak.message.create",
            device.as_str(),
            None,
        )
        .unwrap();
    let received =
        encrypted_envelope_to_payload_with_verified_header(&returned, reconstructed).unwrap();
    assert_eq!(recipient.decrypt_payload(&received).unwrap(), plaintext);
    assert!(recipient.decrypt_payload(&received).is_err());
    let mut tampered = request.clone();
    if let MessageAuthoringContent::Mls {
        encryption_context, ..
    } = &mut tampered.intent.content
    {
        encryption_context.sender_domain = "ak:device:01904100-0000-7000-8000-00000000000e".into();
    }
    assert!(
        outcome
            .verify_for_signing(&tampered, &scope, &auth, None, None, request.created_at)
            .is_err()
    );
}
