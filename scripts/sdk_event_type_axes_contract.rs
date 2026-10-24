#![allow(dead_code, unused_imports)]
use arkret::signatures::{
    Ed25519DetachedJwsSigner, PublicKeyMaterial, SignEventOptions, sign_event,
};
use arkret::*;
use chrono::{TimeZone, Utc};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 19, 0, 0, 0).unwrap()
}
fn key() -> SigningKey {
    SigningKey::from_bytes(&[137; 32])
}
fn station_key() -> SigningKey {
    SigningKey::from_bytes(&[138; 32])
}
fn station() -> DidCoreId {
    DidCoreId::new("ak:did_core:web:sdk-station.arkret.org").unwrap()
}
fn actor() -> ActorId {
    ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:sdk.arkret.org").unwrap(),
        station(),
    ))
}
fn method() -> DidUrl {
    DidUrl::new("did:web:sdk.arkret.org#device".to_owned()).unwrap()
}
fn context() -> ProducerVerificationContext {
    ProducerVerificationContext {
        actor: actor(),
        verification_method: method(),
        public_key: PublicKeyMaterial::Ed25519Raw {
            bytes: key().verifying_key().to_bytes().to_vec(),
        },
        digest_suite: DigestSuite::Sha256,
    }
}
fn id(seed: u8) -> EventId {
    EventId::from_digest(DigestSuite::Sha256, [seed; 32])
}
fn scope() -> ScopeRef {
    ScopeRef::Realm {
        realm_id: RealmId::from_event_id(&id(141)),
    }
}
fn strand() -> StrandId {
    StrandId::from_event_id(&id(142))
}
fn plain() -> PlainPayload<ContentBlock> {
    PlainPayload::new(
        serde_json::from_value(json!({"kind":"ak.content.text","body":"sdk023"})).unwrap(),
    )
}
fn encrypted() -> MlsEncryptedPayload<ContentBlock> {
    MlsEncryptedPayload::new(
        serde_json::from_value(json!({
            "version":"1.0", "content_type":"application/vnd.arkret.message+json",
            "encryption_context":{"epoch":"1","group_state_ref":id(143)},
            "ciphertext":"c2RrMDIzLW9wYXF1ZS1jb250ZW50"
        }))
        .unwrap(),
    )
    .unwrap()
}
fn signed(payload: MessageCreatePayload) -> Event {
    let mut draft = TypedEventDraft::<event_spec::MessageCreate>::new(scope(), actor(), payload)
        .unwrap()
        .author_with_digest_suite(now(), DigestSuite::Sha256)
        .unwrap();
    sign_event(
        &mut draft,
        &Ed25519DetachedJwsSigner::new(key(), method().as_str()),
        SignEventOptions::new().with_created_at(now()),
    )
    .unwrap();
    draft.into_event()
}
fn plaintext_event() -> Event {
    signed(MessageCreatePayload::with_content(
        strand(),
        "discussion",
        plain().into_value(),
    ))
}
fn encrypted_event() -> Event {
    signed(MessageCreatePayload::with_encrypted_content(
        strand(),
        "discussion",
        encrypted(),
    ))
}
fn verified(wire: Event) -> VerifiedSubmission<EventAdmissionSubmission> {
    let bytes = canonical::canonical_json_bytes(&wire).unwrap();
    let original = VerifiedProducerEvent::from_canonical_json_slice(&bytes, &context()).unwrap();
    VerifiedSubmission::from_verified_events(EventAdmissionSubmission::new(wire), &[original])
        .unwrap()
}
fn station_method() -> DidUrl {
    DidUrl::new("did:web:sdk-station.arkret.org#realm-authority".to_owned()).unwrap()
}
fn placeholder(context: DetachedSignatureContext) -> DetachedObjectSignature {
    DetachedObjectSignature {
        context,
        signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
        verification_method: station_method(),
        signed_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
        created_at: now(),
        signature: Base64UrlString::new("A".repeat(86)).unwrap(),
    }
}
fn seal<T: serde::Serialize>(
    value: &T,
    domain: DetachedSignatureContext,
) -> DetachedObjectSignature {
    arkret::signatures::detached_object::sign_detached_object(
        &canonical::unsigned_value(value, &["signature"]).unwrap(),
        domain,
        station_method(),
        now(),
        &station_key(),
    )
    .unwrap()
}
fn verified_commit() -> (RealmCommit, VerifiedRealmCommit) {
    let payload: RealmCreatePayload = serde_json::from_value(json!({"object":{
        "schema":"ak.schema.realm_genesis.v1", "purpose":"collaboration", "genesis_salt":"A".repeat(43),
        "trust_domain":"ak:trust_domain:arkret.org", "security_class":"standard", "governance_station_id":station(),
        "initial_join_rule":"invite", "initial_history_access":"since_join", "initial_discoverability":"invite_only"
    }})).unwrap();
    let mut genesis =
        TypedEventDraft::<event_spec::RealmCreate>::new(ScopeRef::RealmGenesis, actor(), payload)
            .unwrap()
            .author_with_digest_suite(now(), DigestSuite::Sha256)
            .unwrap();
    sign_event(
        &mut genesis,
        &Ed25519DetachedJwsSigner::new(key(), method().as_str()),
        SignEventOptions::new().with_created_at(now()),
    )
    .unwrap();
    VerifiedProducerEvent::verify(genesis.event().clone(), &context()).unwrap();
    let event = genesis.into_event();
    let stream = CommitStreamRef::Realm {
        realm_id: event.realm_id.clone(),
    };
    let mut commit = RealmCommit {
        commit_id: RealmCommitId::from_digest([0; 32]),
        realm_id: event.realm_id.clone(),
        stream_ref: stream.clone(),
        stream_position: 0,
        previous_commit_ref: None,
        event_ref: event.event_id.clone(),
        governance_generation: 0,
        authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone()),
        committed_at: now(),
        producer_signer_fact_digest: None,
        signature: placeholder(DetachedSignatureContext::RealmCommit),
    };
    commit.commit_id = RealmCommitId::from_digest(canonical::sha256_bytes(
        commit.canonical_id_bytes().unwrap(),
    ));
    commit.signature = seal(&commit, DetachedSignatureContext::RealmCommit);
    commit.validate_content_address().unwrap();
    let head = CommitStreamHead {
        stream_ref: stream,
        stream_position: 0,
        commit_id: commit.commit_id.clone(),
    };
    let nonce = Base64UrlString::new("AAAAAAAAAAAAAAAAAAAAAA".to_owned()).unwrap();
    let mut assertion = RealmAuthorityCurrentAssertion {
        realm_id: event.realm_id.clone(),
        current_generation: 0,
        current_service_id: station(),
        last_handoff_ref: None,
        realm_stream_head: head.clone(),
        nonce: nonce.clone(),
        expires_at: now() + chrono::Duration::seconds(60),
        signature: placeholder(DetachedSignatureContext::RealmAuthorityCurrentAssertion),
    };
    assertion.signature = seal(
        &assertion,
        DetachedSignatureContext::RealmAuthorityCurrentAssertion,
    );
    let document = serde_json::from_value(json!({
        "@context":["https://www.w3.org/ns/did/v1"], "id":"did:web:sdk-station.arkret.org",
        "verificationMethod":[{"id":station_method(),"controller":"did:web:sdk-station.arkret.org","type":"Multikey",
            "publicKeyMultibase":canonical::ed25519_pubkey_to_did_key_multibase(station_key().verifying_key().as_bytes())}],
        "authentication":[station_method()], "assertionMethod":[station_method()],
        "service":[{"id":"did:web:sdk-station.arkret.org#station","type":"ArkretService",
            "serviceEndpoint":"https://sdk-station.arkret.org/","serviceKind":"station"}]
    })).unwrap();
    let route = arkret::identity::build_authenticated_did_web_service_resolution(
        station(),
        "station".to_owned(),
        document,
        now(),
    )
    .unwrap();
    let bundle = RealmAuthorityBundle {
        realm_id: event.realm_id.clone(),
        genesis_event: event,
        genesis_commit: commit.clone(),
        authority_transitions: vec![],
        current_generation: 0,
        current_service_id: station(),
        current_route_record: serde_json::to_value(route).unwrap(),
        realm_stream_head: head,
        bundle_issued_at: now(),
        current_assertion: assertion,
    };
    let keys = arkret::identity::RealmAuthorityKeyMap::new().with_key(
        &station_method(),
        PublicKeyMaterial::Ed25519Raw {
            bytes: station_key().verifying_key().to_bytes().to_vec(),
        },
    );
    let authority = arkret::identity::verify_realm_authority_bundle(
        &bundle,
        &arkret::identity::RealmAuthorityFreshness::new(now(), nonce),
        &keys,
    )
    .unwrap();
    let result = VerifiedRealmCommit::verify(commit.clone(), &authority, &keys).unwrap();
    (commit, result)
}
fn assert_event(wire: Event) {
    let input =
        canonical::canonical_json_bytes(&EventAdmissionSubmission::new(wire.clone())).unwrap();
    let value = verified(wire);
    let first = canonical::canonical_json_bytes(&value).unwrap();
    let second = canonical::canonical_json_bytes(&value).unwrap();
    assert_eq!(first, input);
    assert_eq!(second, first);
    let mut detached = value.wire().clone();
    detached
        .event
        .payload
        .insert("unverified_mutation".to_owned(), json!(true));
    assert!(VerifiedSubmission::verify(detached, |_| Ok(context())).is_err());
    assert_eq!(canonical::canonical_json_bytes(&value).unwrap(), first);
    println!("{}", canonical::canonical_sha256(&value).unwrap());
}

// Positive API control: the peer first-admission endpoint exists and accepts verification.
async fn verified_peer_watch(
    client: &Client,
    request: &VerifiedSubmission<PeerWatchAuditReadRequestBody>,
) {
    let _ = client.peer_strand_watch_audit_read(request, 0).await;
}

// Positive control for the exact submit API used by the unverified-wire negative.
async fn verified_event_submit(
    client: &Client,
    request: &VerifiedSubmission<EventAdmissionSubmission>,
) {
    let _ = client.submit_event(request).await;
}

// Positive control for the deferred-publication create endpoint.
async fn verified_security_create(
    client: &Client,
    request: &VerifiedSubmission<SecurityTransactionCreateRequestBody>,
) {
    let _ = client.create_security_transaction(request).await;
}

fn assert_deferred_batch() {
    let event = plaintext_event();
    let event_bytes = canonical::canonical_json_bytes(&event).unwrap();
    let method = DidUrl::new("did:web:sdk.arkret.org#approval").unwrap();
    let approver = Ed25519DetachedJwsSigner::from_seed([139; 32], method.as_str());
    let mut approval = ApprovalSignature {
        input: ApprovalSignatureInput {
            approval_context: ApprovalContext::RealmGovernance {},
            approval_target: ApprovalTarget::Event {
                event_id: event.event_id.clone(),
            },
            request_canonical_digest: Hash::new(canonical::canonical_sha256(&event).unwrap())
                .unwrap(),
            operation: "ak.self.events.command.submit.v1".to_owned(),
            action: CapabilityActionId::MessageCreate,
            realm_id: event.realm_id.clone(),
            initiating_actor_id: event.actor_id.clone(),
            approver_did: Did::new("did:web:sdk.arkret.org").unwrap(),
            approved_at: now(),
            nonce: "sdk023-approval-original-nonce".to_owned(),
        },
        proof: ApprovalSignatureProof {
            kind: ApprovalSignatureProofKind::DetachedJws,
            verification_method: method,
            jws: String::new(),
        },
    };
    approval.proof.jws = approver.sign_detached_jws(
        &signatures::approval_signature::approval_signature_signing_bytes(&approval).unwrap(),
    );
    let key = PublicKeyMaterial::Ed25519Raw {
        bytes: approver.verifying_key().to_bytes().to_vec(),
    };
    signatures::approval_signature::verify_event_approval_signature(
        &approval,
        &event,
        "ak.self.events.command.submit.v1",
        CapabilityActionId::MessageCreate,
        now(),
        &key,
    )
    .unwrap();
    let mut slot = EventAdmissionSubmission::new(event);
    slot.approval_signatures = Some(vec![approval]);
    let batch = EventsSubmitBatchRequestBody::new(vec![slot]).unwrap();
    let original = canonical::canonical_json_bytes(&batch).unwrap();
    let verified = VerifiedSubmission::verify(batch.clone(), |_| Ok(context())).unwrap();
    assert_eq!(
        canonical::canonical_json_bytes(&verified).unwrap(),
        original
    );
    let unit = PreparedEventUnit::new(DigestSuite::Sha256, batch).unwrap();
    unit.validate().unwrap();
    assert_eq!(
        canonical::canonical_json_bytes(&unit.request).unwrap(),
        original
    );
    assert_eq!(
        canonical::canonical_json_bytes(&unit.request.events[0].event).unwrap(),
        event_bytes
    );
    let encoded = canonical::canonical_json_bytes(&unit).unwrap();
    let mut recovered: PreparedEventUnit = serde_json::from_slice(&encoded).unwrap();
    recovered.validate().unwrap();
    assert_eq!(
        canonical::canonical_json_bytes(&recovered).unwrap(),
        encoded
    );
    recovered.request.events[0].approval_signatures = None;
    assert!(recovered.validate().is_err());
    println!("{}", canonical::canonical_sha256(&unit).unwrap());
}
