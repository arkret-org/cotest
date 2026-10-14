//! Recipient admission at the current Garth Signal boundary.
//!
//! The decryptor supplies validated plaintext bytes through the public trait;
//! this suite exercises proof, delivery authority, profile and sequence checks.
//! MLS exporter encryption/decryption is covered by the MLS crate itself.

use arkret_models_collaboration::SignalDeliveryAuthority;
use arkret_models_collaboration::signal_plaintext::{
    PresencePlaintext, PresenceState, seal_signal_plaintext,
};
use arkret_wire::{
    AccountId, ActorId, Base64UrlString, DidCoreId, DidUrl, EventId, SignalEnvelope,
    StationSigningKey,
};
use ed25519_dalek::SigningKey;
use garth::signal::{SignalDecryptor, SignalReceiveOutcome, SignalReceiver};

use super::signal_federation::envelope;

const ALICE_SEED: [u8; 32] = [0x37; 32];
const BOB_SEED: [u8; 32] = [0x38; 32];

struct ProfileDecryptor {
    bytes: Vec<u8>,
}

impl ProfileDecryptor {
    fn presence(signal: &SignalEnvelope, sequence: u64) -> Self {
        let profile = PresencePlaintext::new(
            sequence,
            signal.sender_actor_id.clone(),
            PresenceState::Online,
            30_000,
        )
        .unwrap();
        Self {
            bytes: seal_signal_plaintext(&profile).unwrap(),
        }
    }
}

impl SignalDecryptor for ProfileDecryptor {
    async fn decrypt(&self, _envelope: &SignalEnvelope) -> garth::Result<Vec<u8>> {
        Ok(self.bytes.clone())
    }
}

fn delivery_authority(
    signal: &SignalEnvelope,
    seed: [u8; 32],
    authorization: EventId,
    recipient: AccountId,
) -> SignalDeliveryAuthority {
    let authority = SignalDeliveryAuthority {
        recipient_account_id: recipient,
        key: StationSigningKey {
            actor: signal.sender_actor_id.clone(),
            verification_method: signal.proof.verification_method.clone(),
            public_key_b64u: Base64UrlString::new(arkret_canonical::base64url_encode(
                SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
            ))
            .unwrap(),
            authorization_ref: authorization,
        },
        product_authority: None,
    };
    authority.validate_for_envelope(signal).unwrap();
    authority
}

fn recipient_account() -> AccountId {
    AccountId::new(
        DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station-b.example").unwrap(),
    )
}

#[tokio::test]
async fn signal_recipient_rejects_forged_proof_without_poisoning_sequence() {
    let mut valid = envelope().unwrap();
    let authority = delivery_authority(
        &valid,
        ALICE_SEED,
        crate::fixture_event_id("signal-alice-current-device-authorize"),
        recipient_account(),
    );
    let mut forged = valid.clone();
    crate::harness::attach_signal_proof(&mut forged, &SigningKey::from_bytes(&BOB_SEED));
    let decryptor = ProfileDecryptor::presence(&valid, 1);
    let mut receiver = SignalReceiver::new();
    assert!(
        receiver
            .receive(&forged, &authority, &decryptor, forged.sent_at)
            .await
            .is_err()
    );
    assert!(matches!(
        receiver
            .receive(&valid, &authority, &decryptor, valid.sent_at)
            .await
            .unwrap(),
        SignalReceiveOutcome::Accepted { .. }
    ));
    assert_eq!(
        receiver
            .receive(&valid, &authority, &decryptor, valid.sent_at)
            .await
            .unwrap(),
        SignalReceiveOutcome::StaleSequence
    );
    valid.sender_actor_id = ActorId::account(AccountId::new(
        valid.sender_actor_id.signing_principal_id().clone(),
        DidCoreId::new("ak:did_core:web:station-b.example").unwrap(),
    ));
    crate::harness::attach_signal_proof(&mut valid, &SigningKey::from_bytes(&ALICE_SEED));
    assert!(
        receiver
            .receive(&valid, &authority, &decryptor, valid.sent_at)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn signal_recipient_requires_exact_delivery_authority_and_profile_binding() {
    let signal = envelope().unwrap();
    let authority = delivery_authority(
        &signal,
        ALICE_SEED,
        crate::fixture_event_id("signal-alice-current-device-authorize"),
        recipient_account(),
    );
    let valid = ProfileDecryptor::presence(&signal, 0);
    let mut wrong_actor = signal.clone();
    wrong_actor.sender_actor_id = ActorId::account(AccountId::new(
        signal.sender_actor_id.signing_principal_id().clone(),
        DidCoreId::new("ak:did_core:web:station-b.example").unwrap(),
    ));
    crate::harness::attach_signal_proof(&mut wrong_actor, &SigningKey::from_bytes(&ALICE_SEED));
    assert!(
        SignalReceiver::new()
            .receive(&wrong_actor, &authority, &valid, wrong_actor.sent_at)
            .await
            .is_err()
    );
    let wrong_key = delivery_authority(
        &signal,
        BOB_SEED,
        crate::fixture_event_id("signal-bob-current-device-authorize"),
        recipient_account(),
    );
    assert!(
        SignalReceiver::new()
            .receive(&signal, &wrong_key, &valid, signal.sent_at)
            .await
            .is_err()
    );
    let wrong_profile = ProfileDecryptor::presence(&wrong_actor, 0);
    assert!(
        SignalReceiver::new()
            .receive(&signal, &authority, &wrong_profile, signal.sent_at)
            .await
            .is_err()
    );
    assert_eq!(
        SignalReceiver::new()
            .receive(&signal, &authority, &valid, signal.expires_at)
            .await
            .unwrap(),
        SignalReceiveOutcome::Expired
    );
}

#[tokio::test]
async fn signal_recipient_accepts_agent_without_synthetic_device() {
    let mut signal = envelope().unwrap();
    signal.sender_device_id = None;
    signal.proof.verification_method = DidUrl::new("did:web:alice.example#agent-runtime").unwrap();
    crate::harness::attach_signal_proof(&mut signal, &SigningKey::from_bytes(&ALICE_SEED));
    let authority = delivery_authority(
        &signal,
        ALICE_SEED,
        crate::fixture_event_id("signal-alice-current-agent-authorize"),
        recipient_account(),
    );
    let decryptor = ProfileDecryptor::presence(&signal, 0);
    let outcome = SignalReceiver::new()
        .receive(&signal, &authority, &decryptor, signal.sent_at)
        .await
        .unwrap();
    assert!(matches!(outcome, SignalReceiveOutcome::Accepted { .. }));
}

/// Exercise the actual HTTP client's retry policy with a consumed request and
/// either a lost response or a retryable status.
#[tokio::test]
async fn signal_peer_uncertain_http_outcome_is_not_retried() {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    for response_lost in [true, false] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (finished, mut stop) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            loop {
                let (mut stream, _) = tokio::select! {
                    accepted = listener.accept() => accepted.unwrap(),
                    _ = &mut stop => return requests,
                };
                let mut raw = Vec::new();
                loop {
                    let mut chunk = [0u8; 4096];
                    let read =
                        tokio::time::timeout(Duration::from_secs(3), stream.read(&mut chunk))
                            .await
                            .unwrap()
                            .unwrap();
                    assert_ne!(read, 0, "incomplete HTTP request");
                    raw.extend_from_slice(&chunk[..read]);
                    if let Some(end) = raw.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&raw[..end]);
                        let body_len = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap();
                        if raw.len() >= end + 4 + body_len {
                            break;
                        }
                    }
                }
                requests.push(raw);
                if !response_lost {
                    stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
                }
            }
        });
        let signal = envelope().unwrap();
        let request = arkret_wire::SignalRelayRequest {
            realm_id: signal.realm_id.clone(),
            signals: vec![signal],
        };
        let client = arkret_http_client::Client::builder(
            url::Url::parse(&format!("http://{address}/")).unwrap(),
        )
        .allow_insecure_localhost()
        .timeout(Duration::from_secs(2))
        .retry(arkret_http_client::RetryConfig {
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(1),
            ..arkret_http_client::RetryConfig::standard(2).with_jitter(false)
        })
        .build()
        .unwrap();
        let result: arkret_http_client::Result<arkret_wire::SignalRelayOutcome> =
            client.post("/_arkret/peer/signal", &request).await;
        assert!(result.is_err());
        finished.send(()).unwrap();
        let requests = server.await.unwrap();
        assert_eq!(requests.len(), 1, "response_lost={response_lost}");
        let raw = String::from_utf8_lossy(&requests[0]);
        assert!(!raw.to_ascii_lowercase().contains("idempotency-key:"));
        let (_, body) = raw.split_once("\r\n\r\n").unwrap();
        assert_eq!(
            serde_json::from_str::<arkret_wire::SignalRelayRequest>(body).unwrap(),
            request
        );
    }
}

#[tokio::test]
async fn signal_recipient_preserves_the_authenticated_circle_authority_basis() {
    let mut signal = envelope().unwrap();
    signal.scope_ref = arkret_wire::ScopeRef::Circle {
        realm_id: signal.realm_id.clone(),
        circle_id: arkret_wire::CircleId::from_event_id(&crate::fixture_event_id("signal-circle")),
    };
    signal.parent_realm_authority_commit_id =
        Some(arkret_wire::RealmCommitId::from_digest([0x43; 32]));
    crate::harness::attach_signal_proof(&mut signal, &SigningKey::from_bytes(&ALICE_SEED));
    let authority = delivery_authority(
        &signal,
        ALICE_SEED,
        crate::fixture_event_id("signal-alice-current-device-authorize"),
        recipient_account(),
    );
    let decryptor = ProfileDecryptor::presence(&signal, 1);
    let mut receiver = SignalReceiver::new();
    let mut tampered = signal.clone();
    tampered.parent_realm_authority_commit_id =
        Some(arkret_wire::RealmCommitId::from_digest([0x44; 32]));
    assert!(
        receiver
            .receive(&tampered, &authority, &decryptor, signal.sent_at)
            .await
            .is_err()
    );
    let SignalReceiveOutcome::Accepted {
        authority_commit_id,
        parent_realm_authority_commit_id,
        domain,
        ..
    } = receiver
        .receive(&signal, &authority, &decryptor, signal.sent_at)
        .await
        .unwrap()
    else {
        panic!("authenticated Circle Signal was not accepted");
    };
    assert_eq!(authority_commit_id, signal.authority_commit_id);
    assert_eq!(
        parent_realm_authority_commit_id,
        signal.parent_realm_authority_commit_id
    );
    assert_eq!(domain.scope_ref, signal.scope_ref);
    assert_eq!(domain.sender_actor_id, signal.sender_actor_id);
}

#[tokio::test]
async fn signal_recipient_profile_expiry_cannot_poison_high_water() {
    let signal = envelope().unwrap();
    let authority = delivery_authority(
        &signal,
        ALICE_SEED,
        crate::fixture_event_id("signal-alice-current-device-authorize"),
        recipient_account(),
    );
    let expired = ProfileDecryptor {
        bytes: seal_signal_plaintext(
            &PresencePlaintext::new(
                1024,
                signal.sender_actor_id.clone(),
                PresenceState::Online,
                1_000,
            )
            .unwrap(),
        )
        .unwrap(),
    };
    let now = signal.sent_at + chrono::Duration::seconds(2);
    let mut receiver = SignalReceiver::new();
    assert_eq!(
        receiver
            .receive(&signal, &authority, &expired, now)
            .await
            .unwrap(),
        SignalReceiveOutcome::Expired
    );
    assert!(matches!(
        receiver
            .receive(
                &signal,
                &authority,
                &ProfileDecryptor::presence(&signal, 7),
                now
            )
            .await
            .unwrap(),
        SignalReceiveOutcome::Accepted { .. }
    ));
}

#[tokio::test]
async fn signal_recipient_consumes_formal_dual_action_fixture_without_body_on_refusal()
-> anyhow::Result<()> {
    use arkret_models_collaboration::SignalProductAuthority;
    use arkret_models_collaboration::governance::grant_constraint::{
        CapabilityGrant, GrantConstraint, GrantConstraintEffect, GrantConstraintKind,
    };
    use arkret_models_collaboration::signal_message_stream::{
        MessageStreamFormat, MessageStreamFrame, MessageStreamKeyframe,
    };
    use arkret_wire::{
        CapabilityActionId, CommitStreamHead, CommitStreamRef, GrantId, MessageId, MessageStreamId,
        StrandId,
    };
    let fixture = super::load_fixture_value("signal-message-stream-fixture.json")?;
    let matrix = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "recipient_dual_action_authority_matrix")
        .unwrap();
    let signal = envelope()?;
    let strand: StrandId = "ak:strand:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv".parse()?;
    let original_event = crate::fixture_event_id("signal-product-grant");
    let grant: CapabilityGrant = serde_json::from_value(serde_json::json!({
        "id":GrantId::from_event_id(&original_event), "schema":"ak.schema.capability.v1", "realm_id":signal.realm_id,
        "issuer_id":signal.sender_actor_id, "subject":signal.sender_actor_id,
        "actions":[CapabilityActionId::MESSAGE_STREAM_SEND,CapabilityActionId::MESSAGE_CREATE],
        "resources":[{"kind":"strand","realm_id":signal.realm_id,"strand_id":strand}],
        "status":"active", "issued_at":"2026-07-01T00:00:00.000Z",
        "issuer_authority_refs":[{"kind":"realm_root","realm_id":signal.realm_id,"authority_event_ref":crate::fixture_event_id("signal-product-root"),"authority_generation":0}],
        "authority_root_refs":[{"kind":"realm_root","realm_id":signal.realm_id,"authority_event_ref":crate::fixture_event_id("signal-product-root"),"authority_generation":0}], "authority_depth":1
    }))?;
    let head = CommitStreamHead {
        stream_ref: CommitStreamRef::Realm {
            realm_id: signal.realm_id.clone(),
        },
        commit_id: signal.authority_commit_id.clone(),
        stream_position: 1,
    };
    let material = SignalProductAuthority {
        authority_commit_id: signal.authority_commit_id.clone(),
        parent_realm_authority_commit_id: None,
        current_realm_head: head.clone(),
        current_scope_head: head,
        sent_at: signal.sent_at,
        grants: vec![grant.clone()],
        current_grants: vec![grant],
        historical_product_policies: vec![],
        current_product_policies: vec![],
        owner_actions: vec![],
        profile_actions: vec![],
        agent: None,
    };
    for mutation in matrix["input"]["generator"]["mutations"]
        .as_array()
        .unwrap()
    {
        let mutation = mutation.as_str().unwrap();
        let expected = matrix["expected"][mutation].as_str().unwrap();
        let mut product = material.clone();
        let mut target = strand.clone();
        match mutation {
            "none" => {}
            "missing_send" => product.grants[0]
                .actions
                .retain(|a| a != CapabilityActionId::MESSAGE_STREAM_SEND),
            "missing_create" => product.grants[0]
                .actions
                .retain(|a| a != CapabilityActionId::MESSAGE_CREATE),
            "revoked_source" => product.current_grants.clear(),
            "replacement_grant" => {
                product.current_grants[0].id =
                    GrantId::from_event_id(&crate::fixture_event_id("replacement-product-grant"))
            }
            "wrong_strand" => {
                target = "ak:strand:Aa-h0nYxlvhQk1U9H0yQTY4hZEVTz0be75pj6U70n7qy".parse()?
            }
            "same_principal_other_station" => {
                let mut account = signal.sender_actor_id.as_account_id().unwrap().clone();
                account.station_id = "ak:did_core:web:station-b.example".parse()?;
                product.grants[0].subject=arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(ActorId::account(account));
            }
            "wrong_basis" => {
                product.authority_commit_id = arkret_wire::RealmCommitId::from_digest([0x88; 32])
            }
            "explicit_null" => {
                let mut value = serde_json::to_value(&product)?;
                value["agent"] = serde_json::Value::Null;
                assert!(serde_json::from_value::<SignalProductAuthority>(value).is_err());
                continue;
            }
            "historical_unknown_deny" | "current_unknown_review" => {
                let historical = mutation == "historical_unknown_deny";
                let mut constraint = GrantConstraint::new(
                    GrantConstraintKind::ScopeLimitation,
                    if historical {
                        GrantConstraintEffect::Deny
                    } else {
                        GrantConstraintEffect::RequireReview
                    },
                );
                constraint.allowed_session_ids = vec!["unavailable-private-session".into()];
                if historical {
                    product.grants[0].constraints.push(constraint)
                } else {
                    product.current_grants[0].constraints.push(constraint)
                }
            }
            _ => anyhow::bail!("unimplemented formal product mutation {mutation}"),
        }
        let frame = MessageStreamFrame::Keyframe(MessageStreamKeyframe::new(
            1,
            target,
            MessageId::from_event_id(&crate::fixture_event_id("product-final-message")),
            0,
            MessageStreamId::new_v7_at(1_790_000_000_000),
            0,
            MessageStreamFormat::Plain,
            "transient body",
            false,
        )?);
        let decryptor = ProfileDecryptor {
            bytes: arkret_canonical::canonical_json_bytes(&frame)?,
        };
        let mut authority = delivery_authority(
            &signal,
            ALICE_SEED,
            crate::fixture_event_id("signal-alice-current-device-authorize"),
            recipient_account(),
        );
        authority.product_authority = Some(Box::new(product));
        let mut receiver = SignalReceiver::new();
        let outcome = receiver
            .receive(&signal, &authority, &decryptor, signal.sent_at)
            .await;
        if expected == "reject_before_high_water" {
            assert!(outcome.is_err(), "{mutation}");
            authority.product_authority = Some(Box::new(material.clone()));
            assert!(matches!(
                receiver
                    .receive(&signal, &authority, &decryptor, signal.sent_at)
                    .await?,
                SignalReceiveOutcome::Accepted { .. }
            ));
            continue;
        }
        let SignalReceiveOutcome::Accepted {
            domain,
            plaintext,
            product_authority: Some(material),
            ..
        } = outcome?
        else {
            anyhow::bail!("valid producer frame was not admitted for {mutation}");
        };
        let mut projection = garth::MessageStreamProjection::new();
        let result = projection.apply_plaintext(
            &domain,
            &plaintext,
            &|domain: &garth::SignalSequenceDomain, frame: &arkret_models_collaboration::signal_message_stream::MessageStreamFrame| {
                arkret_policy::signal_authorization::message_stream_allowed(
                    &material,
                    &domain.sender_actor_id,
                    &domain.scope_ref,
                    frame.strand_id(),
                    signal.sent_at,
                )
            },
            signal.sent_at,
        );
        assert_eq!(
            result.is_ok(),
            expected == "show_preview",
            "{mutation}: {result:?}"
        );
        assert_eq!(
            projection.previews().count(),
            usize::from(expected == "show_preview"),
            "{mutation}"
        );
    }
    Ok(())
}
