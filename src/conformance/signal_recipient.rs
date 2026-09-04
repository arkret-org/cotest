//! Real SDK MLS + Garth recipient composition, not a simulated admission gate.
//! Accepted membership/authorization inputs are installed explicitly; this
//! fixture does not claim to exercise remote attestation retrieval or HTTP.

use std::sync::Mutex;

use arkret::mls::{ArkretMlsGroup, ArkretMlsIdentity, ArkretMlsSigner, MlsVerifiedLeafBinding};
use arkret::{AeadNonceReplayTracker, AuthorLeafCredential};
use arkret_signatures::PublicKeyMaterial;
use arkret_wire::{
    AccountId, ActorId, Base64UrlString, DeviceId, DidCoreId, DidUrl, EncryptedPayloadScheme,
    EventId, NonEmptyString, SignalEnvelope,
};
use ed25519_dalek::SigningKey;
use garth::signal::{
    BoxSignalDecryptFuture, SignalDecryptor, SignalReceiver, VerifiedSignalSenderAuthority,
    VerifiedSignalSenderKey,
};

use super::signal_federation::envelope;

const ALICE_SEED: [u8; 32] = [0x37; 32];
const BOB_SEED: [u8; 32] = [0x38; 32];
const CONTENT_SCHEME: EncryptedPayloadScheme = EncryptedPayloadScheme::MlsRfc9420;

struct Recipient {
    state: Mutex<(ArkretMlsGroup, AeadNonceReplayTracker)>,
    winner: String,
}

impl SignalDecryptor for Recipient {
    fn open<'a>(
        &'a self,
        signal: &'a SignalEnvelope,
        sender: &'a VerifiedSignalSenderKey,
    ) -> BoxSignalDecryptFuture<'a> {
        let result = {
            let mut guard = self.state.lock().unwrap();
            let (group, replay) = &mut *guard;
            let authority = match sender.authority() {
                VerifiedSignalSenderAuthority::AccountDevice {
                    device_authorize_event_id,
                    ..
                } => arkret::mls::SignalSenderAuthority::AccountDevice {
                    public_key: sender.public_key(),
                    device_authorize_event_id,
                },
                VerifiedSignalSenderAuthority::Agent {
                    agent_key_authorize_event_id,
                    ..
                } => arkret::mls::SignalSenderAuthority::Agent {
                    public_key: sender.public_key(),
                    verification_method: &signal.proof.verification_method,
                    agent_key_authorize_event_id,
                },
            };
            group
                .open_signal_envelope(signal, CONTENT_SCHEME, authority, &self.winner, replay)
                .map_err(|error| garth::Error::Protocol(error.to_string()))
        };
        Box::pin(async move { result })
    }
}

struct Fixture {
    sender: ArkretMlsGroup,
    recipient: Recipient,
    template: SignalEnvelope,
    authorization: EventId,
}

impl Fixture {
    fn new() -> Self {
        let mut template = envelope().unwrap();
        let authorization = crate::fixture_event_id("signal-alice-current-device-authorize");
        let alice = ArkretMlsIdentity::new_human_device(
            template.sender_actor_id.signing_principal_id().clone(),
            template.sender_device_id.clone().unwrap(),
            ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(&ALICE_SEED)),
        )
        .unwrap();
        let bob_device = DeviceId::new("ak:device:01904100-0000-7000-8000-cccccccccccc").unwrap();
        let bob_actor = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station-b.example").unwrap(),
        ));
        let bob = ArkretMlsIdentity::new_human_device(
            bob_actor.signing_principal_id().clone(),
            bob_device.clone(),
            ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(&BOB_SEED)),
        )
        .unwrap();
        let alice_endpoint = alice.endpoint_identity();
        let bob_endpoint = bob.endpoint_identity();
        let package = bob.key_package_record().unwrap();
        let mut sender = alice
            .create_group(
                template
                    .scope_ref
                    .canonical_effective_scope_key_bytes()
                    .unwrap(),
            )
            .unwrap();
        sender
            .install_local_creator_binding(
                template.sender_actor_id.clone(),
                Some(authorization.clone()),
            )
            .unwrap();
        let add = sender.add_member(&package).unwrap();
        let mut recipient = ArkretMlsGroup::join_from_welcome(bob, &add.welcome).unwrap();
        for group in [&mut sender, &mut recipient] {
            let bindings = group
                .active_author_leaves()
                .into_iter()
                .map(|leaf| {
                    let AuthorLeafCredential::Basic { identity } = leaf.credential else {
                        panic!("expected BasicCredential")
                    };
                    let is_alice = identity
                        == template
                            .sender_device_id
                            .as_ref()
                            .unwrap()
                            .as_str()
                            .as_bytes();
                    assert!(is_alice || identity == bob_device.as_str().as_bytes());
                    MlsVerifiedLeafBinding {
                        leaf_index: leaf.leaf_index,
                        actor_id: if is_alice {
                            template.sender_actor_id.clone()
                        } else {
                            bob_actor.clone()
                        },
                        endpoint: if is_alice {
                            alice_endpoint.clone()
                        } else {
                            bob_endpoint.clone()
                        },
                        credential_ref: NonEmptyString::new(String::from_utf8(identity).unwrap())
                            .unwrap(),
                        signature_key: Base64UrlString::new(arkret_canonical::base64url_encode(
                            &leaf.signature_key,
                        ))
                        .unwrap(),
                        device_authorize_event_id: Some(if is_alice {
                            authorization.clone()
                        } else {
                            crate::fixture_event_id("signal-bob-authorize")
                        }),
                    }
                })
                .collect();
            group.install_verified_leaf_bindings(bindings).unwrap();
        }
        template.encrypted_payload.epoch = sender.epoch();
        Self {
            sender,
            recipient: Recipient {
                state: Mutex::new((recipient, AeadNonceReplayTracker::default())),
                winner: template.encrypted_payload.key_ref.group_state_ref.clone(),
            },
            template,
            authorization,
        }
    }

    fn seal(&mut self, sequence: u64) -> SignalEnvelope {
        let mut signal = self.template.clone();
        let plaintext = serde_json::to_vec(&serde_json::json!({
            "kind": "ak.presence", "payload_sequence": sequence,
            "actor_id": signal.sender_actor_id, "state": "online", "ttl_ms": 30_000
        }))
        .unwrap();
        signal.encrypted_payload = self
            .sender
            .seal_signal_payload(&signal.aead_binding(), CONTENT_SCHEME, &plaintext)
            .unwrap()
            .encrypted_payload;
        crate::harness::attach_signal_proof(&mut signal, &SigningKey::from_bytes(&ALICE_SEED));
        signal
    }

    fn evidence(
        &self,
        signal: &SignalEnvelope,
        seed: [u8; 32],
        authorization: EventId,
    ) -> VerifiedSignalSenderKey {
        VerifiedSignalSenderKey::from_directory_evidence(
            PublicKeyMaterial::Ed25519Raw {
                bytes: SigningKey::from_bytes(&seed)
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            },
            signal.sender_actor_id.clone(),
            signal.sender_device_id.clone().unwrap(),
            signal.proof.verification_method.clone(),
            signal.sender_actor_id.as_account_id().unwrap().clone(),
            authorization,
        )
        .unwrap()
    }
}

#[tokio::test]
async fn signal_recipient_real_mls_rejects_forged_proof_without_poisoning_sequence() {
    let mut fixture = Fixture::new();
    let mut forged = fixture.seal(100);
    crate::harness::attach_signal_proof(&mut forged, &SigningKey::from_bytes(&BOB_SEED));
    // The ciphertext remains decryptable: AEAD cannot authenticate its producer.
    fixture
        .recipient
        .state
        .lock()
        .unwrap()
        .0
        .open_signal_payload(
            &forged.aead_binding(),
            CONTENT_SCHEME,
            &forged.encrypted_payload.nonce,
            &forged.encrypted_payload.ciphertext,
            &mut AeadNonceReplayTracker::default(),
        )
        .unwrap();
    let evidence = fixture.evidence(&forged, ALICE_SEED, fixture.authorization.clone());
    let resolver = |_: &SignalEnvelope| Some(evidence.clone());
    let mut receiver = SignalReceiver::new();
    assert!(
        receiver
            .accept(&forged, &resolver, &fixture.recipient, forged.sent_at)
            .await
            .is_err()
    );
    let valid = fixture.seal(1);
    assert_eq!(
        receiver
            .accept(&valid, &resolver, &fixture.recipient, valid.sent_at)
            .await
            .unwrap()
            .payload_sequence,
        1
    );
}

#[tokio::test]
async fn signal_recipient_requires_exact_account_leaf_key_authorization_and_winner() {
    for mutation in [
        "station",
        "key",
        "authorization",
        "winner",
        "missing_trust",
        "expired",
    ] {
        let mut fixture = Fixture::new();
        let mut candidate = fixture.seal(100);
        let mut seed = ALICE_SEED;
        let mut authorization = fixture.authorization.clone();
        match mutation {
            "station" => {
                candidate.sender_actor_id = ActorId::account(AccountId::new(
                    candidate.sender_actor_id.signing_principal_id().clone(),
                    DidCoreId::new("ak:did_core:web:station-b.example").unwrap(),
                ));
                crate::harness::attach_signal_proof(
                    &mut candidate,
                    &SigningKey::from_bytes(&ALICE_SEED),
                );
            }
            "key" => {
                seed = BOB_SEED;
                crate::harness::attach_signal_proof(&mut candidate, &SigningKey::from_bytes(&seed));
            }
            "authorization" => {
                authorization = crate::fixture_event_id("replacement-device-authorize")
            }
            "winner" => {
                fixture.recipient.winner =
                    crate::fixture_event_id("nonwinning-mls-state").to_string()
            }
            "missing_trust" | "expired" => {}
            _ => unreachable!(),
        }
        let evidence = fixture.evidence(&candidate, seed, authorization);
        let resolver = |_: &SignalEnvelope| (mutation != "missing_trust").then(|| evidence.clone());
        let now = if mutation == "expired" {
            candidate.expires_at
        } else {
            candidate.sent_at
        };
        let mut receiver = SignalReceiver::new();
        let error = receiver
            .accept(&candidate, &resolver, &fixture.recipient, now)
            .await
            .unwrap_err()
            .to_string();
        let reason = match mutation {
            "station" => "differs from the complete accepted MLS leaf actor",
            "key" | "authorization" => {
                "current endpoint authority differs from the accepted MLS leaf"
            }
            "winner" => "not the accepted winning state",
            "missing_trust" => "lacks exact-authority verified state",
            "expired" => "already expired",
            _ => unreachable!(),
        };
        assert!(error.contains(reason), "{mutation}: {error}");
        fixture.recipient.winner = fixture
            .template
            .encrypted_payload
            .key_ref
            .group_state_ref
            .clone();
        let valid = fixture.seal(1);
        let current = fixture.evidence(&valid, ALICE_SEED, fixture.authorization.clone());
        let current_resolver = |_: &SignalEnvelope| Some(current.clone());
        assert_eq!(
            receiver
                .accept(&valid, &current_resolver, &fixture.recipient, valid.sent_at)
                .await
                .unwrap()
                .payload_sequence,
            1,
            "{mutation}"
        );
    }
}

#[tokio::test]
async fn signal_recipient_accepts_a_real_agent_leaf_without_a_synthetic_device() {
    let mut template = envelope().unwrap();
    template.sender_device_id = None;
    template.proof.verification_method =
        DidUrl::new("did:web:alice.example#agent-runtime").unwrap();
    let authorization = crate::fixture_event_id("signal-alice-current-agent-authorize");
    let alice = ArkretMlsIdentity::new_agent(
        template.sender_actor_id.signing_principal_id().clone(),
        template.proof.verification_method.clone(),
        authorization.clone(),
        ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(&ALICE_SEED)),
    )
    .unwrap();
    let bob_device = DeviceId::new("ak:device:01904100-0000-7000-8000-cccccccccccc").unwrap();
    let bob_actor = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station-b.example").unwrap(),
    ));
    let bob = ArkretMlsIdentity::new_human_device(
        bob_actor.signing_principal_id().clone(),
        bob_device.clone(),
        ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(&BOB_SEED)),
    )
    .unwrap();
    let alice_endpoint = alice.endpoint_identity();
    let bob_endpoint = bob.endpoint_identity();
    let package = bob.key_package_record().unwrap();
    let mut sender = alice
        .create_group(
            template
                .scope_ref
                .canonical_effective_scope_key_bytes()
                .unwrap(),
        )
        .unwrap();
    sender
        .install_local_creator_binding(template.sender_actor_id.clone(), None)
        .unwrap();
    let add = sender.add_member(&package).unwrap();
    let mut recipient_group = ArkretMlsGroup::join_from_welcome(bob, &add.welcome).unwrap();
    for group in [&mut sender, &mut recipient_group] {
        let bindings = group
            .active_author_leaves()
            .into_iter()
            .map(|leaf| {
                let AuthorLeafCredential::Basic { identity } = leaf.credential else {
                    panic!("expected BasicCredential")
                };
                let is_agent = identity
                    == template
                        .sender_actor_id
                        .signing_principal_id()
                        .as_str()
                        .as_bytes();
                MlsVerifiedLeafBinding {
                    leaf_index: leaf.leaf_index,
                    actor_id: if is_agent {
                        template.sender_actor_id.clone()
                    } else {
                        bob_actor.clone()
                    },
                    endpoint: if is_agent {
                        alice_endpoint.clone()
                    } else {
                        bob_endpoint.clone()
                    },
                    credential_ref: NonEmptyString::new(String::from_utf8(identity).unwrap())
                        .unwrap(),
                    signature_key: Base64UrlString::new(arkret_canonical::base64url_encode(
                        &leaf.signature_key,
                    ))
                    .unwrap(),
                    device_authorize_event_id: (!is_agent)
                        .then(|| crate::fixture_event_id("signal-bob-agent-fixture-authorize")),
                }
            })
            .collect();
        group.install_verified_leaf_bindings(bindings).unwrap();
    }
    template.encrypted_payload.epoch = sender.epoch();
    let plaintext = serde_json::to_vec(&serde_json::json!({
        "kind": "ak.presence",
        "payload_sequence": 0,
        "actor_id": template.sender_actor_id,
        "state": "online",
        "ttl_ms": 30_000
    }))
    .unwrap();
    let mut signal = template.clone();
    signal.encrypted_payload = sender
        .seal_signal_payload(&signal.aead_binding(), CONTENT_SCHEME, &plaintext)
        .unwrap()
        .encrypted_payload;
    crate::harness::attach_signal_proof(&mut signal, &SigningKey::from_bytes(&ALICE_SEED));
    let evidence = VerifiedSignalSenderKey::from_agent_evidence(
        PublicKeyMaterial::Ed25519Raw {
            bytes: SigningKey::from_bytes(&ALICE_SEED)
                .verifying_key()
                .to_bytes()
                .to_vec(),
        },
        signal.sender_actor_id.clone(),
        signal.proof.verification_method.clone(),
        authorization,
    )
    .unwrap();
    let resolver = |_: &SignalEnvelope| Some(evidence.clone());
    let recipient = Recipient {
        state: Mutex::new((recipient_group, AeadNonceReplayTracker::default())),
        winner: signal.encrypted_payload.key_ref.group_state_ref.clone(),
    };
    let accepted = SignalReceiver::new()
        .accept(&signal, &resolver, &recipient, signal.sent_at)
        .await
        .unwrap();
    assert_eq!(accepted.payload_sequence, 0);
    assert!(matches!(
        accepted.sender_endpoint,
        arkret::SignalSequenceEndpoint::AgentKey { .. }
    ));
}

/// Exercise the actual HTTP client's retry policy with a consumed request and
/// either a lost response or a retryable status. This is a loopback transport
/// test, not a peer-authentication or device-evidence retrieval test.
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
