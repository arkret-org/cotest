//! Focused Signal wire clean-break checks over the production SDK paths.
//!
//! No local wire mirror participates here: typed `SignalEnvelope` values feed
//! the production MLS encrypt/open implementation, including its canonical AAD,
//! sender proof, authority, accepted-state and nonce-replay checks.

use anyhow::{Context, Result, anyhow, ensure};
use arkret::AeadNonceReplayTracker;
use arkret::mls::{ArkretMlsGroup, ArkretMlsIdentity, ArkretMlsSigner, SignalSenderAuthority};
use arkret_canonical::{base64url_decode, base64url_encode};
use arkret_signatures::{Ed25519DetachedJwsSigner, PublicKeyMaterial};
use arkret_wire::{
    AccountId, ActorId, DeviceId, DidCoreId, DidUrl, EventId, Hash, RealmCommitId, RealmId,
    ScopeRef, SignalClass, SignalEncryptedPayload, SignalEnvelope, SignalKeyRef, SignalProof,
};
use chrono::{Duration, TimeZone, Utc};
use ed25519_dalek::SigningKey;

const ALICE_SEED: [u8; 32] = [0x37; 32];
const BOB_SEED: [u8; 32] = [0x38; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalWireExecution {
    pub accepted_effects: usize,
    pub rejected_zero_effects: usize,
    pub aad_fields_bound: usize,
}

#[derive(Default)]
struct ConsumerSink {
    plaintexts: Vec<Vec<u8>>,
}

impl ConsumerSink {
    fn accept(
        &mut self,
        recipient: &ArkretMlsGroup,
        signal: &SignalEnvelope,
        authority: SignalSenderAuthority<'_>,
        replay: &mut AeadNonceReplayTracker,
    ) -> Result<()> {
        let plaintext = recipient.open_signal_envelope(
            signal,
            authority,
            &signal.encrypted_payload.key_ref.group_state_ref,
            &signal.stream_head_ref,
            replay,
        )?;
        self.plaintexts.push(plaintext);
        Ok(())
    }
}

struct Fixture {
    sender: ArkretMlsGroup,
    recipient: ArkretMlsGroup,
    template: SignalEnvelope,
    authorization: EventId,
    public_key: PublicKeyMaterial,
}

impl Fixture {
    fn new() -> Result<Self> {
        let mut template = template()?;
        let authorization = event_id("signal-alice-current-device-authorize")?;
        let alice = ArkretMlsIdentity::new_human_device(
            template.sender_actor_id.clone(),
            template
                .sender_device_id
                .clone()
                .context("fixture sender device")?,
            ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(&ALICE_SEED)),
        )?;
        let mut sender = alice.create_group(&template.scope_ref)?;
        sender.install_local_creator_binding(
            template.sender_actor_id.clone(),
            Some(authorization.clone()),
        )?;
        // Snapshot/restore gives the receiving side the same accepted epoch
        // without inventing a transport-only Welcome shape in this suite.
        let recipient = ArkretMlsGroup::restore_from_state_record(&sender.export_state_record()?)?;
        template.encrypted_payload.epoch = sender.epoch();
        Ok(Self {
            sender,
            recipient,
            template,
            authorization,
            public_key: PublicKeyMaterial::Ed25519Raw {
                bytes: SigningKey::from_bytes(&ALICE_SEED)
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            },
        })
    }

    fn seal(&mut self, payload: &[u8]) -> Result<SignalEnvelope> {
        let mut signal = self.template.clone();
        signal.encrypted_payload = self
            .sender
            .encrypt_signal_payload(&signal.aead_binding(), payload)?
            .encrypted_payload;
        attach_proof(&mut signal)?;
        Ok(signal)
    }

    fn authority(&self) -> SignalSenderAuthority<'_> {
        SignalSenderAuthority::AccountDevice {
            public_key: &self.public_key,
            device_authorize_event_id: &self.authorization,
        }
    }
}

fn event_id(label: &str) -> Result<EventId> {
    let value = match label {
        "signal-alice-current-device-authorize" => {
            "ak:event:ATrYU3cGlcWkAcHXWgJ8sIYfraoV9pIwEHNNStEqHvFh"
        }
        _ => "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
    };
    Ok(EventId::new(value.to_owned())?)
}

fn template() -> Result<SignalEnvelope> {
    let realm_id =
        RealmId::new("ak:realm:AYcmQBZ6x7FCwln_vbdWIyV2tJ4pOJ4rmbd6v_0Y7N9_".to_owned())?;
    let sent_at = Utc
        .with_ymd_and_hms(2026, 7, 28, 12, 0, 0)
        .single()
        .context("fixed Signal time")?;
    let device = DeviceId::new("ak:device:01904100-0000-7000-8000-bbbbbbbbbbbb".to_owned())?;
    Ok(SignalEnvelope {
        realm_id: realm_id.clone(),
        scope_ref: ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        sender_actor_id: ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example".to_owned())?,
            DidCoreId::new("ak:did_core:web:station-a.example".to_owned())?,
        )),
        sender_device_id: Some(device.clone()),
        stream_head_ref: RealmCommitId::new(
            "ak:realm_commit:Ac08ROpjn3Ilj_UaM-_XLY93u4SUTptG0-Q-_CUDb5aS".to_owned(),
        )?,
        signal_class: SignalClass::Session,
        sent_at,
        expires_at: sent_at + Duration::seconds(30),
        encrypted_payload: SignalEncryptedPayload {
            scheme: arkret_wire::SIGNAL_AEAD_SCHEME.to_owned(),
            key_ref: SignalKeyRef {
                group_state_ref: "ak:event:AbyX-ijAQZ4DkcySKE3VusrcCoBFT8DGS4fx8tpo-PNm".to_owned(),
            },
            purpose: arkret_wire::SIGNAL_AEAD_PURPOSE.to_owned(),
            aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
            epoch: 0,
            nonce: "AAAAAAAAAAAAAAAA".to_owned(),
            ciphertext: "AA".to_owned(),
        },
        proof: SignalProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: DidUrl::new(format!("did:web:alice.example#{}", device.as_str()))
                .map_err(|error| anyhow!(error))?,
            envelope_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            domain: None,
            audience: None,
            jws: "a..b".to_owned(),
        },
    })
}

fn attach_proof(signal: &mut SignalEnvelope) -> Result<()> {
    signal.proof.envelope_digest = signal.envelope_digest()?;
    let binding = signal.proof_binding_bytes()?;
    let signer = Ed25519DetachedJwsSigner::new(
        SigningKey::from_bytes(&ALICE_SEED),
        signal.proof.verification_method.as_str(),
    );
    signal.proof.jws = signer.sign_detached_jws(&binding);
    Ok(())
}

fn reject_without_effect(
    fixture: &Fixture,
    signal: &SignalEnvelope,
    sink: &mut ConsumerSink,
    replay: &mut AeadNonceReplayTracker,
) -> Result<()> {
    let before = sink.plaintexts.clone();
    ensure!(
        sink.accept(&fixture.recipient, signal, fixture.authority(), replay)
            .is_err(),
        "mutated Signal unexpectedly opened"
    );
    ensure!(
        sink.plaintexts == before,
        "rejected Signal changed consumer state"
    );
    Ok(())
}

fn assert_aad_field_binding(signal: &SignalEnvelope) -> Result<usize> {
    let baseline = signal
        .aead_binding()
        .aad_bytes(&signal.encrypted_payload.nonce)?;
    let wire = serde_json::to_value(signal)?;
    let mutations = [
        (
            "/realm_id",
            serde_json::json!("ak:realm:AZcmQBZ6x7FCwln_vbdWIyV2tJ4pOJ4rmbd6v_0Y7N9_"),
        ),
        (
            "/scope_ref/realm_id",
            serde_json::json!("ak:realm:AZcmQBZ6x7FCwln_vbdWIyV2tJ4pOJ4rmbd6v_0Y7N9_"),
        ),
        (
            "/sender_actor_id/account_id/station_id",
            serde_json::json!("ak:did_core:web:station-b.example"),
        ),
        (
            "/sender_device_id",
            serde_json::json!("ak:device:01904100-0000-7000-8000-cccccccccccc"),
        ),
        (
            "/stream_head_ref",
            serde_json::json!("ak:realm_commit:AZ08ROpjn3Ilj_UaM-_XLY93u4SUTptG0-Q-_CUDb5aS"),
        ),
        ("/signal_class", serde_json::json!("setup")),
        ("/sent_at", serde_json::json!("2026-07-28T12:00:01.000Z")),
        ("/expires_at", serde_json::json!("2026-07-28T12:00:29.000Z")),
        (
            "/encrypted_payload/scheme",
            serde_json::json!("ak.signal.changed.v1"),
        ),
        (
            "/encrypted_payload/key_ref/group_state_ref",
            serde_json::json!("ak:event:AXehYOgO_p3M5hbOzs6Mhblqek3i9nwaGUec3J9_89_C"),
        ),
        (
            "/encrypted_payload/purpose",
            serde_json::json!("ak.signal.changed.v1"),
        ),
        (
            "/encrypted_payload/aead_profile",
            serde_json::json!("MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519"),
        ),
        ("/encrypted_payload/epoch", serde_json::json!(7)),
        (
            "/encrypted_payload/nonce",
            serde_json::json!("AAAAAAAAAAAAAAAB"),
        ),
    ];
    let mut count = 0;
    for (pointer, replacement) in mutations {
        let mut candidate = wire.clone();
        *candidate
            .pointer_mut(pointer)
            .with_context(|| format!("Signal fixture has no AAD field at {pointer}"))? =
            replacement;
        let candidate: SignalEnvelope = serde_json::from_value(candidate)?;
        ensure!(
            candidate
                .aead_binding()
                .aad_bytes(&candidate.encrypted_payload.nonce)?
                != baseline,
            "{pointer} was not bound by canonical Signal AAD"
        );
        count += 1;
    }
    Ok(count)
}

pub fn run_signal_wire_clean_break() -> Result<SignalWireExecution> {
    let mut accepted_effects = 0;
    let mut rejected_zero_effects = 0;

    // A typed serialization is the authoritative wire closure: deleted fields
    // cannot silently return as local fixture mirrors.
    let sample = template()?;
    let wire = serde_json::to_value(&sample)?;
    ensure!(wire["encrypted_payload"].get("aad_digest").is_none());
    ensure!(
        wire["encrypted_payload"]["key_ref"]
            .get("algorithm")
            .is_none()
    );
    for (path, value) in [
        (
            "aad_digest",
            serde_json::json!(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
        ),
        ("algorithm", serde_json::json!("mls")),
    ] {
        let mut legacy = wire.clone();
        if path == "algorithm" {
            legacy["encrypted_payload"]["key_ref"][path] = value;
        } else {
            legacy["encrypted_payload"][path] = value;
        }
        ensure!(serde_json::from_value::<SignalEnvelope>(legacy).is_err());
        rejected_zero_effects += 1;
    }

    let plaintext = br#"{"kind":"ak.presence","payload_sequence":1}"#;

    // Production happy path reaches the sink exactly once.
    let mut fixture = Fixture::new()?;
    let valid = fixture.seal(plaintext)?;
    let aad_fields_bound = assert_aad_field_binding(&valid)?;
    let mut sink = ConsumerSink::default();
    let mut replay = AeadNonceReplayTracker::default();
    sink.accept(&fixture.recipient, &valid, fixture.authority(), &mut replay)?;
    ensure!(sink.plaintexts == [plaintext.to_vec()]);
    accepted_effects += 1;

    // Ciphertext tamper, with a freshly valid outer proof, reaches AEAD and
    // fails without consuming the nonce or mutating the consumer. The exact
    // original envelope must still open afterwards.
    let mut fixture = Fixture::new()?;
    let valid = fixture.seal(plaintext)?;
    let mut tampered = valid.clone();
    let mut ciphertext = base64url_decode(&tampered.encrypted_payload.ciphertext)?;
    let last = ciphertext.last_mut().context("AEAD ciphertext")?;
    *last ^= 1;
    tampered.encrypted_payload.ciphertext = base64url_encode(&ciphertext);
    attach_proof(&mut tampered)?;
    let mut sink = ConsumerSink::default();
    let mut replay = AeadNonceReplayTracker::default();
    reject_without_effect(&fixture, &tampered, &mut sink, &mut replay)?;
    rejected_zero_effects += 1;
    sink.accept(&fixture.recipient, &valid, fixture.authority(), &mut replay)?;
    accepted_effects += 1;

    // Header tamper gets a valid new envelope proof, but cannot forge the AEAD
    // created over the original canonical header. Failure again leaves replay
    // and consumer state untouched.
    let mut fixture = Fixture::new()?;
    let valid = fixture.seal(plaintext)?;
    let mut rebound = valid.clone();
    rebound.signal_class = SignalClass::Setup;
    attach_proof(&mut rebound)?;
    let mut sink = ConsumerSink::default();
    let mut replay = AeadNonceReplayTracker::default();
    reject_without_effect(&fixture, &rebound, &mut sink, &mut replay)?;
    rejected_zero_effects += 1;
    sink.accept(&fixture.recipient, &valid, fixture.authority(), &mut replay)?;
    accepted_effects += 1;

    // A forged proof is rejected before decryption and likewise cannot poison
    // replay admission.
    let mut fixture = Fixture::new()?;
    let valid = fixture.seal(plaintext)?;
    let mut forged = valid.clone();
    forged.proof.envelope_digest = forged.envelope_digest()?;
    let binding = forged.proof_binding_bytes()?;
    forged.proof.jws = Ed25519DetachedJwsSigner::new(
        SigningKey::from_bytes(&BOB_SEED),
        forged.proof.verification_method.as_str(),
    )
    .sign_detached_jws(&binding);
    let mut sink = ConsumerSink::default();
    let mut replay = AeadNonceReplayTracker::default();
    reject_without_effect(&fixture, &forged, &mut sink, &mut replay)?;
    rejected_zero_effects += 1;
    sink.accept(&fixture.recipient, &valid, fixture.authority(), &mut replay)?;
    accepted_effects += 1;

    Ok(SignalWireExecution {
        accepted_effects,
        rejected_zero_effects,
        aad_fields_bound,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_wire_clean_break_uses_production_open_and_zero_effect_rejections() {
        let execution = run_signal_wire_clean_break().unwrap();
        assert_eq!(execution.accepted_effects, 4);
        assert_eq!(execution.rejected_zero_effects, 5);
        assert_eq!(execution.aad_fields_bound, 14);
    }
}
