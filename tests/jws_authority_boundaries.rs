//! Cross-crate conformance for DID proof authority boundaries.
//!
//! These vectors intentionally use only the public `arkret::identity` surface.
//! A signature-valid key is insufficient unless the method adapter or current
//! registry assertion relationship authorizes it.

use std::collections::BTreeMap;

use arkret::identity::{
    DidDocument, DidKeyLogAuthorityVerifier, DidRegistryReceipt, IdentityError,
    IdentityReceiptWitnessRole, Result as IdentityResult, attach_did_key_log_controller_proof,
    verify_did_key_log,
};
use arkret_identifiers::Did;
use arkret_models_identity::{DidKeyLogEntry, DidKeyLogOperation};
use arkret_wire::{DidUrl, Hash, ReceiptId};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use serde_json::json;

fn did(name: &str) -> Did {
    Did::new(format!("did:web:{name}.cotest.example")).unwrap()
}

fn multibase(key: &SigningKey) -> String {
    arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())
}

struct HistoricalAuthority {
    expected: BTreeMap<u64, (DidUrl, ed25519_dalek::VerifyingKey)>,
    next_seq: u64,
}

impl DidKeyLogAuthorityVerifier for HistoricalAuthority {
    fn verify_entry_authority(
        &mut self,
        entry: &DidKeyLogEntry,
        previous_accepted: Option<&DidKeyLogEntry>,
    ) -> IdentityResult<()> {
        if entry.seq != self.next_seq
            || previous_accepted.map(|previous| previous.seq) != entry.seq.checked_sub(1)
        {
            return Err(IdentityError::Protocol(
                "authority transition was not atomic".to_owned(),
            ));
        }
        let (method, key) = self
            .expected
            .get(&entry.seq)
            .ok_or_else(|| IdentityError::Protocol("no authority for sequence".to_owned()))?;
        for proof in &entry.proofs {
            if &proof.verification_method != method {
                return Err(IdentityError::Protocol(
                    "proof key is not authorized at this sequence".to_owned(),
                ));
            }
            arkret_signatures::Ed25519DetachedJwsVerifier::new()
                .verify_detached_jws(
                    &proof.jws,
                    &entry.proof_binding_bytes(proof)?,
                    &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                        bytes: key.to_bytes().to_vec(),
                    },
                )
                .map_err(|error| IdentityError::Protocol(error.to_string()))?;
        }
        self.next_seq += 1;
        Ok(())
    }
}

fn authority(entries: &[(u64, &DidUrl, &SigningKey)]) -> HistoricalAuthority {
    HistoricalAuthority {
        expected: entries
            .iter()
            .map(|(seq, method, key)| (*seq, ((*method).clone(), key.verifying_key())))
            .collect(),
        next_seq: 0,
    }
}

fn entry(
    subject: &Did,
    seq: u64,
    previous: Option<Hash>,
    method: &DidUrl,
    key: &SigningKey,
) -> DidKeyLogEntry {
    let mut entry = DidKeyLogEntry::build(
        subject.clone(),
        seq,
        if seq == 0 {
            DidKeyLogOperation::Inception
        } else {
            DidKeyLogOperation::Rotate
        },
        previous,
        serde_json::Map::from_iter([("method_state".to_owned(), json!(seq))]),
        Utc::now(),
    )
    .unwrap();
    attach_did_key_log_controller_proof(&mut entry, key, method).unwrap();
    entry
}

#[test]
fn historical_controller_transition_accepts_only_the_authorized_epoch() {
    let subject = did("subject");
    let controller_one = did("controller-one");
    let controller_two = did("controller-two");
    let key_one = SigningKey::from_bytes(&[41u8; 32]);
    let key_two = SigningKey::from_bytes(&[42u8; 32]);
    let rogue_key = SigningKey::from_bytes(&[43u8; 32]);
    let method_one = DidUrl::new(format!("{controller_one}#key-1")).unwrap();
    let method_two = DidUrl::new(format!("{controller_two}#key-2")).unwrap();
    let subject_method = DidUrl::new(format!("{subject}#subject-key")).unwrap();

    let inception = entry(&subject, 0, None, &method_one, &key_one);
    let rotation = entry(
        &subject,
        1,
        Some(inception.head_event_digest.clone()),
        &method_two,
        &key_two,
    );
    verify_did_key_log(
        &[inception, rotation],
        &mut authority(&[(0, &method_one, &key_one), (1, &method_two, &key_two)]),
    )
    .expect("historically authorized third-party controllers must verify");

    for (method, key) in [(&subject_method, &rogue_key), (&method_two, &key_two)] {
        let unauthorized = entry(&subject, 0, None, method, key);
        verify_did_key_log(
            &[unauthorized],
            &mut authority(&[(0, &method_one, &key_one)]),
        )
        .expect_err("subject or future-controller keys must fail closed");
    }
}

#[test]
fn registry_receipt_requires_current_assertion_controller_authority() {
    let registry = did("registry");
    let delegate = did("delegate");
    let host = did("host");
    let key = SigningKey::from_bytes(&[44u8; 32]);
    let delegate_method = DidUrl::new(format!("{delegate}#receipt-key")).unwrap();
    let receipt = DidRegistryReceipt::signed(
        ReceiptId::new("ak:receipt:01904100-0000-7000-8000-000000000044").unwrap(),
        did("subject"),
        3,
        Hash::new(format!("sha256:{}", "44".repeat(32))).unwrap(),
        registry.clone(),
        IdentityReceiptWitnessRole::Writer,
        &key,
        &delegate_method,
    )
    .unwrap();
    let delegated: DidDocument = serde_json::from_value(json!({
        "id": registry,
        "verificationMethod": [{
            "id": delegate_method,
            "type": "Multikey",
            "controller": registry,
            "publicKeyMultibase": multibase(&key)
        }],
        "assertionMethod": [delegate_method]
    }))
    .unwrap();
    receipt
        .verify_with_document(&delegated)
        .expect("current assertion delegation controlled by the registry is valid");

    let host_controlled: DidDocument = serde_json::from_value(json!({
        "id": registry,
        "verificationMethod": [{
            "id": delegate_method,
            "type": "Multikey",
            "controller": host,
            "publicKeyMultibase": multibase(&key)
        }],
        "assertionMethod": [delegate_method]
    }))
    .unwrap();
    receipt
        .verify_with_document(&host_controlled)
        .expect_err("a host-controlled replacement key must not impersonate the registry");

    let wrong_issuer: DidDocument = serde_json::from_value(json!({
        "id": delegate,
        "verificationMethod": [{
            "id": delegate_method,
            "type": "Multikey",
            "controller": delegate,
            "publicKeyMultibase": multibase(&key)
        }],
        "assertionMethod": [delegate_method]
    }))
    .unwrap();
    receipt
        .verify_with_document(&wrong_issuer)
        .expect_err("a valid signature from a different issuer must fail closed");
}
