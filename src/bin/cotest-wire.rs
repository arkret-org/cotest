use std::io::{self, Read};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use arkret::auth::principal_control_realm_id;
use arkret_core::{Did, Hash, Proof, canonical, proof_kind};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
struct CanonicalInput {
    value: Value,
}

#[derive(Debug, Deserialize)]
struct EventProofInput {
    actor_did: String,
    verification_method: String,
    created_at: String,
    event: Value,
}

#[derive(Debug, Deserialize)]
struct PrincipalControlRealmInput {
    principal_id: String,
}

fn main() -> Result<()> {
    let command = std::env::args().nth(1).context("missing command")?;
    let input = read_stdin_json()?;

    let output = match command.as_str() {
        "canonical-json" => canonical_json(input)?,
        "sha256-canonical-json" => sha256_canonical_json(input)?,
        "event-proof" => event_proof(input, EventDigestMode::RawCanonicalJson)?,
        "event-envelope-proof" => event_proof(input, EventDigestMode::RawCanonicalJson)?,
        "principal-control-realm-id" => principal_control_realm(input)?,
        _ => bail!("unknown cotest-wire command {command:?}"),
    };

    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn read_stdin_json() -> Result<Value> {
    let mut stdin = String::new();
    io::stdin()
        .read_to_string(&mut stdin)
        .context("read stdin")?;
    serde_json::from_str(&stdin).context("parse stdin JSON")
}

fn canonical_json(input: Value) -> Result<Value> {
    let input: CanonicalInput = serde_json::from_value(input).context("parse canonical input")?;
    let bytes = canonical::canonical_json_bytes(&input.value).context("canonical JSON encode")?;
    let canonical = String::from_utf8(bytes).context("canonical JSON was not UTF-8")?;
    Ok(json!({ "canonical": canonical }))
}

fn sha256_canonical_json(input: Value) -> Result<Value> {
    let input: CanonicalInput = serde_json::from_value(input).context("parse digest input")?;
    let digest = canonical::canonical_sha256(&input.value).context("canonical JSON digest")?;
    Ok(json!({
        "digest": digest,
        "digest_hex": digest.strip_prefix("sha256:").unwrap_or(digest.as_str()),
    }))
}

fn principal_control_realm(input: Value) -> Result<Value> {
    let input: PrincipalControlRealmInput =
        serde_json::from_value(input).context("parse principal-control realm input")?;
    let principal = Did::new(input.principal_id).context("parse principal DID")?;
    Ok(json!({
        "realm_id": principal_control_realm_id(&principal),
    }))
}

#[derive(Clone, Copy)]
enum EventDigestMode {
    RawCanonicalJson,
}

fn event_proof(input: Value, digest_mode: EventDigestMode) -> Result<Value> {
    let input: EventProofInput =
        serde_json::from_value(input).context("parse event proof input")?;
    let actor = Did::new(input.actor_did.clone()).context("parse actor DID")?;
    let created_at = DateTime::parse_from_rfc3339(&input.created_at)
        .with_context(|| format!("parse proof created_at {:?}", input.created_at))?
        .with_timezone(&Utc);
    let event_digest =
        Hash::new(event_digest(&input.event, digest_mode)?).context("parse event digest")?;
    let signing_key = development_event_signing_key(&input.actor_did);

    let mut proof = Proof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: input.verification_method,
        event_digest,
        created_at,
        domain: None,
        audience: None,
        jws: String::new(),
    };
    let binding_bytes = proof
        .canonical_binding_bytes(&actor)
        .context("encode event proof binding")?;
    proof.jws = arkret_signatures::proof::sign_eddsa_detached_jws(&signing_key, &binding_bytes)
        .map_err(|err| anyhow::anyhow!("sign event proof: {err}"))?;

    serde_json::to_value(proof).context("serialize event proof")
}

fn event_digest(event: &Value, _mode: EventDigestMode) -> Result<String> {
    let mut event = event.clone();
    if let Value::Object(map) = &mut event {
        map.remove("proofs");
        map.remove("unsigned");
        map.remove("effective_scope");
        map.remove("actor_kind");
        map.remove("canonical_digest");
        map.remove("canonical_hash");
    }
    canonical::canonical_sha256(&event).context("hash event digest payload")
}

fn development_event_signing_key(service_did: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"soland:anchorer-ephemeral:");
    hasher.update(service_did.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_digest_uses_producer_envelope_canonical_bytes() {
        let event = json!({
            "event_id": "ak:event:019f3b1c-784d-7fc0-965f-0550baae7184",
            "kind": "ck.member.state",
            "realm_id": "ak:realm:019f3b1c-6fc8-7f20-9715-66c42a93ad02",
            "actor_id": "did:webvh:zQmV5MGgUvFGbi15ajBaMzdXR5KQzL3TVDxM7VFQCv5nCwH5C:01kwxhre7cexz894j3nmsvmqh5",
            "actor_seq": 1,
            "created_at": "2026-07-07T05:45:49Z",
            "hlc": "019f3b1c76c8-0000-ac7eadec",
            "prev_refs": [],
            "refs": [],
            "requirements": {
                "schema": ["ck.schema.event_payload.v1"],
                "features": [],
                "critical_extensions": []
            },
            "payload": {
                "realm_id": "ak:realm:019f3b1c-6fc8-7f20-9715-66c42a93ad02",
                "actor_id": "did:webvh:zQmV5MGgUvFGbi15ajBaMzdXR5KQzL3TVDxM7VFQCv5nCwH5C:01kwxhre7cexz894j3nmsvmqh5",
                "membership": "join",
                "reason": "invite_accept"
            },
            "unsigned": {"trace": "local"},
            "effective_scope": {
                "kind": "realm",
                "realm_id": "ak:realm:019f3b1c-6fc8-7f20-9715-66c42a93ad02"
            },
            "actor_kind": "native",
            "proofs": []
        });

        let digest = event_digest(&event, EventDigestMode::RawCanonicalJson).unwrap();
        let mut producer_event = event.clone();
        let map = producer_event.as_object_mut().unwrap();
        map.remove("proofs");
        map.remove("unsigned");
        map.remove("effective_scope");
        map.remove("actor_kind");

        assert_eq!(
            digest,
            canonical::canonical_sha256(&producer_event).unwrap()
        );
    }
}
