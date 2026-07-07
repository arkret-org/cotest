use std::io::{self, Read};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use cokret_core::{Did, Hash, Proof, canonical, proof_kind};
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

fn main() -> Result<()> {
    let command = std::env::args().nth(1).context("missing command")?;
    let input = read_stdin_json()?;

    let output = match command.as_str() {
        "canonical-json" => canonical_json(input)?,
        "sha256-canonical-json" => sha256_canonical_json(input)?,
        "event-proof" => event_proof(input)?,
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

fn event_proof(input: Value) -> Result<Value> {
    let input: EventProofInput =
        serde_json::from_value(input).context("parse event proof input")?;
    let actor = Did::new(input.actor_did.clone()).context("parse actor DID")?;
    let created_at = DateTime::parse_from_rfc3339(&input.created_at)
        .with_context(|| format!("parse proof created_at {:?}", input.created_at))?
        .with_timezone(&Utc);
    let event_digest = Hash::new(event_digest(&input.event)?).context("parse event digest")?;
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
    proof.jws = cokret_signatures::proof::sign_eddsa_detached_jws(&signing_key, &binding_bytes)
        .map_err(|err| anyhow::anyhow!("sign event proof: {err}"))?;

    serde_json::to_value(proof).context("serialize event proof")
}

fn event_digest(event: &Value) -> Result<String> {
    let mut event = event.clone();
    if let Value::Object(map) = &mut event {
        map.remove("proofs");
        map.remove("unsigned");
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
