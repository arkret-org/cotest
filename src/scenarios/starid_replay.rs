//! ST-1 — Replay-rejection black-box test for starid.
//!
//! Spawns a real `starid` binary in development mode and confirms that
//! submitting the **same** inception payload twice — i.e. the same proof
//! material attached to the same DID-creation request — is rejected the second
//! time with a `cas_conflict` errcode (HTTP 409 Conflict).
//!
//! Why this protects against replay:
//!
//! A webvh DID create generates a DID whose SCID is deterministically derived
//! from the request body. Submitting the **identical** request a second time
//! reconstructs the same SCID, hence the same DID, hence collides with the
//! existing key-log head. starid's CAS layer (see
//! [`crate::store::validate_cas`] in the starid server) rejects the duplicate
//! with `StoreError::Conflict`, which surfaces over HTTP as 409 + errcode
//! `cas_conflict`. An attacker capturing the wire bytes of a legitimate
//! `POST /_starid/webvh/dids` request and re-playing them therefore cannot
//! re-create the DID — which is exactly the replay-rejection guarantee this
//! test pins.
//!
//! Mode: `STARID_DEVELOPMENT_MODE=true` is set by the shared spec, so we omit
//! the `proof` block entirely (dev mode accepts proof-less inceptions). In
//! production mode, the second submission would still be rejected by CAS
//! before proof verification — but exercising the dev path keeps this test
//! free of ed25519 keypair plumbing.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use crate::harness::NonProtocolTestBody;
use crate::scenarios::_helpers::external_binary::{STARID_SPEC, spawn_required};

/// Spawn `starid`, submit one valid DID create, then submit the **identical**
/// body a second time and assert the second request is rejected with HTTP 409
/// and errcode `cas_conflict`.
pub async fn starid_rejects_replayed_inception_run() -> Result<()> {
    let proc = spawn_required(&STARID_SPEC)
        .await
        .context("spawn starid binary for replay-rejection test")?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // Pin every input deterministically so the second submission is byte-for-
    // byte identical — that's what makes this a replay rather than a fresh
    // request. `version_time` is the only field that would otherwise drift.
    let body = NonProtocolTestBody::new(json!({
        "host": "starid.cotest.local",
        "did_public_key_multibase":   "z6MkpTHR8VNsBxYAAWHut2Geadd9jSrW1aD2RJUDg9wQfVAR",
        "update_public_key_multibase": "z6MkrJVnaZkeFzdQDPj9hf3wHd1qxqEsktRkPmCnaGc4MwS5",
        "did_key_id": "did-key-1",
        "update_key_id": "update-key-1",
        "version_time": "2026-01-01T00:00:00.000Z",
    }));

    // First submission: must succeed.
    let first = client
        .post(proc.url("/_starid/webvh/dids"))
        .json(&body)
        .send()
        .await?;
    let first_status = first.status();
    let first_text = first.text().await.unwrap_or_default();
    if !first_status.is_success() {
        bail!("first DID create unexpectedly failed: {first_status} {first_text}");
    }
    let first_body: Value = serde_json::from_str(&first_text)
        .with_context(|| format!("first response is not JSON: {first_text}"))?;
    let first_did = first_body
        .get("did")
        .and_then(Value::as_str)
        .context("first response missing `did`")?
        .to_owned();

    // Second submission: identical body, must be rejected with cas_conflict.
    let second = client
        .post(proc.url("/_starid/webvh/dids"))
        .json(&body)
        .send()
        .await?;
    let second_status = second.status();
    let second_text = second.text().await.unwrap_or_default();

    if second_status.is_success() {
        bail!(
            "REPLAY ACCEPTED — second identical DID create unexpectedly succeeded \
             (status {second_status}); replay protection appears broken. Original DID: \
             {first_did}, second response body: {second_text}"
        );
    }
    if second_status.as_u16() != 409 {
        bail!("expected HTTP 409 on replay, got {second_status}. body: {second_text}");
    }
    let second_body: Value = serde_json::from_str(&second_text)
        .with_context(|| format!("second response is not JSON: {second_text}"))?;
    let errcode = second_body
        .pointer("/error/errcode")
        .or_else(|| second_body.get("errcode"))
        .and_then(Value::as_str)
        .context("second response has no errcode")?;
    if errcode != "cas_conflict" {
        bail!("expected errcode `cas_conflict` on replay, got `{errcode}`. body: {second_text}");
    }

    Ok(())
}
