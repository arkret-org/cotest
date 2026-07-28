//! Round 2+3 / T01 — Seal canonical bytes self-reference exclusion.
//!
//! Spec (round 2+3 cleanup, T01; Anchor→Seal rename per
//! `migration/renames.json`):
//!
//! `seal.schema.json` explicitly excludes `id` and `notary_signature`
//! from the canonical bytes used to compute the Seal id and the
//! notary signature. The receiver MUST:
//!
//!   (a) recompute `H = sha256(canonical_bytes)`; the embedded `id`
//!       MUST satisfy `id == "ak:seal:sha256:" || hex(H)` (content-
//!       addressed form), and
//!   (b) verify `notary_signature` covers exactly `canonical_bytes` (i.e.
//!       the byte stream with `id` / `notary_signature` removed).
//!
//! Any attempt to embed `id` or `notary_signature` into the canonical bytes
//! (self-reference) MUST cause verification to fail. This pins that a
//! Seal whose canonical bytes leak `id` or `notary_signature` is rejected.

use anyhow::{Result, anyhow};
use arkret_identifiers::{Did, Hash, Hlc, RealmId, SealId};
use arkret_wire::{
    NotarySig, PayloadSignature, Seal, SealKind, compute_seal_id, seal_canonical_bytes,
};
use chrono::TimeZone;

fn realm() -> Result<RealmId> {
    RealmId::new("ak:realm:0196419b-0000-7000-8000-00000000014a".to_owned())
        .map_err(|e| anyhow!("realm id: {e}"))
}

/// A `delta` entry is a bare digest: `move` is not an id kind in v1.
fn delta_digest(hex_byte: u8) -> Result<Hash> {
    let hex = format!("{hex_byte:02x}").repeat(32);
    Hash::new(format!("sha256:{hex}")).map_err(|e| anyhow!("delta digest: {e}"))
}

fn seal_id(hex_byte: u8) -> Result<SealId> {
    let hex = format!("{hex_byte:02x}").repeat(32);
    SealId::new(format!("ak:seal:sha256:{hex}")).map_err(|e| anyhow!("seal id: {e}"))
}

fn hash(hex_byte: u8) -> Result<Hash> {
    let hex = format!("{hex_byte:02x}").repeat(32);
    Hash::new(format!("sha256:{hex}")).map_err(|e| anyhow!("hash: {e}"))
}

fn signature() -> PayloadSignature {
    PayloadSignature {
        alg: "EdDSA".to_owned(),
        verification_method: "did:web:notary.example#k1".to_owned(),
        payload_digest: Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap(),
        created_at: chrono::Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
        jws: "AAAA.BBBB.CCCC".to_owned(),
    }
}

fn build_seal() -> Result<Seal> {
    let hlc = Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).map_err(|e| anyhow!("hlc: {e}"))?;
    let _notary =
        Did::new("did:web:notary.example".to_owned()).map_err(|e| anyhow!("notary did: {e}"))?;
    let mut s = Seal {
        id: seal_id(0x00)?,
        realm_id: realm()?,
        predecessor_refs: vec![seal_id(0xaa)?],
        delta: vec![delta_digest(0x11)?, delta_digest(0x22)?],
        control_event_set_root: hash(0x66)?,
        state_root: hash(0x77)?,
        completeness_root: hash(0x88)?,
        notary_seq: 1,
        data_view_root: None,
        data_event_set_root: None,
        availability_root: None,
        coverage_scope: None,
        covered_event_digests: Vec::new(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: NotarySig::Single(signature()),
        sealed_at: chrono::Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
        hlc,
        kind: SealKind::Normal,
    };
    s.id = s.derive_id().map_err(|e| anyhow!("derive id: {e}"))?;
    Ok(s)
}

/// T01 — assert canonical bytes used for Seal id / signature derivation
/// exclude both `id` and `notary_signature` (so injecting them is structurally
/// impossible — the canonical encoder strips them).
pub async fn seal_canonical_no_self_reference_run() -> Result<()> {
    let s = build_seal()?;
    let bytes = seal_canonical_bytes(&s).map_err(|e| anyhow!("canonical bytes: {e}"))?;
    let text = std::str::from_utf8(&bytes).map_err(|e| anyhow!("canonical bytes not utf8: {e}"))?;
    if text.contains("\"id\":") {
        return Err(anyhow!(
            "Seal canonical bytes include `\"id\":` — T01 violated (self-reference leak)"
        ));
    }
    if text.contains("\"notary_signature\"") {
        return Err(anyhow!(
            "Seal canonical bytes include `\"notary_signature\"` -- T01 violated (self-reference leak)"
        ));
    }
    if text.contains("\"jws\"") {
        return Err(anyhow!(
            "Seal canonical bytes leak signature internals (`\"jws\"`) — T01 violated"
        ));
    }
    // Recompute the id from canonical bytes and confirm it matches the
    // stored id (verification path (a)).
    let derived = compute_seal_id(&bytes).map_err(|e| anyhow!("compute id: {e}"))?;
    if derived.as_str() != s.id.as_str() {
        return Err(anyhow!(
            "Seal::derive_id != Seal.id; canonical-bytes/id binding broken"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn seal_canonical_bytes_exclude_self_reference() {
        seal_canonical_no_self_reference_run()
            .await
            .expect("Seal canonical bytes MUST NOT leak id / notary_signature (T01)");
    }
}
