//! Round 2+3 / T01 — Anchor canonical bytes self-reference exclusion.
//!
//! Spec (round 2+3 cleanup, T01):
//!
//! `anchor.schema.json` now explicitly excludes `id` and `anchorer_signature`
//! from the canonical bytes used to compute the Anchor id and the
//! anchorer signature. The receiver MUST:
//!
//!   (a) recompute `H = sha256(canonical_bytes)`; the embedded `id`
//!       MUST satisfy `id == "ck:anchor:" || base32(H)` (form per
//!       deployment), and
//!   (b) verify `anchorer_signature` covers exactly `canonical_bytes` (i.e.
//!       the byte stream with `id` / `anchorer_signature` removed).
//!
//! Any attempt to embed `id` or `anchorer_signature` into the canonical bytes
//! (self-reference) MUST cause verification to fail. This pins that an
//! Anchor whose canonical bytes leak `id` or `anchorer_signature` is rejected.

use anyhow::{Result, anyhow};
use chrono::TimeZone;
use contrix_core::{
    Anchor, AnchorId, AnchorKind, AnchorerSig, Did, Hash, Hlc, MoveId, MoveSignature, SpaceId,
    anchor_canonical_bytes, compute_anchor_id,
};

fn space() -> Result<SpaceId> {
    SpaceId::new("ck:space:0196419b-0000-7000-8000-00000000014a".to_owned())
        .map_err(|e| anyhow!("space id: {e}"))
}

fn move_id(hex_byte: u8) -> Result<MoveId> {
    let hex = format!("{hex_byte:02x}").repeat(32);
    MoveId::new(format!("sha256:{hex}")).map_err(|e| anyhow!("move id: {e}"))
}

fn anchor_id(hex_byte: u8) -> Result<AnchorId> {
    let hex = format!("{hex_byte:02x}").repeat(32);
    AnchorId::new(format!("ck:anchor:sha256:{hex}")).map_err(|e| anyhow!("anchor id: {e}"))
}

fn hash(hex_byte: u8) -> Result<Hash> {
    let hex = format!("{hex_byte:02x}").repeat(32);
    Hash::new(format!("sha256:{hex}")).map_err(|e| anyhow!("hash: {e}"))
}

fn signature() -> MoveSignature {
    MoveSignature {
        alg: "EdDSA".to_owned(),
        verification_method: "did:web:anchorer.example#k1".to_owned(),
        payload_digest: Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap(),
        created_at: chrono::Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
        jws: "AAAA.BBBB.CCCC".to_owned(),
    }
}

fn build_anchor() -> Result<Anchor> {
    let hlc = Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).map_err(|e| anyhow!("hlc: {e}"))?;
    let _anchorer = Did::new("did:web:anchorer.example".to_owned())
        .map_err(|e| anyhow!("anchorer did: {e}"))?;
    let mut a = Anchor {
        id: anchor_id(0x00)?,
        realm_id: space()?,
        predecessor_refs: vec![anchor_id(0xaa)?],
        frontier: vec![move_id(0x11)?, move_id(0x22)?],
        state_root: hash(0x77)?,
        previous_state_root: None,
        previous_digest_algorithm: None,
        anchorer_signature: AnchorerSig::Single(signature()),
        anchored_at: chrono::Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
        hlc,
        kind: AnchorKind::Normal,
    };
    a.id = a.derive_id().map_err(|e| anyhow!("derive id: {e}"))?;
    Ok(a)
}

/// T01 — assert canonical bytes used for Anchor id / signature derivation
/// exclude both `id` and `anchorer_signature` (so injecting them is structurally
/// impossible — the canonical encoder strips them).
pub async fn anchor_canonical_no_self_reference_run() -> Result<()> {
    let a = build_anchor()?;
    let bytes = anchor_canonical_bytes(&a).map_err(|e| anyhow!("canonical bytes: {e}"))?;
    let s = std::str::from_utf8(&bytes).map_err(|e| anyhow!("canonical bytes not utf8: {e}"))?;
    if s.contains("\"id\":") {
        return Err(anyhow!(
            "Anchor canonical bytes include `\"id\":` — T01 violated (self-reference leak)"
        ));
    }
    if s.contains("\"anchorer_signature\"") {
        return Err(anyhow!(
            "Anchor canonical bytes include `\"anchorer_signature\"` -- T01 violated (self-reference leak)"
        ));
    }
    if s.contains("\"jws\"") {
        return Err(anyhow!(
            "Anchor canonical bytes leak signature internals (`\"jws\"`) — T01 violated"
        ));
    }
    // Recompute the id from canonical bytes and confirm it matches the
    // stored id (verification path (a)).
    let derived = compute_anchor_id(&bytes).map_err(|e| anyhow!("compute id: {e}"))?;
    if derived.as_str() != a.id.as_str() {
        return Err(anyhow!(
            "Anchor.derive_id != Anchor.id; canonical-bytes/id binding broken"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn anchor_canonical_bytes_exclude_self_reference() {
        anchor_canonical_no_self_reference_run()
            .await
            .expect("Anchor canonical bytes MUST NOT leak id / anchorer_signature (T01)");
    }
}
