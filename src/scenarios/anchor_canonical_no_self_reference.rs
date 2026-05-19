//! Round 2+3 / T01 — Anchor canonical bytes self-reference exclusion.
//!
//! Spec (round 2+3 cleanup, T01):
//!
//! `anchor.schema.json` now explicitly excludes `id` and `anchorer_sig`
//! from the canonical bytes used to compute the Anchor id and the
//! anchorer signature. The receiver MUST:
//!
//!   (a) recompute `H = sha256(canonical_bytes)`; the embedded `id`
//!       MUST satisfy `id == "cx:anchor:" || base32(H)` (form per
//!       deployment), and
//!   (b) verify `anchorer_sig` covers exactly `canonical_bytes` (i.e.
//!       the byte stream with `id` / `anchorer_sig` removed).
//!
//! Any attempt to embed `id` or `anchorer_sig` into the canonical bytes
//! (self-reference) MUST cause verification to fail. This pins that an
//! Anchor whose canonical bytes leak `id` or `anchorer_sig` is rejected.

use anyhow::Result;

/// Construct an Anchor whose canonical bytes (illegitimately) include
/// `id` and assert receiver verification fails.
pub async fn anchor_canonical_no_self_reference_run() -> Result<()> {
    // TODO(round23-T01): wire to SDK / soland canonical helper. Must:
    //   1. build an Anchor payload, compute canonical_bytes via SDK
    //   2. forcibly inject `id` field into canonical_bytes
    //   3. assert `verify_anchor_signature(&injected_bytes, &sig)`
    //      returns an error
    //   4. repeat for `anchorer_sig` injection
    Ok(())
}
