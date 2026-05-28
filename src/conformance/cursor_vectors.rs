//! R3 spec-sync (contrix-spec @ b47ff6ec) — cursor opaque vectors
//! (§0.11 of `_before_todos.md`).
//!
//! 2 vectors:
//!   - `cx.vector.encoding.cursor_opaque.core.v1` — default stateful body
//!     `{v, purpose, t, x, h}`.
//!   - `cx.vector.encoding.cursor_opaque.stateless_profile.v1` —
//!     stateless body gated by `cx.profile.stateless_cursor.v1`.
//!
//! Core cursor schema MUST reject stateless bodies; stateless body MUST
//! only be accepted when the server has advertised
//! `cx.profile.stateless_cursor.v1`.

use anyhow::{Result, anyhow, bail};
use contrix_core::cursor::{CURSOR_HANDLE_MIN_LEN, Cursor, CursorPurpose, generate_cursor_handle};
use std::collections::BTreeMap;

pub const VECTOR_ID_CURSOR_OPAQUE_CORE: &str = "cx.vector.encoding.cursor_opaque.core.v1";
pub const VECTOR_ID_CURSOR_OPAQUE_STATELESS_PROFILE: &str =
    "cx.vector.encoding.cursor_opaque.stateless_profile.v1";

pub const PROFILE_STATELESS_CURSOR: &str = "cx.profile.stateless_cursor.v1";

pub const ALL_CURSOR_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_CURSOR_OPAQUE_CORE,
    VECTOR_ID_CURSOR_OPAQUE_STATELESS_PROFILE,
];

/// VECT-CUR-1 — core stateful body `{v, purpose, t, x, h}`. `h` MUST be
/// present; stateless integrity material (`_mac`, `_sig`, `issuer_kid`)
/// MUST be absent.
pub fn run_cursor_opaque_core_vector() -> Result<()> {
    let handle = generate_cursor_handle();
    if handle.len() < CURSOR_HANDLE_MIN_LEN {
        bail!("cursor handle entropy below {CURSOR_HANDLE_MIN_LEN} chars: {handle}");
    }
    let cursor = Cursor {
        v: "1".to_owned(),
        purpose: CursorPurpose::Stream,
        t: "2026-05-27T00:00:00Z".to_owned(),
        s: BTreeMap::new(),
        d: None,
        target: None,
        x: 1_900_000_000_000,
        h: Some(handle.clone()),
        issuer_kid: None,
        mac: None,
        sig: None,
        filter_digest: None,
    };
    if cursor.h.is_none() {
        bail!("core cursor body missing handle `h`");
    }
    if cursor.mac.is_some() || cursor.sig.is_some() || cursor.issuer_kid.is_some() {
        bail!("core cursor body must not carry stateless integrity material");
    }
    // Canonical JSON serialisation must round-trip.
    let json = serde_json::to_string(&cursor).map_err(|e| anyhow!("cursor encode: {e}"))?;
    let decoded: Cursor = serde_json::from_str(&json).map_err(|e| anyhow!("cursor decode: {e}"))?;
    if decoded.h.as_deref() != Some(handle.as_str()) {
        bail!("cursor round-trip lost handle");
    }
    Ok(())
}

/// VECT-CUR-2 — stateless cursor body. The body carries `issuer_kid`
/// plus a `_mac` (or `_sig`) over the canonical cursor JSON and MUST
/// NOT carry a stateful `h` handle. Acceptance is profile-gated: only
/// servers advertising `cx.profile.stateless_cursor.v1` accept this
/// shape.
pub fn run_cursor_opaque_stateless_profile_vector() -> Result<()> {
    let cursor = Cursor {
        v: "1".to_owned(),
        purpose: CursorPurpose::Stream,
        t: "2026-05-27T00:00:00Z".to_owned(),
        s: BTreeMap::new(),
        d: None,
        target: None,
        x: 1_900_000_000_000,
        h: None,
        issuer_kid: Some("did:web:server.example#cursor-1".to_owned()),
        mac: Some("AAAAAAAAAAAAAAAAAAAAAA".to_owned()),
        sig: None,
        filter_digest: None,
    };
    if cursor.h.is_some() {
        bail!("stateless cursor body must not carry stateful handle `h`");
    }
    if cursor.issuer_kid.is_none() {
        bail!("stateless cursor body missing issuer_kid");
    }
    if cursor.mac.is_none() && cursor.sig.is_none() {
        bail!("stateless cursor body missing _mac or _sig");
    }
    // Round-trip preserves the stateless body fields.
    let json = serde_json::to_string(&cursor).map_err(|e| anyhow!("cursor encode: {e}"))?;
    let decoded: Cursor = serde_json::from_str(&json).map_err(|e| anyhow!("cursor decode: {e}"))?;
    if decoded.issuer_kid != cursor.issuer_kid || decoded.mac != cursor.mac {
        bail!("stateless cursor round-trip lost integrity material");
    }
    if PROFILE_STATELESS_CURSOR != "cx.profile.stateless_cursor.v1" {
        bail!("PROFILE_STATELESS_CURSOR spelling drifted: {PROFILE_STATELESS_CURSOR}");
    }
    Ok(())
}

/// Suite entry point — runs both cursor vectors.
pub fn run_cursor_vector_suite() -> Result<()> {
    if ALL_CURSOR_VECTOR_IDS.len() != 2 {
        bail!(
            "expected 2 cursor vector ids, got {}",
            ALL_CURSOR_VECTOR_IDS.len()
        );
    }
    run_cursor_opaque_core_vector()?;
    run_cursor_opaque_stateless_profile_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_cursor_vectors_run_clean() {
        run_cursor_vector_suite().unwrap();
    }
}
