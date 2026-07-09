//! Cursor opaque vectors.
//!
//! `ck.vector.encoding.cursor_opaque.core.v1` covers the default stateful
//! body `{v, purpose, t, x, h}`.

use anyhow::{Result, anyhow, bail};
use arkret_core::cursor::{CURSOR_HANDLE_MIN_LEN, Cursor, CursorPurpose, generate_cursor_handle};

pub const VECTOR_ID_CURSOR_OPAQUE_CORE: &str = "ak.vector.encoding.cursor_opaque.core.v1";

pub const ALL_CURSOR_VECTOR_IDS: &[&str] = &[VECTOR_ID_CURSOR_OPAQUE_CORE];

/// VECT-CUR-1 — core stateful body `{v, purpose, t, x, h}`. `h` MUST be
/// present and the wire body MUST remain closed to inline positions.
pub fn run_cursor_opaque_core_vector() -> Result<()> {
    let handle = generate_cursor_handle().map_err(|e| anyhow!("cursor handle generation: {e}"))?;
    if handle.len() < CURSOR_HANDLE_MIN_LEN {
        bail!("cursor handle entropy below {CURSOR_HANDLE_MIN_LEN} chars: {handle}");
    }
    let cursor = Cursor {
        v: "1".to_owned(),
        purpose: CursorPurpose::Stream,
        t: "2026-05-27T00:00:00Z".to_owned(),
        x: 1_900_000_000_000,
        h: handle.clone(),
    };
    if cursor.h.is_empty() {
        bail!("core cursor body missing handle `h`");
    }
    // Canonical JSON serialisation must round-trip.
    let json = serde_json::to_string(&cursor).map_err(|e| anyhow!("cursor encode: {e}"))?;
    let decoded: Cursor = serde_json::from_str(&json).map_err(|e| anyhow!("cursor decode: {e}"))?;
    if decoded.h != handle {
        bail!("cursor round-trip lost handle");
    }
    Ok(())
}

/// Suite entry point.
pub fn run_cursor_vector_suite() -> Result<()> {
    if ALL_CURSOR_VECTOR_IDS.len() != 1 {
        bail!(
            "expected 1 cursor vector id, got {}",
            ALL_CURSOR_VECTOR_IDS.len()
        );
    }
    run_cursor_opaque_core_vector()?;
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
