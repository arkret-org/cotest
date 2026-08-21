//! Cursor opaque vectors.
//!
//! `ak.vector.encoding.cursor_opaque.core.v1` covers the default stateful
//! body `{v, purpose, issued_at, expires_at, h}`.
//! `ak.vector.encoding.cursor_opaque.handle_reject.v1` covers the negative
//! side of `encoding.md` §8.3.1: low-entropy (<22 base64url chars) and
//! malformed (padding / out-of-alphabet / oversized) `h` handles MUST be
//! rejected by the canonical decode chain.

use anyhow::{Result, anyhow, bail};
use arkret_hlc::{CURSOR_HANDLE_MIN_LEN, Cursor, CursorPurpose, generate_cursor_handle};

pub const VECTOR_ID_CURSOR_OPAQUE_CORE: &str = "ak.vector.encoding.cursor_opaque.core.v1";
pub const VECTOR_ID_CURSOR_HANDLE_REJECT: &str =
    "ak.vector.encoding.cursor_opaque.handle_reject.v1";

pub const ALL_CURSOR_VECTOR_IDS: &[&str] =
    &[VECTOR_ID_CURSOR_OPAQUE_CORE, VECTOR_ID_CURSOR_HANDLE_REJECT];

/// VECT-CUR-1 — core stateful body `{v, purpose, issued_at, expires_at, h}`. `h` MUST be
/// present and the wire body MUST remain closed to inline positions.
pub fn run_cursor_opaque_core_vector() -> Result<()> {
    let handle = generate_cursor_handle().map_err(|e| anyhow!("cursor handle generation: {e}"))?;
    if handle.len() < CURSOR_HANDLE_MIN_LEN {
        bail!("cursor handle entropy below {CURSOR_HANDLE_MIN_LEN} chars: {handle}");
    }
    let cursor = Cursor {
        v: "1".to_owned(),
        purpose: CursorPurpose::Stream,
        issued_at: arkret_canonical::parse_timestamp_canonical("2026-05-27T00:00:00.000Z")?,
        expires_at: arkret_canonical::parse_timestamp_canonical("2026-06-03T00:00:00.000Z")?,
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

/// Encode a wire-form `ak:cursor:` token around `handle` without the SDK's
/// encode-side validation, so the receiver-side decode chain is what gets
/// exercised.
fn cursor_token_with_handle(handle: &str) -> Result<String> {
    let cursor = Cursor {
        v: "1".to_owned(),
        purpose: CursorPurpose::Stream,
        issued_at: arkret_canonical::parse_timestamp_canonical("2026-05-27T00:00:00.000Z")?,
        expires_at: arkret_canonical::parse_timestamp_canonical("2026-06-03T00:00:00.000Z")?,
        h: handle.to_owned(),
    };
    let bytes = arkret_canonical::canonical::canonical_json_bytes(&cursor)
        .map_err(|e| anyhow!("cursor body canonicalize: {e}"))?;
    Ok(format!(
        "ak:cursor:{}",
        arkret_canonical::base64url::base64url_encode(&bytes)
    ))
}

/// VECT-CUR-2 — negative handle vectors (`encoding.md` §8.3.1): the decode
/// chain MUST reject low-entropy and malformed `h` handles, and MUST keep
/// accepting the minimum conformant handle.
pub fn run_cursor_handle_reject_vector() -> Result<()> {
    // Receiver clock inside the vector's validity window.
    let now_ms =
        arkret_canonical::parse_timestamp_canonical("2026-05-28T00:00:00.000Z")?.timestamp_millis();

    // Positive control: exactly CURSOR_HANDLE_MIN_LEN base64url chars decode.
    let minimum = cursor_token_with_handle(&"a".repeat(CURSOR_HANDLE_MIN_LEN))?;
    if Cursor::decode_at(&minimum, now_ms).is_err() {
        bail!("minimum {CURSOR_HANDLE_MIN_LEN}-char handle must decode");
    }

    // Low-entropy: one char below the ≥128-bit floor.
    let short = cursor_token_with_handle(&"a".repeat(CURSOR_HANDLE_MIN_LEN - 1))?;
    if Cursor::decode_at(&short, now_ms).is_ok() {
        bail!("handle below {CURSOR_HANDLE_MIN_LEN} base64url chars must be rejected");
    }

    // Malformed: `=` padding is outside the unpadded base64url alphabet.
    let padded = cursor_token_with_handle("aaaaaaaaaaaaaaaaaaaaa=")?;
    if Cursor::decode_at(&padded, now_ms).is_ok() {
        bail!("padded handle must be rejected");
    }

    // Malformed: out-of-alphabet characters.
    let symbols = cursor_token_with_handle("!!!!!!!!!!!!!!!!!!!!!!")?;
    if Cursor::decode_at(&symbols, now_ms).is_ok() {
        bail!("non-base64url handle must be rejected");
    }

    // Malformed: above the 256-char schema ceiling.
    let oversized = cursor_token_with_handle(&"a".repeat(257))?;
    if Cursor::decode_at(&oversized, now_ms).is_ok() {
        bail!("handle above 256 chars must be rejected");
    }

    Ok(())
}

/// Suite entry point.
pub fn run_cursor_vector_suite() -> Result<()> {
    if ALL_CURSOR_VECTOR_IDS.len() != 2 {
        bail!(
            "expected 2 cursor vector ids, got {}",
            ALL_CURSOR_VECTOR_IDS.len()
        );
    }
    run_cursor_opaque_core_vector()?;
    run_cursor_handle_reject_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_vector_runs_clean() {
        run_cursor_vector_suite().unwrap();
    }
}
