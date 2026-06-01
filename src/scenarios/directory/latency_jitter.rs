//! P2F.4 — directory response latency floor + jitter envelope.
//!
//! teabay MUST defend its `lookup` and `search` endpoints against
//! oracle / timing-channel enumeration by:
//!   - delaying every response to at least a normative floor (`LATENCY_FLOOR_MS`), and
//!   - adding uniform jitter from `[0, JITTER_MAX_MS]` on top.
//!
//! The combined observed latency `t` for any single query MUST therefore
//! satisfy `LATENCY_FLOOR_MS <= t <= LATENCY_FLOOR_MS + JITTER_MAX_MS`.
//!
//! This scenario doesn't time real network round-trips — it pins the
//! envelope helpers any teabay binding MUST implement and verifies that
//! the floor / ceiling stay in the spec range.

use anyhow::{Result, anyhow};

/// Normative floor for any teabay directory response (ms).
pub const LATENCY_FLOOR_MS: u64 = 25;
/// Normative maximum jitter added on top of the floor (ms).
pub const JITTER_MAX_MS: u64 = 50;

/// Combined valid latency range for any single directory response.
pub fn latency_envelope_ms() -> (u64, u64) {
    (LATENCY_FLOOR_MS, LATENCY_FLOOR_MS + JITTER_MAX_MS)
}

/// Returns Ok when `observed_ms` is in `[LATENCY_FLOOR_MS,
/// LATENCY_FLOOR_MS + JITTER_MAX_MS]`. Used by the live scenarios in P5
/// to assert real timings; here it's exercised through deterministic
/// inputs.
pub fn assert_latency_in_envelope(observed_ms: u64) -> Result<()> {
    let (lo, hi) = latency_envelope_ms();
    if observed_ms < lo {
        return Err(anyhow!(
            "directory response latency {observed_ms}ms < normative floor {lo}ms"
        ));
    }
    if observed_ms > hi {
        return Err(anyhow!(
            "directory response latency {observed_ms}ms > normative ceiling {hi}ms"
        ));
    }
    Ok(())
}

pub async fn latency_jitter_run() -> Result<()> {
    let (lo, hi) = latency_envelope_ms();
    if lo == 0 {
        return Err(anyhow!(
            "LATENCY_FLOOR_MS MUST be > 0; an unbounded floor leaks the existence \
             of a fast-path responder"
        ));
    }
    if hi <= lo {
        return Err(anyhow!(
            "latency envelope inverted: floor={lo}ms ceiling={hi}ms"
        ));
    }
    // Spot accept / reject vectors.
    for ms in [lo, lo + 1, hi - 1, hi] {
        assert_latency_in_envelope(ms)
            .map_err(|e| anyhow!("expected {ms}ms in envelope; got error: {e}"))?;
    }
    for ms in [0u64, lo.saturating_sub(1), hi + 1, u64::MAX] {
        match assert_latency_in_envelope(ms) {
            Ok(()) => {
                return Err(anyhow!(
                    "expected {ms}ms to be rejected by envelope; got accept"
                ));
            }
            Err(_) => { /* expected */ }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn latency_envelope_accepts_and_rejects() {
        latency_jitter_run().await.unwrap();
    }
}
