//! P4-C.2 — `series_seq_not_monotonic` reason.
//!
//! A PUT envelope whose `series_seq` does not strictly exceed the
//! existing tip's `series_seq` MUST be rejected with 409 +
//! `series_seq_not_monotonic`.

use anyhow::{Result, anyhow};
fn is_monotonic_advance(tip: u64, candidate: u64) -> bool {
    candidate > tip
}

pub async fn series_seq_not_monotonic_run() -> Result<()> {
    if arkret_core::error::ReasonCode::SERIES_SEQ_NOT_MONOTONIC != "series_seq_not_monotonic" {
        return Err(anyhow!(
            "arkret_core::error::ReasonCode::SERIES_SEQ_NOT_MONOTONIC spelling drifted: \
             series_seq_not_monotonic"
        ));
    }
    if !is_monotonic_advance(2, 3) {
        return Err(anyhow!("monotonic advance 2 -> 3 should be allowed"));
    }
    if is_monotonic_advance(3, 3) {
        return Err(anyhow!("equal series_seq must not be accepted as advance"));
    }
    if is_monotonic_advance(3, 2) {
        return Err(anyhow!("regression series_seq must not be accepted"));
    }
    // TODO(P4-impl): live PUT with series_seq=1 after a tip of
    // series_seq=2 has landed → expect 409 series_seq_not_monotonic.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn monotonic_advance_only() {
        series_seq_not_monotonic_run().await.unwrap();
    }
}
