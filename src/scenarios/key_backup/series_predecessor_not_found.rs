//! P4-C.3 — `series_predecessor_not_found` reason.
//!
//! A PUT envelope referencing a `supersedes` id that does not exist on
//! the server MUST be rejected with 409 + `series_predecessor_not_found`.

use anyhow::{Result, anyhow};
use arkret_identifiers::BackupSeriesId;
pub async fn series_predecessor_not_found_run() -> Result<()> {
    if arkret_wire::ReasonCode::SERIES_PREDECESSOR_NOT_FOUND != "series_predecessor_not_found" {
        return Err(anyhow!(
            "arkret_wire::ReasonCode::SERIES_PREDECESSOR_NOT_FOUND spelling drifted: \
             series_predecessor_not_found"
        ));
    }
    // UUIDv7 literal: lowercase hex, version nibble = 7, variant nibble ∈
    // {8,9,a,b}; see `arkret-rust-sdk crates/identifiers` is_lowercase_typed_uuid.
    let _series =
        BackupSeriesId::new("ak:backup_series:01999999-0000-7000-8000-00000000bbb1".to_owned())
            .map_err(|e| anyhow!("BackupSeriesId: {e}"))?;

    // TODO(P4-impl): live PUT carries supersedes=ak:backup:<random>
    // (no envelope by that id exists on server) → expect 409
    // series_predecessor_not_found.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn predecessor_check_pinned() {
        series_predecessor_not_found_run().await.unwrap();
    }
}
