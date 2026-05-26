//! P4-C.3 — `series_predecessor_not_found` reason.
//!
//! A PUT envelope referencing a `supersedes` id that does not exist on
//! the server MUST be rejected with 409 + `series_predecessor_not_found`.

use anyhow::{Result, anyhow};

use contrix_core::{BackupSeriesId, error::ERROR_CODE_SERIES_PREDECESSOR_NOT_FOUND};

pub async fn series_predecessor_not_found_run() -> Result<()> {
    if ERROR_CODE_SERIES_PREDECESSOR_NOT_FOUND != "series_predecessor_not_found" {
        return Err(anyhow!(
            "ERROR_CODE_SERIES_PREDECESSOR_NOT_FOUND spelling drifted: \
             {ERROR_CODE_SERIES_PREDECESSOR_NOT_FOUND}"
        ));
    }
    let _series = BackupSeriesId::new(
        "cx:backup_series:01999999-0000-7000-8000-0000000bs001".to_owned(),
    )
    .map_err(|e| anyhow!("BackupSeriesId: {e}"))?;

    // TODO(P4-impl): live PUT carries supersedes=cx:backup:<random>
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
