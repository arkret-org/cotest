//! Phase 7 — terminal `DELETE /api/v1/keys/backups/{id}` after the restore
//! family has finished consuming the backup material.

use anyhow::Result;
use reqwest::StatusCode;

use crate::harness::{ContrixServer, expect_json};

pub async fn run(server: &ContrixServer, token: &str) -> Result<()> {
    let backup_delete = expect_json(
        server
            .http()
            .delete(server.url("/api/v1/keys/backups/backup-alice-01"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(backup_delete["ok"], true);
    Ok(())
}
