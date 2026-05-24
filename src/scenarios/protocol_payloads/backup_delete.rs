//! Terminal `DELETE /api/v1/keys/backups/{id}`.

use anyhow::Result;
use reqwest::StatusCode;

use crate::harness::{ContrixServer, expect_json};

use super::key_backups::BACKUP_ID;

pub async fn run(server: &ContrixServer, token: &str) -> Result<()> {
    let backup_delete = expect_json(
        server
            .http()
            .delete(server.url(&format!("/api/v1/keys/backups/{BACKUP_ID}")))
            .bearer_auth(token)
            .header(
                "x-contrix-key-backup-delete-proof",
                format!("dev-ssk-delete:v1:did:web:alice.example:{BACKUP_ID}"),
            ),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(backup_delete["deleted"], true);
    Ok(())
}
