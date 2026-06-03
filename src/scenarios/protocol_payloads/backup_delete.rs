//! Terminal `DELETE /_cokret/self/keys/backups/{id}`.

use anyhow::Result;
use reqwest::StatusCode;

use super::key_backups::BACKUP_ID;
use crate::harness::{CokretServer, expect_json};

pub async fn run(server: &CokretServer, token: &str) -> Result<()> {
    let backup_delete = expect_json(
        server
            .http()
            .delete(server.url(&format!("/_cokret/self/keys/backups/{BACKUP_ID}")))
            .bearer_auth(token)
            .header(
                "x-cokret-key-backup-delete-proof",
                format!("dev-ssk-delete:v1:did:web:alice.example:{BACKUP_ID}"),
            ),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(backup_delete["deleted"], true);
    Ok(())
}
