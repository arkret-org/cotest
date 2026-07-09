//! Terminal `DELETE /_arkret/self/keys/backups/{id}`.

use anyhow::Result;
use arkret_core::{
    KeyBackupDeleteDevelopmentProof, KeyBackupDeleteProof, KeysBackupsDeleteRequestBody,
};
use reqwest::StatusCode;

use super::key_backups::BACKUP_ID;
use crate::harness::{CokretServer, expect_json};

pub async fn run(server: &CokretServer, token: &str) -> Result<()> {
    let body = KeysBackupsDeleteRequestBody {
        proof: KeyBackupDeleteProof::Development(KeyBackupDeleteDevelopmentProof::new(format!(
            "dev-ssk-delete:v1:did:web:alice.example:{BACKUP_ID}"
        ))),
        reason: Some("user_requested".to_owned()),
    };
    let backup_delete = expect_json(
        server
            .http()
            .delete(server.url(&format!("/_arkret/self/keys/backups/{BACKUP_ID}")))
            .bearer_auth(token)
            .json(&body),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(backup_delete["deleted"], true);
    Ok(())
}
