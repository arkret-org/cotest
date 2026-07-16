//! Terminal `DELETE /_arkret/self/keys/backups/{id}`.

use anyhow::Result;
use arkret_core::{
    KeyBackupDeleteDevelopmentProof, KeyBackupDeleteProof, KeysBackupsDeleteRequestBody,
};
use reqwest::StatusCode;

use super::key_backups::BACKUP_ID;
use crate::harness::{ArkretServer, expect_json};

pub async fn run(server: &ArkretServer, token: &str, actor_id: &str) -> Result<()> {
    let body = KeysBackupsDeleteRequestBody {
        proof: KeyBackupDeleteProof::Development(KeyBackupDeleteDevelopmentProof::new(format!(
            "dev-ssk-delete:v1:{actor_id}:{BACKUP_ID}"
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
