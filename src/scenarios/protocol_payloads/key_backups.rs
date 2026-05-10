//! Phase 3 — `/api/v1/keys/backups/*` PUT / list / describe / GET.
//!
//! Stores Alice's MLS-export backup, enumerates the collection, walks the
//! describe surfaces (collection + restore-state), and fetches the stored
//! backup back. Deletion is deferred to [`super::backup_delete`] which runs
//! after the full restore lifecycle so the backup material remains available
//! through the restore phases.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ContrixServer, expect_json};

pub async fn run(server: &ContrixServer, token: &str) -> Result<()> {
    put_backup(server, token).await?;
    list_backups(server, token).await?;
    describe_backup_surfaces(server, token).await?;
    get_backup(server, token).await?;
    Ok(())
}

async fn put_backup(server: &ContrixServer, token: &str) -> Result<()> {
    let backup_put = expect_json(
        server
            .http()
            .put(server.url("/api/v1/keys/backups/backup-alice-01"))
            .bearer_auth(token)
            .json(&json!({
                "schema": "cx.schema.key_backup.v1",
                "backup_id": "backup-alice-01",
                "class": "mls_export",
                "encryption": {
                    "alg": "xchacha20poly1305",
                    "kdf": "argon2id"
                },
                "items": [
                    {
                        "kind": "mls_group_state",
                        "ref": "group:default",
                        "todo": "replace scaffold payload with encrypted export blob"
                    }
                ]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(backup_put["ok"], true);
    assert_eq!(backup_put["state"], "stored_in_memory_scaffold");
    Ok(())
}

async fn list_backups(server: &ContrixServer, token: &str) -> Result<()> {
    let backup_list = expect_json(
        server
            .http()
            .get(server.url("/api/v1/keys/backups"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert!(backup_list["backups"].as_array().unwrap().len() >= 1);
    Ok(())
}

async fn describe_backup_surfaces(server: &ContrixServer, token: &str) -> Result<()> {
    let key_backups_describe = expect_json(
        server
            .http()
            .get(server.url("/api/v1/keys/backups/describe"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        key_backups_describe["contract"],
        "contrix.rest.key_backups_describe.v1"
    );
    assert_eq!(key_backups_describe["schema"], "cx.schema.key_backup.v1");
    assert_eq!(
        key_backups_describe["restore_state_describe_path"],
        "/api/v1/keys/backups/restore-state/describe"
    );

    let restore_state_describe = expect_json(
        server
            .http()
            .get(server.url("/api/v1/keys/backups/restore-state/describe"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_state_describe["contract"],
        "contrix.rest.key_backup_restore_state_store_describe.v1"
    );
    Ok(())
}

async fn get_backup(server: &ContrixServer, token: &str) -> Result<()> {
    let backup_get = expect_json(
        server
            .http()
            .get(server.url("/api/v1/keys/backups/backup-alice-01"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(backup_get["backup"]["schema"], "cx.schema.key_backup.v1");
    Ok(())
}
