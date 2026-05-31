//! Phase 3 — `/api/v1/keys/backups/*` PUT / list / describe / GET.
//!
//! Stores Alice's MLS-history backup, enumerates the collection, walks the
//! key-backup descriptor, and fetches the stored backup back.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ContrixServer, expect_json};

pub const BACKUP_ID: &str = "cx:backup:01964137-0000-7000-8000-000000000000";

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
            .put(server.url(&format!("/api/v1/keys/backups/{BACKUP_ID}")))
            .bearer_auth(token)
            .json(&json!({
                "backup_id": BACKUP_ID,
                "actor_id": "did:web:alice.example",
                "device_id": "cx:device:01964137-0000-7000-8000-000000000000",
                "series_id": "cx:backup_series:01964137-0000-7000-8000-000000000000",
                "series_seq": 0,
                "backup_class": "mls_history",
                "backup_version": "kb_1",
                "created_at": "2026-04-26T00:00:00Z",
                "encryption": {
                    "recipient_method": "device_snapshot_secret",
                    "recipient_key_ref": "cx:device:01964137-0000-7000-8000-000000000000",
                    "aead": {"name": "xchacha20_poly1305", "nonce": "nonce"}
                },
                "contents": [
                    {
                        "item_type": "mls_group_state",
                        "mls_group_id": "group_default",
                        "epoch": 0
                    }
                ],
                "ciphertext": "ciphertext",
                "ciphertext_digest": "sha256:2108421084217842908421084210842121084210842178429084210842108421"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(backup_put["state"], "accepted");
    assert_eq!(backup_put["backup"]["backup_id"], BACKUP_ID);
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
    assert!(!backup_list["backups"].as_array().unwrap().is_empty());
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
    assert_eq!(key_backups_describe["operations"][0], "cx.keys.backups.put");
    Ok(())
}

async fn get_backup(server: &ContrixServer, token: &str) -> Result<()> {
    let backup_get = expect_json(
        server
            .http()
            .get(server.url(&format!("/api/v1/keys/backups/{BACKUP_ID}")))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(backup_get["backup_id"], BACKUP_ID);
    assert_eq!(backup_get["backup_class"], "mls_history");
    Ok(())
}
