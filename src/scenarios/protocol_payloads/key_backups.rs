//! Phase 3 — `/_cokret/self/keys/backups/*` PUT / list / describe / GET.
//!
//! Stores Alice's MLS-history backup, enumerates the collection, walks the
//! key-backup descriptor, and fetches the stored backup back.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{CokretServer, expect_json};

pub const BACKUP_ID: &str = "ck:backup:01964137-0000-7000-8000-000000000000";

pub async fn run(server: &CokretServer, token: &str) -> Result<()> {
    put_backup(server, token).await?;
    list_backups(server, token).await?;
    describe_backup_surfaces(server, token).await?;
    get_backup(server, token).await?;
    Ok(())
}

async fn put_backup(server: &CokretServer, token: &str) -> Result<()> {
    let backup_put = expect_json(
        server
            .http()
            .put(server.url(&format!("/_cokret/self/keys/backups/{BACKUP_ID}")))
            .bearer_auth(token)
            .json(&json!({
                "backup_id": BACKUP_ID,
                "actor_id": "did:web:alice.example",
                "device_id": "ck:device:01964137-0000-7000-8000-000000000000",
                "series_id": "ck:backup_series:01964137-0000-7000-8000-000000000000",
                "series_seq": 0,
                "backup_class": "mls_history",
                "backup_version": "kb_1",
                "created_at": "2026-04-26T00:00:00Z",
                "encryption": {
                    "recipient_method": "secret_storage_key",
                    "recipient_key_ref": "mls_group_secrets_backup_key",
                    "aead": {"name": "xchacha20_poly1305", "aead_profile": "ck.aead.xchacha20_poly1305.v1", "nonce": "nonce"}
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

async fn list_backups(server: &CokretServer, token: &str) -> Result<()> {
    let backup_list = expect_json(
        server
            .http()
            .get(server.url("/_cokret/self/keys/backups"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert!(!backup_list["backups"].as_array().unwrap().is_empty());
    Ok(())
}

async fn describe_backup_surfaces(server: &CokretServer, token: &str) -> Result<()> {
    let key_backups_describe = expect_json(
        server
            .http()
            .get(server.url("/_cokret/self/keys/backups/describe"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        key_backups_describe["contract"],
        "cokret.rest.key_backups_describe.v1"
    );
    assert_eq!(key_backups_describe["schema"], "ck.schema.key_backup.v1");
    assert_eq!(key_backups_describe["operations"][0], "ck.self.keys.backups.put");
    Ok(())
}

async fn get_backup(server: &CokretServer, token: &str) -> Result<()> {
    let backup_get = expect_json(
        server
            .http()
            .get(server.url(&format!("/_cokret/self/keys/backups/{BACKUP_ID}")))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(backup_get["backup_id"], BACKUP_ID);
    assert_eq!(backup_get["backup_class"], "mls_history");
    Ok(())
}
