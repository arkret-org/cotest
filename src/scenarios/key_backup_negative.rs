use anyhow::{Result, anyhow, bail};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{ContrixServer, TestServerGroup, expect_json, expect_response};

const BACKUP_ID: &str = "cx:backup:01975510-0000-7000-8000-0000000000d3";
const DEVICE_A: &str = "cx:device:01975510-0000-7000-8000-0000000000a1";
const DEVICE_B: &str = "cx:device:01975510-0000-7000-8000-0000000000b2";

pub async fn key_backup_put_get_negative_run() -> Result<()> {
    let group = TestServerGroup::single("d3-key-backup-negative").await?;
    let server = group.server(0);
    let alice = server
        .register_client("did:web:alice-d3.example", "@alice-d3", DEVICE_A)
        .await?;
    let bob = server
        .register_client("did:web:bob-d3.example", "@bob-d3", "dev_bob_d3")
        .await?;

    let mut missing_ciphertext = backup_body(&alice.actor, DEVICE_A, BACKUP_ID);
    missing_ciphertext
        .as_object_mut()
        .ok_or_else(|| anyhow!("backup body was not an object"))?
        .remove("ciphertext");
    expect_backup_error(
        alice
            .put(&format!("/api/v1/keys/backups/{BACKUP_ID}"))
            .json(&missing_ciphertext),
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await?;

    let body_id_mismatch = backup_body(
        &alice.actor,
        DEVICE_A,
        "cx:backup:01975510-0000-7000-8000-0000000000ff",
    );
    expect_backup_error(
        alice
            .put(&format!("/api/v1/keys/backups/{BACKUP_ID}"))
            .json(&body_id_mismatch),
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await?;

    let wrong_actor = backup_body(&bob.actor, DEVICE_A, BACKUP_ID);
    expect_backup_error(
        alice
            .put(&format!("/api/v1/keys/backups/{BACKUP_ID}"))
            .json(&wrong_actor),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let accepted = expect_json(
        alice
            .put(&format!("/api/v1/keys/backups/{BACKUP_ID}"))
            .json(&backup_body(&alice.actor, DEVICE_A, BACKUP_ID)),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(accepted["backup"]["backup_id"], BACKUP_ID);

    expect_backup_error(
        bob.get(&format!("/api/v1/keys/backups/{BACKUP_ID}")),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    if strict_device_digest_negatives_enabled() {
        reject_wrong_device_on_put(server, &alice.token, &alice.actor).await?;
        reject_digest_mismatch_on_put(server, &alice.token, &alice.actor).await?;
        reject_wrong_device_on_get(server, &alice.actor).await?;
    }

    Ok(())
}

async fn reject_wrong_device_on_put(
    server: &ContrixServer,
    token: &str,
    actor: &str,
) -> Result<()> {
    let id = "cx:backup:01975510-0000-7000-8000-0000000000d4";
    let body = backup_body(actor, DEVICE_B, id);
    expect_backup_error(
        server
            .http()
            .put(server.url(&format!("/api/v1/keys/backups/{id}")))
            .bearer_auth(token)
            .json(&body),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await
}

async fn reject_digest_mismatch_on_put(
    server: &ContrixServer,
    token: &str,
    actor: &str,
) -> Result<()> {
    let id = "cx:backup:01975510-0000-7000-8000-0000000000d5";
    let mut body = backup_body(actor, DEVICE_A, id);
    body["ciphertext"] = Value::String("tampered-ciphertext".to_owned());
    body["ciphertext_digest"] = Value::String(
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
    );
    expect_backup_error(
        server
            .http()
            .put(server.url(&format!("/api/v1/keys/backups/{id}")))
            .bearer_auth(token)
            .json(&body),
        StatusCode::BAD_REQUEST,
        "digest_mismatch",
    )
    .await
}

async fn reject_wrong_device_on_get(server: &ContrixServer, actor: &str) -> Result<()> {
    let device_b_token = crate::harness::dev_login(server, actor, DEVICE_B).await?;
    expect_backup_error(
        server
            .http()
            .get(server.url(&format!("/api/v1/keys/backups/{BACKUP_ID}")))
            .bearer_auth(&device_b_token),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await
}

fn backup_body(actor: &str, device_id: &str, backup_id: &str) -> Value {
    json!({
        "backup_id": backup_id,
        "actor_id": actor,
        "device_id": device_id,
        "series_id": backup_id.replacen("cx:backup:", "cx:backup_series:", 1),
        "series_seq": 0,
        "backup_class": "mls_history",
        "backup_version": "kb_1",
        "created_at": "2026-05-18T00:00:00Z",
        "encryption": {
            "recipient_method": "secret_storage_key",
            "recipient_key_ref": "mls_group_secrets_backup_key",
            "aead": {"name": "xchacha20_poly1305", "aead_profile": "cx.aead.xchacha20_poly1305.v1", "nonce": "cotest-d3-nonce"}
        },
        "contents": [
            {
                "item_type": "mls_group_state",
                "mls_group_id": "group_d3",
                "epoch": 0
            }
        ],
        "ciphertext": "cotest-d3-ciphertext",
        "ciphertext_digest": "sha256:2108421084217842908421084210842121084210842178429084210842108421"
    })
}

async fn expect_backup_error(
    builder: reqwest::RequestBuilder,
    status: StatusCode,
    errcode: &str,
) -> Result<()> {
    let response = expect_response(builder, status).await?;
    let body = response.json()?;
    let actual = body
        .pointer("/error/errcode")
        .or_else(|| body.pointer("/error/code"))
        .or_else(|| body.get("errcode"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if actual != errcode {
        bail!("expected errcode {errcode}, got {actual:?}. body: {body}");
    }
    Ok(())
}

fn strict_device_digest_negatives_enabled() -> bool {
    std::env::var("COTEST_STRICT_KEY_BACKUP_DEVICE_DIGEST")
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes"))
}
