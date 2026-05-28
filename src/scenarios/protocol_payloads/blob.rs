//! Phase 8 — `/api/v1/blob/{upload,get}`.
//!
//! Confirms that a sha-mismatch upload is rejected with `409`, then runs the
//! happy-path upload + range GET. The returned `blob_ref` is consumed by the
//! range GET in the same phase, so no state escapes.

use anyhow::Result;
use reqwest::StatusCode;

use crate::harness::{ContrixServer, expect_json, expect_status, expect_text};

pub async fn run(server: &ContrixServer, token: &str) -> Result<()> {
    sha_mismatch_is_rejected(server, token).await?;
    upload_then_range_get(server, token).await?;
    Ok(())
}

async fn sha_mismatch_is_rejected(server: &ContrixServer, token: &str) -> Result<()> {
    expect_status(
        server
            .http()
            .post(server.url("/api/v1/blob/upload"))
            .bearer_auth(token)
            .header(
                "x-contrix-content-digest",
                "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            )
            .body("encrypted-bytes"),
        StatusCode::CONFLICT,
    )
    .await?;
    Ok(())
}

async fn upload_then_range_get(server: &ContrixServer, token: &str) -> Result<()> {
    let blob = expect_json(
        server
            .http()
            .post(server.url("/api/v1/blob/upload"))
            .bearer_auth(token)
            .header("content-type", "text/plain")
            .body("encrypted-bytes"),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(blob["size"], 15);
    assert!(
        blob["blob_ref"]
            .as_str()
            .unwrap()
            .starts_with("cx:blob:sha256:")
    );

    let range = expect_text(
        server
            .http()
            .get(server.url(&format!(
                "/api/v1/blob/get?blob_ref={}&purpose=message.attachment",
                blob["blob_ref"].as_str().unwrap()
            )))
            .bearer_auth(token)
            .header("range", "bytes=0-8"),
        StatusCode::PARTIAL_CONTENT,
    )
    .await?;
    assert_eq!(range, "encrypted");
    Ok(())
}
