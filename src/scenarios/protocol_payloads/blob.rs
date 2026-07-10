//! Phase 8 — `/_arkret/self/blob/{upload,get}`.
//!
//! Confirms that a sha-mismatch upload is rejected with `409`, then runs the
//! happy-path upload + range GET. The returned `blob_ref` is consumed by the
//! range GET in the same phase, so no state escapes.

use anyhow::Result;
use reqwest::StatusCode;

use crate::harness::{ArkretServer, expect_json, expect_status, expect_text};

pub async fn run(server: &ArkretServer, token: &str) -> Result<()> {
    sha_mismatch_is_rejected(server, token).await?;
    upload_then_range_get(server, token).await?;
    Ok(())
}

async fn sha_mismatch_is_rejected(server: &ArkretServer, token: &str) -> Result<()> {
    expect_status(
        server
            .http()
            .post(server.url("/_arkret/self/blob/upload"))
            .bearer_auth(token)
            .header(
                "x-arkret-content-digest",
                "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            )
            .multipart(crate::scenarios::delivery_media::blob_upload_form(
                b"encrypted-bytes",
                "text/plain",
            )?),
        StatusCode::CONFLICT,
    )
    .await?;
    Ok(())
}

async fn upload_then_range_get(server: &ArkretServer, token: &str) -> Result<()> {
    let blob = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/blob/upload"))
            .bearer_auth(token)
            .multipart(crate::scenarios::delivery_media::blob_upload_form(
                b"encrypted-bytes",
                "text/plain",
            )?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(blob["size_bytes"], 15);
    assert!(
        blob["blob_ref"]
            .as_str()
            .unwrap()
            .starts_with("ak:blob:sha256:")
    );

    let range = expect_text(
        server
            .http()
            .get(server.url(&format!(
                "/_arkret/self/blob/get?blob_ref={}&purpose=message.attachment",
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
