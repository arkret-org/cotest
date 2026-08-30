use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::Utc;
use reqwest::{StatusCode, Url};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::scenarios::_helpers::external_binary::{TEABAY_SPEC, try_spawn};

pub async fn teabay_signed_ingest_negative_run() -> Result<()> {
    let Some(proc) = try_spawn(&TEABAY_SPEC)
        .await
        .context("spawn teabay binary for signed ingest negative test")?
    else {
        return Ok(());
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let url = proc.url("/_arkret/find/directory/announce");
    let body = serde_json::to_vec(&json!({
        "discovery_event": {
            "event_id": "ak:event:ASWGTju1AH5ri82iFC0b-lZTclyFRuOI8TagaYiq5ZD2",
            "kind": "ak.actor.discovery",
            "realm_id": "ak:realm:ATH75ame6bMfYpXtcoLOVb7FKmgpWVniZZqVBz1dUdQa",
            "scope_ref": {
                "kind": "realm",
                "realm_id": "ak:realm:ATH75ame6bMfYpXtcoLOVb7FKmgpWVniZZqVBz1dUdQa"
            },
            "actor_id": "ak:did_core:key:z6MkrJVnaZkeFzdQyRo91my9QRBqmbW4cSUCQY4fVn4N1",
            "station_id": "ak:did_core:web:soland.cotest.local",
            "actor_seq": 1,
            "created_at": "2026-05-18T00:00:00.000Z",
            "prev_refs": [],
            "refs": [],
            "payload": {
                "resource_id": "ak:did_core:key:z6MkrJVnaZkeFzdQyRo91my9QRBqmbW4cSUCQY4fVn4N1",
                "value": {
                    "resource_kind": "actor",
                    "discoverability": "public",
                    "directory_ids": ["ak:did_core:web:teabay.cotest.local"]
                }
            },
            "proofs": []
        },
        "source_refs": ["ak:event:ASWGTju1AH5ri82iFC0b-lZTclyFRuOI8TagaYiq5ZD2"],
        "as_of": arkret_canonical::format_timestamp_canonical(Utc::now()),
        "station_id": "ak:did_core:web:soland.cotest.local"
    }))?;

    let now = Utc::now().timestamp();

    let missing_digest = fake_signed_headers(&url, now - 1, now + 300, "did:web:unknown#push");
    assert_ingest_rejected(
        client
            .post(&url)
            .header("signature-input", missing_digest.signature_input)
            .header("signature", missing_digest.signature)
            .header("content-type", "application/json")
            .body(body.clone())
            .send()
            .await?,
        StatusCode::UNAUTHORIZED,
        "signature_invalid",
        "missing content-digest",
    )
    .await?;

    let unknown_key = fake_signed_headers(&url, now - 1, now + 300, "did:web:unknown#push");
    assert_ingest_rejected(
        signed_request(&client, &url, &body, unknown_key, true)
            .send()
            .await?,
        StatusCode::UNAUTHORIZED,
        "signature_invalid",
        "unknown key",
    )
    .await?;

    // This is the actual transport-signature fail-closed control: the request
    // carries a fresh content-digest and a plausible service key id, but the
    // Ed25519 signature bytes are all zeroes. There is no Event Envelope
    // `dev-proof` in this path; accepting it would mean teabay bypassed HTTP
    // Message Signatures verification for signed directory ingest.
    let forged_signature =
        fake_signed_headers(&url, now - 1, now + 300, "did:web:teabay.cotest.local#push");
    assert_ingest_rejected(
        signed_request(&client, &url, &body, forged_signature, true)
            .send()
            .await?,
        StatusCode::UNAUTHORIZED,
        "signature_invalid",
        "forged signature bytes",
    )
    .await?;

    let expired = fake_signed_headers(&url, now - 60, now - 6, "did:web:unknown#push");
    assert_ingest_rejected(
        signed_request(&client, &url, &body, expired, true)
            .send()
            .await?,
        StatusCode::UNAUTHORIZED,
        "signature_invalid",
        "expired signature",
    )
    .await?;

    let future = fake_signed_headers(&url, now + 6, now + 300, "did:web:unknown#push");
    assert_ingest_rejected(
        signed_request(&client, &url, &body, future, true)
            .send()
            .await?,
        StatusCode::UNAUTHORIZED,
        "signature_invalid",
        "future signature",
    )
    .await?;

    Ok(())
}

struct FakeSignedHeaders {
    signature_input: String,
    signature: String,
    content_digest: String,
}

fn fake_signed_headers(url: &str, created: i64, expires: i64, key_id: &str) -> FakeSignedHeaders {
    let signature_input = format!(
        "sig1=(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\");created={created};expires={expires};keyid=\"{key_id}\";alg=\"ed25519\""
    );
    let signature = format!("sig1=:{}:", BASE64_STANDARD.encode([0u8; 64]));
    let parsed = Url::parse(url).expect("test URL is valid");
    let authority = parsed
        .host_str()
        .map(|host| match parsed.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        })
        .unwrap_or_default();
    let digest = Sha256::digest(
        format!(
            "POST\n{}\n{}\n{}",
            parsed.as_str(),
            authority,
            signature_input
        )
        .as_bytes(),
    );
    FakeSignedHeaders {
        signature_input,
        signature,
        content_digest: format!("sha-256=:{}:", BASE64_STANDARD.encode(digest)),
    }
}

fn signed_request(
    client: &reqwest::Client,
    url: &str,
    body: &[u8],
    signed: FakeSignedHeaders,
    valid_body_digest: bool,
) -> reqwest::RequestBuilder {
    let digest = if valid_body_digest {
        format!("sha-256=:{}:", BASE64_STANDARD.encode(Sha256::digest(body)))
    } else {
        signed.content_digest
    };
    client
        .post(url)
        .header("signature-input", signed.signature_input)
        .header("signature", signed.signature)
        .header("content-digest", digest)
        .header("content-type", "application/json")
        .body(body.to_vec())
}

async fn assert_ingest_rejected(
    response: reqwest::Response,
    expected_status: StatusCode,
    expected_errcode: &str,
    label: &str,
) -> Result<()> {
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if status != expected_status {
        bail!("{label}: expected HTTP {expected_status}, got {status}. body: {text}");
    }
    let problem: arkret_wire::Problem = serde_json::from_str(&text)
        .with_context(|| format!("{label}: rejection response is not JSON: {text}"))?;
    let errcode = problem.code();
    if errcode != expected_errcode {
        bail!("{label}: expected errcode {expected_errcode}, got {errcode:?}. body: {problem:?}");
    }
    Ok(())
}
