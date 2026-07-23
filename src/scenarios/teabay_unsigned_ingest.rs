//! TB-3 — Gate test: "unsigned ingest must be rejected".
//!
//! Posts a valid-shape `ak.find.directory.command.announce` body to teabay **without** the
//! RFC 9421 `Signature-Input` / `Signature` headers (and without any other
//! transport-level authentication) and asserts the request is rejected with a
//! 401 / 403 + an errcode that points at the missing transport signature.
//!
//! ## Status — TB-1 has landed (2026-05-18)
//!
//! teabay now mounts an Ed25519 HTTP Message Signature middleware on its
//! ingest sub-router. See
//! `teabay/crates/server/src/middleware/http_sig.rs` for the verifier and
//! `teabay/crates/server/src/routing.rs::directory_router` for the
//! `.hoop(http_sig_middleware)` wire. The 5-step verify chain in
//! `crates/server/src/ingest/verify.rs` therefore no longer relies on a
//! load-bearing comment to claim the transport is authenticated; the
//! middleware enforces it for real, with `TEABAY_REQUIRE_HTTP_SIG=true`
//! as the secure default.
//!
//! The in-process unit tests at `cargo test -p server --lib http_sig`
//! already verify the rejection logic in isolation (signed pass,
//! unsigned 401, wrong-key 401, body-mutated 401, malformed 400). This
//! scenario remains the **end-to-end** regression guard against the
//! `.hoop(...)` being silently dropped from `routing.rs` — it spawns the
//! real teabay binary and POSTs over real HTTP. Because that requires
//! `TEABAY_BIN` + `DATABASE_URL`, the wrapping `#[ignore]` stays;
//! opt-in via `cargo test --test teabay_unsigned_ingest -- --ignored`.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde_json::{Value, json};

use crate::scenarios::_helpers::external_binary::{TEABAY_SPEC, spawn_required};

/// Send an unsigned announce; expect rejection at the transport layer.
pub async fn teabay_rejects_unsigned_ingest_run() -> Result<()> {
    let proc = spawn_required(&TEABAY_SPEC)
        .await
        .context("spawn teabay binary for unsigned-ingest rejection test")?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let url = proc.url("/_arkret/find/directory/announce");

    // Construct a body that *would* be shape-valid if the transport were
    // signed. We aren't testing the verify chain here — we're testing that
    // the request never reaches it without a Signature/Signature-Input pair.
    let body = json!({
        "resource_kind": "space",
        "resource_id": "cotest-tb3-unsigned-resource",
        "principal_server_did": "did:web:soland.cotest.local",
        "discovery_state": {
            "discoverability": "public",
            "directory_services": ["did:web:teabay.cotest.local"],
            "proof": { "detached_jws": "" }
        },
        "source_refs": ["urn:cotest:tb3:source-ref:1"],
        "as_of": arkret_canonical::format_timestamp_canonical(Utc::now()),
    });

    // Notice: no Signature-Input / Signature / Content-Digest headers. This
    // is precisely the wire-shape of an attacker replaying / fabricating an
    // ingest call without controlling the resource's governance key.
    let resp = client.post(&url).json(&body).send().await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();

    // Gate assertion: an unsigned ingest MUST be rejected at the transport
    // layer. 401 (no credentials presented) is the most spec-aligned answer;
    // 403 (credentials present but not authorised) is also acceptable.
    let code = status.as_u16();
    if !(code == 401 || code == 403) {
        bail!(
            "UNSIGNED INGEST WAS NOT REJECTED at the transport layer — got HTTP {status}. \
             body: {text}\n\
             TB-1 mounted the HTTP signature middleware on the ingest sub-router \
             (`teabay/crates/server/src/routing.rs::directory_router`). Getting anything \
             other than 401/403 here means either the `.hoop(...)` got dropped, \
             `TEABAY_REQUIRE_HTTP_SIG` was forced to `false` for this run, or the \
             middleware short-circuited unsigned envelopes by mistake. Either way, \
             unsigned callers can push ingest records right now."
        );
    }

    // When the gate lands, the errcode should point at the missing signature
    // rather than at a generic auth failure — surface it for clarity.
    let body: Value = serde_json::from_str(&text)
        .with_context(|| format!("rejection response is not JSON: {text}"))?;
    let errcode = body
        .pointer("/error/code")
        .or_else(|| body.pointer("/error/errcode"))
        .or_else(|| body.get("errcode"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if errcode.is_empty() {
        bail!("unsigned ingest was rejected ({status}) but response has no errcode. body: {body}");
    }

    Ok(())
}
