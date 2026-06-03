//! T1.3 — End-to-end gate: a soland running in production mode
//! (`SOLAND_DEVELOPMENT_MODE=false`) MUST refuse Event Envelopes that
//! carry the yougen dev-proof placeholder (`type=="dev-proof"`,
//! `jws=="a..b"`, or empty `jws`).
//!
//! ## Why this scenario exists
//!
//! yougen historically attached a placeholder proof
//! (`EventEnvelope::attach_placeholder_proof`) from `OperationBuilder::build`
//! so the dev-mode soland would accept the envelope. If a user pointed a
//! dev-feature yougen build at a *production* soland, that placeholder
//! would leak onto the wire. T1.3 closes the hole on both sides:
//!
//! - **yougen** (`yougen/src/operation.rs`) — feature-gates the placeholder attach on `dev_proof`;
//!   production builds default to `ProofMode::Production`, and `api.rs::submit_event_envelope` runs
//!   a pre-submit guard that fails closed when no real signer is wired.
//! - **soland** (`soland/src/routing/events/event_log.rs`) — even when a client claims
//!   `type="dev-proof"` or carries the `"a..b"` placeholder JWS, production mode rejects the
//!   request with `dev_proof_in_production` (`401 Unauthorized`).
//!
//! ## What this scenario asserts
//!
//! The E2E harness spawns the soland binary with
//! `SOLAND_DEVELOPMENT_MODE=false` and submits an Event Envelope whose
//! proof carries the dev-proof shape. The request MUST be rejected with
//! HTTP 401 or 403.
//!
//! Two paths can produce the rejection, and both are acceptable signals
//! that the production stance is healthy:
//!
//! 1. The proof check fires (`dev_proof_in_production`) — preferred, since it directly proves the
//!    T1.3 soland guard is wired.
//! 2. The auth wall fires first (`unauthenticated`) — also acceptable. Production-mode soland does
//!    not expose `POST /api/v1/auth/dev-login`, so without a real OAuth bearer the request never
//!    makes it to the proof check. That itself is the production safety posture working as
//!    intended.
//!
//! Either way, a 2xx here would mean a production soland accepted a
//! dev-proof event — a hard security regression.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::scenarios::_helpers::external_binary::{
    SOLAND_SPEC, skip_reason, try_spawn_with_extra_env,
};

/// Soland production target MUST refuse the yougen dev-proof placeholder.
pub async fn production_rejects_placeholder_proof_e2e_run() -> Result<()> {
    // Spawn soland with `SOLAND_DEVELOPMENT_MODE=false`. The dynamic
    // env entry takes precedence over `SOLAND_SPEC.extra_env` (which
    // hardcodes `=1` for the rest of the suite), so the same binary
    // boots in production posture for this scenario only.
    let Some(proc) = try_spawn_with_extra_env(
        &SOLAND_SPEC,
        &[
            ("SOLAND_DEVELOPMENT_MODE", "false"),
            ("SOLAND_METRICS_BIND", "127.0.0.1:0"),
        ],
    )
    .await
    .context("spawn soland binary for production-mode placeholder-proof rejection test")?
    else {
        let reason = skip_reason(&SOLAND_SPEC)
            .map(|reason| reason.describe(SOLAND_SPEC.service))
            .unwrap_or_else(|| "soland binary became unavailable after preflight".to_owned());
        bail!(
            "production placeholder-proof rejection was explicitly selected \
             but soland could not be spawned: {reason}. Set SOLAND_BIN to the \
             built soland binary in CI/local runs, or build the sibling soland \
             checkout before running this ignored test."
        );
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let url = proc.url("/api/v1/events");

    // Build an envelope that *looks* like a yougen `OperationBuilder::build()`
    // output before T1.3 — a `cx.message.create` payload with the
    // detached-JWS placeholder proof (`jws == "a..b"`). Production
    // soland's `validate_event_proofs` MUST reject this with
    // `dev_proof_in_production`. The `Bearer` header is intentionally
    // bogus; if the auth wall fires first, we accept `unauthenticated`
    // as a defence-in-depth signal that the production server never
    // exposes the proof path to unauthenticated clients.
    let actor = "did:web:alice.cotest.local";
    let realm_id = "ck:realm:0196419b-0000-7000-8000-cot13t13t13t";
    let event_id = "ck:event:0196419b-0000-7000-8000-pp1pp1pp1pp1";
    let envelope = json!({
        "event_id": event_id,
        "kind": "cx.message.create",
        "actor_id": actor,
        "actor_seq": 1,
        "realm_id": realm_id,
        "created_at": "2026-05-19T00:00:00.000Z",
        "hlc": "1747613100000-0-cotest",
        "prev_refs": [],
        "refs": [],
        "payload": {"body": "hi"},
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": format!("{actor}#yougen"),
            "event_digest":
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "created_at": "2026-05-19T00:00:00.000Z",
            // The yougen pre-T1.3 placeholder. T1.3 soland MUST reject
            // this on a production server with `dev_proof_in_production`.
            "jws": "a..b",
        }]
    });

    let resp = client
        .post(&url)
        .bearer_auth("cotest-bogus-token-not-a-real-session")
        .json(&envelope)
        .send()
        .await
        .context("POST /api/v1/events to production soland")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();

    // Gate: production soland MUST refuse the placeholder. 401 (no
    // valid session and/or dev-proof rejection) is the primary signal;
    // 403 is acceptable as a secondary forbidden path.
    let code = status.as_u16();
    if !(code == 401 || code == 403) {
        bail!(
            "PRODUCTION SOLAND ACCEPTED PLACEHOLDER PROOF — got HTTP {status}. \
             body: {text}\n\
             T1.3 wired `dev_proof_in_production` into \
             `soland/src/routing/events/event_log.rs::validate_event_proofs` \
             (search for `dev_proof_in_production`). Getting anything other \
             than 401/403 means either the guard was disabled, \
             SOLAND_DEVELOPMENT_MODE leaked back to `true`, or the soland \
             binary the cotest harness located does not contain the T1.3 fix."
        );
    }

    let body: Value = serde_json::from_str(&text)
        .with_context(|| format!("rejection response is not JSON: {text}"))?;
    let errcode = body
        .pointer("/error/errcode")
        .or_else(|| body.pointer("/error/code"))
        .or_else(|| body.get("errcode"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if errcode.is_empty() {
        bail!(
            "production soland rejected placeholder proof ({status}) but \
             response carries no errcode. body: {body}"
        );
    }
    // LIMITATION (see _code_review/cotest/02_security.md #3): this request
    // uses a deliberately-bogus bearer, so production soland's auth wall almost
    // always fires *before* the proof-guard, returning `unauthenticated`. That
    // path only proves the auth wall exists — it does NOT independently
    // exercise the `dev_proof_in_production` proof-guard. Only the
    // `dev_proof_in_production` errcode confirms the proof-guard is wired.
    // Acquiring a real production session to force the guard is not possible
    // here (production disables dev-login — verified below), so the independent
    // proof-guard regression test lives in soland's own repo
    // (`validate_event_proofs` unit tests). We accept both codes but surface
    // which one fired so a CI reader can tell whether the guard was actually
    // hit this run.
    if errcode != "dev_proof_in_production" && errcode != "unauthenticated" {
        bail!(
            "production soland rejected placeholder proof but with an \
             unexpected errcode `{errcode}` (expected `dev_proof_in_production` \
             or `unauthenticated`). status={status} body={body}"
        );
    }
    if errcode == "unauthenticated" {
        eprintln!(
            "[production_rejects_placeholder_proof] NOTE: auth wall fired first \
             (`unauthenticated`); the `dev_proof_in_production` proof-guard was \
             NOT independently exercised this run. See soland in-repo \
             `validate_event_proofs` tests for the dedicated guard regression."
        );
    }

    // Belt-and-braces positive control: production soland MUST NOT
    // expose `POST /api/v1/auth/dev-login` (a 404 here doubles as a
    // sanity check that we really did boot in production mode).
    let dev_login_url = proc.url("/api/v1/auth/dev-login");
    let dev_login_resp = client
        .post(&dev_login_url)
        .json(&json!({"actor": actor, "device_id": "cotest-dev"}))
        .send()
        .await
        .context("POST /api/v1/auth/dev-login probe on production soland")?;
    let dev_login_status = dev_login_resp.status();
    // dev-login in production returns `AppError::not_found` → 404.
    // Anything other than 4xx here means we are not in production mode.
    if !(dev_login_status == StatusCode::NOT_FOUND
        || dev_login_status == StatusCode::UNAUTHORIZED
        || dev_login_status == StatusCode::FORBIDDEN)
    {
        let dev_login_body = dev_login_resp.text().await.unwrap_or_default();
        bail!(
            "production soland still exposes dev-login (HTTP {dev_login_status}): \
             {dev_login_body}\n\
             SOLAND_DEVELOPMENT_MODE leaked back to `true` — the proof-check \
             gate above may be a false negative."
        );
    }

    Ok(())
}
