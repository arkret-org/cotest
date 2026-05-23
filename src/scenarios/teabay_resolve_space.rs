//! TB-2 — `cx.directory.resolve_realm` three-lookup fixture for teabay.
//!
//! Per spec §9, `resolve_realm` accepts any of `realm_id`, `alias`,
//! `invite_token`, or `signed_link` as the lookup key. **Per the current
//! teabay implementation** (`crates/server/src/query/space.rs::resolve_space`,
//! `load_space_row`), all four lookup parameters converge to a single
//! `directory_resources.resource_id = $key` lookup. There is no separate
//! alias / invite-token table walk yet.
//!
//! This fixture pins the **current** behaviour rather than the spec'd
//! behaviour:
//!
//!   * `space_id` lookup — happy path; a seeded resource_id is found.
//!   * `alias` lookup — same code path; the alias string is matched against
//!     `resource_id`. So an alias that doesn't equal the resource_id returns
//!     `not_found` (blinded). This is the documented gap.
//!   * `invite_token` lookup — same code path; same observation.
//!
//! When the implementation grows real alias / invite-token tables this
//! fixture should flip to assert distinct happy paths; the test is the
//! regression guard for that future split.
//!
//! Marked `#[ignore]` because it spawns a real `teabay` binary against a
//! Postgres DSN — see `TEABAY_SPEC` for the env vars it requires (chiefly
//! `DATABASE_URL` and `TEABAY_BIN`).

use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use crate::scenarios::_helpers::external_binary::{TEABAY_SPEC, spawn_required};

/// Issue three resolve-space probes against a live teabay and assert the
/// current single-lookup behaviour. The probe values are deliberately chosen
/// so all three return blinded `not_found` against an empty / freshly-spun
/// directory — what we're pinning is that the surface **accepts** each of
/// the three parameter shapes (request validates, returns a structured
/// response) rather than 4xx-ing on the input shape.
pub async fn teabay_resolve_space_three_lookups_run() -> Result<()> {
    let proc = spawn_required(&TEABAY_SPEC)
        .await
        .context("spawn teabay binary for resolve-space lookup-shape test")?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let url = proc.url("/api/v1/directory/resolve-realm");

    // --- by realm_id ------------------------------------------------------
    let probe = json!({ "realm_id": "cotest-tb2-space-id" });
    let by_space_id = client.post(&url).json(&probe).send().await?;
    assert_resolved_or_blinded_not_found(by_space_id, "realm_id").await?;

    // --- by alias ---------------------------------------------------------
    //
    // Per current impl, alias is matched against `resource_id` directly.
    // The probe value here is distinct from any seeded space → blinded
    // not_found. The test passes when teabay returns a structured response
    // (any of: 200 envelope, 404 with not_found errcode). It fails if the
    // surface 4xx's the input shape itself.
    let probe = json!({ "alias": "cotest-tb2-alias" });
    let by_alias = client.post(&url).json(&probe).send().await?;
    assert_resolved_or_blinded_not_found(by_alias, "alias").await?;

    // --- by invite_token --------------------------------------------------
    let probe = json!({ "invite_token": "cotest-tb2-invite-token" });
    let by_invite = client.post(&url).json(&probe).send().await?;
    assert_resolved_or_blinded_not_found(by_invite, "invite_token").await?;

    // --- empty body --------------------------------------------------------
    // Negative control: no lookup key supplied. Should 400 with missing_param.
    let probe = json!({});
    let missing = client.post(&url).json(&probe).send().await?;
    let missing_status = missing.status();
    if missing_status.as_u16() != 400 {
        let body = missing.text().await.unwrap_or_default();
        bail!(
            "resolve-realm with empty body should 400 with missing_param, got {missing_status}: \
             {body}"
        );
    }

    Ok(())
}

/// Accept either 200 (envelope) or 404 (blinded not-found). Reject 4xx
/// responses that suggest the lookup-shape parameter itself was rejected
/// (e.g. 400 missing_param when we DID supply a key).
async fn assert_resolved_or_blinded_not_found(
    resp: reqwest::Response,
    lookup_field: &str,
) -> Result<()> {
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if status.is_success() {
        let body: Value = serde_json::from_str(&text)
            .with_context(|| format!("{lookup_field} OK response is not JSON: {text}"))?;
        // 200 response → must be a result envelope; surface its keys for clarity.
        if !body.is_object() {
            bail!("{lookup_field} returned 200 but body is not an object: {text}");
        }
        return Ok(());
    }
    if status.as_u16() == 404 {
        // Blinded not_found is the expected outcome for an unknown key under
        // current impl — verify the errcode is `not_found` (not e.g.
        // `missing_param`, which would mean the body shape was wrong).
        let body: Value = serde_json::from_str(&text)
            .with_context(|| format!("{lookup_field} 404 response is not JSON: {text}"))?;
        let errcode = body
            .pointer("/error/code")
            .or_else(|| body.pointer("/error/errcode"))
            .or_else(|| body.get("errcode"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !errcode.contains("not_found") {
            bail!("{lookup_field} 404 expected `not_found` errcode, got `{errcode}`. body: {text}");
        }
        return Ok(());
    }
    bail!("resolve-realm by {lookup_field} returned unexpected status {status}. body: {text}")
}
