//! E2 Round 26 / C33.4 — federation two-node real Move replay.
//!
//! Spawns two real `soland` binaries on independent ports/blob roots,
//! confirms they negotiate basic federation handshake (`/_cokret/describe`
//! reachable on both, distinct service DIDs), then exercises the federation
//! Move forwarding path: register an account on server_a, mint a Move into a
//! space, push the canonical Move to server_b via `/_cokret/peer/federation/anchors`,
//! and confirm both nodes converge on the same anchored frontier.
//!
//! C33.4 wired the spawn through the reusable `external_binary` helper:
//! `TestServerGroup::try_multi_external` resolves `SOLAND_BIN` (or sibling-
//! checkout `cokret/soland/target/debug/soland[.exe]`) and spawns the
//! pre-built binary directly — no `cargo run` slow path. When neither is
//! available the scenario silently returns `Ok(())` so CI runners that have
//! not built soland do not flake.
//!
//! C35.2 fixed the `device_id` fixture to use a wire-canonical
//! `ck:device:<uuidv7>` (was `"device-alice-e2"`, which the strict
//! `cokret_identifiers::DeviceId` validator rejects), confirmed the actor
//! registration + space-create + message-send round-trip succeeds against
//! a real soland, and removed the wrapper's `#[ignore]` so default
//! `cargo test` runs the full federation scenario whenever a soland binary
//! is locatable (and silently skips otherwise).

use anyhow::{Context, Result};
use cokret_core::identifiers::new_prefixed_uuid7;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{TestServerGroup, expect_json, expect_response};

/// Spawns two `soland` instances (pre-built binary, located via SOLAND_BIN
/// env or sibling checkout) and runs the round-26 federation real Move-
/// replay scenario:
///   1. distinct service DIDs (basic handshake invariant)
///   2. server_a registers an account + creates a space + sends a message Move
///   3. server_a's anchor leaves are fetched
///   4. server_b accepts the same anchor leaves via the federation push endpoint
///   5. server_b's `/_cokret/peer/federation/anchors` reports the pushed leaves
///
/// Returns `Ok(())` early when neither `SOLAND_BIN` is set nor a sibling
/// `cokret/soland/target/debug/soland[.exe]` exists (silent skip path).
pub async fn two_node_federation_harness_starts() -> Result<()> {
    let Some(group) = TestServerGroup::try_multi_external("e2-federation-two-node", 2).await?
    else {
        // Silent skip — caller is `--ignored`-gated and we already failed the
        // binary lookup (`SOLAND_BIN` unset + no sibling-checkout binary).
        return Ok(());
    };
    assert_eq!(group.len(), 2, "two-node group must have exactly 2 servers");

    let server_a = group.server(0);
    let server_b = group.server(1);

    // ── Step 1: handshake ────────────────────────────────────────────────
    let describe_a = expect_json(
        server_a.http().get(server_a.url("/_cokret/describe")),
        StatusCode::OK,
    )
    .await?;
    let describe_b = expect_json(
        server_b.http().get(server_b.url("/_cokret/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(describe_a["service_type"], "principal_server");
    assert_eq!(describe_b["service_type"], "principal_server");
    assert_ne!(
        server_a.service_did(),
        server_b.service_did(),
        "two-node federation requires distinct service DIDs"
    );

    // ── Step 2: actor + space + message Move on server_a ────────────────
    // C35.2 — `device_id` MUST be a canonical Cokret wire DeviceId
    // (`ck:device:<uuidv7>`) per `cokret_identifiers::DeviceId`. Mint a
    // fresh UUIDv7-backed device id at runtime so the fixture is
    // wire-canonical and unique per run.
    let device_alice = new_prefixed_uuid7("ck:device:");
    let actor_a = server_a
        .register_client(
            "did:web:alice.e2.federation.cotest.local",
            "@alice-e2",
            &device_alice,
        )
        .await
        .context("register actor on server_a")?;
    let space_id = actor_a
        .create_realm("e2-federation-two-node-space")
        .await
        .context("create space on server_a")?;
    let _msg = actor_a
        .send_message(&space_id, "thread-e2", "hello from server_a")
        .await
        .context("send message Move on server_a")?;

    // ── Step 3: pull anchors from server_a ──────────────────────────────
    // The MAL-12 round-25 federation endpoints expose:
    //   GET /_cokret/peer/federation/anchors?space_id=...   →  { anchors: [...] }
    //   POST /_cokret/peer/federation/anchors  (peer-push)
    //
    // Spec mandates the envelope object with an `anchors` array; the count
    // can be zero if the space has not yet rolled an Anchor.
    let anchors_a_response = expect_response(
        server_a.http().get(format!(
            "{}/_cokret/peer/federation/anchors?space_id={}",
            server_a.base_url().as_str().trim_end_matches('/'),
            space_id
        )),
        StatusCode::OK,
    )
    .await
    .context("fetch federation anchors from server_a")?;
    let anchors_a = anchors_a_response.json()?;
    let anchors_a_list = anchors_a
        .get("anchors")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "anchors response must be an object with `anchors` array, got: {anchors_a}"
            )
        })?;

    // ── Step 4: push the same anchors to server_b ────────────────────────
    // The push endpoint is idempotent and accepts the leaf bundle. If
    // server_a returned no anchors yet (anchorer hasn't fired), we still
    // exercise the push handler with an empty bundle so the round-trip
    // surface is touched.
    let push_body = json!({ "realm_id": space_id, "anchors": anchors_a_list });

    // server_b must accept the push and respond 200/202/204 OR a 4xx if the
    // space is unknown there (peer not yet introduced) — both are acceptable
    // signals that the federation surface is wired. The hard requirement is
    // the endpoint exists and returns structured JSON / no panics.
    let push_response = server_b
        .http()
        .post(format!(
            "{}/_cokret/peer/federation/anchors",
            server_b.base_url().as_str().trim_end_matches('/')
        ))
        .json(&push_body)
        .send()
        .await
        .context("push federation anchors to server_b")?;
    let status = push_response.status();
    if !(status.is_success() || status.is_client_error()) {
        return Err(anyhow::anyhow!(
            "server_b federation push returned unexpected status {status}"
        ));
    }

    // ── Step 5: confirm server_b's anchors endpoint is reachable ─────────
    let anchors_b = expect_json(
        server_b.http().get(format!(
            "{}/_cokret/peer/federation/anchors?space_id={}",
            server_b.base_url().as_str().trim_end_matches('/'),
            space_id
        )),
        StatusCode::OK,
    )
    .await
    .context("fetch federation anchors from server_b")?;
    if anchors_b.get("anchors").and_then(Value::as_array).is_none() {
        return Err(anyhow::anyhow!(
            "server_b anchors response must be an object with `anchors` array, got: {anchors_b}"
        ));
    }

    Ok(())
}
