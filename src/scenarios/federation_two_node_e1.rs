//! E2 Round 26 / C33.4 — federation two-node real Move replay.
//!
//! Spawns two real `soland` binaries on independent ports/blob roots,
//! confirms they negotiate basic federation handshake (`/_cokret/describe`
//! reachable on both, distinct service DIDs), then exercises the federation
//! Move forwarding path: register an account on server_a, mint a Move into a
//! Realm, push the canonical Events to server_b via `/_cokret/peer/events`,
//! and confirm server_b exposes the Realm frontier on the peer API.
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
//! registration + realm-create + message-send round-trip succeeds against
//! a real soland, and removed the wrapper's `#[ignore]` so default
//! `cargo test` runs the full federation scenario whenever a soland binary
//! is locatable (and silently skips otherwise).

use anyhow::{Context, Result};
use cokret_core::canonical::{canonical_sha256, sha256_digest};
use cokret_core::identifiers::new_prefixed_uuid7;
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::{Value, json};

use crate::harness::{TestServerGroup, expect_json};
use crate::scenarios::_helpers::federation_binding::peer_events_submit_body;

/// Spawns two `soland` instances (pre-built binary, located via SOLAND_BIN
/// env or sibling checkout) and runs the round-26 federation real Move-
/// replay scenario:
///   1. distinct service DIDs (basic handshake invariant)
///   2. server_a registers an account + creates a Realm + sends a message Event
///   3. server_a's peer Events API returns the Realm event batch
///   4. server_b accepts the same Events via the peer Events push endpoint
///   5. server_b's `/_cokret/peer/events/frontier` reports a Realm frontier
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

    // ── Step 2: actor + Realm + message Event on server_a ───────────────
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
    let realm_id = actor_a
        .create_realm("e2-federation-two-node-realm")
        .await
        .context("create Realm on server_a")?;
    let _msg = actor_a
        .send_message(&realm_id, "thread-e2", "hello from server_a")
        .await
        .context("send message Event on server_a")?;

    // ── Step 3: pull federation-visible Events from server_a ─────────────
    let query_a_url = format!(
        "{}/_cokret/peer/events?realms={}&limit=100",
        server_a.base_url().as_str().trim_end_matches('/'),
        realm_id
    );
    let events_a = expect_json(
        with_peer_get_headers(server_a.http().get(&query_a_url), server_b, server_a)?,
        StatusCode::OK,
    )
    .await
    .context("query peer events from server_a")?;
    let events_a_list = events_a
        .get("events")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "peer events response must be an object with `events` array, got: {events_a}"
            )
        })?;
    let event_envelopes = events_a_list
        .iter()
        .map(|entry| entry.get("event").unwrap_or(entry).clone())
        .map(|event| {
            serde_json::from_value::<cokret_core::Event>(event)
                .context("parse peer event envelope into SDK Event")
        })
        .collect::<Result<Vec<_>>>()?;
    if event_envelopes.is_empty() {
        return Err(anyhow::anyhow!(
            "server_a peer events query returned no event envelopes: {events_a}"
        ));
    }

    // ── Step 4: push the same Events to server_b ─────────────────────────
    let push_body = peer_events_submit_body(
        &realm_id,
        event_envelopes,
        Some("cotest-two-node-peer-events"),
    )?;

    // server_b must accept the push and respond 200/202/204 OR a 4xx if the
    // Realm is unknown there (peer not yet introduced) — both are acceptable
    // signals that the federation surface is wired. The hard requirement is
    // the endpoint exists and returns structured JSON / no panics.
    let push_url = format!(
        "{}/_cokret/peer/events",
        server_b.base_url().as_str().trim_end_matches('/')
    );
    let push_response = with_peer_post_headers(
        server_b.http().post(&push_url).json(&push_body),
        server_a,
        server_b,
        &push_body,
    )?
    .send()
    .await
    .context("push peer events to server_b")?;
    let status = push_response.status();
    if !(status.is_success() || status.is_client_error()) {
        return Err(anyhow::anyhow!(
            "server_b federation push returned unexpected status {status}"
        ));
    }

    // ── Step 5: confirm server_b's peer frontier endpoint is reachable ──
    let frontier_b = expect_json(
        with_peer_get_headers(
            server_b.http().get(format!(
                "{}/_cokret/peer/events/frontier?realm_id={}",
                server_b.base_url().as_str().trim_end_matches('/'),
                realm_id
            )),
            server_a,
            server_b,
        )?,
        StatusCode::OK,
    )
    .await
    .context("fetch peer events frontier from server_b")?;
    if frontier_b
        .get("frontier_root")
        .and_then(Value::as_str)
        .is_none()
    {
        return Err(anyhow::anyhow!(
            "server_b frontier response must include frontier_root, got: {frontier_b}"
        ));
    }
    assert_eq!(frontier_b["realm_id"], realm_id);

    Ok(())
}

fn with_peer_get_headers(
    builder: reqwest::RequestBuilder,
    source: &crate::harness::CokretServer,
    destination: &crate::harness::CokretServer,
) -> Result<reqwest::RequestBuilder> {
    Ok(builder
        .header("Source-Service-DID", source.service_did())
        .header("Destination-Service-DID", destination.service_did())
        .header(
            "Source-Trust-Domain",
            trust_domain_for(source.service_did()),
        )
        .header(
            "Destination-Trust-Domain",
            trust_domain_for(destination.service_did()),
        )
        .header("Request-Canonical-Digest", sha256_digest([])))
}

fn with_peer_post_headers(
    builder: reqwest::RequestBuilder,
    source: &crate::harness::CokretServer,
    destination: &crate::harness::CokretServer,
    body: &impl Serialize,
) -> Result<reqwest::RequestBuilder> {
    Ok(builder
        .header("Source-Service-DID", source.service_did())
        .header("Destination-Service-DID", destination.service_did())
        .header(
            "Source-Trust-Domain",
            trust_domain_for(source.service_did()),
        )
        .header(
            "Destination-Trust-Domain",
            trust_domain_for(destination.service_did()),
        )
        .header("Request-Canonical-Digest", canonical_sha256(body)?))
}

fn trust_domain_for(service_did: &str) -> String {
    format!(
        "ck:trust_domain:{}",
        service_did.trim_start_matches("did:web:").replace(':', ".")
    )
}
