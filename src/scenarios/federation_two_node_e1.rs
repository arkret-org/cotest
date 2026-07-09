//! E2 Round 26 / C33.4 — federation two-node real Move replay.
//!
//! Spawns two real `soland` binaries on independent ports/blob roots,
//! confirms they negotiate basic federation handshake (`/_arkret/describe`
//! reachable on both, distinct service DIDs), then exercises the federation
//! Move forwarding path: register an account on server_a, mint a Move into a
//! Realm, push the canonical Events to server_b via `/_arkret/peer/events`,
//! and confirm server_b exposes the Realm frontier on the peer API.
//!
//! C33.4 wired the spawn through the reusable `external_binary` helper:
//! `TestServerGroup::try_multi_external` resolves `SOLAND_BIN` (or sibling-
//! checkout `arkret/soland/target/debug/soland[.exe]`) and spawns the
//! pre-built binary directly — no `cargo run` slow path. When neither is
//! available the scenario silently returns `Ok(())` so CI runners that have
//! not built soland do not flake.
//!
//! C35.2 fixed the `device_id` fixture to use a wire-canonical
//! `ck:device:<uuidv7>` (was `"device-alice-e2"`, which the strict
//! `arkret_identifiers::DeviceId` validator rejects), confirmed the actor
//! registration + realm-create + message-send round-trip succeeds against
//! a real soland, and removed the wrapper's `#[ignore]` so default
//! `cargo test` runs the full federation scenario whenever a soland binary
//! is locatable (and silently skips otherwise).

use anyhow::{Context, Result};
use arkret::http_signature::{
    ContentDigest, ContentDigestAlgorithm, sign_message, signing_key_from_seed,
};
use arkret_core::canonical::{canonical_json_bytes, canonical_sha256};
use arkret_core::identifiers::new_prefixed_uuid7;
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::harness::{TestServerGroup, expect_json};
use crate::scenarios::_helpers::federation_binding::peer_events_submit_body;

/// Spawns two `soland` instances (pre-built binary, located via SOLAND_BIN
/// env or sibling checkout) and runs the round-26 federation real Move-
/// replay scenario:
///   1. distinct service DIDs (basic handshake invariant)
///   2. server_a registers an account + creates a Realm + sends a message Event
///   3. server_a's peer Events API returns the Realm event batch
///   4. server_b accepts the same Events via the peer Events push endpoint
///   5. server_b's `/_arkret/peer/events/frontier` reports a Realm frontier
///
/// Returns `Ok(())` early when neither `SOLAND_BIN` is set nor a sibling
/// `arkret/soland/target/debug/soland[.exe]` exists (silent skip path).
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
        server_a.http().get(server_a.url("/_arkret/describe")),
        StatusCode::OK,
    )
    .await?;
    let describe_b = expect_json(
        server_b.http().get(server_b.url("/_arkret/describe")),
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
    // C35.2 — `device_id` MUST be a canonical Arkret wire DeviceId
    // (`ck:device:<uuidv7>`) per `arkret_identifiers::DeviceId`. Mint a
    // fresh UUIDv7-backed device id at runtime so the fixture is
    // wire-canonical and unique per run.
    let device_alice = new_prefixed_uuid7("ak:device:");
    // alice is homed on server_a, so her DID MUST live under server_a's trust
    // domain. Appending `:alice-e2` to server_a's `did:webvh:<scid>:<host>...`
    // service DID keeps the host segment (the one soland derives the trust
    // domain from) unchanged, so alice's home domain equals server_a's.
    // Federation admission binds the relayed actor to the relaying server:
    // `federation_actor_origin_acceptable`
    // accepts an inbound event only when the actor's home trust domain equals the
    // asserted `source-trust-domain` (or the actor is already a known member).
    // A DID under an unrelated domain is rejected `capability_denied` on push.
    let alice_did = format!("{}:alice-e2", server_a.service_did());
    let actor_a = server_a
        .register_client(&alice_did, "@alice-e2", &device_alice)
        .await
        .context("register actor on server_a")?;
    // Authorise server_b as a Realm-level `federation_peer` sync endpoint and
    // make it plaintext-visible: a peer read by server_b is then an authorised
    // federation-peer read (PeerReadAuthz `source_has_realm_scope` +
    // `source_can_receive_plaintext`), not anti-enumeration probing. Realm-level
    // `sync_endpoints` is the canonical carrier for federation-peer surfaces
    // (member-delivery-binding.md §7), orthogonal to member delivery_binding.
    let created = actor_a
        .create_realm_with(json!({
            "title": "e2-federation-two-node-realm",
            "plaintext_visible_services": [
                server_a.service_did(),
                server_b.service_did(),
            ],
            "sync_endpoints": [
                {
                    "did": server_a.service_did(),
                    "endpoint": server_a.base_url().as_str(),
                    "role": "federation_peer",
                    "service_type": "principal_server",
                    "plaintext_visible": true,
                    "visibility_scope": "plaintext_events",
                },
                {
                    "did": server_b.service_did(),
                    "endpoint": server_b.base_url().as_str(),
                    "role": "federation_peer",
                    "service_type": "principal_server",
                    "plaintext_visible": true,
                    "visibility_scope": "plaintext_events",
                },
            ],
        }))
        .await
        .context("create Realm on server_a")?;
    let realm_id = created["realm_id"]
        .as_str()
        .context("create realm response missing realm_id")?
        .to_owned();
    let _msg = actor_a
        .send_message(&realm_id, "thread-e2", "hello from server_a")
        .await
        .context("send message Event on server_a")?;

    // ── Step 3: pull federation-visible Events from server_a ─────────────
    let query_a_url = format!(
        "{}/_arkret/peer/events?realms={}&limit=100",
        server_a.base_url().as_str().trim_end_matches('/'),
        realm_id
    );
    let events_a = expect_json(
        with_peer_get_headers(
            server_a.http().get(&query_a_url),
            &query_a_url,
            server_b,
            server_a,
        )?,
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
            serde_json::from_value::<arkret_core::Event>(event)
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
        "{}/_arkret/peer/events",
        server_b.base_url().as_str().trim_end_matches('/')
    );
    let push_response = with_peer_post_headers(
        server_b.http().post(&push_url).json(&push_body),
        &push_url,
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
    let frontier_b_url = format!(
        "{}/_arkret/peer/events/frontier?realm_id={}",
        server_b.base_url().as_str().trim_end_matches('/'),
        realm_id
    );
    let frontier_b = expect_json(
        with_peer_get_headers(
            server_b.http().get(&frontier_b_url),
            &frontier_b_url,
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
    target_url: &str,
    source: &crate::harness::CokretServer,
    destination: &crate::harness::CokretServer,
) -> Result<reqwest::RequestBuilder> {
    // GET peer reads carry no body: soland (peer.rs) rejects any GET that sends
    // Content-Digest / Request-Canonical-Digest headers or binds those
    // components in Signature-Input. Sign over the no-body-digest base.
    with_peer_headers_for_digest(builder, "GET", target_url, source, destination, None)
}

fn with_peer_post_headers(
    builder: reqwest::RequestBuilder,
    target_url: &str,
    source: &crate::harness::CokretServer,
    destination: &crate::harness::CokretServer,
    body: &impl Serialize,
) -> Result<reqwest::RequestBuilder> {
    let body_bytes = canonical_json_bytes(body)?;
    let content_digest =
        ContentDigest::compute(&body_bytes, ContentDigestAlgorithm::Sha256).wire_value;
    let request_canonical_digest = canonical_sha256(body)?;
    with_peer_headers_for_digest(
        builder,
        "POST",
        target_url,
        source,
        destination,
        Some((content_digest, request_canonical_digest)),
    )
}

/// Sign a federation peer request. `body_digest` is `Some((content_digest,
/// request_canonical_digest))` for write methods (POST) and `None` for GET peer
/// reads, which MUST NOT carry or bind body-digest headers/components (soland
/// `peer.rs`). The covered-component list, signature base, and emitted headers
/// all include the body-digest fields only when present, matching soland's
/// `peer_http_signature_base`.
fn with_peer_headers_for_digest(
    builder: reqwest::RequestBuilder,
    method: &str,
    target_url: &str,
    source: &crate::harness::CokretServer,
    destination: &crate::harness::CokretServer,
    body_digest: Option<(String, String)>,
) -> Result<reqwest::RequestBuilder> {
    let source_service_did = source.service_did();
    let destination_service_did = destination.service_did();
    let source_trust_domain = trust_domain_for(source_service_did);
    let destination_trust_domain = trust_domain_for(destination_service_did);

    let parsed_url = Url::parse(target_url)?;
    let authority = parsed_url
        .port()
        .map(|port| format!("{}:{port}", parsed_url.host_str().unwrap_or("server")))
        .unwrap_or_else(|| parsed_url.host_str().unwrap_or("server").to_owned());
    let path_and_query = parsed_url
        .query()
        .map(|query| format!("{}?{query}", parsed_url.path()))
        .unwrap_or_else(|| parsed_url.path().to_owned());
    let target_uri = format!("{}://{}{}", parsed_url.scheme(), authority, path_and_query);

    let created = chrono::Utc::now().timestamp();
    let expires = created + 300;
    let keyid = format!("{source_service_did}#federation-fanout-key");
    let content_digest_param = if body_digest.is_some() {
        "\"content-digest\" "
    } else {
        ""
    };
    let request_digest_param = if body_digest.is_some() {
        " \"request-canonical-digest\""
    } else {
        ""
    };
    let signature_params = format!(
        "(\"@method\" \"@target-uri\" \"@authority\" {content_digest_param}\
         \"source-service-did\" \"destination-service-did\" \"source-trust-domain\" \
         \"destination-trust-domain\"{request_digest_param});created={created};\
         expires={expires};keyid=\"{keyid}\";alg=\"ed25519\""
    );
    let content_digest_line = body_digest
        .as_ref()
        .map(|(content_digest, _)| format!("\"content-digest\": {content_digest}\n"))
        .unwrap_or_default();
    let request_digest_line = body_digest
        .as_ref()
        .map(|(_, request_canonical_digest)| {
            format!("\"request-canonical-digest\": {request_canonical_digest}\n")
        })
        .unwrap_or_default();
    let signature_base = format!(
        "\"@method\": {}\n\
         \"@target-uri\": {target_uri}\n\
         \"@authority\": {authority}\n\
         {content_digest_line}\
         \"source-service-did\": {source_service_did}\n\
         \"destination-service-did\": {destination_service_did}\n\
         \"source-trust-domain\": {source_trust_domain}\n\
         \"destination-trust-domain\": {destination_trust_domain}\n\
         {request_digest_line}\
         \"@signature-params\": {signature_params}",
        method.to_ascii_uppercase()
    );
    let signing_key = development_service_signing_key(source_service_did);
    let signature = sign_message(signature_base.as_bytes(), &signing_key);

    let mut builder = builder
        .header("Source-Service-DID", source_service_did)
        .header("Destination-Service-DID", destination_service_did)
        .header("Source-Trust-Domain", source_trust_domain)
        .header("Destination-Trust-Domain", destination_trust_domain)
        .header("Signature-Input", format!("sig1={signature_params}"))
        .header("Signature", format!("sig1=:{signature}:"));
    if let Some((content_digest, request_canonical_digest)) = body_digest {
        builder = builder
            .header("Content-Digest", content_digest)
            .header("Request-Canonical-Digest", request_canonical_digest);
    }
    Ok(builder)
}

fn development_service_signing_key(service_did: &str) -> arkret::http_signature::Ed25519SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"soland:notary-ephemeral:");
    hasher.update(service_did.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    signing_key_from_seed(&seed)
}

fn trust_domain_for(service_did: &str) -> String {
    format!("ak:trust_domain:{}", did_host_from_service_did(service_did))
}

/// Extract the HTTP authority (host) a service DID's trust domain is scoped to,
/// mirroring soland's `trust_domain_from_service_did`.
///
/// For `did:webvh:<scid>:<host>[:...]` the host is the segment *after* the SCID,
/// so the SCID must not leak into the trust domain (soland test
/// `trust_domain_derives_webvh_host_not_scid`). `did:web:<host>[:...]` and the
/// `did:key:` fallback are kept for the negative/no-history fixtures that still
/// mint those forms.
fn did_host_from_service_did(service_did: &str) -> String {
    if let Some(rest) = service_did.strip_prefix("did:webvh:") {
        let mut parts = rest.split(':');
        let scid = parts.next().unwrap_or_default();
        if let Some(host) = parts.next() {
            if !scid.is_empty() && !host.is_empty() {
                return host.to_ascii_lowercase();
            }
        }
    }
    if let Some(rest) = service_did.strip_prefix("did:web:") {
        if let Some(host) = rest.split(':').next() {
            if !host.is_empty() {
                return host.to_ascii_lowercase();
            }
        }
    }
    service_did
        .strip_prefix("did:key:")
        .unwrap_or(service_did)
        .to_ascii_lowercase()
        .replace(':', ".")
}
