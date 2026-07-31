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
//! `ak:device:<uuidv7>` (was `"device-alice-e2"`, which the strict
//! `arkret_identifiers::DeviceId` validator rejects), confirmed the actor
//! registration + realm-create + message-send round-trip succeeds against
//! a real soland, and removed the wrapper's `#[ignore]` so default
//! `cargo test` runs the full federation scenario whenever a soland binary
//! is locatable (and silently skips otherwise).

use anyhow::{Context, Result};
use arkret_canonical::{canonical_json_bytes, canonical_sha256};
use arkret_identifiers::new_prefixed_uuid7;
use arkret_signatures::http_signature::{
    ContentDigest, ContentDigestAlgorithm, sign_message, signing_key_from_seed,
};
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::{Value, json};
use url::Url;

use crate::harness::{
    TestServerGroup, event_envelope_with_chain, expect_json,
    member_join_payload_with_delivery_binding, realm_bootstrap_event_batch, realm_create_payload,
    refresh_event_proof,
};
use crate::scenarios::_helpers::federation_binding::{
    peer_events_submit_body, peer_events_submit_body_with_delivery_frontier,
};
use crate::scenarios::federation_collaboration::actor_did_for_service;

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
    assert_eq!(describe_a["service_kind"], "principal_server");
    assert_eq!(describe_b["service_kind"], "principal_server");
    assert_ne!(
        server_a.service_id(),
        server_b.service_id(),
        "two-node federation requires distinct service DIDs"
    );

    // ── Step 2: actor + Realm + message Event on server_a ───────────────
    // C35.2 — `device_id` MUST be a canonical Arkret wire DeviceId
    // (`ak:device:<uuidv7>`) per `arkret_identifiers::DeviceId`. Mint a
    // fresh UUIDv7-backed device id at runtime so the fixture is
    // wire-canonical and unique per run.
    let device_alice = new_prefixed_uuid7("ak:device:");
    // The actor DID is hosted by server_a's service authority. Deployment trust
    // domains are independent ServiceDescribe claims and are not DID hosts.
    let alice_did = actor_did_for_service(server_a.service_id(), "alice-e2")?;
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
    let realm_id = new_prefixed_uuid7("ak:realm:");
    let realm_input = json!({
        "title": "e2-federation-two-node-realm",
        "plaintext_visible_services": [
            {
                "service_id": server_a.service_id(),
                "service_kind": "principal_server",
                "data_classes": ["message_content"],
                "purposes": ["federated_plaintext_delivery"],
                "visibility": "private_plaintext",
            },
            {
                "service_id": server_b.service_id(),
                "service_kind": "principal_server",
                "data_classes": ["message_content"],
                "purposes": ["federated_plaintext_delivery"],
                "visibility": "private_plaintext",
            },
        ],
        "sync_endpoints": [
            {
                "did": server_a.service_id(),
                "endpoint": server_a.base_url().as_str(),
                "role": "federation_peer",
                "service_kind": "principal_server",
                "plaintext_visible": true,
                "visibility_scope": "plaintext_events",
            },
            {
                "did": server_b.service_id(),
                "endpoint": server_b.base_url().as_str(),
                "role": "federation_peer",
                "service_kind": "principal_server",
                "plaintext_visible": true,
                "visibility_scope": "plaintext_events",
            },
        ],
    });
    let realm_payload = realm_create_payload(
        &actor_a.actor,
        server_a.service_id(),
        &realm_id,
        &realm_input,
    );
    let mut bootstrap_events =
        realm_bootstrap_event_batch(&actor_a.actor, &realm_id, realm_payload)?;
    // The genesis unit is `ak.realm.create` plus the closed follow-up facets, so
    // the create Event is this actor's causal predecessor for the rest of the batch.
    let realm_create_id = bootstrap_events[0]["event_id"]
        .as_str()
        .context("Realm create lacks event_id")?
        .to_owned();
    let mut delivery_policy = event_envelope_with_chain(
        &actor_a.actor,
        &realm_id,
        "ak.realm.delivery_binding_policy",
        json!({
            "realm_id": realm_id,
            "allowed_binding_sources": ["explicit"],
            "allowed_recipient_services": [server_b.service_id()]
        }),
        1,
        Some(&realm_create_id),
    );
    attach_delivery_policy_cell_contract(&mut delivery_policy)?;
    refresh_event_proof(&mut delivery_policy)?;
    let delivery_policy_id = delivery_policy["event_id"]
        .as_str()
        .context("delivery policy lacks event_id")?
        .to_owned();
    let binding = event_envelope_with_chain(
        &actor_a.actor,
        &realm_id,
        "ak.member.state",
        member_join_payload_with_delivery_binding(
            &realm_id,
            &actor_a.actor,
            json!({
                "recipient_service_id": server_b.service_id(),
                "recipient_service_kind": "principal_server",
                "binding_scope": "realm",
                "binding_source": "explicit",
                "delivery_modes": ["events", "sync"],
                "service_acceptance_ref": "ak:event:01904100-0000-7000-8000-fedc0000e201",
                "resolved_at": "2026-05-02T00:00:00.000Z"
            }),
        )?,
        2,
        Some(&delivery_policy_id),
    );
    let binding_event_id = binding["event_id"]
        .as_str()
        .context("delivery binding lacks event_id")?
        .to_owned();
    bootstrap_events.extend([delivery_policy, binding]);
    expect_json(
        actor_a
            .post("/_arkret/self/events")
            .json(&json!({"events": bootstrap_events})),
        StatusCode::OK,
    )
    .await
    .context("create Realm bootstrap on server_a")?;
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
    let mut event_envelopes = events_a_list
        .iter()
        .map(|entry| entry.get("event").unwrap_or(entry).clone())
        .map(|event| {
            serde_json::from_value::<arkret_wire::Event>(event)
                .context("parse peer event envelope into SDK Event")
        })
        .collect::<Result<Vec<_>>>()?;
    event_envelopes.sort_by(|left, right| {
        left.actor_id
            .cmp(&right.actor_id)
            .then_with(|| left.actor_seq.cmp(&right.actor_seq))
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    if event_envelopes.is_empty() {
        return Err(anyhow::anyhow!(
            "server_a peer events query returned no event envelopes: {events_a}"
        ));
    }

    // ── Step 4: push the same Events to server_b ─────────────────────────
    let message_index = event_envelopes
        .iter()
        .position(|event| event.kind.as_str() == arkret_wire::EventKind::MESSAGE_CREATE)
        .context("peer query did not return the authored message")?;
    let later_events = event_envelopes.split_off(message_index);
    let push_body = peer_events_submit_body(
        &realm_id,
        event_envelopes,
        Some("cotest-two-node-peer-bootstrap"),
    )?;

    let push_url = format!(
        "{}/_arkret/peer/events",
        server_b.base_url().as_str().trim_end_matches('/')
    );
    let push_result = expect_json(
        with_peer_post_headers(
            server_b.http().post(&push_url).json(&push_body),
            &push_url,
            server_a,
            server_b,
            &push_body,
        )?,
        StatusCode::OK,
    )
    .await
    .context("push peer events to server_b")?;
    anyhow::ensure!(
        push_result["accepted"]
            .as_array()
            .is_some_and(|accepted| !accepted.is_empty()),
        "server_b did not accept any pushed federation Event: {push_result}"
    );

    let message_body = peer_events_submit_body_with_delivery_frontier(
        &realm_id,
        later_events,
        &[arkret_identifiers::EventId::new(binding_event_id)?],
        Some("cotest-two-node-peer-events"),
    )?;
    let message_result = expect_json(
        with_peer_post_headers(
            server_b.http().post(&push_url).json(&message_body),
            &push_url,
            server_a,
            server_b,
            &message_body,
        )?,
        StatusCode::OK,
    )
    .await
    .context("push post-bootstrap peer events to server_b")?;
    anyhow::ensure!(
        message_result["accepted"]
            .as_array()
            .is_some_and(|accepted| !accepted.is_empty()),
        "server_b did not accept the pushed federation message: {message_result}"
    );

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

fn attach_delivery_policy_cell_contract(event: &mut Value) -> Result<()> {
    let cell = format!(
        "ak:cell:ak.component.realm.delivery_binding_policy.v1:{}",
        arkret_wire::NULL_SUBJECT
    );
    let payload = event["payload"].clone();
    event["preconditions"] = json!([{
        "cell": cell,
        "predicate": {"op": "head_eq", "value": null}
    }]);
    event["effects"] = json!([{
        "cell": cell,
        "op": {"kind": "set", "value": payload}
    }]);
    Ok(())
}

fn with_peer_get_headers(
    builder: reqwest::RequestBuilder,
    target_url: &str,
    source: &crate::harness::ArkretServer,
    destination: &crate::harness::ArkretServer,
) -> Result<reqwest::RequestBuilder> {
    // GET peer reads carry no body: soland (peer.rs) rejects any GET that sends
    // Content-Digest / Request-Canonical-Digest headers or binds those
    // components in Signature-Input. Sign over the no-body-digest base.
    with_peer_headers_for_digest(builder, "GET", target_url, source, destination, None)
}

fn with_peer_post_headers(
    builder: reqwest::RequestBuilder,
    target_url: &str,
    source: &crate::harness::ArkretServer,
    destination: &crate::harness::ArkretServer,
    body: &impl Serialize,
) -> Result<reqwest::RequestBuilder> {
    let body_bytes = canonical_json_bytes(body)?;
    let content_digest =
        ContentDigest::compute(&body_bytes, ContentDigestAlgorithm::Sha256).wire_value;
    let request_canonical_digest = canonical_sha256(body)?;
    let builder = with_peer_headers_for_digest(
        builder,
        "POST",
        target_url,
        source,
        destination,
        Some((content_digest, request_canonical_digest)),
    )?;
    Ok(builder.body(body_bytes))
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
    source: &crate::harness::ArkretServer,
    destination: &crate::harness::ArkretServer,
    body_digest: Option<(String, String)>,
) -> Result<reqwest::RequestBuilder> {
    let source_service_id = source.service_id();
    let destination_service_id = destination.service_id();
    let source_trust_domain = source.trust_domain().as_str();
    let destination_trust_domain = destination.trust_domain().as_str();

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
    let keyid = format!("{source_service_id}#federation-fanout-key");
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
         \"source-service-id\" \"destination-service-id\" \"source-trust-domain\" \
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
         \"source-service-id\": {source_service_id}\n\
         \"destination-service-id\": {destination_service_id}\n\
         \"source-trust-domain\": {source_trust_domain}\n\
         \"destination-trust-domain\": {destination_trust_domain}\n\
         {request_digest_line}\
         \"@signature-params\": {signature_params}",
        method.to_ascii_uppercase()
    );
    let signing_key = signing_key_from_seed(source.notary_signing_key_seed());
    let signature = sign_message(signature_base.as_bytes(), &signing_key);

    let mut builder = builder
        .header("Source-Service-ID", source_service_id)
        .header("Destination-Service-ID", destination_service_id)
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
