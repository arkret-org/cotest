//! TB-3 — Gate test: "unsigned ingest must be rejected".
//!
//! Posts a valid-shape `ak.find.directory.command.announce.v1` body to teabay **without** the
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
use serde_json::json;

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
    let discovery_event_id =
        arkret_wire::EventId::new("ak:event:ASWGTju1AH5ri82iFC0b-lZTclyFRuOI8TagaYiq5ZD2")?;
    let discovery_realm_id =
        arkret_wire::RealmId::new("ak:realm:ATH75ame6bMfYpXtcoLOVb7FKmgpWVniZZqVBz1dUdQa")?;
    let discovery_actor_id = arkret_wire::DidCoreId::new(
        "ak:did_core:key:z6MkrJVnaZkeFzdQyRo91my9QRBqmbW4cSUCQY4fVn4N1",
    )?;
    let station_id = arkret_wire::DidCoreId::new("ak:did_core:web:soland.cotest.local")?;
    let directory_id = arkret_wire::DidCoreId::new("ak:did_core:web:teabay.cotest.local")?;
    let as_of = Utc::now();
    let mut source_ref_access =
        arkret_models_collaboration::history_key::DirectorySourceRefAccess {
            kind: arkret_models_collaboration::history_key::DirectorySourceRefAccessKind::DirectoryAnnounce,
            source_id: station_id.clone(),
            directory_id: directory_id.clone(),
            realm_id: discovery_realm_id.clone(),
            discovery_event_id: discovery_event_id.clone(),
            source_refs: vec![discovery_event_id.clone()],
            as_of,
            expires_at: as_of + chrono::Duration::minutes(5),
            proof: arkret_wire::PayloadProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: arkret_wire::DidUrl::new(
                    "did:web:soland.cotest.local#notary-key",
                )
                .map_err(anyhow::Error::msg)?,
                payload_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(
                    b"placeholder",
                ))?,
                created_at: as_of,
                domain: Some("ak:trust_domain:cotest.local".to_owned()),
                audience: Some(arkret_wire::Audience::Single(directory_id.to_string())),
                proof_purpose: None,
                jws: "e30..c2ln".to_owned(),
            },
        };
    source_ref_access.proof.payload_digest = source_ref_access.payload_digest()?;
    let body = arkret_models_discovery::DirectoryAnnounceRequestBody {
        discovery_event: arkret_wire::Event {
            event_id: discovery_event_id.clone(),
            kind: arkret_wire::EventKind::ActorDiscovery,
            realm_id: discovery_realm_id.clone(),
            scope_ref: arkret_wire::event_envelope::ScopeRef::Realm {
                realm_id: discovery_realm_id.clone(),
            },
            actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                discovery_actor_id.clone(),
                station_id.clone(),
            )),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_seq: 1,
            created_at: arkret_canonical::parse_timestamp_canonical("2026-05-18T00:00:00.000Z")?,
            hlc: None,
            prev_refs: Vec::new(),
            refs: Vec::new(),
            causal_refs: Vec::new(),
            preconditions: Vec::new(),
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            // `Event::payload` is an open `BTreeMap<String, Value>` on the wire
            // type; the discovery record shape lives in the schema, not in Rust.
            payload: serde_json::from_value(json!({
                "resource_id": discovery_actor_id.as_str(),
                "value": {
                    "resource_kind": "actor",
                    "discoverability": "public",
                    "directory_ids": ["ak:did_core:web:teabay.cotest.local"]
                }
            }))?,
            unsigned: std::collections::BTreeMap::new(),
            proofs: Vec::new(),
            requirements: arkret_wire::EventRequirements::default(),
        },
        source_ref_access,
        as_of,
        ttl_seconds: None,
        supersedes_announce_id: None,
    };

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
    let problem: arkret_wire::Problem = serde_json::from_str(&text)
        .with_context(|| format!("rejection response is not JSON: {text}"))?;
    let errcode = problem.code();
    if errcode.is_empty() {
        bail!(
            "unsigned ingest was rejected ({status}) but response has no errcode. body: {problem:?}"
        );
    }

    Ok(())
}
