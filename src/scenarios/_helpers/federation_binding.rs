//! Shared `service_binding_ref` construction for federation peer-submit
//! scenarios (`POST /_cokret/peer/events`).
//!
//! Spec: `cokret-spec/spec/v1/zh/sync/federation.md` §4.1 request table and
//! §4.1.1 (`reducer_profile_digest` computation, normative):
//!
//! * `reducer_profile_digest` — registry-derived canonical digest of the
//!   `reducer-profile-registry.json` row for the profile soland declares in
//!   `ck.peer.events.query.describe.supported_profiles` (`ck.profile.federation_minimal.v1`).
//!   Computed via [`crate::conformance::reducer_profile_digest`]; pinned by
//!   `ck.vector.federation.reducer_profile_digest.v1`.
//! * `membership_frontier` / `delivery_binding_frontier` — `id[]` causal frontiers of the sender's
//!   view. The harness acts as the origin peer of a fabricated realm whose entire causal history is
//!   the submitted batch, so the frontier is the batch's head Event IDs (events not referenced by
//!   any other batch event's `prev_refs`).
//! * `realm_policy_digest` — spec v1 registers no computation vector for this field (sender-local
//!   "Realm policy hash"); the harness hashes its own realm-policy snapshot object under an
//!   explicitly harness-scoped domain string so it can never be mistaken for a spec identifier.

use std::collections::HashSet;

use anyhow::Result;
use cokret_core::canonical::canonical_sha256;
use serde_json::{Value, json};

use crate::conformance::{FEDERATION_MINIMAL_PROFILE_ID, reducer_profile_digest};

/// Head Event IDs of a fabricated batch: every `event_id` that no other batch
/// event references via `prev_refs` (entries may be plain id strings or
/// objects carrying an `event_id` member). Falls back to a fixed placeholder
/// id when the batch carries no usable ids, matching the previous behaviour.
pub fn batch_frontier_event_ids(events: &[Value]) -> Vec<String> {
    let mut referenced: HashSet<String> = HashSet::new();
    for event in events {
        let Some(prev_refs) = event.get("prev_refs").and_then(Value::as_array) else {
            continue;
        };
        for entry in prev_refs {
            let id = entry
                .as_str()
                .or_else(|| entry.get("event_id").and_then(Value::as_str));
            if let Some(id) = id {
                referenced.insert(id.to_owned());
            }
        }
    }
    let heads: Vec<String> = events
        .iter()
        .filter_map(|event| event.get("event_id").and_then(Value::as_str))
        .filter(|id| !referenced.contains(*id))
        .map(str::to_owned)
        .collect();
    if heads.is_empty() {
        vec!["ck:event:01904100-0000-7000-8000-fedc00000000".to_owned()]
    } else {
        heads
    }
}

/// Build the §4.1 `service_binding_ref` for a peer events submit whose
/// sender-side causal frontier is `frontier`.
pub fn peer_service_binding_ref(realm_id: &str, frontier: &[String]) -> Result<Value> {
    Ok(json!({
        "realm_id": realm_id,
        // No registered computation vector exists for realm_policy_digest in
        // spec v1; this is the harness's sender-local realm policy snapshot
        // hash (see module docs).
        "realm_policy_digest": canonical_sha256(&json!({
            "domain": "cotest.harness.realm_policy_snapshot.v1",
            "realm_id": realm_id,
        }))?,
        "membership_frontier": frontier,
        "delivery_binding_frontier": frontier,
        "destination_service_type": "principal_server",
        "reducer_profile_digest": reducer_profile_digest(FEDERATION_MINIMAL_PROFILE_ID)?,
    }))
}

/// Full `POST /_cokret/peer/events` request body for a fabricated batch.
pub fn peer_events_submit_body(
    realm_id: &str,
    events: Vec<Value>,
    idempotency_key: Option<&str>,
) -> Result<Value> {
    let frontier = batch_frontier_event_ids(&events);
    let mut body = json!({
        "service_binding_ref": peer_service_binding_ref(realm_id, &frontier)?,
        "events": events,
    });
    if let Some(key) = idempotency_key {
        body["idempotency_key"] = Value::String(key.to_owned());
    }
    Ok(body)
}
