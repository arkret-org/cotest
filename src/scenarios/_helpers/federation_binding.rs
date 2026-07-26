//! Shared `service_binding_ref` construction for federation peer-submit
//! scenarios (`POST /_arkret/peer/events`).
//!
//! Spec: `arkret-spec/spec/v1/zh/sync/federation.md` §4.1 request table and
//! §4.1.1 (`reducer_profile_digest` computation, normative):
//!
//! * `reducer_profile_digest` — registry-derived canonical digest of the
//!   `reducer-profile-registry.json` row for the profile soland declares in
//!   `ak.peer.events.query.describe.supported_profiles` (`ak.profile.federation_minimal.v1`).
//!   Computed via [`crate::conformance::reducer_profile_digest`]; pinned by
//!   `ak.vector.federation.reducer_profile_digest.v1`.
//! * `membership_frontier` / `delivery_binding_frontier` — `id[]` causal frontiers of the sender's
//!   view. The harness acts as the origin peer of a fabricated realm whose entire causal history is
//!   the submitted batch, so the frontier is the batch's head Event IDs (events not referenced by
//!   any other batch event's `prev_refs`).
//! * `realm_policy_digest` — spec v1 registers no computation vector for this field (sender-local
//!   "Realm policy hash"); the harness hashes its own realm-policy snapshot object under an
//!   explicitly harness-scoped domain string so it can never be mistaken for a spec identifier.

use std::collections::HashSet;

use anyhow::{Context, Result};
use arkret_canonical::canonical_sha256;
use arkret_identifiers::{EventId, Hash, RealmId};
use arkret_models_collaboration::event_sync::{
    EventsSubmitFederationRequestBody, FederationServiceBindingRef,
};
use arkret_wire::Event;
use serde_json::json;

use crate::conformance::{
    FEDERATION_MINIMAL_PROFILE_ID, reducer_profile_digest as registry_reducer_profile_digest,
};

/// Head Event IDs of a fabricated batch: every `event_id` that no other batch
/// event references via `prev_refs` (entries may be plain id strings or
/// objects carrying an `event_id` member). Falls back to a fixed placeholder
/// id when the batch carries no usable ids, matching the previous behaviour.
pub fn batch_frontier_event_ids(events: &[Event]) -> Result<Vec<EventId>> {
    let mut referenced: HashSet<String> = HashSet::new();
    for event in events {
        for entry in &event.prev_refs {
            referenced.insert(entry.as_str().to_owned());
        }
    }
    let heads: Vec<EventId> = events
        .iter()
        .filter(|event| !referenced.contains(event.event_id.as_str()))
        .map(|event| event.event_id.clone())
        .collect();
    if heads.is_empty() {
        Ok(vec![
            EventId::new("ak:event:01904100-0000-7000-8000-fedc00000000".to_owned())
                .context("fallback federation frontier event id is invalid")?,
        ])
    } else {
        Ok(heads)
    }
}

/// Build the §4.1 `service_binding_ref` for a peer events submit whose
/// sender-side causal frontier is `frontier`.
pub fn peer_service_binding_ref(
    realm_id: &str,
    frontier: &[EventId],
) -> Result<FederationServiceBindingRef> {
    peer_service_binding_ref_with_delivery(realm_id, frontier, frontier)
}

/// Build the §4.1 `service_binding_ref` separating the membership frontier from
/// the `delivery_binding_frontier`.
///
/// The bootstrap helpers default `delivery_binding_frontier = batch heads`,
/// which only holds while the receiver has no prior member binding to be stale
/// against (federation.md §4.1: a push that first establishes the Realm has no
/// local binding). Once the receiver already hosts a member whose effective
/// `delivery_binding.recipient_service_id = Destination-Service-ID`, the
/// sender MUST instead assert that member's delivery-binding causal frontier
/// (reachable in the receiver's Realm view), or the receiver fails closed with
/// `delivery_binding_stale`.
pub fn peer_service_binding_ref_with_delivery(
    realm_id: &str,
    membership_frontier: &[EventId],
    delivery_binding_frontier: &[EventId],
) -> Result<FederationServiceBindingRef> {
    let realm_policy_digest = canonical_sha256(&json!({
        "domain": "cotest.harness.realm_policy_snapshot.v1",
        "realm_id": realm_id,
    }))?;
    Ok(FederationServiceBindingRef {
        realm_id: RealmId::new(realm_id.to_owned())
            .with_context(|| format!("invalid federation realm_id `{realm_id}`"))?,
        // No registered computation vector exists for realm_policy_digest in
        // spec v1; this is the harness's sender-local realm policy snapshot
        // hash (see module docs).
        realm_policy_digest: Hash::new(realm_policy_digest)
            .context("invalid federation realm_policy_digest")?,
        membership_frontier: membership_frontier.to_vec(),
        delivery_binding_frontier: delivery_binding_frontier.to_vec(),
        destination_service_kind: "principal_server".to_owned(),
        reducer_profile_digest: Hash::new(registry_reducer_profile_digest(
            FEDERATION_MINIMAL_PROFILE_ID,
        )?)
        .context("invalid federation reducer_profile_digest")?,
    })
}

/// Full `POST /_arkret/peer/events` request body for a fabricated batch.
pub fn peer_events_submit_body(
    realm_id: &str,
    events: Vec<Event>,
    _idempotency_key: Option<&str>,
) -> Result<EventsSubmitFederationRequestBody> {
    let frontier = batch_frontier_event_ids(&events)?;
    Ok(EventsSubmitFederationRequestBody {
        service_binding_ref: peer_service_binding_ref(realm_id, &frontier)?,
        events,
        seals: Vec::new(),
        signer_key_evidence: Vec::new(),
        agent_signer_evidence_bundle: None,
    })
}

/// Like [`peer_events_submit_body`] but asserts an explicit
/// `delivery_binding_frontier` — the receiver-reachable causal frontier of the
/// member whose `delivery_binding.recipient_service_id` equals the destination
/// service (federation.md §4.1). Use when pushing to a Realm the receiver
/// already hosts a delivery-bound member for.
pub fn peer_events_submit_body_with_delivery_frontier(
    realm_id: &str,
    events: Vec<Event>,
    delivery_binding_frontier: &[EventId],
    _idempotency_key: Option<&str>,
) -> Result<EventsSubmitFederationRequestBody> {
    let membership_frontier = batch_frontier_event_ids(&events)?;
    Ok(EventsSubmitFederationRequestBody {
        service_binding_ref: peer_service_binding_ref_with_delivery(
            realm_id,
            &membership_frontier,
            delivery_binding_frontier,
        )?,
        events,
        seals: Vec::new(),
        signer_key_evidence: Vec::new(),
        agent_signer_evidence_bundle: None,
    })
}
