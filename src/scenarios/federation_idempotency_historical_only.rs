//! C3 — multi-server federation idempotency + historical_only
//! scenario.
//!
//! Spec: sibling `arkret-spec` checkout, federation idempotency and
//! `historical_only` diagnostic semantics.
//!
//! Scenario shape (cross-project wire-shape, in-memory; no live
//! services):
//!
//! 1. **Server A** constructs a `federation_transaction` request:
//!    - `Source-Trust-Domain = ak:trust_domain:a`
//!    - `Destination-Trust-Domain = ak:trust_domain:b`
//!    - `Request-Canonical-Digest = sha256:<hash>`
//!    - request body `X`, carrying `idempotency_key=idem-c3-001`
//! 2. **Server B** receives the request, runs the cache key composition (`source_did + dest_did +
//!    request_canonical_digest + idempotency_key
//!     + origin_key_state_digest`), and caches the response under both the
//!    *strict key* (with `origin_key_state_digest`) and the
//!    *canonical-replay key* (without it).
//! 3. **Server A** revokes its service key — simulated by flipping the `origin_key_state_digest`
//!    from `state-A` to `state-B`.
//! 4. **Server A** replays the same idempotency key. The strict-key lookup misses (key state
//!    advanced) but the canonical-replay key hits → the receiver returns the cached body marked
//!    with `reason_code=historical_only`, `historical_only=true`, AND records zero new reducer side
//!    effects.
//!
//! Assertions (non-`#[ignore]`, wire-shape gates):
//!
//! - cache key composition includes `origin_key_state_digest` (strict key diverges across key-state
//!   rotation while the canonical-replay key stays stable).
//! - the signing-transcript fragment built via [`federation_trust_domain_transcript_fragment`] is
//!   byte-stable across calls and contains the three header names in lowercase quoted form plus the
//!   source/destination/canonical-hash values.
//! - the cached body returned on canonical-replay carries `reason_code=historical_only` AND
//!   `historical_only=true`, and the recorded "new reducer side effect" counter stays at the
//!   original value (zero increment on replay).
//!
//! The full live multi-server e2e (docker / live soland + teabay
//! processes, network HTTP, real key rotation) stays `#[ignore]` with
//! `TODO(federation-idempotency-e2e-docker)`.
//!
//! Cotest does NOT depend on `soland` or `teabay` — the SDK federation
//! surface and a small in-memory cache reproduce the wire shape both
//! services implement.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use arkret_core::canonical::{canonical_json_bytes, sha256_digest};
use arkret_core::{
    HEADER_DESTINATION_TRUST_DOMAIN, HEADER_REQUEST_CANONICAL_DIGEST, HEADER_SOURCE_TRUST_DOMAIN,
    Hash, TypedTrustDomainId, federation_trust_domain_transcript_fragment,
};
use serde_json::{Value, json};

// ── Canonical pins for the C3 vector ────────────────────────────────────

/// The security-closure vector id this scenario exercises. Same literal
/// as `cotest::scenarios::security_closure_vectors::VECTOR_FEDERATION_IDEMPOTENCY_AFTER_KEY_REVOKE`,
/// repeated here so a grep on `federation_idempotency_historical_only`
/// finds the binding directly.
pub const VECTOR_ID: &str = "ak.vector.federation.idempotency_after_key_revoke.v1";

/// Canonical `reason_code` carried on a cache-replay-after-key-revoke
/// response. The SDK constant is the authoritative source — this pin
/// guards drift between the SDK and the cotest scenario.
pub const HISTORICAL_ONLY_REASON: &str = "historical_only";

// ── In-memory composite idempotency key (mirrors soland federation) ─────

/// In-memory composite idempotency key. Mirrors
/// `soland::routing::federation::federation::FederationIdempotencyKey` byte-for-byte (`strict()`
/// + `canonical_replay()` produce the same digests) but stays inside
/// cotest so the harness does not depend on the soland crate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FederationCacheKey {
    pub source_did: String,
    pub dest_did: String,
    pub request_canonical_digest: String,
    pub idempotency_key: String,
    pub origin_key_state_digest: String,
}

impl FederationCacheKey {
    /// Strict cache key — equal to a cached entry only when ALL fields
    /// match, including `origin_key_state_digest`. Used to gate "fresh
    /// idempotent replay against the same key state".
    pub fn strict(&self) -> String {
        let canonical = canonical_json_bytes(&json!({
            "source_did": self.source_did,
            "dest_did": self.dest_did,
            "request_canonical_digest": self.request_canonical_digest,
            "idempotency_key": self.idempotency_key,
            "origin_key_state_digest": self.origin_key_state_digest,
        }))
        .unwrap_or_default();
        sha256_digest(&canonical)
    }

    /// Canonical-replay cache key — drops `origin_key_state_digest`. Used
    /// to detect a post-key-rotation replay; if the strict key misses
    /// but the canonical-replay key hits, the receiver MUST return the
    /// cached body marked `reason_code=historical_only` and MUST NOT
    /// re-run side effects.
    pub fn canonical_replay(&self) -> String {
        let canonical = canonical_json_bytes(&json!({
            "source_did": self.source_did,
            "dest_did": self.dest_did,
            "request_canonical_digest": self.request_canonical_digest,
            "idempotency_key": self.idempotency_key,
        }))
        .unwrap_or_default();
        sha256_digest(&canonical)
    }
}

// ── Simulated Server B ───────────────────────────────────────────────────

/// Minimal in-memory federation receiver. Tracks:
/// - strict-key → cached response,
/// - canonical-replay-key → cached response,
/// - a "reducer side-effects fired" counter so the scenario can assert the historical_only replay
///   path does NOT fire fresh side effects.
#[derive(Debug, Default)]
pub struct SimulatedFederationReceiver {
    /// This receiver's configured trust domain. Inbound requests whose
    /// `Destination-Trust-Domain` does not match are rejected with
    /// `cross_domain_replay_rejected`.
    pub configured_trust_domain: String,
    strict_cache: BTreeMap<String, Value>,
    canonical_replay_cache: BTreeMap<String, Value>,
    pub side_effects_fired: u64,
}

impl SimulatedFederationReceiver {
    pub fn new(trust_domain: impl Into<String>) -> Self {
        Self {
            configured_trust_domain: trust_domain.into(),
            ..Default::default()
        }
    }

    /// Receive a federation request from server A. Returns the response
    /// body and increments `side_effects_fired` on a fresh accept.
    ///
    /// Outcomes:
    /// - strict-key cache hit → return cached body unchanged (no new side effects),
    /// - canonical-replay-key cache hit (different `origin_key_state_digest`) → return cached body
    ///   marked `reason_code=historical_only`, `historical_only=true` (no new side effects),
    /// - cache miss → mint a fresh response, populate both cache slots, increment
    ///   `side_effects_fired`.
    ///
    /// The receiver also enforces the
    /// `cross_domain_replay_rejected` guard if `destination_trust_domain`
    /// does not match its configured value — exercising the same
    /// invariant teabay's `verify_federation_trust_domain_headers`
    /// implements.
    pub fn receive(
        &mut self,
        key: &FederationCacheKey,
        destination_trust_domain: &str,
        fresh_response_factory: impl FnOnce() -> Value,
    ) -> Result<Value> {
        if destination_trust_domain != self.configured_trust_domain {
            return Err(anyhow!(
                "cross_domain_replay_rejected: destination_trust_domain {:?} \
                 does not match receiver configuration {:?}",
                destination_trust_domain,
                self.configured_trust_domain
            ));
        }
        // Strict key — true freshness (same key state, same body).
        if let Some(cached) = self.strict_cache.get(&key.strict()) {
            return Ok(cached.clone());
        }
        // Canonical-replay key — post-key-rotation replay; the cached
        // body is returned but marked `historical_only`. No fresh side
        // effects.
        if let Some(cached) = self.canonical_replay_cache.get(&key.canonical_replay()) {
            return Ok(mark_historical_only(cached.clone()));
        }
        // Fresh accept — fire side effects, cache under both keys.
        let response = fresh_response_factory();
        self.side_effects_fired = self.side_effects_fired.saturating_add(1);
        self.strict_cache.insert(key.strict(), response.clone());
        self.canonical_replay_cache
            .insert(key.canonical_replay(), response.clone());
        Ok(response)
    }
}

/// Add `reason_code=historical_only` + `historical_only=true` to a
/// JSON body. Mirrors soland::routing::federation::federation::mark_response_historical_only.
fn mark_historical_only(mut response: Value) -> Value {
    if let Some(object) = response.as_object_mut() {
        object.insert(
            "reason_code".to_owned(),
            Value::String(HISTORICAL_ONLY_REASON.to_owned()),
        );
        object.insert("historical_only".to_owned(), Value::Bool(true));
    }
    response
}

// ── Scenario driver ─────────────────────────────────────────────────────

/// Run the C3 scenario end-to-end against the in-memory simulated
/// receiver. Returns `Ok(())` when every assertion passes.
pub fn run_federation_idempotency_historical_only() -> Result<()> {
    // Server A → Server B identifiers.
    let source_did = "did:web:server-a.example".to_owned();
    let dest_did = "did:web:server-b.example".to_owned();
    let source_td = TypedTrustDomainId::new("ak:trust_domain:a")
        .map_err(|e| anyhow!("typed source trust domain construction failed: {e}"))?;
    let dest_td = TypedTrustDomainId::new("ak:trust_domain:b")
        .map_err(|e| anyhow!("typed destination trust domain construction failed: {e}"))?;

    // Request body X — canonical-JSON over a small federation_transaction.
    let body_x = json!({
        "operation": "ak.self.events.command.submit",
        "envelopes": [{"kind": "ak.message.text", "payload": {"body": "federation-c3"}}],
        "idempotency_key": "idem-c3-001",
    });
    let body_x_bytes = canonical_json_bytes(&body_x)
        .map_err(|e| anyhow!("canonical_json_bytes(body_x) failed: {e}"))?;
    let request_canonical_digest = Hash::new(sha256_digest(&body_x_bytes))
        .map_err(|e| anyhow!("typed request canonical hash failed: {e}"))?;

    // Initial key state (before A revokes / rotates).
    let key_state_a = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let key_state_b = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let initial_key = FederationCacheKey {
        source_did,
        dest_did,
        request_canonical_digest: request_canonical_digest.as_str().to_owned(),
        idempotency_key: "idem-c3-001".to_owned(),
        origin_key_state_digest: key_state_a.to_owned(),
    };
    let post_rotation_key = FederationCacheKey {
        origin_key_state_digest: key_state_b.to_owned(),
        ..initial_key.clone()
    };

    // Cache-key composition assertion: strict keys differ once
    // `origin_key_state_digest` flips; canonical-replay keys stay equal.
    if initial_key.strict() == post_rotation_key.strict() {
        return Err(anyhow!(
            "strict cache key MUST diverge across origin_key_state_digest rotation"
        ));
    }
    if initial_key.canonical_replay() != post_rotation_key.canonical_replay() {
        return Err(anyhow!(
            "canonical-replay cache key MUST stay stable across origin_key_state_digest rotation"
        ));
    }

    // Signing-transcript fragment assertion: SDK helper output is
    // byte-stable across calls.
    let fragment_a = federation_trust_domain_transcript_fragment(
        &source_td,
        &dest_td,
        &request_canonical_digest,
    );
    let fragment_b = federation_trust_domain_transcript_fragment(
        &source_td,
        &dest_td,
        &request_canonical_digest,
    );
    if fragment_a != fragment_b {
        return Err(anyhow!(
            "federation_trust_domain_transcript_fragment is not byte-stable across calls"
        ));
    }
    // Fragment MUST contain the three header names in lowercase + values.
    for required in [
        HEADER_SOURCE_TRUST_DOMAIN.to_ascii_lowercase(),
        HEADER_DESTINATION_TRUST_DOMAIN.to_ascii_lowercase(),
        HEADER_REQUEST_CANONICAL_DIGEST.to_ascii_lowercase(),
    ] {
        if !fragment_a.contains(&required) {
            return Err(anyhow!(
                "transcript fragment missing lowercase header name {required:?}: {fragment_a}"
            ));
        }
    }
    for required_value in [
        source_td.as_str(),
        dest_td.as_str(),
        request_canonical_digest.as_str(),
    ] {
        if !fragment_a.contains(required_value) {
            return Err(anyhow!(
                "transcript fragment missing required header value {required_value:?}: {fragment_a}"
            ));
        }
    }

    // Drive Server B against the scenario.
    let mut server_b = SimulatedFederationReceiver::new("ak:trust_domain:b");

    // 1) First push — fresh accept.
    let first = server_b.receive(&initial_key, dest_td.as_str(), || {
        json!({
            "ok": true,
            "operation": "ak.self.events.command.submit",
            "accepted": 1,
            "request_canonical_digest": request_canonical_digest.as_str(),
        })
    })?;
    if first.get("historical_only").is_some() {
        return Err(anyhow!(
            "fresh accept response MUST NOT carry historical_only marker"
        ));
    }
    if server_b.side_effects_fired != 1 {
        return Err(anyhow!(
            "fresh accept MUST fire exactly one reducer side effect; got {}",
            server_b.side_effects_fired
        ));
    }

    // 2) Replay with the SAME key state — strict cache hit; same body, no new side effects, no
    //    historical_only marker.
    let same_state_replay = server_b.receive(
        &initial_key,
        dest_td.as_str(),
        || json!({"ok": true, "side_effect_should_not_fire": true}),
    )?;
    if same_state_replay.get("historical_only").is_some() {
        return Err(anyhow!(
            "strict-key replay MUST NOT mark the response historical_only"
        ));
    }
    if server_b.side_effects_fired != 1 {
        return Err(anyhow!(
            "strict-key replay MUST NOT fire fresh side effects; counter={}",
            server_b.side_effects_fired
        ));
    }

    // 3) Server A revokes its service key (origin_key_state_digest flips from state-A to state-B)
    //    and replays the same idempotency key.
    let historical_replay = server_b.receive(
        &post_rotation_key,
        dest_td.as_str(),
        || json!({"ok": true, "side_effect_should_not_fire": true}),
    )?;
    if historical_replay.get("reason_code").and_then(Value::as_str)
        != Some(arkret_core::ErrorCode::HISTORICAL_ONLY)
    {
        return Err(anyhow!(
            "post-rotation replay MUST carry reason_code=historical_only; got {:?}",
            historical_replay
        ));
    }
    if historical_replay
        .get("historical_only")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(anyhow!(
            "post-rotation replay MUST carry historical_only=true; got {:?}",
            historical_replay
        ));
    }
    if server_b.side_effects_fired != 1 {
        return Err(anyhow!(
            "post-rotation replay MUST NOT fire fresh side effects; counter advanced to {}",
            server_b.side_effects_fired
        ));
    }

    // 4) Cross-trust-domain replay (wrong destination) — MUST reject with
    //    cross_domain_replay_rejected.
    let wrong_dest = server_b.receive(
        &post_rotation_key,
        "ak:trust_domain:wrong",
        || json!({"unreachable": true}),
    );
    match wrong_dest {
        Err(err)
            if err
                .to_string()
                .contains(arkret_core::ReasonCode::CROSS_DOMAIN_REPLAY_REJECTED) => {}
        other => {
            return Err(anyhow!(
                "wrong destination MUST be rejected with \
                 cross_domain_replay_rejected; got {other:?}"
            ));
        }
    }
    if server_b.side_effects_fired != 1 {
        return Err(anyhow!(
            "cross-domain-rejected request MUST NOT fire side effects; counter={}",
            server_b.side_effects_fired
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wire-shape gate (non-ignored) — build a `FederationTrustHeaders`-
    /// equivalent triple via the SDK federation surface, call the transcript
    /// fragment helper, and assert the bytes contain the three header
    /// names in lowercase + the carried values.
    ///
    /// Tests pass without a running soland / teabay; the scenario
    /// driver runs entirely against an in-memory simulated receiver.
    #[test]
    fn federation_trust_headers_transcript_fragment_contains_lowercase_names_and_values() {
        let source_td = TypedTrustDomainId::new("ak:trust_domain:a").unwrap();
        let dest_td = TypedTrustDomainId::new("ak:trust_domain:b").unwrap();
        let request_canonical_digest = Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let fragment = federation_trust_domain_transcript_fragment(
            &source_td,
            &dest_td,
            &request_canonical_digest,
        );
        // The three header names MUST appear in lowercase (RFC 9421 §2.2).
        assert!(
            fragment.contains(&HEADER_SOURCE_TRUST_DOMAIN.to_ascii_lowercase()),
            "fragment missing lowercase source-trust-domain header name: {fragment}"
        );
        assert!(
            fragment.contains(&HEADER_DESTINATION_TRUST_DOMAIN.to_ascii_lowercase()),
            "fragment missing lowercase destination-trust-domain header name: {fragment}"
        );
        assert!(
            fragment.contains(&HEADER_REQUEST_CANONICAL_DIGEST.to_ascii_lowercase()),
            "fragment missing lowercase request-canonical-digest header name: {fragment}"
        );
        // The carried values MUST appear verbatim.
        assert!(
            fragment.contains(source_td.as_str()),
            "fragment missing source trust domain value: {fragment}"
        );
        assert!(
            fragment.contains(dest_td.as_str()),
            "fragment missing destination trust domain value: {fragment}"
        );
        assert!(
            fragment.contains(request_canonical_digest.as_str()),
            "fragment missing request canonical hash value: {fragment}"
        );
        // Byte-stable: a second call returns the same bytes.
        let fragment_again = federation_trust_domain_transcript_fragment(
            &source_td,
            &dest_td,
            &request_canonical_digest,
        );
        assert_eq!(fragment, fragment_again);
    }

    /// Non-ignored — drive the full in-memory multi-server scenario.
    #[test]
    fn scenario_federation_idempotency_historical_only_in_memory() {
        run_federation_idempotency_historical_only().expect(
            "federation idempotency historical_only scenario must pass against in-memory rig",
        );
    }

    /// Non-ignored — cache key composition pin. Strict key diverges
    /// across `origin_key_state_digest` rotation, canonical-replay key
    /// stays stable.
    #[test]
    fn cache_key_composition_includes_origin_key_state_digest() {
        let mut key = FederationCacheKey {
            source_did: "did:web:a.example".to_owned(),
            dest_did: "did:web:b.example".to_owned(),
            request_canonical_digest: format!("sha256:{}", "a".repeat(64)),
            idempotency_key: "idem-001".to_owned(),
            origin_key_state_digest: format!("sha256:{}", "b".repeat(64)),
        };
        let strict_a = key.strict();
        let replay_a = key.canonical_replay();
        key.origin_key_state_digest = format!("sha256:{}", "c".repeat(64));
        let strict_b = key.strict();
        let replay_b = key.canonical_replay();
        assert_ne!(
            strict_a, strict_b,
            "strict key must include origin_key_state_digest"
        );
        assert_eq!(
            replay_a, replay_b,
            "canonical-replay key must omit origin_key_state_digest"
        );
    }

    /// Non-ignored — pin the historical_only marker against the SDK
    /// constant. Drift between scenario / SDK / soland is what this
    /// gate catches.
    #[test]
    fn historical_only_reason_pin_matches_sdk_constant() {
        assert_eq!(
            HISTORICAL_ONLY_REASON,
            arkret_core::ErrorCode::HISTORICAL_ONLY
        );
    }

    /// Live multi-server e2e — boots real soland + teabay processes via
    /// docker, performs a real key rotation, and observes the federation
    /// idempotency cache HTTP behaviour. Stays `#[ignore]` until the
    /// docker harness is wired.
    /// Gating: needs live soland + teabay binaries via docker plus a key-
    /// rotation harness so the idempotency cache replay can be observed end-
    /// to-end.
    /// Issue: federation-idempotency-e2e-docker
    /// Tier: live
    #[test]
    #[ignore = "TODO(federation-idempotency-e2e-docker): needs live soland + teabay + key rotation harness"]
    fn live_multi_server_federation_historical_only_docker_e2e() {
        // 1. Boot a 2-service test rig (soland-A + teabay-B) with `ak:trust_domain:a` and
        //    `ak:trust_domain:b` respectively.
        // 2. soland-A signs and POSTs a federation_transaction request to teabay-B carrying
        //    Source-/Destination-Trust-Domain headers + Request-Canonical-Digest + Idempotency-Key.
        // 3. Confirm teabay-B caches the response (200 accepted), side effects fire (directory row
        //    inserted, etc.).
        // 4. Rotate soland-A's service key (origin_key_state_digest flips).
        // 5. Replay the same request bytes.
        // 6. Assert teabay-B returns the cached body with `reason_code=historical_only` AND no new
        //    directory rows / push fan-out / index updates.
        // 7. Assert the recorded message-signature transcript includes the three trust-domain
        //    headers (lowercase, RFC 9421 §2.2).
    }
}
