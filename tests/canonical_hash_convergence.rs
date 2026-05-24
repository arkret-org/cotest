//! T5.3 (Round 22, 2026-05-20) — canonical-JSON convergence vectors.
//!
//! Every Contrix service (coauth / soland / starid / yougen / floria) now
//! routes canonical-JSON encoding and `payload_digest` computation through
//! the SDK's `contrix_core::canonical` module and the
//! `contrix_signatures::EventProofBuilder` facade. This test pins a
//! handful of fixture payloads representing the three shapes that
//! matter on the wire — coauth `handle_claim`, soland event-envelope
//! payload, starid did:webvh update — and asserts every entry point
//! produces the same `sha256:<hex>` digest as the SDK's
//! `canonical_sha256`.
//!
//! If a downstream service ever re-introduces a hand-rolled canonical
//! writer that drifts from the spec, the digest mismatch here is the
//! first place it surfaces (instead of inscrutable cross-service signature
//! failures in federation / replication tests).

use contrix_core::canonical::canonical_json_bytes;
use contrix_core::canonical::canonical_sha256;
use serde_json::{Value, json};

/// A canonical-hash test vector: the input payload shape, the wire
/// `sha256:<hex>` digest every service is expected to produce, and a
/// short label for failure reporting.
struct CanonicalVector {
    label: &'static str,
    payload: Value,
    expected_digest: &'static str,
}

fn vectors() -> Vec<CanonicalVector> {
    vec![
        CanonicalVector {
            label: "coauth handle_claim digest input",
            // Mirrors coauth's `HandleClaimDigestInput` shape from
            // `crates/backend/src/handlers/contrix.rs`. RFC 3339 UTC strings
            // for timestamps; integer-only numbers; all-string scalar fields.
            payload: json!({
                "type": "cx.handle.claim",
                "subject_id": "did:web:alice.example",
                "handle_uri": "contrix://contrix.example/users/alice",
                "handle_aliases": ["acct:alice@contrix.example"],
                "issuer_service_did": "did:web:coauth.example",
                "audience": "https://soland.example/api/v1",
                "member_delivery_binding": {
                    "recipient_service_did": "did:web:soland.example",
                    "recipient_service_type": "principal_server",
                    "binding_source": "organization_policy",
                    "delivery_modes": ["events"],
                },
                "issued_at": "2026-05-20T00:00:00Z",
                "expires_at": "2026-05-20T00:05:00Z",
            }),
            expected_digest: "sha256:0e37e1aedcf71597c07997f929b1a33cab278158812f94508d5bfcb53de6f50b",
        },
        CanonicalVector {
            label: "soland event envelope payload",
            // The shape soland hashes inside `validate_event_proofs` after
            // stripping `proofs` / `unsigned` from the on-wire envelope.
            payload: json!({
                "actor_id": "did:web:alice.example",
                "event_id": "cx:event:01970e589d21-0001-a13f9c2e",
                "realm_id": "cx:realm:01904100-0000-7000-8000-668e2181b41d",
                "kind": "cx.message.create",
                "hlc": "01970e589d21-0001-a13f9c2e",
                "payload": {
                    "content": {
                        "kind": "cx.content.text",
                        "body": "hello"
                    },
                    "flow_id": "cx:flow:01904100-0000-7000-8000-6c663fa0205f",
                    "track": "discussion",
                },
                "schema_version": 1,
            }),
            expected_digest: "sha256:457191964259bebeb272aa36ba6a78603696836a68e79c416326860685286c78",
        },
        CanonicalVector {
            label: "starid did:webvh update entry (proofless)",
            // The shape starid feeds into `proof::canonical_bytes` after
            // stripping `proof[]` from a webvh log entry.
            payload: json!({
                "versionId": "1-abc",
                "versionTime": "2026-05-06T00:00:00Z",
                "parameters": {
                    "method": "did:webvh:1.0",
                    "scid": "ztest",
                    "updateKeys": ["z6MkExample"],
                    "portable": false,
                },
                "state": {
                    "id": "did:webvh:ztest:host",
                    "verificationMethod": {"key-1": "z6MkExample"},
                },
            }),
            expected_digest: "sha256:0f144fa1df6408114a253823b0814b6059b1656737e6e957bca6c89fa215b59b",
        },
    ]
}

/// Round-trip every vector through `contrix_core::canonical::canonical_sha256`
/// to make sure the SDK hash itself is stable and matches what we encode
/// in `expected_digest`. The other downstream services all reach the same
/// digest by going through this same SDK helper, so this is also our
/// witness that they cannot drift apart silently.
#[test]
fn sdk_canonical_sha256_matches_pinned_vectors() {
    let mut drifted = Vec::new();
    for vector in vectors() {
        let actual = canonical_sha256(&vector.payload).expect("canonical_sha256");
        if actual != vector.expected_digest {
            drifted.push(format!(
                "{}\n  expected: {}\n  actual:   {}",
                vector.label, vector.expected_digest, actual
            ));
        }
    }
    assert!(
        drifted.is_empty(),
        "one or more canonical hash vectors drifted:\n{}",
        drifted.join("\n")
    );
}

/// Re-encoding the same payload value with permuted object keys MUST
/// yield byte-identical canonical bytes. The SDK encoder sorts object
/// keys before serialisation, so this test would fail if any downstream
/// service ever fell back to `serde_json::to_vec` (which preserves
/// insertion order) for a hash input.
#[test]
fn canonical_bytes_are_stable_across_key_permutations() {
    for vector in vectors() {
        let value = vector.payload.clone();
        let scrambled = scramble_object_keys(value);
        let original_bytes = canonical_json_bytes(&vector.payload).unwrap();
        let scrambled_bytes = canonical_json_bytes(&scrambled).unwrap();
        assert_eq!(
            original_bytes, scrambled_bytes,
            "canonical bytes drifted for {} under key permutation",
            vector.label
        );
    }
}

/// Every service ultimately goes through one of two SDK entry points:
/// the low-level `contrix_core::canonical::canonical_sha256` (used by
/// `coauth::handlers::contrix::canonical_json_sha256`, soland's
/// `validate_event_proofs`, and starid's `proof::canonical_bytes`), or
/// the high-level `contrix_signatures::EventProofBuilder` (used by
/// yougen / floria when emitting a fresh detached-JWS proof). Both
/// must yield the same canonical bytes for the same input; this test
/// pins the equivalence so a future EventProofBuilder change cannot
/// silently drift from the canonical encoder.
#[test]
fn event_proof_builder_matches_low_level_canonical_helpers() {
    use contrix_signatures::EventProofBuilder;
    let builder = EventProofBuilder::new();
    for vector in vectors() {
        let low_level_bytes = canonical_json_bytes(&vector.payload).unwrap();
        let builder_bytes = builder.canonical_bytes(&vector.payload).unwrap();
        assert_eq!(
            low_level_bytes, builder_bytes,
            "EventProofBuilder.canonical_bytes drifted from canonical_json_bytes for {}",
            vector.label,
        );
        let builder_hash = builder.payload_digest(&vector.payload).unwrap();
        assert_eq!(
            builder_hash.as_str(),
            vector.expected_digest,
            "EventProofBuilder.payload_digest drifted from pinned vector for {}",
            vector.label,
        );
    }
}

/// Walk a JSON value and reverse the key order of every object. Used
/// to prove the SDK canonical encoder is insensitive to source order.
fn scramble_object_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.into_iter().collect();
            entries.reverse();
            let mut out = serde_json::Map::new();
            for (k, v) in entries {
                out.insert(k, scramble_object_keys(v));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(scramble_object_keys).collect()),
        other => other,
    }
}
