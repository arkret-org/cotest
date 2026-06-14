//! T5.3 (Round 22, 2026-05-20) — canonical-JSON convergence vectors.
//!
//! Every Cokret service (coauth / soland / starid / yougen / floria) now
//! routes canonical-JSON encoding and `payload_digest` computation through
//! the SDK's `cokret_core::canonical` module and the
//! `cokret_signatures::EventProofBuilder` facade. This test pins a
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

use cokret_core::canonical::{canonical_json_bytes, canonical_sha256};
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
            // `crates/backend/src/handlers/cokret.rs`. RFC 3339 UTC strings
            // for timestamps; integer-only numbers; all-string scalar fields.
            //
            // R3.1 wire rename (cokret-spec @ 7157ee8): the previous
            // `handle_uri: "cokret://cokret.example/users/alice"` field
            // is now `handle: "alice:cokret.example"`. Field order is
            // irrelevant in canonical JSON (keys are sorted), but the digest
            // changes because both the field name and the value bytes change.
            payload: json!({
                "type": "ck.handle.claim",
                "subject_id": "did:web:alice.example",
                "handle": "alice:cokret.example",
                "handle_aliases": ["acct:alice@cokret.example"],
                "issuer_service_did": "did:web:coauth.example",
                "audience": "https://soland.example/_cokret",
                "member_delivery_binding": {
                    "recipient_service_did": "did:web:soland.example",
                    "recipient_service_type": "principal_server",
                    "binding_source": "organization_policy",
                    "delivery_modes": ["events"],
                },
                "issued_at": "2026-05-20T00:00:00Z",
                "expires_at": "2026-05-20T00:05:00Z",
            }),
            // R3.1 digest — recomputed after the `handle_uri` → `handle`
            // wire rename. Source of truth: SDK's
            // `cokret_core::canonical::canonical_sha256` over the canonical
            // JSON bytes of the payload above. If this digest drifts, the
            // first place to look is whether any downstream service has
            // re-introduced a hand-rolled canonical encoder. To regenerate:
            // `cargo test -p cotest --test canonical_hash_convergence \
            //  dump_canonical_digests -- --ignored --nocapture`.
            expected_digest: "sha256:36d8d1066819cdae75cfc9ff759eb84ac406be79e09aa6fe7b4d3134efeb6bd7",
        },
        CanonicalVector {
            label: "soland event envelope payload",
            // The shape soland hashes inside `validate_event_proofs` after
            // stripping `proofs` / `unsigned` from the on-wire envelope.
            payload: json!({
                "actor_id": "did:web:alice.example",
                "event_id": "ck:event:01970e589d21-0001-a13f9c2e",
                "realm_id": "ck:realm:01904100-0000-7000-8000-668e2181b41d",
                "kind": "ck.message.create",
                "hlc": "01970e589d21-0001-a13f9c2e",
                "payload": {
                    "content": {
                        "kind": "ck.content.text",
                        "body": "hello"
                    },
                    "strand_id": "ck:strand:01904100-0000-7000-8000-6c663fa0205f",
                    "track_name": "discussion",
                },
                "schema_version": 1,
            }),
            expected_digest: "sha256:c6ac8d2252b00d8185070dcd700bfadc5109d871d6ad4a9c74386790740e7fa0",
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

/// Round-trip every vector through `cokret_core::canonical::canonical_sha256`
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

/// Diagnostic: prints the SDK-computed canonical digest for every vector.
/// Run with `cargo test -p cotest --test canonical_hash_convergence \
/// dump_canonical_digests -- --nocapture` to regenerate the pinned values
/// after a fixture rename.
#[test]
#[ignore = "diagnostic — run with --nocapture to print canonical digests"]
fn dump_canonical_digests() {
    for vector in vectors() {
        let actual = canonical_sha256(&vector.payload).expect("canonical_sha256");
        println!("{} => {}", vector.label, actual);
    }
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
/// the low-level `cokret_core::canonical::canonical_sha256` (used by
/// `coauth::handlers::cokret::canonical_json_sha256`, soland's
/// `validate_event_proofs`, and starid's `proof::canonical_bytes`), or
/// the high-level `cokret_signatures::EventProofBuilder` (used by
/// yougen / floria when emitting a fresh detached-JWS proof). Both
/// must yield the same canonical bytes for the same input; this test
/// pins the equivalence so a future EventProofBuilder change cannot
/// silently drift from the canonical encoder.
#[test]
fn event_proof_builder_matches_low_level_canonical_helpers() {
    use cokret_signatures::EventProofBuilder;
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

// ─── R3.2 (cokret-spec @ b56cab1) — MemberIdentity / roster digests ──────
//
// VECT-COT-5: the R3.2 wire-breaking rename split the single
// `identity_state_digest` into three distinct digests with distinct
// formulas. This baseline pins each helper's `sha256:<hex>` output over a
// fully-pinned fixture so a future formula drift in the SDK surfaces here
// first (instead of as a cross-service cache mismatch).
//
// To regenerate after an intentional formula change:
//   cargo test -p cotest --test canonical_hash_convergence \
//     dump_r3_2_identity_digests -- --ignored --nocapture

fn pinned_r3_2_inputs() -> (
    cokret_core::RealmId,
    cokret_core::Did,
    Vec<cokret_core::models::EffectiveIdentityEntry>,
    Vec<cokret_core::models::RosterHandleClaimDigestEntry>,
) {
    use cokret_core::models::{
        EffectiveIdentityEntry, HandleBindingState, MemberIdentitySegment,
        RosterHandleClaimDigestEntry,
    };
    use cokret_core::{Did, EventId, Hash, RealmId};

    let realm = RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap();
    let actor = Did::new("did:web:alice.acme.example".to_owned()).unwrap();
    let events = vec![
        EffectiveIdentityEntry {
            event_id: EventId::new("ck:event:01904100-0000-7000-8000-000000000a01").unwrap(),
            segment: MemberIdentitySegment::MemberIdentity,
            payload_digest: Hash::new(
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap(),
        },
        EffectiveIdentityEntry {
            event_id: EventId::new("ck:event:01904100-0000-7000-8000-000000000a02").unwrap(),
            segment: MemberIdentitySegment::MemberIdentity,
            payload_digest: Hash::new(
                "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            )
            .unwrap(),
        },
    ];
    let claims = vec![RosterHandleClaimDigestEntry {
        claim_digest: Hash::new(
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        )
        .unwrap(),
        binding_state: HandleBindingState::Verified,
        expires_at: Some(
            chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 6, 20, 0, 0, 0)
                .single()
                .unwrap(),
        ),
    }];
    (realm, actor, events, claims)
}

#[test]
fn r3_2_identity_digests_match_pinned_baseline() {
    use cokret_core::models::{
        MemberIdentitySegment, member_display_state_digest, member_identity_effective_set_digest,
    };
    let (realm, actor, events, claims) = pinned_r3_2_inputs();

    // `expected_state_digest` — writer-observed effective-set guard.
    let effective_set = member_identity_effective_set_digest(
        &realm,
        &actor,
        MemberIdentitySegment::MemberIdentity,
        &events,
    )
    .expect("effective-set digest");
    assert_eq!(
        effective_set, "sha256:d9ea65535af71900678142cac05baa63edb10e63451cbc322a69dec0c6731372",
        "member_identity_effective_set_digest baseline drifted (R3.2 VECT-COT-5)"
    );

    // roster `member_display_state_digest` — folds visible handle claims.
    let display_state =
        member_display_state_digest(&realm, &actor, &events, &claims).expect("display digest");
    assert_eq!(
        display_state, "sha256:abc38bb7cfdd01535018bf8e7ec866f094657c48efa5b5a100689dc39f087cd3",
        "member_display_state_digest baseline drifted (R3.2 VECT-COT-5)"
    );

    // The two digests MUST be distinct (different formula + inputs).
    assert_ne!(
        effective_set, display_state,
        "expected_state_digest and member_display_state_digest MUST differ"
    );
}

#[test]
#[ignore = "diagnostic — run with --nocapture to regenerate the R3.2 identity digest baseline"]
fn dump_r3_2_identity_digests() {
    use cokret_core::models::{
        MemberIdentitySegment, member_display_state_digest, member_identity_effective_set_digest,
    };
    let (realm, actor, events, claims) = pinned_r3_2_inputs();
    let effective_set = member_identity_effective_set_digest(
        &realm,
        &actor,
        MemberIdentitySegment::MemberIdentity,
        &events,
    )
    .expect("effective-set digest");
    let display_state =
        member_display_state_digest(&realm, &actor, &events, &claims).expect("display digest");
    println!("member_identity_effective_set_digest => {effective_set}");
    println!("member_display_state_digest         => {display_state}");
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
