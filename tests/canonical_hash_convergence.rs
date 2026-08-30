//! T5.3 (Round 22, 2026-05-20) — canonical-JSON convergence vectors.
//!
//! Every Arkret service (coauth / soland / inkson / floria) now
//! routes canonical-JSON encoding and `payload_digest` computation through
//! the SDK's `arkret_canonical` module and the
//! `arkret_signatures::EventProofBuilder` facade. This test pins a
//! handful of fixture payloads representing the three shapes that
//! matter on the wire — coauth `handle_claim`, soland event-envelope
//! payload, did:webvh log update — and asserts every entry point
//! produces the same `sha256:<hex>` digest as the SDK's
//! `canonical_sha256`.
//!
//! If a downstream service ever re-introduces a hand-rolled canonical
//! writer that drifts from the spec, the digest mismatch here is the
//! first place it surfaces (instead of inscrutable cross-service signature
//! failures in federation / replication tests).

use arkret_canonical::{
    blake3_digest, canonical_hash, canonical_json_bytes, canonical_sha256, verify_digest,
};
use cotest::conformance::{CanonicalFixtureBuilder, CanonicalFixtureSuite};
use serde_json::{Value, json};

/// A canonical-hash test vector: the input payload shape, the wire
/// `sha256:<hex>` digest every service is expected to produce, and a
/// short label for failure reporting.
struct CanonicalVector {
    vector_id: &'static str,
    label: &'static str,
    payload: Value,
    expected_digest: &'static str,
}

fn vectors() -> Vec<CanonicalVector> {
    vec![
        CanonicalVector {
            vector_id: "ak.cotest_vector.canonical_hash.coauth_handle_claim.v1",
            label: "coauth handle_claim digest input",
            // Mirrors coauth's `HandleClaimDigestInput` shape from
            // `crates/backend/src/handlers/arkret.rs`. RFC 3339 UTC strings
            // for timestamps; integer-only numbers; all-string scalar fields.
            //
            // R3.1 wire rename (arkret-spec @ 7157ee8): the previous
            // `handle_uri: "arkret://arkret.example/users/alice"` field
            // is now `handle: "alice:arkret.example"`. Field order is
            // irrelevant in canonical JSON (keys are sorted), but the digest
            // changes because both the field name and the value bytes change.
            payload: json!({
                "type": "ak.handle.claim",
                "subject_account_id": {
                    "principal_id": "ak:did_core:web:alice.example",
                    "station_id": "ak:did_core:web:station.example"
                },
                "handle": "alice:arkret.example",
                "handle_aliases": ["acct:alice@arkret.example"],
                "issuer_id": "ak:did_core:web:coauth.example",
                "audience": "https://soland.example/_arkret",
                "issued_at": "2026-05-20T00:00:00.000Z",
                "expires_at": "2026-05-20T00:05:00.000Z",
            }),
            // R3.1 digest — recomputed after the `handle_uri` → `handle`
            // wire rename. Source of truth: SDK's
            // `arkret_canonical::canonical_sha256` over the canonical
            // JSON bytes of the payload above. If this digest drifts, the
            // first place to look is whether any downstream service has
            // re-introduced a hand-rolled canonical encoder. To regenerate:
            // `cargo test -p cotest --test canonical_hash_convergence \
            //  dump_canonical_digests -- --ignored --nocapture`.
            expected_digest: "sha256:be0d07256d6f5fb2a889cd88e87f6099792bb7e4fb0f6e518f6d00e2c2a6717a",
        },
        CanonicalVector {
            vector_id: "ak.cotest_vector.canonical_hash.soland_event_envelope.v1",
            label: "soland event envelope payload",
            // The shape soland hashes inside `validate_event_proofs` after
            // stripping `proofs` / `unsigned` from the on-wire envelope.
            payload: json!({
                "actor_id": "ak:did_core:web:alice.example",
                "event_id": "ak:event:AaIU5-FloksbTF8lIRYIpxdzmtMlKw6ZQ46eU2SAH2-4",
                "realm_id": "ak:realm:AQptIWDEF2d4jlsnzTQVXGqZs6h-vPkYXuYqwewKqIjr",
                "kind": "ak.message.create",
                "hlc": "01970e589d21-0001-a13f9c2e",
                "payload": {
                    "content": {
                        "kind": "ak.content.text",
                        "body": "hello"
                    },
                    "strand_id": "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9",
                    "track_name": "discussion",
                },
                "schema_version": 1,
            }),
            // Regenerated after the Realm id in this payload moved to its
            // Event-derived complete digest token: the Realm id sits inside
            // this Event's preimage, so editing it necessarily moves the digest.
            expected_digest: "sha256:55d6eae483299a0a39625377a63f7d4416374d9544c9974632a007d725f8454c",
        },
        CanonicalVector {
            vector_id: "ak.cotest_vector.canonical_hash.webvh_log_update.v1",
            label: "did:webvh update entry (proofless)",
            // The shape a did:webvh provider feeds into the canonical proof
            // encoder after stripping `proof[]` from a webvh log entry.
            payload: json!({
                "versionId": "1-abc",
                "versionTime": "2026-05-06T00:00:00.000Z",
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
            expected_digest: "sha256:cda74f4697a972c9bd6c70add695d13ddf6508dc737d629587e6de0644246a80",
        },
        CanonicalVector {
            vector_id: "ak.cotest_vector.canonical_hash.webvh_default_handle_claim.v1",
            label: "coauth handle_claim digest input (did:webvh default subjects)",
            // identity-did.md §3: v1 core defaults BOTH principal and service
            // DIDs to `did:webvh`; `did:web` is reserved for explicit no-history
            // / personal_node profiles + method-adapter tests. The other vectors
            // here exercise `did:web` (still a MUST-support method); this one
            // pins canonical convergence on the DEFAULT `did:webvh:<scid>:…`
            // path so a service that hand-rolls canonical encoding for the
            // default method drifts the digest here first. The SCID below is a
            // fixed deterministic test constant (NOT a live anchored value).
            payload: json!({
                "type": "ak.handle.claim",
                "subject_account_id": {
                    "principal_id": "ak:did_core:webvh:zcotesthandleclaimscid000000000000",
                    "station_id": "ak:did_core:webvh:zcoteststationscid000000000000000"
                },
                "handle": "alice:arkret.example",
                "handle_aliases": ["acct:alice@arkret.example"],
                "issuer_id": "ak:did_core:webvh:zcotestcoauthscid0000000000000000",
                "audience": "https://soland.example/_arkret",
                "issued_at": "2026-05-20T00:00:00.000Z",
                "expires_at": "2026-05-20T00:05:00.000Z",
            }),
            // Pinned via `cargo test -p cotest --test canonical_hash_convergence \
            //  dump_canonical_digests -- --ignored --nocapture`.
            expected_digest: "sha256:8f880c851f355ced30f48526fa91c37813159d9263e10c30331ee551020ff2d7",
        },
    ]
}

fn canonical_fixture_suite() -> CanonicalFixtureSuite {
    let mut builder = CanonicalFixtureBuilder::new("ak.profile.cotest.canonical_hash.v1")
        .version("2026-06-19")
        .description("Canonical hash convergence vectors shared through the SDK fixture builder.");
    for vector in vectors() {
        builder
            .push(vector.vector_id, &vector.payload)
            .expect("build canonical fixture vector");
    }
    builder.finish()
}

/// Round-trip every vector through `arkret_canonical::canonical_sha256`
/// to make sure the SDK hash itself is stable and matches what we encode
/// in `expected_digest`. The other downstream services all reach the same
/// digest by going through this same SDK helper, so this is also our
/// witness that they cannot drift apart silently.
#[test]
fn sdk_canonical_sha256_matches_pinned_vectors() {
    let mut drifted = Vec::new();
    let suite = canonical_fixture_suite();
    for (vector, generated) in vectors().into_iter().zip(suite.vectors.iter()) {
        generated
            .assert_matches_input()
            .expect("fixture self-check");
        let actual = canonical_sha256(&generated.input).expect("canonical_sha256");
        if actual != vector.expected_digest || generated.expected_digest != vector.expected_digest {
            drifted.push(format!(
                "{}\n  expected: {}\n  builder:  {}\n  actual:   {}",
                vector.label, vector.expected_digest, generated.expected_digest, actual
            ));
        }
    }
    assert!(
        drifted.is_empty(),
        "one or more canonical hash vectors drifted:\n{}",
        drifted.join("\n")
    );
}

#[test]
fn sdk_blake3_digest_backend_matches_known_vector() {
    let digest = blake3_digest(b"");
    assert_eq!(
        digest,
        "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
    assert!(arkret_identifiers::Hash::new(digest.clone()).is_ok());
    verify_digest(b"", &digest).expect("empty BLAKE3 digest verifies");
    assert!(verify_digest(b"not-empty", &digest).is_err());

    let payload = json!({ "b": 2, "a": 1 });
    let canonical = canonical_hash(&payload, "blake3").expect("canonical BLAKE3");
    assert!(canonical.starts_with("blake3:"));
    assert!(arkret_identifiers::Hash::new(canonical).is_ok());
}

/// Diagnostic: prints the SDK-computed canonical digest for every vector.
/// Run with `cargo test -p cotest --test canonical_hash_convergence \
/// dump_canonical_digests -- --nocapture` to regenerate the pinned values
/// after a fixture rename.
/// Gating: diagnostic-only — prints canonical digests; run explicitly with
/// `--nocapture` after a fixture rename.
/// Tier: contract
#[test]
#[ignore = "diagnostic — run with --nocapture to print canonical digests"]
fn dump_canonical_digests() {
    for vector in canonical_fixture_suite().vectors {
        println!("{} => {}", vector.vector_id, vector.expected_digest);
    }
}

/// Re-encoding the same payload value with permuted object keys MUST
/// yield byte-identical canonical bytes. The SDK encoder sorts object
/// keys before serialisation, so this test would fail if any downstream
/// service ever fell back to `serde_json::to_vec` (which preserves
/// insertion order) for a hash input.
#[test]
fn canonical_bytes_are_stable_across_key_permutations() {
    for vector in canonical_fixture_suite().vectors {
        let value = vector.input.clone();
        let scrambled = scramble_object_keys(value);
        let original_bytes = canonical_json_bytes(&vector.input).unwrap();
        let scrambled_bytes = canonical_json_bytes(&scrambled).unwrap();
        assert_eq!(
            original_bytes, scrambled_bytes,
            "canonical bytes drifted for {} under key permutation",
            vector.vector_id
        );
    }
}

/// Every service ultimately goes through one of two SDK entry points:
/// the low-level `arkret_canonical::canonical_sha256` (used by
/// `coauth::handlers::arkret::canonical_json_sha256` and soland's
/// `validate_event_proofs`), or
/// the high-level `arkret_signatures::EventProofBuilder` (used by
/// inkson / floria when emitting a fresh detached-JWS proof). Both
/// must yield the same canonical bytes for the same input; this test
/// pins the equivalence so a future EventProofBuilder change cannot
/// silently drift from the canonical encoder.
#[test]
fn event_proof_builder_matches_low_level_canonical_helpers() {
    use arkret_signatures::EventProofBuilder;
    let builder = EventProofBuilder::new();
    for vector in canonical_fixture_suite().vectors {
        let low_level_bytes = canonical_json_bytes(&vector.input).unwrap();
        let builder_bytes = builder.canonical_bytes(&vector.input).unwrap();
        assert_eq!(
            low_level_bytes, builder_bytes,
            "EventProofBuilder.canonical_bytes drifted from canonical_json_bytes for {}",
            vector.vector_id,
        );
        let builder_hash = builder.payload_digest(&vector.input).unwrap();
        assert_eq!(
            builder_hash.as_str(),
            vector.expected_digest,
            "EventProofBuilder.payload_digest drifted from pinned vector for {}",
            vector.vector_id,
        );
    }
}

// ─── R3.2 (arkret-spec @ b56cab1) — MemberIdentity / roster digests ──────
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
    arkret_identifiers::RealmId,
    arkret_wire::ActorId,
    Vec<arkret_models_identity::EffectiveIdentityEntry>,
    Vec<arkret_models_identity::RosterHandleClaimDigestEntry>,
) {
    use arkret_identifiers::{DidCoreId, EventId, Hash, RealmId};
    use arkret_models_identity::{
        EffectiveIdentityEntry, HandleBindingState, MemberIdentitySegment,
        RosterHandleClaimDigestEntry,
    };

    let realm = RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K").unwrap();
    let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        DidCoreId::new("ak:did_core:web:alice.acme.example".to_owned()).unwrap(),
        DidCoreId::new("ak:did_core:web:station.acme.example".to_owned()).unwrap(),
    ));
    let events = vec![
        EffectiveIdentityEntry {
            event_id: EventId::new("ak:event:AaaV5G8rACWz0A_AfDNtAvW_ConNcll4oFZ_LaD4uJgJ")
                .unwrap(),
            segment: MemberIdentitySegment::MemberIdentity,
            payload_digest: Hash::new(
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap(),
        },
        EffectiveIdentityEntry {
            event_id: EventId::new("ak:event:AVSR9-fIfK6zH9lp2bY3NSMx92UnNqdqIre2mtDySANm")
                .unwrap(),
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
    use arkret_models_identity::{
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
        effective_set, "sha256:ae2a995158ba4c13a2230f708cf4eaea6dbeeb3834af30bceb534cf354d79dc8",
        "member_identity_effective_set_digest baseline drifted (R3.2 VECT-COT-5)"
    );

    // roster `member_display_state_digest` — folds visible handle claims.
    let display_state =
        member_display_state_digest(&realm, &actor, &events, &claims).expect("display digest");
    assert_eq!(
        display_state, "sha256:969393d2016a3485391441f28e009c4ac529df6763791d9aab35ccddaea7fee0",
        "member_display_state_digest baseline drifted (R3.2 VECT-COT-5)"
    );

    // The two digests MUST be distinct (different formula + inputs).
    assert_ne!(
        effective_set, display_state,
        "expected_state_digest and member_display_state_digest MUST differ"
    );
}

/// Gating: diagnostic-only — regenerates the R3.2 identity digest baseline;
/// run explicitly with `--nocapture`.
/// Tier: contract
#[test]
#[ignore = "diagnostic — run with --nocapture to regenerate the R3.2 identity digest baseline"]
fn dump_r3_2_identity_digests() {
    use arkret_models_identity::{
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
