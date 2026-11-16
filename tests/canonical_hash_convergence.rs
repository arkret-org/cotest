//! Fixed SDK canonical-encoding and identity-digest vectors.
//! These tests call SDK helpers directly; they do not exercise service writers.

use arkret_canonical::{
    blake3_digest, canonical_hash, canonical_json_bytes, canonical_sha256, verify_digest,
};
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
                "audience": "https://coland.example/_arkret",
                "issued_at": "2026-05-20T00:00:00.000Z",
                "expires_at": "2026-05-20T00:05:00.000Z",
            }),
            // Fixed canonical SHA-256 digest over the fixture above.
            expected_digest: "sha256:d16c9427ace94189dfd45741a7fa22d69b4fb58989c4df362aded31c1893a4f5",
        },
        CanonicalVector {
            vector_id: "ak.cotest_vector.canonical_hash.coland_event_envelope.v1",
            label: "coland event envelope payload",
            // The shape coland hashes inside `validate_event_proofs` after
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
            }),
            // Regenerated after the Realm id in this payload moved to its
            // Event-derived complete digest token: the Realm id sits inside
            // this Event's preimage, so editing it necessarily moves the digest.
            expected_digest: "sha256:51cb96f097b2ae752e9bd35a7784014dcfabd82de2b0cf1bf6c86869acf47eb2",
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
                "audience": "https://coland.example/_arkret",
                "issued_at": "2026-05-20T00:00:00.000Z",
                "expires_at": "2026-05-20T00:05:00.000Z",
            }),
            expected_digest: "sha256:9fa581799dd6b550c912479327c13aa9cab0583ead3571514619f82e50f2c566",
        },
    ]
}

#[test]
fn sdk_canonical_sha256_matches_pinned_vectors() {
    for vector in vectors() {
        let actual = canonical_sha256(&vector.payload).expect("canonical_sha256");
        assert_eq!(
            actual, vector.expected_digest,
            "{} ({})",
            vector.label, vector.vector_id
        );
    }
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

/// Re-encoding the same payload value with permuted object keys MUST
/// yield byte-identical canonical bytes. The SDK encoder sorts object
/// keys before serialisation; an order-sensitive SDK encoder must fail here.
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
            vector.vector_id
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

fn pinned_r3_2_inputs() -> (
    arkret_identifiers::RealmId,
    arkret_wire::ActorId,
    Vec<arkret_models_identity::EffectiveIdentityEntry>,
    Vec<arkret_models_identity::RosterHandleClaimDigestEntry>,
) {
    use arkret_identifiers::{DidCoreId, EventId, Hash, RealmId};
    use arkret_models_identity::{
        EffectiveIdentityEntry, HandleClaimStatus, MemberIdentitySegment,
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
        status: HandleClaimStatus::Verified,
        revocation_digest: None,
        cache_expires_at: chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 6, 20, 0, 0, 0)
            .single()
            .unwrap(),
    }];
    (realm, actor, events, claims)
}

#[test]
fn r3_2_identity_digests_match_pinned_baseline() {
    use arkret_models_identity::{
        member_display_state_digest, member_identity_effective_set_digest,
    };
    let (realm, actor, events, claims) = pinned_r3_2_inputs();

    // `expected_state_digest` — writer-observed effective-set guard over the
    // exact signed payloads (decision 0115); its byte-exact known answers live
    // in expected-state-digest-kat-fixture.json. The empty set digests `[]`.
    let effective_set = member_identity_effective_set_digest(&[]).expect("effective-set digest");
    assert_eq!(
        effective_set, "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
        "member_identity_effective_set_digest of the empty set drifted"
    );

    // Roster projection binds the complete tagged Account actor and canonical
    // UTC milliseconds. Pin the JCS digest of that exact current projection.
    let display_state =
        member_display_state_digest(&realm, &actor, &events, &claims).expect("display digest");
    assert_eq!(
        display_state, "sha256:21f43db8df102ff41543c13ebe686d025700e6e998d06c3ea25cc0aa6e39990a",
        "member_display_state_digest baseline drifted (R3.2 VECT-COT-5)"
    );

    // The two digests MUST be distinct (different formula + inputs).
    assert_ne!(
        effective_set, display_state,
        "expected_state_digest and member_display_state_digest MUST differ"
    );
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
