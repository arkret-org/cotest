//! T8.2 — property-based vectors for canonical JSON convergence.
//!
//! Complements the deterministic `canonical_hash_convergence.rs` KAT
//! suite by generating *random* JSON objects and asserting:
//!
//!  1. **Key order independence.** Encoding the same logical object in two distinct key orders MUST
//!     yield byte-identical canonical bytes.
//!  2. **Idempotency.** Two consecutive `canonical_json_bytes` calls on the same value MUST agree
//!     byte-for-byte.
//!  3. **Hash convergence.** `canonical_sha256` is a function of the logical value alone, not its
//!     representation order.
//!  4. **Unicode invariance.** Strings containing emoji and CJK characters survive the encode →
//!     decode round-trip.
//!  5. **Unknown-field preservation.** Canonicalisation is encoding, not schema-filtering —
//!     extra/unknown fields stay in the bytes.
//!
//! Cases per property are capped at 64.

use cokret_core::canonical::{canonical_json_bytes, canonical_json_string, canonical_sha256};
use proptest::prelude::*;
use serde_json::{Map, Value, json};

const PROPTEST_CASES: u32 = 64;
const MIN_SAFE_JSON_INTEGER: i64 = -9_007_199_254_740_991;
const MAX_SAFE_JSON_INTEGER: i64 = 9_007_199_254_740_991;

fn arb_canonical_string() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof![
            proptest::char::range('\u{0020}', '\u{007E}'),
            proptest::char::range('\u{4E00}', '\u{4F00}'),
            proptest::char::range('\u{1F300}', '\u{1F9FF}'),
        ],
        0..16,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

fn arb_leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (MIN_SAFE_JSON_INTEGER..=MAX_SAFE_JSON_INTEGER).prop_map(|n| json!(n)),
        arb_canonical_string().prop_map(Value::String),
    ]
}

fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = arb_leaf();
    leaf.prop_recursive(3, 32, 4, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            proptest::collection::hash_map("[a-z_][a-z0-9_]{0,8}", inner, 0..4).prop_map(|m| {
                let mut map = Map::new();
                for (k, v) in m {
                    map.insert(k, v);
                }
                Value::Object(map)
            }),
        ]
    })
}

/// Same `Value::Object` rebuilt with reverse insertion order.
fn reverse_keys(value: &Value) -> Value {
    if let Value::Object(map) = value {
        let mut reversed = Map::new();
        let mut keys: Vec<&String> = map.keys().collect();
        keys.reverse();
        for k in keys {
            reversed.insert(k.clone(), reverse_keys(&map[k]));
        }
        Value::Object(reversed)
    } else if let Value::Array(items) = value {
        Value::Array(items.iter().map(reverse_keys).collect())
    } else {
        value.clone()
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    /// Encoding a value in two distinct key orders produces identical
    /// canonical bytes.
    #[test]
    fn canonical_bytes_equal_under_key_permutation(value in arb_value()) {
        let a = canonical_json_bytes(&value).expect("encode a");
        let b = canonical_json_bytes(&reverse_keys(&value)).expect("encode b");
        prop_assert_eq!(a, b);
    }

    /// Encoding is idempotent.
    #[test]
    fn encoding_is_byte_stable(value in arb_value()) {
        let a = canonical_json_bytes(&value).expect("encode 1");
        let b = canonical_json_bytes(&value).expect("encode 2");
        prop_assert_eq!(a, b);
    }

    /// `canonical_sha256` is order-invariant.
    #[test]
    fn canonical_hash_order_invariant(value in arb_value()) {
        let a = canonical_sha256(&value).expect("hash a");
        let b = canonical_sha256(&reverse_keys(&value)).expect("hash b");
        prop_assert_eq!(a, b);
    }

    /// Unicode (emoji, BMP, surrogate pair pieces) survives a canonical
    /// encode → JSON decode round-trip.
    #[test]
    fn unicode_string_round_trip(s in arb_canonical_string()) {
        let value = json!({ "msg": s.clone() });
        let bytes = canonical_json_bytes(&value).expect("encode unicode");
        let parsed: Value = serde_json::from_slice(&bytes).expect("decode canonical bytes");
        prop_assert_eq!(parsed.get("msg").and_then(Value::as_str).map(str::to_owned), Some(s));
    }

    /// Unknown fields are preserved verbatim in the canonical output.
    #[test]
    fn extra_fields_preserved(
        known in "[a-z]{1,8}",
        unknown in "[a-z]{1,8}",
        v1 in arb_leaf(),
        v2 in arb_leaf(),
    ) {
        prop_assume!(known != unknown);
        let value = json!({ known.clone(): v1, unknown.clone(): v2 });
        let s = canonical_json_string(&value).expect("encode");
        prop_assert!(s.contains(&known) && s.contains(&unknown));
    }
}
