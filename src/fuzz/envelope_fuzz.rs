//! CT-19 — wire-envelope fuzz harness.
//!
//! Drives random / `Arbitrary`-derived inputs through the SDK's envelope
//! deserializers + schema validators. Any panic, unwrap, or arithmetic
//! overflow escaping the validator boundary is treated as a finding (the
//! caller asserts via `catch_unwind`).
//!
//! Each `fuzz_*` entry point takes opaque `&[u8]` input, derives an
//! `Arbitrary` fuzz struct from it via `Unstructured`, serializes the
//! struct to JSON bytes, and feeds those bytes through the matching SDK
//! validator. All branches return `Ok(())` when the validator either
//! accepts the input or rejects it with a typed `Err` — only a panic
//! escapes via `catch_unwind` (the caller's responsibility).

use std::panic;

use arbitrary::{Arbitrary, Unstructured};
use arkret_core::{ANCHOR_SCHEMA, EVENT_SCHEMA, ProtocolSchemaRegistry, SNAPSHOT_SCHEMA, schema};
use serde::Serialize;
use serde_json::{Value, json};

/// Reusable schema registry. The artifact-backed registry is preferred (it
/// has the published schemas mounted) but falls back to the empty default
/// registry so the harness still runs in environments where the artifact
/// directory is not vendored.
fn registry() -> ProtocolSchemaRegistry {
    schema::schema_registry_from_default_spec_artifacts()
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// Wraps a panic-safe call so a panic inside the validator surfaces as a
/// fuzz finding rather than aborting the test process.
fn catch<F: FnOnce() + panic::UnwindSafe>(f: F) -> Result<(), String> {
    match panic::catch_unwind(f) {
        Ok(()) => Ok(()),
        Err(payload) => {
            // Coerce the panic payload to a readable message so the caller
            // can include the offending fuzz input in the failure report.
            let message = if let Some(s) = payload.downcast_ref::<&'static str>() {
                (*s).to_owned()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "<non-string panic payload>".to_owned()
            };
            Err(message)
        }
    }
}

// ── Event envelope ──────────────────────────────────────────────────────────

/// `arbitrary`-derived input that mirrors the `EventEnvelope` wire shape.
/// All free-form fields (`payload`, `unsigned`, `proofs`, `refs`) use
/// `ArbValue` so the deserializer sees realistic JSON variety.
#[derive(Debug, Arbitrary)]
pub struct FuzzEventInput {
    pub event_id: String,
    pub kind: String,
    pub realm_id: String,
    pub actor_id: String,
    pub actor_seq: u64,
    pub created_at: String,
    pub hlc_physical_ms: u64,
    pub hlc_logical: u32,
    pub prev_refs: Vec<String>,
    pub refs: Vec<ArbRefValue>,
    pub payload: ArbValue,
    pub include_seal_ref: bool,
    pub seal_ref: String,
}

#[derive(Debug, Arbitrary)]
pub struct ArbRefValue {
    pub id: String,
    pub role: String,
    pub critical: bool,
}

impl FuzzEventInput {
    fn to_json(&self) -> Value {
        let hlc = json!({
            "physical_ms": self.hlc_physical_ms,
            "logical": self.hlc_logical,
        });
        let mut envelope = json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "realm_id": self.realm_id,
            "actor_id": self.actor_id,
            "actor_seq": self.actor_seq,
            "created_at": self.created_at,
            "hlc": hlc,
            "prev_refs": self.prev_refs,
            "refs": self.refs.iter().map(|r| json!({
                "id": r.id,
                "role": r.role,
                "critical": r.critical,
            })).collect::<Vec<_>>(),
            "payload": self.payload.0,
            "proofs": [],
        });
        if self.include_seal_ref {
            envelope["seal_ref"] = Value::String(self.seal_ref.clone());
        }
        envelope
    }
}

/// Fuzz the `EventEnvelope` deserialization + schema-validation path.
///
/// Three sub-paths are exercised back-to-back so a panic in any of them is
/// caught:
///   1. Raw `serde_json::from_slice` over the random bytes (catches panics in the wire
///      deserializer).
///   2. `serde_json::from_value::<EventEnvelope>` over the `Arbitrary`-shaped JSON (catches
///      `From<Value>` / `TryFrom` panics, e.g. ID parsers that `unwrap()` on malformed inputs).
///   3. `ProtocolSchemaRegistry::validate_value(EVENT_SCHEMA, ...)` over the same JSON value
///      (catches schema-validator panics on pathological shapes — recursive arrays, deeply nested
///      objects, etc.).
pub fn fuzz_event_envelope(data: &[u8]) -> Result<(), String> {
    catch(|| {
        let _ = serde_json::from_slice::<arkret_core::EventEnvelope>(data);
    })?;
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzEventInput::arbitrary(&mut unstructured) else {
        return Ok(());
    };
    fuzz_via_value(&input.to_json(), EVENT_SCHEMA, |v| {
        let _ = serde_json::from_value::<arkret_core::EventEnvelope>(v.clone());
    })
}

// ── Move envelope ───────────────────────────────────────────────────────────

#[derive(Debug, Arbitrary)]
pub struct FuzzMoveInput {
    pub id: String,
    pub issuer: String,
    pub realm_id: String,
    pub seal_ref: String,
    pub hlc_physical_ms: u64,
    pub hlc_logical: u32,
    pub sig_alg: ArbSigAlg,
    pub sig_value: String,
    pub sig_key: String,
    pub preconditions: Vec<ArbValue>,
    pub effects: Vec<ArbValue>,
    pub refs: Vec<ArbValue>,
}

#[derive(Debug, Arbitrary)]
pub enum ArbSigAlg {
    Ed,
    Es256,
    Es384,
    Es512,
    Junk,
}

impl ArbSigAlg {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Ed => "EdDSA",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Es512 => "ES512",
            Self::Junk => "Foo",
        }
    }
}

impl FuzzMoveInput {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "issuer": self.issuer,
            "realm_id": self.realm_id,
            "preconditions": self.preconditions.iter().map(|v| &v.0).collect::<Vec<_>>(),
            "effects": self.effects.iter().map(|v| &v.0).collect::<Vec<_>>(),
            "seal_ref": self.seal_ref,
            "refs": self.refs.iter().map(|v| &v.0).collect::<Vec<_>>(),
            "hlc": {
                "physical_ms": self.hlc_physical_ms,
                "logical": self.hlc_logical,
            },
            "sig": {
                "alg": self.sig_alg.as_str(),
                "value": self.sig_value,
                "key": self.sig_key,
            }
        })
    }
}

/// Fuzz the `Move` wire shape — same three-stage panic-catch pattern as
/// `fuzz_event_envelope`. Move has no dedicated schema id in the SDK's
/// `*_SCHEMA` constant list, so we skip the `validate_value` leg and rely
/// on `serde_json::from_value::<Move>` to exercise the typed validator.
pub fn fuzz_move_envelope(data: &[u8]) -> Result<(), String> {
    catch(|| {
        let _ = serde_json::from_slice::<arkret_core::Move>(data);
    })?;
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzMoveInput::arbitrary(&mut unstructured) else {
        return Ok(());
    };
    let value = input.to_json();
    catch(|| {
        let _ = serde_json::from_value::<arkret_core::Move>(value.clone());
    })
}

// ── Seal envelope ───────────────────────────────────────────────────────────

#[derive(Debug, Arbitrary)]
pub struct FuzzSealInput {
    pub id: String,
    pub realm_id: String,
    pub predecessor_refs: Vec<String>,
    pub delta: Vec<String>,
    pub control_event_set_root: String,
    pub state_root: String,
    pub completeness_root: String,
    pub notary_seq: u64,
    pub sealed_at: String,
    pub hlc: String,
    pub notary_signature: ArbValue,
}

impl FuzzSealInput {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "realm_id": self.realm_id,
            "predecessor_refs": self.predecessor_refs,
            "delta": self.delta,
            "control_event_set_root": self.control_event_set_root,
            "state_root": self.state_root,
            "completeness_root": self.completeness_root,
            "notary_seq": self.notary_seq,
            "notary_signature": self.notary_signature.0,
            "sealed_at": self.sealed_at,
            "hlc": self.hlc,
        })
    }
}

/// Fuzz the `Seal` wire shape. Uses both `from_slice` over the raw bytes
/// and the artifact-backed `ANCHOR_SCHEMA` validator (SDK constant name;
/// its value is the current `ak.schema.seal.v1`) to exercise both layers.
pub fn fuzz_seal_envelope(data: &[u8]) -> Result<(), String> {
    catch(|| {
        let _ = serde_json::from_slice::<arkret_core::Seal>(data);
    })?;
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzSealInput::arbitrary(&mut unstructured) else {
        return Ok(());
    };
    fuzz_via_value(&input.to_json(), ANCHOR_SCHEMA, |v| {
        let _ = serde_json::from_value::<arkret_core::Seal>(v.clone());
    })
}

// ── Snapshot chunk header ──────────────────────────────────────────────────

#[derive(Debug, Arbitrary)]
pub struct FuzzSnapshotChunkInput {
    pub chunk_id: u32,
    pub digest: String,
    pub bytes_b64url: String,
}

impl FuzzSnapshotChunkInput {
    fn to_json(&self) -> Value {
        json!({
            "chunk_id": self.chunk_id,
            "digest": self.digest,
            "bytes": self.bytes_b64url,
        })
    }
}

/// Fuzz the `SnapshotChunk` wire shape. `SNAPSHOT_SCHEMA` covers the
/// manifest-level envelope, so the schema validator leg uses the snapshot
/// schema id while the typed-deserialization leg uses `SnapshotChunk` to
/// shake out base64-url decoder edge cases (which the existing snapshot
/// chunker `Deserializer::deserialize` impl unwraps internally).
pub fn fuzz_snapshot_chunk(data: &[u8]) -> Result<(), String> {
    catch(|| {
        let _ = serde_json::from_slice::<arkret_core::SnapshotChunk>(data);
    })?;
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzSnapshotChunkInput::arbitrary(&mut unstructured) else {
        return Ok(());
    };
    fuzz_via_value(&input.to_json(), SNAPSHOT_SCHEMA, |v| {
        let _ = serde_json::from_value::<arkret_core::SnapshotChunk>(v.clone());
    })
}

// ── Internal: schema validator + typed deserializer leg ────────────────────

/// Serialize `value` to JSON bytes, then exercise (a) raw `from_slice`,
/// (b) the schema validator for `schema_id`, and (c) a caller-supplied
/// typed deserializer closure. Any panic in any leg is reported.
fn fuzz_via_value<F>(value: &Value, schema_id: &str, typed: F) -> Result<(), String>
where
    F: FnOnce(&Value) + panic::UnwindSafe,
{
    catch(|| {
        if let Ok(bytes) = serde_json::to_vec(value) {
            // Run the deserializer over the canonical bytes too — fuzz inputs
            // sometimes only break the wire parser after one round of
            // re-serialization (e.g. integer-as-string coercion).
            let _ = serde_json::from_slice::<Value>(&bytes);
        }
    })?;
    catch(|| {
        let _ = registry().validate_value(schema_id, value);
    })?;
    catch(|| {
        typed(value);
    })
}

// ── Convenience wrapper for typed re-serialization ─────────────────────────

/// Round-trip a typed envelope through `serde_json::to_value` and back; the
/// smoke test uses this against valid handcrafted envelopes to confirm the
/// fuzz harness's `catch` layer doesn't smother legitimate panics from
/// reachable code paths.
#[allow(dead_code)]
pub fn round_trip_via_value<T>(value: &T) -> Result<(), String>
where
    T: Serialize + serde::de::DeserializeOwned + panic::RefUnwindSafe,
{
    catch(|| {
        let serialized = serde_json::to_value(value).expect("serialize fuzz round-trip value");
        let _ = serde_json::from_value::<T>(serialized);
    })
}

// ── Arbitrary newtype wrappers around `serde_json::Value` ──────────────────
//
// `serde_json::Value` does not (and cannot) implement `Arbitrary` directly
// because it allows unbounded recursion. We bound the recursion depth and
// branching factor here so a single 4 KiB fuzz input cannot explode into a
// gigabytes-of-JSON tree.

/// Bounded random `serde_json::Value`. Depth and array/object length are
/// capped so the harness stays linear in input size.
#[derive(Debug)]
pub struct ArbValue(pub Value);

impl<'a> Arbitrary<'a> for ArbValue {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(arb_value(u, 0)?))
    }
}

const MAX_DEPTH: u32 = 4;
const MAX_BRANCH: usize = 4;

fn arb_value(u: &mut Unstructured<'_>, depth: u32) -> arbitrary::Result<Value> {
    if depth >= MAX_DEPTH {
        return Ok(Value::Null);
    }
    // Tag in [0, 7) — Null / Bool / NumI / NumU / NumF / String / Array / Object.
    let tag: u8 = u.int_in_range(0..=7)?;
    Ok(match tag {
        0 => Value::Null,
        1 => Value::Bool(bool::arbitrary(u)?),
        2 => Value::Number(i64::arbitrary(u)?.into()),
        3 => Value::Number(u64::arbitrary(u)?.into()),
        4 => serde_json::Number::from_f64(f64::arbitrary(u)?).map_or(Value::Null, Value::Number),
        5 => Value::String(String::arbitrary(u)?),
        6 => {
            let len: usize = u.int_in_range(0..=MAX_BRANCH)?;
            let mut arr = Vec::with_capacity(len);
            for _ in 0..len {
                arr.push(arb_value(u, depth + 1)?);
            }
            Value::Array(arr)
        }
        _ => {
            let len: usize = u.int_in_range(0..=MAX_BRANCH)?;
            let mut map = serde_json::Map::with_capacity(len);
            for _ in 0..len {
                let key = String::arbitrary(u)?;
                map.insert(key, arb_value(u, depth + 1)?);
            }
            Value::Object(map)
        }
    })
}
