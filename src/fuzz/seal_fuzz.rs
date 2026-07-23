//! C.8 — Seal-envelope deep fuzz harness.
//!
//! Companion to `envelope_fuzz::fuzz_seal_envelope`: this module
//! drives a wider set of `Arbitrary` inputs that exercise the Seal
//! validator's edge cases — long predecessor chains and malformed signatures.
//!
//! Same panic-catch contract as the existing harness: any panic
//! escaping the validator boundary surfaces as `Err(message)`; typed
//! `Result::Err` is acceptable.

use std::panic;

use arbitrary::{Arbitrary, Unstructured};
use arkret_schema as schema;
use arkret_wire::ANCHOR_SCHEMA;
use serde_json::{Value, json};

fn registry() -> arkret_schema::ProtocolSchemaRegistry {
    schema::schema_registry_from_default_spec_artifacts()
        .ok()
        .flatten()
        .unwrap_or_default()
}

fn catch<F: FnOnce() + panic::UnwindSafe>(f: F) -> Result<(), String> {
    match panic::catch_unwind(f) {
        Ok(()) => Ok(()),
        Err(payload) => {
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

/// Wide-range Seal input. Predecessor refs are bounded to keep the
/// harness linear in input size — without the cap, `arbitrary` happily
/// produces multi-megabyte vectors that exercise allocator behaviour
/// rather than the validator.
const MAX_PREDS: usize = 16;
const MAX_DELTA: usize = 16;

#[derive(Debug, Arbitrary)]
pub struct FuzzSealDeepInput {
    pub id: String,
    pub realm_id: String,
    pub control_event_set_root: String,
    pub state_root: String,
    pub completeness_root: String,
    pub notary_seq: u64,
    pub sealed_at: String,
    pub hlc: String,
    pub include_signature: bool,
    pub sig_alg: ArbSigAlg,
    pub sig_value: String,
    pub sig_key: String,
    pub predecessor_count: u8,
    pub delta_count: u8,
    pub predecessor_template: String,
    pub delta_template: String,
}

#[derive(Debug, Arbitrary)]
pub enum ArbSigAlg {
    Ed,
    Es256,
    Es384,
    Es512,
    /// Unknown alg — should be a typed `Err`, not a panic.
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

impl FuzzSealDeepInput {
    fn to_json(&self) -> Value {
        let pred_count = (self.predecessor_count as usize).min(MAX_PREDS);
        let delta_count = (self.delta_count as usize).min(MAX_DELTA);
        let predecessor_refs: Vec<Value> = (0..pred_count)
            .map(|i| Value::String(format!("{}-{i}", self.predecessor_template)))
            .collect();
        let delta: Vec<Value> = (0..delta_count)
            .map(|i| Value::String(format!("{}-{i}", self.delta_template)))
            .collect();
        let mut envelope = json!({
            "id": self.id,
            "realm_id": self.realm_id,
            "predecessor_refs": predecessor_refs,
            "delta": delta,
            "control_event_set_root": self.control_event_set_root,
            "state_root": self.state_root,
            "completeness_root": self.completeness_root,
            "notary_seq": self.notary_seq,
            "sealed_at": self.sealed_at,
            "hlc": self.hlc,
        });
        if self.include_signature {
            envelope["notary_signature"] = json!({
                "alg": self.sig_alg.as_str(),
                "value": self.sig_value,
                "key": self.sig_key,
            });
        }
        envelope
    }
}

/// Drive a Seal envelope through:
///   1. `from_slice` on the raw fuzz bytes (catches wire parser panics);
///   2. Schema validator against `ANCHOR_SCHEMA` (SDK constant name; its value is the current
///      `ak.schema.seal.v1`);
///   3. Typed `from_value::<Seal>` deserialization.
pub fn fuzz_seal_deep(data: &[u8]) -> Result<(), String> {
    catch(|| {
        let _ = serde_json::from_slice::<arkret_wire::Seal>(data);
    })?;
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzSealDeepInput::arbitrary(&mut unstructured) else {
        return Ok(());
    };
    let value = input.to_json();
    catch(|| {
        let _ = registry().validate_value(ANCHOR_SCHEMA, &value);
    })?;
    catch(|| {
        let _ = serde_json::from_value::<arkret_wire::Seal>(value.clone());
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_does_not_panic() {
        let _ = fuzz_seal_deep(&[]);
    }

    #[test]
    fn pathological_input_does_not_panic() {
        // Tiny input — forces `Unstructured` to early-return Err, which the
        // harness must handle without panicking.
        let _ = fuzz_seal_deep(&[0u8]);
        // Slightly larger; exercises the discriminator branches.
        let _ = fuzz_seal_deep(&[0xff; 64]);
        let _ = fuzz_seal_deep(&[0xaa; 4096]);
    }
}
