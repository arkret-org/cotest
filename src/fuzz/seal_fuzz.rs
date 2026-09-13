//! C.8 — Seal-envelope deep fuzz harness.
//!
//! Companion to `envelope_fuzz::fuzz_seal_envelope`: this module
//! drives a wider set of `Arbitrary` inputs that exercise the Seal
//! validator's edge cases — predecessor linkage and malformed signatures.
//!
//! Same panic-catch contract as the existing harness: any panic
//! escaping the validator boundary surfaces as `Err(message)`; typed
//! `Result::Err` is acceptable.

use arbitrary::{Arbitrary, Unstructured};
use arkret_wire::SchemaId;
use serde_json::{Value, json};

use super::envelope_fuzz::ArbValue;
use super::panic_guard::catch;

fn registry() -> arkret_schema::ProtocolSchemaRegistry {
    arkret_schema_conformance::schema_registry_from_default_spec_artifacts()
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// Wide-range Seal input.
const MAX_DELTA: usize = 16;

#[derive(Debug, Arbitrary)]
pub struct FuzzSealDeepInput {
    pub id: String,
    pub realm_id: String,
    pub control_event_set_root: String,
    pub state_root: String,
    pub notary_seq: u64,
    pub sealed_at: String,
    pub hlc: String,
    pub include_signature: bool,
    pub include_predecessor: bool,
    pub delta_count: u8,
    pub predecessor_template: String,
    pub delta_template: String,
    pub availability_receipt_digests: Vec<String>,
    pub configuration_ref: String,
    pub command_results: ArbValue,
    pub notary_signature: ArbValue,
}

impl FuzzSealDeepInput {
    fn to_json(&self) -> Value {
        let delta_count = (self.delta_count as usize).min(MAX_DELTA);
        let predecessor_ref = if self.include_predecessor {
            Value::String(self.predecessor_template.clone())
        } else {
            Value::Null
        };
        let delta: Vec<Value> = (0..delta_count)
            .map(|i| Value::String(format!("{}-{i}", self.delta_template)))
            .collect();
        let mut envelope = json!({
            "id": self.id,
            "realm_id": self.realm_id,
            "predecessor_ref": predecessor_ref,
            "delta": delta,
            "control_event_set_root": self.control_event_set_root,
            "state_root": self.state_root,
            "notary_seq": self.notary_seq,
            "availability_receipt_digests": self.availability_receipt_digests,
            "sealed_at": self.sealed_at,
            "hlc": self.hlc,
            "configuration_ref": self.configuration_ref,
            "command_results": self.command_results.0,
        });
        if self.include_signature {
            envelope["notary_signature"] = self.notary_signature.0.clone();
        }
        envelope
    }
}

/// Drive a Seal envelope through:
///   1. `from_slice` on the raw fuzz bytes (catches wire parser panics);
///   2. Schema validator against `SchemaId::SEAL_V1` (SDK constant name; its value is the current
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
        let _ = registry().validate_value(SchemaId::SEAL_V1, &value);
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
