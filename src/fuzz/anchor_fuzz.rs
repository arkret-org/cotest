//! C.8 — Anchor-envelope deep fuzz harness.
//!
//! Companion to `envelope_fuzz::fuzz_anchor_envelope`: this module
//! drives a wider set of `Arbitrary` inputs that exercise the anchor
//! validator's edge cases — long predecessor chains, conflicting kind
//! discriminators, and malformed signatures.
//!
//! Same panic-catch contract as the existing harness: any panic
//! escaping the validator boundary surfaces as `Err(message)`; typed
//! `Result::Err` is acceptable.

use std::panic;

use arbitrary::{Arbitrary, Unstructured};
use serde_json::{Value, json};

use contrix_core::{ANCHOR_SCHEMA, schema};

fn registry() -> contrix_core::ProtocolSchemaRegistry {
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

/// Wide-range anchor input. Predecessor refs are bounded to keep the
/// harness linear in input size — without the cap, `arbitrary` happily
/// produces multi-megabyte vectors that exercise allocator behaviour
/// rather than the validator.
const MAX_PREDS: usize = 16;
const MAX_FRONTIER: usize = 16;

#[derive(Debug, Arbitrary)]
pub struct FuzzAnchorDeepInput {
    pub id: String,
    pub realm_id: String,
    pub state_root: String,
    pub anchored_at: String,
    pub hlc_physical_ms: u64,
    pub hlc_logical: u32,
    pub include_signature: bool,
    pub sig_alg: ArbSigAlg,
    pub sig_value: String,
    pub sig_key: String,
    pub predecessor_count: u8,
    pub frontier_count: u8,
    pub predecessor_template: String,
    pub frontier_template: String,
}

#[derive(Debug, Arbitrary)]
pub enum ArbAnchorKind {
    Normal,
    Compaction,
    /// Free-form string — the validator's discriminator MUST reject
    /// unknown variants without panicking.
    Junk,
}

#[allow(dead_code)]
impl ArbAnchorKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Compaction => "compaction",
            Self::Junk => "what-even-is-this-kind",
        }
    }
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

impl FuzzAnchorDeepInput {
    fn to_json(&self) -> Value {
        let pred_count = (self.predecessor_count as usize).min(MAX_PREDS);
        let frontier_count = (self.frontier_count as usize).min(MAX_FRONTIER);
        let predecessor_refs: Vec<Value> = (0..pred_count)
            .map(|i| Value::String(format!("{}-{i}", self.predecessor_template)))
            .collect();
        let frontier: Vec<Value> = (0..frontier_count)
            .map(|i| Value::String(format!("{}-{i}", self.frontier_template)))
            .collect();
        let mut envelope = json!({
            "id": self.id,
            "realm_id": self.realm_id,
            "predecessor_refs": predecessor_refs,
            "frontier": frontier,
            "state_root": self.state_root,
            "anchored_at": self.anchored_at,
            "hlc": {
                "physical_ms": self.hlc_physical_ms,
                "logical": self.hlc_logical,
            },
        });
        if self.include_signature {
            envelope["anchorer_signature"] = json!({
                "alg": self.sig_alg.as_str(),
                "value": self.sig_value,
                "key": self.sig_key,
            });
        }
        envelope
    }
}

/// Drive an anchor envelope through:
///   1. `from_slice` on the raw fuzz bytes (catches wire parser panics);
///   2. Schema validator against `ANCHOR_SCHEMA`;
///   3. Typed `from_value::<Anchor>` deserialization.
pub fn fuzz_anchor_deep(data: &[u8]) -> Result<(), String> {
    catch(|| {
        let _ = serde_json::from_slice::<contrix_core::Anchor>(data);
    })?;
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzAnchorDeepInput::arbitrary(&mut unstructured) else {
        return Ok(());
    };
    let value = input.to_json();
    catch(|| {
        let _ = registry().validate_value(ANCHOR_SCHEMA, &value);
    })?;
    catch(|| {
        let _ = serde_json::from_value::<contrix_core::Anchor>(value.clone());
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_does_not_panic() {
        let _ = fuzz_anchor_deep(&[]);
    }

    #[test]
    fn pathological_input_does_not_panic() {
        // Tiny input — forces `Unstructured` to early-return Err, which the
        // harness must handle without panicking.
        let _ = fuzz_anchor_deep(&[0u8]);
        // Slightly larger; exercises the discriminator branches.
        let _ = fuzz_anchor_deep(&[0xff; 64]);
        let _ = fuzz_anchor_deep(&[0xaa; 4096]);
    }
}
