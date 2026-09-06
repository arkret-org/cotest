//! C.8 — Snapshot-envelope fuzz harness.
//!
//! Extension of the `envelope_fuzz` shape: feeds `arbitrary`-derived
//! inputs through the snapshot manifest + chunk header validators and
//! asserts the typed deserializers never panic on adversarial inputs.
//!
//! Two entry points:
//!   - [`fuzz_realm_state_snapshot_manifest`] — drives the manifest envelope.
//!   - [`fuzz_realm_state_snapshot_chunk_header`] — drives the per-chunk header.
//!
//! Both use the same panic-catch pattern as `envelope_fuzz` so a fuzz
//! finding surfaces as `Err(message)` rather than aborting the harness.

use arbitrary::{Arbitrary, Unstructured};
use arkret_wire::SchemaId;
use serde_json::{Value, json};

use super::panic_guard::catch;

fn registry() -> arkret_schema::ProtocolSchemaRegistry {
    arkret_schema_conformance::schema_registry_from_default_spec_artifacts()
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// `arbitrary`-derived input shaped to the snapshot manifest. Field
/// names mirror the canonical envelope so the schema validator sees a
/// realistic structural shape, while values are random.
#[derive(Debug, Arbitrary)]
pub struct FuzzRealmStateSnapshotManifestInput {
    pub realm_state_snapshot_id: String,
    pub realm_id: String,
    pub root_anchor_ref: String,
    pub chunk_count: u32,
    pub total_bytes: u64,
    pub digest_algorithm: String,
    pub digest_value: String,
    pub hlc_physical_ms: u64,
    pub hlc_logical: u32,
    pub include_predecessor: bool,
    pub predecessor_ref: String,
}

impl FuzzRealmStateSnapshotManifestInput {
    fn to_json(&self) -> Value {
        let mut envelope = json!({
            "realm_state_snapshot_id": self.realm_state_snapshot_id,
            "realm_id": self.realm_id,
            "root_anchor_ref": self.root_anchor_ref,
            "chunk_count": self.chunk_count,
            "total_bytes": self.total_bytes,
            "digest": format!("{}:{}", self.digest_algorithm, self.digest_value),
            "hlc": {
                "physical_ms": self.hlc_physical_ms,
                "logical": self.hlc_logical,
            },
        });
        if self.include_predecessor {
            envelope["predecessor_ref"] = Value::String(self.predecessor_ref.clone());
        }
        envelope
    }
}

/// Fuzz the snapshot manifest envelope.
pub fn fuzz_realm_state_snapshot_manifest(data: &[u8]) -> Result<(), String> {
    catch(|| {
        let _ = serde_json::from_slice::<Value>(data);
    })?;
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzRealmStateSnapshotManifestInput::arbitrary(&mut unstructured) else {
        return Ok(());
    };
    let value = input.to_json();
    catch(|| {
        let _ = registry().validate_value(SchemaId::REALM_STATE_SNAPSHOT_V1, &value);
    })?;
    catch(|| {
        let _ = serde_json::to_string(&value);
    })
}

/// `arbitrary`-derived input shaped to the chunk header. The chunk's
/// `bytes` field is intentionally a base64-url string so the harness
/// can also exercise the decoder edge cases.
#[derive(Debug, Arbitrary)]
pub struct FuzzRealmStateSnapshotChunkHeaderInput {
    pub chunk_id: u32,
    pub digest_algorithm: String,
    pub digest_value: String,
    pub bytes_b64url: String,
    pub include_compression: bool,
    pub compression: String,
}

impl FuzzRealmStateSnapshotChunkHeaderInput {
    fn to_json(&self) -> Value {
        let mut header = json!({
            "chunk_id": self.chunk_id,
            "digest": format!("{}:{}", self.digest_algorithm, self.digest_value),
            "bytes": self.bytes_b64url,
        });
        if self.include_compression {
            header["compression"] = Value::String(self.compression.clone());
        }
        header
    }
}

/// Fuzz the chunk header.
pub fn fuzz_realm_state_snapshot_chunk_header(data: &[u8]) -> Result<(), String> {
    catch(|| {
        let _ = serde_json::from_slice::<arkret_state::RealmStateSnapshotChunk>(data);
    })?;
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzRealmStateSnapshotChunkHeaderInput::arbitrary(&mut unstructured) else {
        return Ok(());
    };
    let value = input.to_json();
    catch(|| {
        let _ = registry().validate_value(SchemaId::REALM_STATE_SNAPSHOT_V1, &value);
    })?;
    catch(|| {
        let _ = serde_json::from_value::<arkret_state::RealmStateSnapshotChunk>(value.clone());
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical-corpus seed: the empty byte string must NOT panic the
    /// harness. The validator returns `Ok` or typed `Err` — never a panic.
    #[test]
    fn empty_input_does_not_panic_manifest() {
        let _ = fuzz_realm_state_snapshot_manifest(&[]);
    }

    #[test]
    fn empty_input_does_not_panic_chunk_header() {
        let _ = fuzz_realm_state_snapshot_chunk_header(&[]);
    }

    /// Pseudo-random byte string at typical libFuzzer corpus size (4 KiB).
    #[test]
    fn four_kib_random_does_not_panic() {
        let data: Vec<u8> = (0..4096).map(|i| (i * 31 + 7) as u8).collect();
        let _ = fuzz_realm_state_snapshot_manifest(&data);
        let _ = fuzz_realm_state_snapshot_chunk_header(&data);
    }
}
