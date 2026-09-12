//! C.8 — Snapshot-envelope fuzz harness.
//!
//! Extension of the `envelope_fuzz` shape: feeds `arbitrary`-derived
//! inputs through the snapshot manifest + chunk header validators and
//! asserts the typed deserializers never panic on adversarial inputs.
//!
//! Two entry points:
//!   - [`fuzz_realm_state_snapshot_manifest`] — drives the manifest envelope.
//!   - [`fuzz_realm_state_snapshot_chunk_lists`] — drives a chunk payload's four auxiliary lists.
//!
//! Both use the same panic-catch pattern as `envelope_fuzz` so a fuzz
//! finding surfaces as `Err(message)` rather than aborting the harness.

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

/// `arbitrary`-derived input shaped to the snapshot manifest. Field
/// names mirror the canonical envelope so the schema validator sees a
/// realistic structural shape, while values are random.
#[derive(Debug, Arbitrary)]
pub struct FuzzRealmStateSnapshotManifestInput {
    pub id: String,
    pub realm_id: String,
    pub reducer_profile: String,
    pub security_class: String,
    pub schema_profile_refs: Vec<String>,
    pub state_digest: String,
    pub frontier: ArbValue,
    pub event_set_commitment: ArbValue,
    pub chunks: ArbValue,
    pub created_by: String,
    pub created_at: String,
    pub authority_binding: ArbValue,
    pub signature: ArbValue,
    pub eligibility_context: ArbValue,
}

impl FuzzRealmStateSnapshotManifestInput {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "realm_id": self.realm_id,
            "reducer_profile": self.reducer_profile,
            "security_class": self.security_class,
            "schema_profile_refs": self.schema_profile_refs,
            "state_digest": self.state_digest,
            "frontier": self.frontier.0,
            "event_set_commitment": self.event_set_commitment.0,
            "chunks": self.chunks.0,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "authority_binding": self.authority_binding.0,
            "signature": self.signature.0,
            "eligibility_context": self.eligibility_context.0,
        })
    }
}

/// Fuzz the snapshot manifest envelope.
pub fn fuzz_realm_state_snapshot_manifest(data: &[u8]) -> Result<(), String> {
    catch(|| {
        let _ = serde_json::from_slice::<arkret_state::RealmStateSnapshotManifest>(data);
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
        let _ = serde_json::from_value::<arkret_state::RealmStateSnapshotManifest>(value.clone());
    })
}

/// `arbitrary`-derived input shaped to a chunk payload's auxiliary lists.
///
/// `conflict_records[]`, `soft_failed[]`, `quarantined[]` and `erasure_stubs[]`
/// are not `state_digest` leaves, so nothing downstream re-derives them: a
/// decoder that mis-parses one hands the caller a wrong `⊥` or erasure set with
/// no digest to catch it. The `conflict_records` union is fuzzed on its `kind`
/// tag for the same reason.
#[derive(Debug, Arbitrary)]
pub struct FuzzRealmStateSnapshotChunkListsInput {
    pub realm_state_snapshot_ref: String,
    pub index: u32,
    pub reducer_profile: String,
    pub conflict_kind: String,
    pub cell_ref: String,
    pub event_id: String,
    pub actor_id: String,
    pub actor_seq: u64,
    pub include_soft_failed: bool,
    pub include_quarantined: bool,
    pub include_erasure_stub: bool,
    pub stub_schema: String,
}

impl FuzzRealmStateSnapshotChunkListsInput {
    fn to_json(&self) -> Value {
        let non_accepted = json!({
            "event_id": self.event_id,
            "actor_id": self.actor_id,
            "actor_seq": self.actor_seq,
        });
        json!({
            "chunk_kind": "realm_state_snapshot_chunk",
            "realm_state_snapshot_ref": self.realm_state_snapshot_ref,
            "index": self.index,
            "reducer_profile": self.reducer_profile,
            "items": [],
            "conflict_records": [{
                "kind": self.conflict_kind,
                "cell_ref": self.cell_ref,
                "event_id": self.event_id,
                "actor_id": self.actor_id,
                "actor_seq": self.actor_seq,
            }],
            "soft_failed": if self.include_soft_failed {
                json!([non_accepted])
            } else {
                json!([])
            },
            "quarantined": if self.include_quarantined {
                json!([non_accepted])
            } else {
                json!([])
            },
            "erasure_stubs": if self.include_erasure_stub {
                json!([{"cell_ref": self.cell_ref, "stub": {"schema": self.stub_schema}}])
            } else {
                json!([])
            },
        })
    }
}

/// Fuzz a chunk payload's auxiliary lists.
pub fn fuzz_realm_state_snapshot_chunk_lists(data: &[u8]) -> Result<(), String> {
    catch(|| {
        let _ = serde_json::from_slice::<arkret_state::RealmStateSnapshotChunkPayload>(data);
    })?;
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzRealmStateSnapshotChunkListsInput::arbitrary(&mut unstructured) else {
        return Ok(());
    };
    let value = input.to_json();
    catch(|| {
        let _ = registry().validate_value(SchemaId::REALM_STATE_SNAPSHOT_CHUNK_V1, &value);
    })?;
    catch(|| {
        let _ =
            serde_json::from_value::<arkret_state::RealmStateSnapshotChunkPayload>(value.clone());
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
        let _ = fuzz_realm_state_snapshot_chunk_lists(&[]);
    }

    /// Pseudo-random byte string at typical libFuzzer corpus size (4 KiB).
    #[test]
    fn four_kib_random_does_not_panic() {
        let data: Vec<u8> = (0..4096).map(|i| (i * 31 + 7) as u8).collect();
        let _ = fuzz_realm_state_snapshot_manifest(&data);
        let _ = fuzz_realm_state_snapshot_chunk_lists(&data);
    }
}
