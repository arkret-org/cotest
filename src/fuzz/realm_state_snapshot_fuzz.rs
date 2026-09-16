//! Authority snapshot and commit fuzz harness.
//!
//! The objects a governance Station hands a joining client are the signed
//! typed snapshot and the per-stream commit tails. Both are parsed before any
//! signature is checked, so a panic in either deserializer is reachable
//! pre-authentication. Three entry points:
//!
//!   - [`fuzz_realm_state_snapshot`] — the signed typed snapshot envelope.
//!   - [`fuzz_realm_commit`] — one authority-signed commit, including the shape validator that
//!     enforces the position / predecessor rule.
//!   - [`fuzz_stream_scan_outcome`] — a returned stream tail, including the contiguity check that
//!     walks predecessor links pairwise.
//!
//! All three use the same panic-catch pattern as `envelope_fuzz`, so a finding
//! surfaces as `Err(message)` rather than aborting the harness.

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

/// `arbitrary`-derived input shaped to the signed typed snapshot.
///
/// `visible_stream_heads` is the member worth shaking: it is the caller's only
/// evidence of which streams the snapshot covers, and a decoder that mis-parses
/// it hands the client a silently narrower or wider approved set.
#[derive(Debug, Arbitrary)]
pub struct FuzzRealmStateSnapshotInput {
    pub snapshot_id: String,
    pub realm_id: String,
    pub authority_generation: u64,
    pub head_stream_kind: String,
    pub head_circle_id: String,
    pub head_position: u64,
    pub head_commit_id: String,
    pub current_state_entries: ArbValue,
    pub history_access: String,
    pub floor_position: u64,
    pub created_at: String,
    pub signature: ArbValue,
}

impl FuzzRealmStateSnapshotInput {
    fn to_json(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "realm_id": self.realm_id,
            "authority_generation": self.authority_generation,
            "visible_stream_heads": [{
                "stream_ref": {
                    "kind": self.head_stream_kind,
                    "realm_id": self.realm_id,
                    "circle_id": self.head_circle_id,
                },
                "stream_position": self.head_position,
                "commit_id": self.head_commit_id,
            }],
            "current_state_entries": self.current_state_entries.0,
            "retention_and_history_floor": {
                "history_access": self.history_access,
                "stream_floors": [{
                    "stream_ref": {
                        "kind": self.head_stream_kind,
                        "realm_id": self.realm_id,
                        "circle_id": self.head_circle_id,
                    },
                    "oldest_position": self.floor_position,
                }],
            },
            "created_at": self.created_at,
            "signature": self.signature.0,
        })
    }
}

/// Fuzz the signed typed snapshot envelope.
pub fn fuzz_realm_state_snapshot(data: &[u8]) -> Result<(), String> {
    catch(|| {
        let _ = serde_json::from_slice::<arkret_wire::RealmStateSnapshot>(data);
    })?;
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzRealmStateSnapshotInput::arbitrary(&mut unstructured) else {
        return Ok(());
    };
    let value = input.to_json();
    catch(|| {
        let _ = registry().validate_value(SchemaId::REALM_STATE_SNAPSHOT_V1, &value);
    })?;
    catch(|| {
        let _ = serde_json::from_value::<arkret_wire::RealmStateSnapshot>(value.clone());
    })
}

/// `arbitrary`-derived input shaped to one authority-signed commit.
#[derive(Debug, Arbitrary)]
pub struct FuzzRealmCommitInput {
    pub commit_id: String,
    pub realm_id: String,
    pub stream_kind: String,
    pub circle_id: String,
    pub sidecar_id: String,
    pub stream_position: u64,
    pub previous_commit_ref: Option<String>,
    pub event_ref: String,
    pub authority_generation: u64,
    pub authority_ref: String,
    pub committed_at: String,
    pub signature: ArbValue,
}

impl FuzzRealmCommitInput {
    fn to_json(&self) -> Value {
        json!({
            "commit_id": self.commit_id,
            "realm_id": self.realm_id,
            "stream_ref": {
                "kind": self.stream_kind,
                "realm_id": self.realm_id,
                "circle_id": self.circle_id,
                "sidecar_id": self.sidecar_id,
            },
            "stream_position": self.stream_position,
            "previous_commit_ref": self.previous_commit_ref,
            "event_ref": self.event_ref,
            "authority_generation": self.authority_generation,
            "authority_ref": self.authority_ref,
            "committed_at": self.committed_at,
            "signature": self.signature.0,
        })
    }
}

/// Fuzz one `RealmCommit`, including its position / predecessor shape rule.
pub fn fuzz_realm_commit(data: &[u8]) -> Result<(), String> {
    catch(|| {
        let _ = serde_json::from_slice::<arkret_wire::RealmCommit>(data);
    })?;
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzRealmCommitInput::arbitrary(&mut unstructured) else {
        return Ok(());
    };
    let value = input.to_json();
    catch(|| {
        let _ = registry().validate_value(SchemaId::REALM_COMMIT_V1, &value);
    })?;
    catch(|| {
        if let Ok(commit) = serde_json::from_value::<arkret_wire::RealmCommit>(value.clone()) {
            let _ = commit.validate_shape();
        }
    })
}

/// `arbitrary`-derived input shaped to a returned stream tail.
#[derive(Debug, Arbitrary)]
pub struct FuzzStreamScanOutcomeInput {
    pub commits: ArbValue,
    pub truncated: bool,
    pub realm_id: String,
    pub stream_kind: String,
    pub circle_id: String,
    pub after_position: Option<u64>,
    pub limit: u16,
}

impl FuzzStreamScanOutcomeInput {
    fn outcome_json(&self) -> Value {
        json!({
            "commits": self.commits.0,
            "truncated": self.truncated,
        })
    }

    fn request_json(&self) -> Value {
        json!({
            "realm_id": self.realm_id,
            "stream_ref": {
                "kind": self.stream_kind,
                "realm_id": self.realm_id,
                "circle_id": self.circle_id,
            },
            "after_position": self.after_position,
            "limit": self.limit,
        })
    }
}

/// Fuzz a stream tail against its own request, exercising the contiguity walk.
pub fn fuzz_stream_scan_outcome(data: &[u8]) -> Result<(), String> {
    catch(|| {
        let _ = serde_json::from_slice::<arkret_wire::StreamScanOutcome>(data);
    })?;
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzStreamScanOutcomeInput::arbitrary(&mut unstructured) else {
        return Ok(());
    };
    let outcome_value = input.outcome_json();
    let request_value = input.request_json();
    catch(|| {
        let outcome = serde_json::from_value::<arkret_wire::StreamScanOutcome>(outcome_value);
        let request = serde_json::from_value::<arkret_wire::StreamScanRequest>(request_value);
        if let (Ok(outcome), Ok(request)) = (outcome, request) {
            let _ = outcome.validate_for_request(&request);
        }
    })
}
