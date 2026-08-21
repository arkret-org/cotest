//! Cross-server redaction wire-model conformance vectors.

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{emit_vector, expected_outcome, load_local_fixture};
use crate::conformance::{required_str, validate_profile};

/// Redacted Move cross-server projection vectors.
pub fn run_redacted_cross_server_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("redacted_cross_server_fixture.json")?;
    validate_profile(&fixture, "ak.profile.redacted_cross_server_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("redacted_cross_server missing vectors[]"))?;
    if vectors.len() < 2 {
        bail!(
            "redacted_cross_server requires >= 2 vectors, got {}",
            vectors.len()
        );
    }

    let mut saw_member_tombstone = false;
    let mut saw_author_audit = false;
    let mut saw_un_redaction = false;
    for vector in vectors {
        let name = required_str(vector, "name")?;
        if expected_outcome(vector, name)? != "accept" {
            bail!("vector {name} outcome must be accept");
        }
        let viewer_is_author = vector
            .get("viewer_is_author")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} missing viewer_is_author"))?;
        let projection = vector
            .pointer("/expected/projection_on_peer_b")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing projection_on_peer_b"))?;
        let body_visible = vector
            .pointer("/expected/body_visible")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        match name {
            "redaction_propagates_to_peer_b_member_sees_tombstone" => {
                if viewer_is_author || projection != "tombstone_only" || body_visible {
                    bail!("vector {name} member view must be tombstone_only with body hidden");
                }
                saw_member_tombstone = true;
            }
            "redaction_propagates_author_audit_view_full_body" => {
                if !viewer_is_author || projection != "audit_view" || !body_visible {
                    bail!("vector {name} author view must be audit_view with body visible");
                }
                saw_author_audit = true;
            }
            "un_redaction_move_propagates_cross_server_restores_body" => {
                if !vector
                    .get("redaction_then_un_redaction")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                    || !body_visible
                    || projection != "body_visible"
                {
                    bail!("vector {name} un-redaction must restore body_visible");
                }
                saw_un_redaction = true;
            }
            other => bail!("redacted_cross_server unexpected vector {other}"),
        }
        emit_vector(
            "redacted_cross_server.vector",
            vector,
            json!({
                "name": name,
                "viewer_is_author": viewer_is_author,
                "projection": projection,
                "body_visible": body_visible,
            }),
        );
    }
    if !(saw_member_tombstone && saw_author_audit && saw_un_redaction) {
        bail!("redacted_cross_server must cover member_tombstone + author_audit + un_redaction");
    }
    Ok(())
}
