//! Composite-state subject and key-encoding conformance vectors.

use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{emit_vector, load_local_fixture};
use crate::conformance::{canonical_json, required_str, validate_profile};

/// W11 — composite state subject encoding (B4) round-trip.
///
/// Spec §9.5: `state_subject = base64url_nopad(sha256(canonical_json(components_array)))`.
/// Each vector pins its expected canonical JSON form and expected hash so an
/// encoder change is caught loudly.
pub fn run_composite_state_subject_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("composite_state_subject_fixture.json")?;
    validate_profile(&fixture, "ak.profile.composite_state_subject_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("composite_state_subject fixture missing vectors"))?;

    let kinds = ["ak.device.authorize", "ak.device.revoke"];
    let mut covered: std::collections::BTreeSet<String> = Default::default();

    for vector in vectors {
        let (name, kind) = validate_encoded_vector(vector, "composite_state_subject.encoded")?;
        if !kinds.contains(&kind.as_str()) {
            bail!("vector {name} kind {kind} is not a registered composite-subject kind");
        }
        covered.insert(kind);
    }

    for kind in kinds {
        if !covered.contains(kind) {
            bail!("composite state subject fixture missing coverage for {kind}");
        }
    }
    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("composite_state_subject fixture missing negative_vectors"))?;
    let mut saw_reorder = false;
    let mut saw_pipe = false;
    for vector in negatives {
        let name = required_str(vector, "name")?;
        let must_differ = required_str(vector, "must_differ_from")?;
        if let Some(components) = vector.get("components_array") {
            let computed = compute_state_subject(components)?;
            if computed == must_differ {
                bail!(
                    "negative vector {name} produced canonical state_subject (would mask reorder bug)"
                );
            }
            saw_reorder = true;
        } else if let Some(pipe) = vector.get("pipe_form").and_then(Value::as_str) {
            // Hash the literal pipe-separated string; it MUST NOT match the
            // canonical hash form.
            let digest = Sha256::digest(pipe.as_bytes());
            if b64url_nopad(&digest) == must_differ {
                bail!(
                    "negative vector {name} pipe-form hash matches canonical state_subject (encoder is using pipe form)"
                );
            }
            saw_pipe = true;
        } else {
            bail!("negative vector {name} requires components_array or pipe_form");
        }
    }
    if !(saw_reorder && saw_pipe) {
        bail!(
            "composite state subject fixture must include both reorder and pipe-form negative vectors"
        );
    }
    Ok(())
}
/// B3 — composite (cell, subject) state-key encoding determinism.
pub fn run_composite_state_key_encoding_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("composite_state_key_encoding_fixture.json")?;
    validate_profile(
        &fixture,
        "ak.profile.composite_state_key_encoding_vectors.v1",
    )?;

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("composite_state_key_encoding fixture missing vectors[]"))?;
    if vectors.len() < 3 {
        bail!(
            "composite_state_key_encoding fixture has {} vectors, expected >= 3",
            vectors.len()
        );
    }

    for v in vectors {
        let (name, kind) = validate_encoded_vector(v, "composite_state_key_encoding.encoded")?;
        if kind.starts_with("cx.") {
            bail!("active composite state key vector {name} still uses removed kind {kind}");
        }
    }

    // Ordering-negative: the wrong-order array MUST hash to a different subject.
    let ordering = fixture
        .get("ordering_negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            anyhow!("composite_state_key_encoding fixture missing ordering_negative_vectors[]")
        })?;
    let mut saw_ordering = false;
    for v in ordering {
        let name = required_str(v, "name")?;
        let components = v
            .get("components_array")
            .ok_or_else(|| anyhow!("ordering negative {name} missing components_array"))?;
        let must_differ = required_str(v, "must_differ_from")?;
        let computed = compute_state_subject(components)?;
        if computed == must_differ {
            bail!(
                "ordering negative {name} produced canonical state_subject (would mask reorder bug)"
            );
        }
        saw_ordering = true;
    }
    if !saw_ordering {
        bail!("composite_state_key_encoding fixture must include at least one ordering negative");
    }

    Ok(())
}

fn validate_encoded_vector(vector: &Value, transcript_kind: &str) -> Result<(String, String)> {
    let name = required_str(vector, "name")?;
    let kind = required_str(vector, "kind")?;
    let components = vector
        .get("components_array")
        .ok_or_else(|| anyhow!("vector {name} missing components_array"))?;
    let expected_cj = required_str(vector, "expected_canonical_json")?;
    let actual_cj = canonical_json(components)?;
    if actual_cj != expected_cj {
        bail!("vector {name} canonical_json drift: expected {expected_cj}, got {actual_cj}");
    }
    let expected_subject = required_str(vector, "expected_state_subject")?;
    let actual_subject = compute_state_subject(components)?;
    if actual_subject != expected_subject {
        bail!(
            "vector {name} state_subject drift: expected {expected_subject}, got {actual_subject}"
        );
    }
    emit_vector(
        transcript_kind,
        vector,
        json!({
            "name": name,
            "kind": kind,
            "state_subject": actual_subject,
            "canonical_json": actual_cj,
        }),
    );
    Ok((name.to_owned(), kind.to_owned()))
}

fn b64url_nopad(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
fn compute_state_subject(components_array: &Value) -> Result<String> {
    let cj = canonical_json(components_array)?;
    let digest = Sha256::digest(cj.as_bytes());
    Ok(b64url_nopad(&digest))
}
