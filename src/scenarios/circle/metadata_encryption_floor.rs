//! P2F.3 — Circle `metadata_encryption_floor` may only tighten the
//! parent Realm's floor (CKP-0007 §3.4.1).
//!
//! Normative rule (CKP-0007 §3.4.1, paraphrased): effective metadata floor
//! = max(parent Realm `metadata_encryption_floor`, Circle
//! `metadata_encryption_floor` if present, Space
//! `child_scope_policy.metadata_encryption_floor` if in placement context,
//! object profile requirement). Comparison order is
//! `allow_plaintext < e2ee_required`; any write below the effective floor
//! MUST `failed_precondition`
//! (`reason="metadata_encryption_floor_violation"`).
//!
//! In other words, a Circle MAY raise the floor (e.g. Realm=`allow_plaintext`
//! → Circle=`e2ee_required` is fine), but never lower it (Realm=
//! `e2ee_required` + Circle=`allow_plaintext` MUST be rejected with
//! `metadata_encryption_floor_violation`).
//!
//! `metadata_encryption_floor` is binary and fully symmetric with
//! `content_encryption_floor`. The SDK exposes the
//! [`EncryptionFloor`] enum but no reducer-pure
//! `validate_metadata_floor_tightens` helper; this scenario pins both the
//! enum's strictness ordering and a local helper that any future reducer
//! SHOULD mirror.

use anyhow::{Result, anyhow};
use cokret_core::EncryptionFloor;
use cokret_core::error::REASON_METADATA_ENCRYPTION_FLOOR_VIOLATION;

/// Strictness rank for the two floor values: stricter → larger rank.
fn rank(floor: EncryptionFloor) -> u8 {
    match floor {
        EncryptionFloor::AllowPlaintext => 0,
        EncryptionFloor::E2eeRequired => 1,
    }
}

/// Reducer-pure validator: a Circle MAY tighten its parent Realm's
/// `metadata_encryption_floor` floor, but MUST NOT loosen it. Returns
/// `Ok(())` when the Circle's floor is `>=` the Realm's floor in
/// strictness; otherwise `Err` whose message carries the canonical
/// [`REASON_METADATA_ENCRYPTION_FLOOR_VIOLATION`] reason code.
fn validate_metadata_floor_tightens(
    realm_floor: EncryptionFloor,
    circle_floor: EncryptionFloor,
) -> Result<()> {
    if rank(circle_floor) >= rank(realm_floor) {
        Ok(())
    } else {
        Err(anyhow!(
            "reason={REASON_METADATA_ENCRYPTION_FLOOR_VIOLATION}: \
             Circle metadata_encryption_floor={circle_floor:?} is laxer than \
             parent Realm metadata_encryption_floor={realm_floor:?}; Circle MAY \
             only tighten the floor (CKP-0007 §3.4.1)"
        ))
    }
}

/// Compute the effective metadata floor as the max of (realm, circle?,
/// space_policy?, object_profile?) — the same `max` semantics the spec
/// uses for write-acceptance.
fn effective_floor(
    realm: EncryptionFloor,
    circle: Option<EncryptionFloor>,
    space_policy: Option<EncryptionFloor>,
    object_profile: Option<EncryptionFloor>,
) -> EncryptionFloor {
    let mut best = realm;
    for candidate in [circle, space_policy, object_profile].into_iter().flatten() {
        if rank(candidate) > rank(best) {
            best = candidate;
        }
    }
    best
}

pub async fn metadata_encryption_floor_run() -> Result<()> {
    use EncryptionFloor::*;

    // ── Strictness order MUST be allow_plaintext < e2ee_required.
    if rank(AllowPlaintext) >= rank(E2eeRequired) {
        return Err(anyhow!(
            "strictness order drifted: allow_plaintext={} e2ee_required={}",
            rank(AllowPlaintext),
            rank(E2eeRequired)
        ));
    }

    // ── Wire shape: pin the snake_case literals against
    //    spec/v1/artifacts/schemas/circle.schema.json.
    for (variant, expected) in [
        (AllowPlaintext, "allow_plaintext"),
        (E2eeRequired, "e2ee_required"),
    ] {
        let v = serde_json::to_value(variant).map_err(|e| anyhow!("serialise: {e}"))?;
        let s = v
            .as_str()
            .ok_or_else(|| anyhow!("MUST serialise as JSON string"))?
            .to_owned();
        if s != expected {
            return Err(anyhow!(
                "EncryptionFloor::{variant:?} MUST serialise to \
                 `{expected}`; got `{s}`"
            ));
        }
        let parsed: EncryptionFloor =
            serde_json::from_str(&format!("\"{expected}\"")).map_err(|e| anyhow!("parse: {e}"))?;
        if parsed != variant {
            return Err(anyhow!(
                "round-trip lost variant; expected {variant:?}, got {parsed:?}"
            ));
        }
    }

    // ── Accept: Realm=allow_plaintext, Circle MAY pick either value.
    for circle in [AllowPlaintext, E2eeRequired] {
        validate_metadata_floor_tightens(AllowPlaintext, circle).map_err(|e| {
            anyhow!("expected accept Realm=AllowPlaintext Circle={circle:?}; got: {e}")
        })?;
    }

    // ── Accept: Realm=e2ee_required, Circle=e2ee_required (equal).
    validate_metadata_floor_tightens(E2eeRequired, E2eeRequired)?;

    // ── Reject: Realm=e2ee_required, Circle=allow_plaintext (laxer).
    match validate_metadata_floor_tightens(E2eeRequired, AllowPlaintext) {
        Ok(()) => {
            return Err(anyhow!(
                "expected reject Realm=E2eeRequired Circle=AllowPlaintext; got accept"
            ));
        }
        Err(e) => {
            let msg = e.to_string();
            if !msg.contains(REASON_METADATA_ENCRYPTION_FLOOR_VIOLATION) {
                return Err(anyhow!(
                    "expected reason={REASON_METADATA_ENCRYPTION_FLOOR_VIOLATION}; got: {msg}"
                ));
            }
        }
    }

    // ── effective_floor takes max across all four sources.
    let effective = effective_floor(AllowPlaintext, Some(E2eeRequired), None, None);
    if effective != E2eeRequired {
        return Err(anyhow!(
            "effective_floor(AllowPlaintext, E2eeRequired, _, _) MUST be \
             E2eeRequired; got {effective:?}"
        ));
    }
    let effective = effective_floor(AllowPlaintext, None, Some(E2eeRequired), None);
    if effective != E2eeRequired {
        return Err(anyhow!(
            "effective_floor MUST take max across all sources; expected E2eeRequired, got {effective:?}"
        ));
    }
    let effective = effective_floor(AllowPlaintext, None, None, Some(E2eeRequired));
    if effective != E2eeRequired {
        return Err(anyhow!(
            "effective_floor object_profile lift failed; expected E2eeRequired, got {effective:?}"
        ));
    }
    // Realm alone is the floor when no other source narrows.
    let effective = effective_floor(E2eeRequired, None, None, None);
    if effective != E2eeRequired {
        return Err(anyhow!(
            "effective_floor with no overrides MUST equal realm; got {effective:?}"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn metadata_floor_only_tightens() {
        metadata_encryption_floor_run().await.unwrap();
    }
}
