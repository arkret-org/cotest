//! P2F.3 — Circle `metadata_encryption_floor` may only tighten the
//! parent Realm's floor (CXP-0007 §3.4.1).
//!
//! Spec text:
//!
//! > Effective metadata profile = max(parent Realm
//! > `metadata_encryption_profile`, Circle `metadata_encryption_floor` if
//! > present, Space `child_scope_policy.metadata_encryption_floor` if in
//! > placement context, object profile requirement). 比较顺序为
//! > `content_only < minimal_encrypted < full_encrypted`; 任何写入若低于
//! > effective profile MUST `failed_precondition`
//! > (`reason="metadata_encryption_floor_violation"`).
//!
//! In other words, a Circle MAY raise the floor (e.g. Realm=`content_only`
//! → Circle=`minimal_encrypted` is fine), but never lower it (Realm=
//! `minimal_encrypted` + Circle=`content_only` MUST be rejected with
//! `metadata_encryption_floor_violation`).
//!
//! The SDK exposes the [`CircleMetadataEncryptionFloor`] enum but no
//! reducer-pure `validate_metadata_floor_tightens` helper; this scenario
//! pins both the enum's strictness ordering and a local helper that any
//! future reducer SHOULD mirror.

use anyhow::{Result, anyhow};
use cokret_core::CircleMetadataEncryptionFloor;
use cokret_core::error::REASON_METADATA_ENCRYPTION_FLOOR_VIOLATION;

/// Strictness rank for the three floor values: stricter → larger rank.
fn rank(floor: CircleMetadataEncryptionFloor) -> u8 {
    match floor {
        CircleMetadataEncryptionFloor::ContentOnly => 0,
        CircleMetadataEncryptionFloor::MinimalEncrypted => 1,
        CircleMetadataEncryptionFloor::FullEncrypted => 2,
    }
}

/// Reducer-pure validator: a Circle MAY tighten its parent Realm's
/// `metadata_encryption_profile` floor, but MUST NOT loosen it. Returns
/// `Ok(())` when the Circle's floor is `>=` the Realm's floor in
/// strictness; otherwise `Err` whose message carries the canonical
/// [`REASON_METADATA_ENCRYPTION_FLOOR_VIOLATION`] reason code.
fn validate_metadata_floor_tightens(
    realm_floor: CircleMetadataEncryptionFloor,
    circle_floor: CircleMetadataEncryptionFloor,
) -> Result<()> {
    if rank(circle_floor) >= rank(realm_floor) {
        Ok(())
    } else {
        Err(anyhow!(
            "reason={REASON_METADATA_ENCRYPTION_FLOOR_VIOLATION}: \
             Circle metadata_encryption_floor={circle_floor:?} is laxer than \
             parent Realm metadata_encryption_profile={realm_floor:?}; Circle MAY \
             only tighten the floor (CXP-0007 §3.4.1)"
        ))
    }
}

/// Compute the effective metadata floor as the max of (realm, circle?,
/// space_policy?, object_profile?) — the same `max` semantics the spec
/// uses for write-acceptance.
fn effective_floor(
    realm: CircleMetadataEncryptionFloor,
    circle: Option<CircleMetadataEncryptionFloor>,
    space_policy: Option<CircleMetadataEncryptionFloor>,
    object_profile: Option<CircleMetadataEncryptionFloor>,
) -> CircleMetadataEncryptionFloor {
    let mut best = realm;
    for candidate in [circle, space_policy, object_profile].into_iter().flatten() {
        if rank(candidate) > rank(best) {
            best = candidate;
        }
    }
    best
}

pub async fn metadata_encryption_floor_run() -> Result<()> {
    use CircleMetadataEncryptionFloor::*;

    // ── Strictness order MUST be content_only < minimal_encrypted < full_encrypted.
    if !(rank(ContentOnly) < rank(MinimalEncrypted) && rank(MinimalEncrypted) < rank(FullEncrypted))
    {
        return Err(anyhow!(
            "strictness order drifted: content_only={} minimal={} full={}",
            rank(ContentOnly),
            rank(MinimalEncrypted),
            rank(FullEncrypted)
        ));
    }

    // ── Wire shape: pin the snake_case literals against
    //    spec/v1/artifacts/schemas/circle.schema.json.
    for (variant, expected) in [
        (ContentOnly, "content_only"),
        (MinimalEncrypted, "minimal_encrypted"),
        (FullEncrypted, "full_encrypted"),
    ] {
        let v = serde_json::to_value(variant).map_err(|e| anyhow!("serialise: {e}"))?;
        let s = v
            .as_str()
            .ok_or_else(|| anyhow!("MUST serialise as JSON string"))?
            .to_owned();
        if s != expected {
            return Err(anyhow!(
                "CircleMetadataEncryptionFloor::{variant:?} MUST serialise to \
                 `{expected}`; got `{s}`"
            ));
        }
        let parsed: CircleMetadataEncryptionFloor =
            serde_json::from_str(&format!("\"{expected}\"")).map_err(|e| anyhow!("parse: {e}"))?;
        if parsed != variant {
            return Err(anyhow!(
                "round-trip lost variant; expected {variant:?}, got {parsed:?}"
            ));
        }
    }

    // ── Accept: Realm=content_only, Circle MAY pick any of the three.
    for circle in [ContentOnly, MinimalEncrypted, FullEncrypted] {
        validate_metadata_floor_tightens(ContentOnly, circle).map_err(|e| {
            anyhow!("expected accept Realm=ContentOnly Circle={circle:?}; got: {e}")
        })?;
    }

    // ── Accept: Realm=minimal_encrypted, Circle ∈ {minimal_encrypted, full_encrypted}.
    validate_metadata_floor_tightens(MinimalEncrypted, MinimalEncrypted)?;
    validate_metadata_floor_tightens(MinimalEncrypted, FullEncrypted)?;

    // ── Reject: Realm=minimal_encrypted, Circle=content_only (laxer).
    match validate_metadata_floor_tightens(MinimalEncrypted, ContentOnly) {
        Ok(()) => {
            return Err(anyhow!(
                "expected reject Realm=MinimalEncrypted Circle=ContentOnly; got accept"
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

    // ── Reject: Realm=full_encrypted, Circle ∈ {content_only, minimal_encrypted}.
    for lax in [ContentOnly, MinimalEncrypted] {
        match validate_metadata_floor_tightens(FullEncrypted, lax) {
            Ok(()) => {
                return Err(anyhow!(
                    "expected reject Realm=FullEncrypted Circle={lax:?}; got accept"
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
    }

    // ── Accept: Realm=full_encrypted, Circle=full_encrypted (equal).
    validate_metadata_floor_tightens(FullEncrypted, FullEncrypted)?;

    // ── effective_floor takes max across all four sources.
    let effective = effective_floor(ContentOnly, Some(MinimalEncrypted), None, None);
    if effective != MinimalEncrypted {
        return Err(anyhow!(
            "effective_floor(ContentOnly, MinimalEncrypted, _, _) MUST be \
             MinimalEncrypted; got {effective:?}"
        ));
    }
    let effective = effective_floor(
        ContentOnly,
        Some(MinimalEncrypted),
        Some(FullEncrypted),
        None,
    );
    if effective != FullEncrypted {
        return Err(anyhow!(
            "effective_floor MUST take max across all sources; expected FullEncrypted, got {effective:?}"
        ));
    }
    let effective = effective_floor(MinimalEncrypted, None, None, Some(FullEncrypted));
    if effective != FullEncrypted {
        return Err(anyhow!(
            "effective_floor object_profile lift failed; expected FullEncrypted, got {effective:?}"
        ));
    }
    // Realm alone is the floor when no other source narrows.
    let effective = effective_floor(MinimalEncrypted, None, None, None);
    if effective != MinimalEncrypted {
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
