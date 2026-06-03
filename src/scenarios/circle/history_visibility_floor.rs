//! P2F.3 — Circle effective history visibility takes the stricter of
//! `(realm_floor, circle_setting)` (CXP-0007 §3.4).
//!
//! Spec text:
//!
//! > Effective history visibility = 父 Realm policy floor 与 Circle
//! > `history_visibility` 的更严格者. Circle MAY 收紧父 Realm,不得放宽
//! > 父 Realm 的隐私/合规下限.
//!
//! Strictness order over [`HistoryVisibility`] (least strict → most strict):
//!
//!   `world_readable < shared < invited < joined`
//!
//! The `restricted` variant is profile-specific; the spec leaves it as an
//! authorization filter on top of `joined` membership semantics and the
//! conformance enum stays at the 4 cleanly-ordered values for visibility
//! floor comparison. The SDK does not currently expose
//! `compute_effective_history_visibility`; this scenario therefore defines
//! the reducer-pure helper locally and exercises every interesting
//! `(realm, circle)` pair.

use anyhow::{Result, anyhow};
use cokret_core::HistoryVisibility;

/// Strictness rank for the 4 ordered `history_visibility` levels. Returns
/// `None` for `Restricted` since it is a profile-evaluated overlay, not
/// part of the linear floor ordering.
fn strictness_rank(v: &HistoryVisibility) -> Option<u8> {
    match v {
        HistoryVisibility::WorldReadable => Some(0),
        HistoryVisibility::Shared => Some(1),
        HistoryVisibility::Invited => Some(2),
        HistoryVisibility::Joined => Some(3),
        HistoryVisibility::Restricted => None,
    }
}

/// Reducer-pure helper: effective Circle history visibility is the
/// stricter of the parent Realm floor and the Circle's own setting.
/// Returns `Err` if either input is `Restricted` (profile must resolve
/// that elsewhere — it is not in the linear floor space).
fn compute_effective_history_visibility(
    realm_floor: HistoryVisibility,
    circle_setting: HistoryVisibility,
) -> Result<HistoryVisibility> {
    let r = strictness_rank(&realm_floor).ok_or_else(|| {
        anyhow!("realm floor `restricted` is not in the linear floor space (CXP-0007 §3.4)")
    })?;
    let c = strictness_rank(&circle_setting).ok_or_else(|| {
        anyhow!("circle setting `restricted` is not in the linear floor space (CXP-0007 §3.4)")
    })?;
    Ok(if r >= c { realm_floor } else { circle_setting })
}

pub async fn history_visibility_floor_run() -> Result<()> {
    use HistoryVisibility::*;

    // ── Realm floor stricter than Circle setting → take Realm.
    let cases_realm_wins: &[(HistoryVisibility, HistoryVisibility, HistoryVisibility)] = &[
        (Joined, WorldReadable, Joined),
        (Joined, Shared, Joined),
        (Joined, Invited, Joined),
        (Invited, WorldReadable, Invited),
        (Invited, Shared, Invited),
        (Shared, WorldReadable, Shared),
    ];
    for (realm, circle, expected) in cases_realm_wins {
        let got = compute_effective_history_visibility(realm.clone(), circle.clone())?;
        if got != *expected {
            return Err(anyhow!(
                "realm-wins case realm={realm:?} circle={circle:?}: expected \
                 {expected:?}, got {got:?}"
            ));
        }
    }

    // ── Circle setting stricter than Realm floor → take Circle.
    let cases_circle_wins: &[(HistoryVisibility, HistoryVisibility, HistoryVisibility)] = &[
        (WorldReadable, Joined, Joined),
        (WorldReadable, Invited, Invited),
        (WorldReadable, Shared, Shared),
        (Shared, Joined, Joined),
        (Shared, Invited, Invited),
        (Invited, Joined, Joined),
    ];
    for (realm, circle, expected) in cases_circle_wins {
        let got = compute_effective_history_visibility(realm.clone(), circle.clone())?;
        if got != *expected {
            return Err(anyhow!(
                "circle-wins case realm={realm:?} circle={circle:?}: expected \
                 {expected:?}, got {got:?}"
            ));
        }
    }

    // ── Equal levels → return that level.
    for level in [WorldReadable, Shared, Invited, Joined] {
        let got = compute_effective_history_visibility(level.clone(), level.clone())?;
        if got != level {
            return Err(anyhow!(
                "equal-levels case ({level:?}, {level:?}) MUST yield {level:?}; got {got:?}"
            ));
        }
    }

    // ── Strictness ordering MUST be the spec ordering
    //    `world_readable < shared < invited < joined`.
    let ordered = [WorldReadable, Shared, Invited, Joined];
    for window in ordered.windows(2) {
        let a = strictness_rank(&window[0]).unwrap();
        let b = strictness_rank(&window[1]).unwrap();
        if a >= b {
            return Err(anyhow!(
                "strictness ordering broken: rank({:?})={a} should be < rank({:?})={b}",
                window[0],
                window[1]
            ));
        }
    }

    // ── `Restricted` MUST be rejected as a floor input on either side
    //    (it lives off the linear order).
    if compute_effective_history_visibility(Restricted, Joined).is_ok() {
        return Err(anyhow!(
            "expected reject of realm_floor=restricted on linear floor compute"
        ));
    }
    if compute_effective_history_visibility(Joined, Restricted).is_ok() {
        return Err(anyhow!(
            "expected reject of circle_setting=restricted on linear floor compute"
        ));
    }

    // ── Pin wire shape: each variant serialises to the snake_case string
    //    the spec uses on `ck.realm.policy` / `cx.circle.*` payloads.
    for (variant, expected) in [
        (WorldReadable, "world_readable"),
        (Shared, "shared"),
        (Invited, "invited"),
        (Joined, "joined"),
        (Restricted, "restricted"),
    ] {
        let s = serde_json::to_value(&variant).map_err(|e| anyhow!("serialise: {e}"))?;
        let s = s
            .as_str()
            .ok_or_else(|| anyhow!("HistoryVisibility MUST serialise as a JSON string"))?
            .to_owned();
        if s != expected {
            return Err(anyhow!(
                "HistoryVisibility::{variant:?} MUST serialise to `{expected}`; got `{s}`"
            ));
        }
        let parsed: HistoryVisibility =
            serde_json::from_str(&format!("\"{expected}\"")).map_err(|e| anyhow!("parse: {e}"))?;
        if parsed != variant {
            return Err(anyhow!(
                "round-trip HistoryVisibility lost variant; expected {variant:?}, got {parsed:?}"
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn effective_history_visibility_takes_stricter() {
        history_visibility_floor_run().await.unwrap();
    }
}
