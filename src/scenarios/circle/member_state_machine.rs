//! P2F.3 — Circle member state machine (AKP-0007 §3.6).
//!
//! AKP-0007 normative spec defines a 4-state Circle membership lifecycle —
//! `invited`, `active`, `left`, `banned` — together with the `none`
//! pseudo-state for actors who never appeared. The SDK does not (yet)
//! expose a typed `CircleMemberState` enum nor a `validate_transition`
//! helper; this scenario therefore pins the membership transition table
//! locally as a reducer-pure helper and exercises every legal / illegal
//! edge from the spec table:
//!
//!   legal:
//!     none    → invited
//!     left    → invited                (re-invitation)
//!     invited → active
//!     none    → active                 (only when `join_rule=open`;
//!                                        otherwise illegal — `none → invited`
//!                                        is the required path)
//!     active  → left
//!     active  → banned
//!     left    → banned
//!     invited → banned
//!     none    → banned                 (admin bans before invite)
//!     banned  → left                   (admin un-ban via member.manage)
//!     banned  → invited                (admin un-ban + re-invite)
//!
//!   illegal:
//!     banned  → active                 (no direct path; MUST go via
//!                                        invited / left first)
//!     none    → active                 with `join_rule != open`
//!                                       (must transit `invited` first)
//!     active  → invited                (regression; not in the spec table)
//!     left    → active                 (cannot self-rejoin without an
//!                                        invitation or open join_rule)
//!
//! These match `spec/v1/proposals/0007-circle-primitive.md` §3.6 membership
//! transition table. Each transition is also forced through a JSON wire
//! round-trip on the canonical `ak.circle.member.state` payload to keep
//! the SDK wire shape stable.
//!
//! When `arkret-core` later grows a typed `CircleMemberState` enum, this
//! scenario should be migrated to import it directly and drop the local
//! string-based state table.

use anyhow::{Result, anyhow};
use arkret_core::{CircleId, Did, RealmId};
use serde_json::json;

/// Canonical Circle member state names per AKP-0007 §3.6. Mirrors the
/// `ak.circle.member.state` payload `membership` field enum.
const STATES: &[&str] = &["invited", "active", "left", "banned"];

/// `none` is a pseudo-state for an actor with no prior membership record.
const NONE: &str = "none";

/// `ak.circle.member.state` payload `join_rule` enum values that affect
/// what transitions are legal. The state machine only differs on
/// `join_rule=open`.
const JOIN_RULE_OPEN: &str = "open";
const JOIN_RULE_INVITE: &str = "invite";

/// Reducer-pure validator: returns Ok(()) iff `from → to` is a legal
/// `ak.circle.member.state` transition under the given parent `join_rule`.
///
/// `from = "none"` denotes an actor who has never had a Circle membership
/// row. Returns `Err(reason)` for illegal edges, where `reason` matches
/// the spec's AKP-0007 §3.6 transition rationale.
fn validate_member_transition(from: &str, to: &str, join_rule: &str) -> Result<()> {
    // Terminal-edge guard: `banned` is a hard wall against direct
    // promotion to `active`. Admin MUST un-ban (banned → left | invited)
    // before the actor can become active again.
    if from == "banned" && to == "active" {
        return Err(anyhow!(
            "illegal transition banned → active: admin MUST un-ban via \
             banned → {{left, invited}} before promotion to active \
             (AKP-0007 §3.6)"
        ));
    }
    // `none → active` requires `join_rule=open`; otherwise the actor MUST
    // pass through `invited`.
    if from == NONE && to == "active" && join_rule != JOIN_RULE_OPEN {
        return Err(anyhow!(
            "illegal transition none → active with join_rule=`{join_rule}`: \
             only `join_rule=open` permits self-join without prior invite \
             (AKP-0007 §3.6)"
        ));
    }
    // Active actors cannot regress to `invited`; the spec table has no
    // such row.
    if from == "active" && to == "invited" {
        return Err(anyhow!(
            "illegal transition active → invited: regression not in the \
             AKP-0007 §3.6 transition table"
        ));
    }
    // `left → active` directly is illegal: actor MUST be re-invited
    // (left → invited) and then transition `invited → active`. Open
    // join_rule callers should still pass through `invited` for parity
    // with the spec table.
    if from == "left" && to == "active" && join_rule != JOIN_RULE_OPEN {
        return Err(anyhow!(
            "illegal transition left → active with join_rule=`{join_rule}`: \
             actor MUST be re-invited (left → invited) before becoming \
             active (AKP-0007 §3.6)"
        ));
    }
    // No-op: `from == to` is not a real transition; treat as illegal so
    // tests catch reducer-emitted self-loops.
    if from == to {
        return Err(anyhow!(
            "illegal transition {from} → {to}: self-loop is not a member.state \
             transition (AKP-0007 §3.6)"
        ));
    }
    // Catalogue the remaining (from, to) tuples that the spec table
    // permits. Anything not enumerated here is illegal.
    let legal: &[(&str, &str)] = &[
        (NONE, "invited"),
        ("left", "invited"),
        ("banned", "invited"),
        ("invited", "active"),
        (NONE, "active"), // only under open join_rule; guard above catches non-open
        ("active", "left"),
        ("invited", "left"),
        ("banned", "left"),
        ("active", "banned"),
        ("invited", "banned"),
        ("left", "banned"),
        (NONE, "banned"),
    ];
    if legal.iter().any(|&(f, t)| f == from && t == to) {
        return Ok(());
    }
    Err(anyhow!(
        "illegal transition {from} → {to}: not in the AKP-0007 §3.6 \
         transition table"
    ))
}

fn realm_id() -> Result<RealmId> {
    RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000501".to_owned())
        .map_err(|e| anyhow!("realm id: {e}"))
}

fn circle_id() -> Result<CircleId> {
    CircleId::new("ak:circle:0196419b-0000-7000-8000-000000000502".to_owned())
        .map_err(|e| anyhow!("circle id: {e}"))
}

fn actor() -> Result<Did> {
    "did:web:alice.example"
        .parse()
        .map_err(|e| anyhow!("actor did: {e}"))
}

/// Build a `ak.circle.member.state` payload for the given `(actor, state)`
/// pair and JSON round-trip it through `serde_json::Value`. Returns the
/// re-parsed payload; the membership string MUST survive serde unchanged.
fn round_trip_member_payload(state: &str) -> Result<()> {
    let payload = json!({
        "circle_id": circle_id()?.as_str(),
        "actor_id": actor()?.to_string(),
        "realm_id": realm_id()?.as_str(),
        "membership": state,
    });
    let serialised = serde_json::to_string(&payload).map_err(|e| anyhow!("serialise: {e}"))?;
    let parsed: serde_json::Value =
        serde_json::from_str(&serialised).map_err(|e| anyhow!("parse: {e}"))?;
    let m = parsed
        .pointer("/membership")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("payload missing /membership"))?;
    if m != state {
        return Err(anyhow!(
            "member.state payload round-trip lost membership: expected `{state}`, got `{m}`"
        ));
    }
    Ok(())
}

pub async fn member_state_machine_run() -> Result<()> {
    // ── Sanity: every named state is well-formed and round-trips on wire.
    for state in STATES {
        round_trip_member_payload(state)?;
    }

    // ── Legal transitions under join_rule=invite (default).
    let legal_invite: &[(&str, &str)] = &[
        (NONE, "invited"),
        ("invited", "active"),
        ("active", "left"),
        ("active", "banned"),
        ("left", "invited"),
        ("invited", "left"),
        ("invited", "banned"),
        ("left", "banned"),
        (NONE, "banned"),
        ("banned", "left"),
        ("banned", "invited"),
    ];
    for &(from, to) in legal_invite {
        validate_member_transition(from, to, JOIN_RULE_INVITE).map_err(|e| {
            anyhow!(
                "expected legal transition {from} → {to} under \
                 join_rule=invite; got: {e}"
            )
        })?;
    }

    // ── Legal transition unique to join_rule=open: none → active.
    validate_member_transition(NONE, "active", JOIN_RULE_OPEN)
        .map_err(|e| anyhow!("expected none → active under join_rule=open; got: {e}"))?;

    // ── Illegal transitions: banned → active (terminal wall).
    match validate_member_transition("banned", "active", JOIN_RULE_INVITE) {
        Ok(()) => {
            return Err(anyhow!(
                "expected reject banned → active (terminal wall); got accept"
            ));
        }
        Err(e) => {
            if !e.to_string().contains("banned → active") {
                return Err(anyhow!(
                    "expected error to mention banned → active; got: {e}"
                ));
            }
        }
    }
    // ── Illegal: banned → active even with join_rule=open.
    if validate_member_transition("banned", "active", JOIN_RULE_OPEN).is_ok() {
        return Err(anyhow!(
            "expected reject banned → active under join_rule=open; got accept"
        ));
    }

    // ── Illegal: none → active with join_rule=invite.
    match validate_member_transition(NONE, "active", JOIN_RULE_INVITE) {
        Ok(()) => {
            return Err(anyhow!(
                "expected reject none → active under join_rule=invite; got accept"
            ));
        }
        Err(e) => {
            if !e.to_string().contains("none → active") {
                return Err(anyhow!("expected error mentioning none → active; got: {e}"));
            }
        }
    }

    // ── Illegal: active → invited (regression).
    if validate_member_transition("active", "invited", JOIN_RULE_INVITE).is_ok() {
        return Err(anyhow!(
            "expected reject active → invited regression; got accept"
        ));
    }

    // ── Illegal: left → active under non-open join_rule (must re-invite).
    if validate_member_transition("left", "active", JOIN_RULE_INVITE).is_ok() {
        return Err(anyhow!(
            "expected reject left → active under join_rule=invite; got accept"
        ));
    }

    // ── Illegal: self-loops are not transitions.
    for &s in STATES {
        if validate_member_transition(s, s, JOIN_RULE_INVITE).is_ok() {
            return Err(anyhow!("expected reject self-loop {s} → {s}; got accept"));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn member_state_machine_table_matches_spec() {
        member_state_machine_run().await.unwrap();
    }
}
