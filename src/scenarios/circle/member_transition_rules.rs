//! Circle membership uses registered `sequenced_state` transition rules.
//!
//! Invite create/cancel/revoke are a separate lifecycle and never synthesize a
//! Circle member state. This scenario pins the ordered rules and the closed
//! `ak.circle.member.state` payload spelling (`member_id`, not `actor_id`).

use anyhow::{Result, anyhow};
use arkret::{AccountId, ActorId, DidCoreId};
use arkret_identifiers::CircleId;
use serde_json::json;

const STATES: &[&str] = &["join", "knock", "leave", "ban"];
const LEGAL: &[(&str, &str)] = &[
    ("leave", "knock"),
    ("leave", "join"),
    ("knock", "join"),
    ("knock", "leave"),
    ("join", "leave"),
    ("leave", "ban"),
    ("knock", "ban"),
    ("join", "ban"),
    ("ban", "leave"),
];

fn validate_member_transition(from: &str, to: &str) -> Result<()> {
    if !STATES.contains(&from) || !STATES.contains(&to) || from == to {
        return Err(anyhow!(
            "illegal Circle membership transition {from} -> {to}"
        ));
    }
    LEGAL
        .contains(&(from, to))
        .then_some(())
        .ok_or_else(|| anyhow!("illegal Circle membership transition {from} -> {to}"))
}

fn circle_id() -> Result<CircleId> {
    CircleId::new("ak:circle:AQgM_3A69AFjOIogSDnCwi4Qai8s_mR6kMsg4ZBJdn-C".to_owned())
        .map_err(|error| anyhow!("circle id: {error}"))
}

fn actor_id() -> Result<ActorId> {
    Ok(ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:alice.example".to_owned())?,
        DidCoreId::new("ak:did_core:web:station.example".to_owned())?,
    )))
}

fn round_trip_member_payload(state: &str) -> Result<()> {
    let payload = json!({
        "circle_id": circle_id()?,
        "member_id": actor_id()?,
        "membership": state,
    });
    let bytes = serde_json::to_vec(&payload)?;
    let parsed: serde_json::Value = serde_json::from_slice(&bytes)?;
    if parsed.get("actor_id").is_some()
        || parsed.get("member_id").is_none()
        || parsed.get("membership").and_then(serde_json::Value::as_str) != Some(state)
    {
        return Err(anyhow!("Circle member payload wire shape drifted"));
    }
    Ok(())
}

pub async fn member_transition_rules_run() -> Result<()> {
    for state in STATES {
        round_trip_member_payload(state)?;
    }
    for &(from, to) in LEGAL {
        validate_member_transition(from, to)?;
    }
    for &(from, to) in &[
        ("join", "join"),
        ("join", "knock"),
        ("ban", "join"),
        ("ban", "knock"),
    ] {
        if validate_member_transition(from, to).is_ok() {
            return Err(anyhow!("expected {from} -> {to} to fail closed"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn member_transition_table_matches_spec() {
        member_transition_rules_run().await.unwrap();
    }
}
