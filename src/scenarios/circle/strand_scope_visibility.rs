//! P2F.3 — Circle-scoped Strand envelopes stamp `ScopeRef::Circle`.
//!
//! Pins the serde shape of [`arkret_wire::ScopeRef`] for both
//! variants (`Realm` and `Circle`) and asserts that the Circle variant
//! retains both `realm_id` and `circle_id` across a JSON round-trip — the
//! envelope-vs-payload visibility binding required by AKP-0007.

use anyhow::{Result, anyhow};
use arkret_identifiers::{CircleId, RealmId};
use arkret_wire::ScopeRef;
use serde_json::json;

fn realm_id() -> Result<RealmId> {
    RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000301".to_owned())
        .map_err(|e| anyhow!("realm id: {e}"))
}

fn circle_id() -> Result<CircleId> {
    CircleId::new("ak:circle:0196419b-0000-7000-8000-000000000302".to_owned())
        .map_err(|e| anyhow!("circle id: {e}"))
}

pub async fn strand_scope_visibility_run() -> Result<()> {
    // Realm-only scope: shape `{ "kind": "realm", "realm_id": "..." }`.
    let realm = ScopeRef::Realm {
        realm_id: realm_id()?,
    };
    let realm_json = serde_json::to_value(&realm).map_err(|e| anyhow!("serialise realm: {e}"))?;
    let kind = realm_json.get("kind").and_then(|v| v.as_str());
    if kind != Some("realm") {
        return Err(anyhow!(
            "ScopeRef::Realm MUST serialise with kind=\"realm\"; got {kind:?}"
        ));
    }
    if realm_json.get("circle_id").is_some() {
        return Err(anyhow!(
            "ScopeRef::Realm MUST NOT carry circle_id; got {realm_json:?}"
        ));
    }

    // Circle scope: shape `{ "kind": "circle", "realm_id": "...", "circle_id": "..." }`.
    let circle = ScopeRef::Circle {
        realm_id: realm_id()?,
        circle_id: circle_id()?,
    };
    let circle_json =
        serde_json::to_value(&circle).map_err(|e| anyhow!("serialise circle: {e}"))?;
    let kind = circle_json.get("kind").and_then(|v| v.as_str());
    if kind != Some("circle") {
        return Err(anyhow!(
            "ScopeRef::Circle MUST serialise with kind=\"circle\"; got {kind:?}"
        ));
    }
    let circle_id_field = circle_json.get("circle_id").and_then(|v| v.as_str());
    if circle_id_field != Some(circle_id()?.as_str()) {
        return Err(anyhow!(
            "ScopeRef::Circle MUST carry circle_id; got {circle_id_field:?}"
        ));
    }

    // Round-trip from a hand-rolled JSON payload to assert the wire form
    // is the contract (and not just the Rust struct).
    let wire = json!({
        "kind": "circle",
        "realm_id": realm_id()?.as_str(),
        "circle_id": circle_id()?.as_str(),
    });
    let parsed: ScopeRef =
        serde_json::from_value(wire).map_err(|e| anyhow!("parse circle wire: {e}"))?;
    if parsed.circle_id().map(|c| c.as_str()) != Some(circle_id()?.as_str()) {
        return Err(anyhow!("round-tripped ScopeRef::Circle dropped circle_id"));
    }
    if parsed.realm_id().as_str() != realm_id()?.as_str() {
        return Err(anyhow!("round-tripped ScopeRef::Circle dropped realm_id"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn effective_scope_circle_round_trip() {
        strand_scope_visibility_run().await.unwrap();
    }
}
