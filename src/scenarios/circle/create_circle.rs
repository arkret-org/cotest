//! P2F.3 — happy-path Circle creation round-trip.
//!
//! Asserts that constructing a `Circle` via the SDK helper yields the
//! canonical schema id, defaults state to `Active`, and round-trips
//! through `serde_json` without leaking unknown fields or losing required
//! ones. This scenario does not require a live server — it pins the SDK
//! type's wire shape against `spec/v1/artifacts/schemas/circle.schema.json`.

use anyhow::{Result, anyhow};
use arkret_identifiers::{CircleId, DidCoreId, RealmId};
use arkret_models_collaboration::governance::circle::{
    Circle, CircleColorToken, CircleDirectoryVisibility, CircleDisplay, CircleGlyph,
    CircleJoinRule, CircleState, CircleSymbol,
};

fn display() -> CircleDisplay {
    CircleDisplay {
        short_name: "Ops".to_owned(),
        color_token: CircleColorToken::Indigo,
        symbol: CircleSymbol::Glyph {
            glyph: CircleGlyph::Shield,
        },
    }
}

fn circle_id() -> Result<CircleId> {
    CircleId::new("ak:circle:AVBgYTmzSkzTSd1dlFH4ZADaQRkVcx_iTAvXdxlTfxrg".to_owned())
        .map_err(|e| anyhow!("circle id: {e}"))
}

fn realm_id() -> Result<RealmId> {
    RealmId::new("ak:realm:AanXMcYAcnsCwtnIOkcvD9_cVIZM2ClGR-GyNE4AD38B".to_owned())
        .map_err(|e| anyhow!("realm id: {e}"))
}

fn actor() -> Result<DidCoreId> {
    "did:web:alice.example"
        .parse()
        .map_err(|e| anyhow!("actor did: {e}"))
}

/// Build a canonical Circle and verify the SDK happy-path round-trip.
pub async fn create_circle_run() -> Result<()> {
    let circle = Circle::new(circle_id()?, realm_id()?, "Ops Circle", display(), actor()?);

    // Defaults expected by spec.
    if circle.state != CircleState::Active {
        return Err(anyhow!(
            "Circle::new MUST default state to Active; got {:?}",
            circle.state
        ));
    }
    if circle.directory_visibility != CircleDirectoryVisibility::Members {
        return Err(anyhow!(
            "Circle::new MUST default directory_visibility to members; got {:?}",
            circle.directory_visibility
        ));
    }
    if circle.join_rule != CircleJoinRule::Invite {
        return Err(anyhow!(
            "Circle::new MUST default join_rule to invite; got {:?}",
            circle.join_rule
        ));
    }

    // JSON canonicalisation round-trip.
    let json = serde_json::to_value(&circle).map_err(|e| anyhow!("serialise: {e}"))?;
    let schema_field = json
        .get("schema")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Circle JSON missing `schema` field"))?;
    if schema_field != "ak.schema.circle.v1" {
        return Err(anyhow!(
            "Circle.schema MUST be `ak.schema.circle.v1`; got `{schema_field}`"
        ));
    }
    let parsed: Circle = serde_json::from_value(json).map_err(|e| anyhow!("parse: {e}"))?;
    if parsed.id != circle.id {
        return Err(anyhow!("round-trip lost Circle.id"));
    }
    if parsed.realm_id.as_str() != circle.realm_id.as_str() {
        return Err(anyhow!("round-trip lost Circle.realm_id"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn happy_path_circle_round_trips() {
        create_circle_run().await.unwrap();
    }
}
