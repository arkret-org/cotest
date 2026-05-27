//! P2F.3 — envelope vs payload `scope_circle_id` mismatch is rejected.
//!
//! Reducers MUST reject events whose [`EffectiveScope::Circle.circle_id`]
//! disagrees with the `scope_circle_id` declared inside the payload's
//! object (Flow / Space / Morph). This scenario builds two hand-rolled
//! wire envelopes that exercise that contract — one in which the binding
//! is consistent (accept), one in which envelope and payload point at
//! different Circles (reject — `circle_realm_mismatch` family).
//!
//! The scenario doesn't talk to a live reducer; it instead pins the
//! consistency check that any reducer / SDK helper MUST perform before
//! accepting the envelope. The check is local to the envelope bytes.

use anyhow::{Result, anyhow};
use contrix_core::{CircleId, EffectiveScope, RealmId};
use serde_json::{Value, json};

fn realm_id() -> Result<RealmId> {
    RealmId::new("cx:realm:0196419b-0000-7000-8000-000000000401".to_owned())
        .map_err(|e| anyhow!("realm id: {e}"))
}

fn circle_a() -> Result<CircleId> {
    CircleId::new("cx:circle:0196419b-0000-7000-8000-000000000402".to_owned())
        .map_err(|e| anyhow!("circle a: {e}"))
}

fn circle_b() -> Result<CircleId> {
    CircleId::new("cx:circle:0196419b-0000-7000-8000-000000000403".to_owned())
        .map_err(|e| anyhow!("circle b: {e}"))
}

/// Local consistency check that any reducer MUST perform: when an event
/// envelope carries [`EffectiveScope::Circle`] AND the inner payload
/// declares a `scope_circle_id`, the two MUST agree on both realm_id and
/// circle_id. Returns `Ok(())` when consistent, `Err(reason)` when not.
fn assert_envelope_payload_scope_agrees(
    envelope_scope: &EffectiveScope,
    payload: &Value,
) -> Result<()> {
    let payload_realm = payload.pointer("/object/realm_id").and_then(|v| v.as_str());
    let payload_circle = payload
        .pointer("/object/scope_circle_id")
        .and_then(|v| v.as_str());
    match envelope_scope {
        EffectiveScope::Realm { realm_id } => {
            if let Some(circle) = payload_circle {
                return Err(anyhow!(
                    "reason=scope_rebind_forbidden: envelope is Realm-scoped \
                     but payload binds scope_circle_id={circle}"
                ));
            }
            if let Some(payload_realm) = payload_realm
                && payload_realm != realm_id.as_str()
            {
                return Err(anyhow!(
                    "reason=circle_realm_mismatch: envelope realm_id={} \
                     differs from payload realm_id={payload_realm}",
                    realm_id.as_str()
                ));
            }
        }
        EffectiveScope::Circle {
            realm_id,
            circle_id,
        } => {
            if let Some(payload_realm) = payload_realm
                && payload_realm != realm_id.as_str()
            {
                return Err(anyhow!(
                    "reason=circle_realm_mismatch: envelope realm_id={} \
                     differs from payload realm_id={payload_realm}",
                    realm_id.as_str()
                ));
            }
            match payload_circle {
                None => {
                    return Err(anyhow!(
                        "reason=scope_rebind_forbidden: envelope is Circle-scoped \
                         on {} but payload omits scope_circle_id",
                        circle_id.as_str()
                    ));
                }
                Some(c) if c != circle_id.as_str() => {
                    return Err(anyhow!(
                        "reason=circle_realm_mismatch: envelope circle_id={} \
                         differs from payload scope_circle_id={c}",
                        circle_id.as_str()
                    ));
                }
                Some(_) => { /* agree */ }
            }
        }
    }
    Ok(())
}

pub async fn effective_scope_mismatch_run() -> Result<()> {
    let envelope_scope = EffectiveScope::Circle {
        realm_id: realm_id()?,
        circle_id: circle_a()?,
    };

    // ── Accept: envelope and payload agree on circle_a.
    let consistent_payload = json!({
        "object": {
            "realm_id": realm_id()?.as_str(),
            "scope_circle_id": circle_a()?.as_str(),
        }
    });
    assert_envelope_payload_scope_agrees(&envelope_scope, &consistent_payload)
        .map_err(|e| anyhow!("expected accept on agreeing envelope/payload; got: {e}"))?;

    // ── Reject: payload declares a different Circle (circle_b).
    let mismatched_payload = json!({
        "object": {
            "realm_id": realm_id()?.as_str(),
            "scope_circle_id": circle_b()?.as_str(),
        }
    });
    match assert_envelope_payload_scope_agrees(&envelope_scope, &mismatched_payload) {
        Ok(()) => {
            return Err(anyhow!(
                "expected reject on envelope/payload circle_id mismatch; got accept"
            ));
        }
        Err(e) => {
            let msg = e.to_string();
            if !msg.contains("circle_realm_mismatch") {
                return Err(anyhow!(
                    "expected reason=circle_realm_mismatch in error; got: {msg}"
                ));
            }
        }
    }

    // ── Reject: payload omits scope_circle_id under a Circle-scoped envelope.
    let unscoped_payload = json!({
        "object": { "realm_id": realm_id()?.as_str() }
    });
    match assert_envelope_payload_scope_agrees(&envelope_scope, &unscoped_payload) {
        Ok(()) => {
            return Err(anyhow!(
                "expected reject on envelope-Circle / payload-no-scope; got accept"
            ));
        }
        Err(e) => {
            let msg = e.to_string();
            if !msg.contains("scope_rebind_forbidden") {
                return Err(anyhow!(
                    "expected reason=scope_rebind_forbidden in error; got: {msg}"
                ));
            }
        }
    }

    // ── Reject: envelope-Realm but payload tries to bind a circle.
    let realm_envelope = EffectiveScope::Realm {
        realm_id: realm_id()?,
    };
    let illicit_circle = json!({
        "object": {
            "realm_id": realm_id()?.as_str(),
            "scope_circle_id": circle_a()?.as_str(),
        }
    });
    match assert_envelope_payload_scope_agrees(&realm_envelope, &illicit_circle) {
        Ok(()) => {
            return Err(anyhow!(
                "expected reject on Realm-envelope / Circle-payload; got accept"
            ));
        }
        Err(e) => {
            let msg = e.to_string();
            if !msg.contains("scope_rebind_forbidden") {
                return Err(anyhow!(
                    "expected reason=scope_rebind_forbidden in error; got: {msg}"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn envelope_payload_scope_mismatch_rejected() {
        effective_scope_mismatch_run().await.unwrap();
    }
}
