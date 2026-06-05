//! P2F.3 — `scope_circle_id` is reducer-immutable (`scope_rebind_forbidden`).
//!
//! CKP-0007 §3.4 normative spec:
//!
//! > 改绑 `scope_circle_id` 默认 reducer 拒绝
//! > (`failed_precondition` `reason="scope_rebind_forbidden"`); profile MAY
//! > 允许,但 MUST audit-paired high-risk update. 所有已存在 Message / 子
//! > 内容保留其写入时的 `effective_scope` 与旧 scope MLS;新内容才进新 scope.
//!
//! The companion scenario [`effective_scope_mismatch`] pins the
//! *envelope-vs-payload* consistency check (same event, two declared
//! scopes). This scenario instead pins the *prev-vs-next* check on the
//! materialised object — i.e. two `ck.flow.update` events for the same
//! `entity_id` whose `scope_circle_id` values diverge MUST be rejected by
//! `validate_no_scope_rebind(prev, next)` with the
//! `scope_rebind_forbidden` reason code.
//!
//! The SDK does not currently expose a typed `validate_no_scope_rebind`
//! function — this scenario therefore defines a reducer-pure helper
//! locally that any future SDK helper / reducer SHOULD match bit-for-bit.

use anyhow::{Result, anyhow};
use cokret_core::error::REASON_SCOPE_REBIND_FORBIDDEN;
use cokret_core::{CircleId, Did, Flow, FlowId, RealmId};
use serde_json::Value;

fn realm_id() -> Result<RealmId> {
    RealmId::new("ck:realm:0196419b-0000-7000-8000-000000000602".to_owned())
        .map_err(|e| anyhow!("realm id: {e}"))
}

fn flow_id() -> Result<FlowId> {
    // `Flow::new` now takes a typed `FlowId` (was a raw String). The id MUST be
    // a strict `ck:flow:<uuid7>` literal; all four prev/next states below share
    // the same entity id so the scope-rebind helper compares the same Flow.
    FlowId::new("ck:flow:0196419b-0000-7000-8000-000000000605".to_owned())
        .map_err(|e| anyhow!("flow id: {e}"))
}

fn circle_a() -> Result<CircleId> {
    CircleId::new("ck:circle:0196419b-0000-7000-8000-000000000603".to_owned())
        .map_err(|e| anyhow!("circle a: {e}"))
}

fn circle_b() -> Result<CircleId> {
    CircleId::new("ck:circle:0196419b-0000-7000-8000-000000000604".to_owned())
        .map_err(|e| anyhow!("circle b: {e}"))
}

fn actor() -> Result<Did> {
    "did:web:alice.example"
        .parse()
        .map_err(|e| anyhow!("actor did: {e}"))
}

/// Reducer-pure invariant: for two sequential states of the same Flow /
/// Space / Morph entity (`prev`, `next`), the `scope_circle_id` MUST NOT
/// change. Specifically:
///   - `None → None`         OK (Realm-default stays Realm-default)
///   - `Some(C) → Some(C)`   OK (same Circle, same scope)
///   - `None → Some(C)`      rejected (scope rebind)
///   - `Some(C) → None`      rejected (scope rebind)
///   - `Some(A) → Some(B)`   rejected (scope rebind across Circles)
///
/// Profile MAY allow rebind via an explicit audited high-risk path; this
/// helper assumes default profile (rebind forbidden).
///
/// Returns `Err` whose message contains the
/// [`REASON_SCOPE_REBIND_FORBIDDEN`] reason code so callers can match on
/// the wire reason.
fn validate_no_scope_rebind(prev: Option<&CircleId>, next: Option<&CircleId>) -> Result<()> {
    match (prev, next) {
        (None, None) => Ok(()),
        (Some(a), Some(b)) if a.as_str() == b.as_str() => Ok(()),
        (None, Some(b)) => Err(anyhow!(
            "reason={REASON_SCOPE_REBIND_FORBIDDEN}: scope_circle_id rebind \
             from Realm-default to circle_id={} forbidden (CKP-0007 §3.4)",
            b.as_str()
        )),
        (Some(a), None) => Err(anyhow!(
            "reason={REASON_SCOPE_REBIND_FORBIDDEN}: scope_circle_id rebind \
             from circle_id={} to Realm-default forbidden (CKP-0007 §3.4)",
            a.as_str()
        )),
        (Some(a), Some(b)) => Err(anyhow!(
            "reason={REASON_SCOPE_REBIND_FORBIDDEN}: scope_circle_id rebind \
             from circle_id={} to circle_id={} forbidden (CKP-0007 §3.4)",
            a.as_str(),
            b.as_str()
        )),
    }
}

pub async fn scope_circle_id_immutability_run() -> Result<()> {
    // ── Build a Flow with scope_circle_id=Some(circle_a) and confirm it
    //    serialises to wire shape with the field set.
    let mut flow_a = Flow::new(flow_id()?, realm_id()?, "Quarterly review", actor()?);
    flow_a.scope_circle_id = Some(circle_a()?);

    let json_a: Value =
        serde_json::to_value(&flow_a).map_err(|e| anyhow!("serialise flow_a: {e}"))?;
    let scope_field = json_a
        .get("scope_circle_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Flow JSON missing scope_circle_id; got {json_a:?}"))?;
    if scope_field != circle_a()?.as_str() {
        return Err(anyhow!(
            "Flow.scope_circle_id wire value drifted; expected {}, got {scope_field}",
            circle_a()?.as_str()
        ));
    }
    let parsed_a: Flow =
        serde_json::from_value(json_a).map_err(|e| anyhow!("parse flow_a: {e}"))?;
    if parsed_a.scope_circle_id.as_ref().map(|c| c.as_str()) != Some(circle_a()?.as_str()) {
        return Err(anyhow!("Flow.scope_circle_id round-trip lost the binding"));
    }

    // ── Same prev/next: accept.
    validate_no_scope_rebind(
        parsed_a.scope_circle_id.as_ref(),
        parsed_a.scope_circle_id.as_ref(),
    )
    .map_err(|e| anyhow!("expected accept on identical prev/next; got: {e}"))?;

    // ── None → None: accept.
    validate_no_scope_rebind(None, None)
        .map_err(|e| anyhow!("expected accept on None → None; got: {e}"))?;

    // ── circle_a → circle_a (build a sibling next-state Flow): accept.
    let mut flow_a_next = Flow::new(flow_id()?, realm_id()?, "Quarterly review v2", actor()?);
    flow_a_next.scope_circle_id = Some(circle_a()?);
    validate_no_scope_rebind(
        parsed_a.scope_circle_id.as_ref(),
        flow_a_next.scope_circle_id.as_ref(),
    )
    .map_err(|e| anyhow!("expected accept on same-circle update; got: {e}"))?;

    // ── Rebind: circle_a → circle_b: reject with scope_rebind_forbidden.
    let mut flow_b = Flow::new(flow_id()?, realm_id()?, "Quarterly review v3", actor()?);
    flow_b.scope_circle_id = Some(circle_b()?);
    match validate_no_scope_rebind(
        parsed_a.scope_circle_id.as_ref(),
        flow_b.scope_circle_id.as_ref(),
    ) {
        Ok(()) => {
            return Err(anyhow!(
                "expected reject on circle_a → circle_b rebind; got accept"
            ));
        }
        Err(e) => {
            let msg = e.to_string();
            if !msg.contains(REASON_SCOPE_REBIND_FORBIDDEN) {
                return Err(anyhow!(
                    "expected reason={REASON_SCOPE_REBIND_FORBIDDEN} in error; got: {msg}"
                ));
            }
        }
    }

    // ── Rebind: circle_a → None: reject (Circle → Realm-default).
    let mut flow_none = Flow::new(flow_id()?, realm_id()?, "downgrade", actor()?);
    flow_none.scope_circle_id = None;
    match validate_no_scope_rebind(
        parsed_a.scope_circle_id.as_ref(),
        flow_none.scope_circle_id.as_ref(),
    ) {
        Ok(()) => {
            return Err(anyhow!(
                "expected reject on circle_a → None rebind; got accept"
            ));
        }
        Err(e) => {
            let msg = e.to_string();
            if !msg.contains(REASON_SCOPE_REBIND_FORBIDDEN) {
                return Err(anyhow!(
                    "expected reason={REASON_SCOPE_REBIND_FORBIDDEN}; got: {msg}"
                ));
            }
        }
    }

    // ── Rebind: None → circle_b: reject (Realm-default → Circle).
    match validate_no_scope_rebind(None, flow_b.scope_circle_id.as_ref()) {
        Ok(()) => {
            return Err(anyhow!(
                "expected reject on None → circle_b rebind; got accept"
            ));
        }
        Err(e) => {
            let msg = e.to_string();
            if !msg.contains(REASON_SCOPE_REBIND_FORBIDDEN) {
                return Err(anyhow!(
                    "expected reason={REASON_SCOPE_REBIND_FORBIDDEN}; got: {msg}"
                ));
            }
        }
    }

    // ── Wire round-trip the rebind-rejection envelopes: pin that both
    //    prev / next survive serde without dropping scope_circle_id.
    let prev_json = serde_json::to_value(&parsed_a).map_err(|e| anyhow!("serialise prev: {e}"))?;
    let next_json = serde_json::to_value(&flow_b).map_err(|e| anyhow!("serialise next: {e}"))?;
    let prev_field = prev_json
        .get("scope_circle_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("prev wire dropped scope_circle_id"))?;
    let next_field = next_json
        .get("scope_circle_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("next wire dropped scope_circle_id"))?;
    if prev_field == next_field {
        return Err(anyhow!(
            "wire round-trip MUST preserve the divergence: prev={prev_field} \
             next={next_field}"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scope_circle_id_is_immutable_across_updates() {
        scope_circle_id_immutability_run().await.unwrap();
    }
}
