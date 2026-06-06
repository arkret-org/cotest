//! Protocol-artifact drift validator allowlist refresh.
//!
//! Each constant lists the **new** identifiers introduced by the spec
//! change set (`2a4d39b..a77b9958e3c6535a39bf468d661a23ae5d38cb10`).
//! The pinned sets are cross-checked against the live canonical registry
//! files inside `cokret-spec` so any drop / rename / typo fails cotest
//! loudly.
//!
//! Surfaces refreshed:
//!
//! * **capability action allowlist**: `ck.morph.create`
//! * **error code allowlist**: `delivery_binding_stale`, `delivery_binding_handed_over`,
//!   `historical_only`
//! * **id_kind allowlist** for `object_ref` context: `ck:space:` joins the accepted set
//! * **schema $defs / OpenAPI component allowlist**: `EventsSubscribeFrame`, `SnapshotBootstrap`,
//!   `EventsFrontierAccountClientState`, `EventsFrontierFederationPeerState`,
//!   `EventsFrontierAnonymousHealthResponse`, `PolicyCheckRequestBody`, `PolicyCheckOutcome`,
//!   `FederationServiceBindingRef`, `EventsSubmitBatchRequestBody`, `EventsSubmitFederationRequestBody`,
//!   `third_party_invite`, `space_state_transition_payload`, `space_object_tombstone_payload`

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::{load_artifact_json, load_artifact_yaml};

/// New capability action introduced by round 4 (7fae9ba).
pub const NEW_CAPABILITY_ACTIONS: &[&str] = &["ck.morph.create"];

/// New error codes introduced by round 4 (7446832 + 7fae9ba).
pub const NEW_ERROR_CODES: &[&str] = &[
    "delivery_binding_stale",
    "delivery_binding_handed_over",
    "historical_only",
];

/// New typed-id kinds accepted inside `object_ref` (369f544).
pub const NEW_OBJECT_REF_ID_KINDS: &[&str] = &["space"];

/// New schema `$defs` introduced by round 4 (d74bb75 + 369f544 + 58c5926).
pub const NEW_SCHEMA_DEFS: &[&str] = &[
    "third_party_invite",
    "space_state_transition_payload",
    "space_object_tombstone_payload",
    "EventsSubscribeFrame",
    "SnapshotBootstrap",
];

/// New OpenAPI components introduced by round 4 (d74bb75 + 7446832).
pub const NEW_OPENAPI_COMPONENTS: &[&str] = &[
    "EventsSubmitBatchRequestBody",
    "EventsSubmitFederationRequestBody",
    "FederationServiceBindingRef",
    "EventsFrontierAccountClientState",
    "EventsFrontierFederationPeerState",
    "EventsFrontierAnonymousHealthResponse",
    "PolicyCheckRequestBody",
    "PolicyCheckOutcome",
    "EventsSubscribeFrame",
];

/// Run the drift-allowlist refresh suite. Each new identifier must be
/// present in the canonical registry — otherwise cotest reports the drift
/// loudly so the implementer projects don't ship wire shape that the
/// canonical artifact has already removed.
pub fn run_protocol_artifact_allowlist_suite() -> Result<()> {
    check_capability_actions_present(NEW_CAPABILITY_ACTIONS)?;
    check_error_codes_present(NEW_ERROR_CODES)?;
    check_id_kinds_present(NEW_OBJECT_REF_ID_KINDS)?;
    check_schema_defs_present(NEW_SCHEMA_DEFS)?;
    check_openapi_components_present(NEW_OPENAPI_COMPONENTS)?;
    Ok(())
}

fn check_capability_actions_present(required: &[&str]) -> Result<()> {
    let registry = load_artifact_json("registry/capability-action-registry.json")
        .or_else(|_| load_artifact_json("registry/capability-actions.json"))
        .map_err(|err| anyhow!("capability action registry not loadable: {err}"))?;
    let actions = collect_strings(
        &registry,
        &["actions", "capability_actions", "entries", "items"],
    )?;
    for action in required {
        if !actions.contains(*action) {
            bail!(
                "protocol-artifact allowlist: capability action `{action}` not found in canonical registry"
            );
        }
    }
    Ok(())
}

fn check_error_codes_present(required: &[&str]) -> Result<()> {
    let registry = load_artifact_json("registry/error-code-registry.json")?;
    let codes = collect_strings(&registry, &["codes", "error_codes", "errors", "entries"])?;
    for code in required {
        if !codes.contains(*code) {
            bail!(
                "protocol-artifact allowlist: error code `{code}` not found in canonical registry"
            );
        }
    }
    Ok(())
}

fn check_id_kinds_present(required: &[&str]) -> Result<()> {
    let registry = load_artifact_json("registry/id-kind-registry.json")?;
    let mut kinds: BTreeSet<String> = BTreeSet::new();
    for arr_key in ["id_kinds", "special_forms"] {
        if let Some(arr) = registry.get(arr_key).and_then(Value::as_array) {
            for entry in arr {
                if let Some(k) = entry.get("kind").and_then(Value::as_str) {
                    kinds.insert(k.to_owned());
                }
            }
        }
    }
    for kind in required {
        if !kinds.contains(*kind) {
            bail!(
                "protocol-artifact allowlist: id_kind `{kind}` not present in canonical id-kind-registry"
            );
        }
    }
    Ok(())
}

fn check_schema_defs_present(required: &[&str]) -> Result<()> {
    // The new $defs live under `event-payload.schema.json#/$defs` (most),
    // `event-envelope.schema.json#/$defs` (some), or as standalone schemas. We
    // search every schema file's `$defs` map plus the top-level `$id`s.
    let registry = load_artifact_json("registry/schema-registry.json")?;
    let mut found = BTreeSet::<String>::new();
    let schemas = registry
        .get("schemas")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("schema-registry.json missing `schemas` array"))?;
    for schema in schemas {
        if let Some(rel) = schema.get("file").and_then(Value::as_str) {
            let path = super::spec_artifacts_root().join(rel);
            if !path.is_file() {
                continue;
            }
            let raw = match std::fs::read_to_string(&path) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let value: Value = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Some(defs) = value.get("$defs").and_then(Value::as_object) {
                for key in defs.keys() {
                    found.insert(key.clone());
                }
            }
            // Schema id `schema` field on the top object (e.g.
            // EventsSubscribeFrame might live as a standalone schema in
            // future); accept the schema_id too.
            if let Some(schema_id) = schema.get("schema_id").and_then(Value::as_str) {
                found.insert(schema_id.to_owned());
            }
        }
    }
    // Also accept identifiers that appear in the OpenAPI components map
    // (some round-4 names are OpenAPI-side, e.g. EventsSubscribeFrame can
    // double-up as both).
    if let Ok(openapi) = load_artifact_yaml("openapi/cokret-service-api.openapi.yaml") {
        if let Some(components) = openapi
            .get("components")
            .and_then(|c| c.get("schemas"))
            .and_then(serde_yaml::Value::as_mapping)
        {
            for (k, _) in components {
                if let Some(name) = k.as_str() {
                    found.insert(name.to_owned());
                }
            }
        }
    }
    for def in required {
        if !found.contains(*def) {
            bail!(
                "protocol-artifact allowlist: schema $def `{def}` not present in any canonical schema file or OpenAPI components map"
            );
        }
    }
    Ok(())
}

fn check_openapi_components_present(required: &[&str]) -> Result<()> {
    let openapi = load_artifact_yaml("openapi/cokret-service-api.openapi.yaml")?;
    let components = openapi
        .get("components")
        .and_then(|c| c.get("schemas"))
        .and_then(serde_yaml::Value::as_mapping)
        .ok_or_else(|| anyhow!("openapi components.schemas missing"))?;
    let names: BTreeSet<String> = components
        .iter()
        .filter_map(|(k, _)| k.as_str().map(str::to_owned))
        .collect();
    for component in required {
        if !names.contains(*component) {
            bail!(
                "protocol-artifact allowlist: OpenAPI component `{component}` missing from canonical openapi schemas"
            );
        }
    }
    Ok(())
}

/// Collect strings from one of the candidate array keys in a registry
/// document. Each entry is expected to expose either a top-level string
/// id field or a recognised id property.
fn collect_strings(registry: &Value, keys: &[&str]) -> Result<BTreeSet<String>> {
    for key in keys {
        if let Some(arr) = registry.get(*key).and_then(Value::as_array) {
            let mut out = BTreeSet::new();
            for entry in arr {
                if let Some(s) = entry.as_str() {
                    out.insert(s.to_owned());
                    continue;
                }
                for cand in [
                    "id",
                    "action",
                    "name",
                    "code",
                    "error_code",
                    "capability_action",
                ] {
                    if let Some(v) = entry.get(cand).and_then(Value::as_str) {
                        out.insert(v.to_owned());
                    }
                }
            }
            return Ok(out);
        }
    }
    Err(anyhow!(
        "registry missing all candidate array keys: {:?}",
        keys
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drift_allowlist_matches_canonical_registry() {
        run_protocol_artifact_allowlist_suite()
            .expect("round-4 drift allowlist must agree with canonical spec registry");
    }
}
