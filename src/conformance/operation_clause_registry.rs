use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::load_artifact_json;

const CLAUSE_REGISTRY: &str = "registry/operation-clause-registry.json";
const OPERATION_REGISTRY: &str = "registry/operation-registry.json";

pub fn validate_operation_clause_registry() -> Result<()> {
    let clauses = load_artifact_json(CLAUSE_REGISTRY)?;
    let operations = load_artifact_json(OPERATION_REGISTRY)?;
    let active = clauses
        .get("clauses")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("operation clause registry missing clauses[]"))?;
    let operation_rows = operations
        .get("operations")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("operation registry missing operations[]"))?;
    if operation_rows.is_empty() {
        bail!("operation registry has no operations");
    }

    let mut ids = BTreeSet::new();
    let mut all_operation_clauses = 0usize;
    let allowed_selectors = BTreeSet::from([
        "all_operations",
        "openapi_protected_operations",
        "write_operations",
        "http_operations",
        "stream_operations",
        "partial_outcome_operations",
        "privacy_sensitive_operations",
    ]);
    for clause in active {
        if clause.get("status").and_then(Value::as_str) != Some("active") {
            continue;
        }
        let id = clause
            .get("clause_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("active operation clause missing clause_id"))?;
        if !ids.insert(id) {
            bail!("duplicate operation clause id {id}");
        }
        let selector = clause
            .pointer("/selector/kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("{id} missing selector.kind"))?;
        if !allowed_selectors.contains(selector) {
            bail!("{id} uses unknown selector {selector}");
        }
        if selector == "all_operations" {
            all_operation_clauses += 1;
        }
        if clause
            .get("required_evidence")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
        {
            bail!("{id} has no required evidence");
        }
    }
    if all_operation_clauses < 2 || !ids.contains("AK-OP-001") || !ids.contains("AK-OP-005") {
        bail!("operation clauses do not close universal shape and error behavior");
    }
    Ok(())
}
