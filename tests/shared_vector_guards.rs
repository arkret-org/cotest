use std::fs;
use std::path::PathBuf;

use anyhow::{Result, anyhow};
use serde_json::Value;

#[test]
fn reducer_profile_registry_and_sdk_support_set_agree() -> Result<()> {
    let registry: Value = serde_json::from_str(&fs::read_to_string(
        manifest_dir()
            .parent()
            .expect("cotest has workspace parent")
            .join("arkret-spec")
            .join("spec")
            .join("v1")
            .join("artifacts")
            .join("registry")
            .join("reducer-profile-registry.json"),
    )?)?;

    let active_rows = registry
        .get("profiles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|row| row.get("status").and_then(Value::as_str) == Some("active"))
        .collect::<Vec<_>>();
    assert!(!active_rows.is_empty(), "active reducer registry is empty");

    let active_ids = active_rows
        .iter()
        .map(|row| {
            row.get("profile_id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("active reducer profile lacks profile_id"))
        })
        .collect::<Result<Vec<_>>>()?;
    let sdk_ids = arkret_wire::ReducerProfileId::ALL
        .iter()
        .map(|id| id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        active_ids, sdk_ids,
        "Spec registry and generated SDK reducer profile ids must agree"
    );
    assert_eq!(active_ids, [arkret_wire::CORE_REDUCER_PROFILE]);
    Ok(())
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
