use std::fs;
use std::path::PathBuf;

use anyhow::{Result, anyhow};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct PrincipalControlRealmVectors {
    vectors: Vec<PrincipalControlRealmVector>,
}

#[derive(Deserialize)]
struct PrincipalControlRealmVector {
    principal_id: String,
    principal_control_realm_id: String,
}

#[test]
fn principal_control_realm_vectors_match_sdk() -> Result<()> {
    let fixture: PrincipalControlRealmVectors =
        read_json_fixture("principal-control-realm-vectors.json")?;
    assert!(!fixture.vectors.is_empty(), "PCR vector fixture is empty");

    for vector in fixture.vectors {
        let principal = arkret::Did::new(vector.principal_id.clone())
            .map_err(|error| anyhow!("invalid vector DID {}: {error}", vector.principal_id))?;
        let actual = arkret_models_identity::did_document::principal_control_realm_id(&principal);
        assert_eq!(
            actual, vector.principal_control_realm_id,
            "principal_control_realm_id drift for {}",
            vector.principal_id
        );
    }
    Ok(())
}

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
    assert_eq!(
        active_ids,
        arkret_policy::generated::profiles::REDUCER_PROFILE_IDS,
        "Spec registry and generated SDK reducer profile ids must agree"
    );
    assert_eq!(active_ids, [arkret_wire::CORE_REDUCER_PROFILE]);
    Ok(())
}

fn read_json_fixture<T: for<'de> Deserialize<'de>>(name: &str) -> Result<T> {
    let path = manifest_dir().join("e2e").join("fixtures").join(name);
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
