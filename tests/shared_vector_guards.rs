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
        let actual = arkret_core::principal_control_realm_id(&principal);
        assert_eq!(
            actual, vector.principal_control_realm_id,
            "principal_control_realm_id drift for {}",
            vector.principal_id
        );
    }
    Ok(())
}

#[test]
fn reducer_profile_digest_vectors_cover_active_registry() -> Result<()> {
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

    for row in active_rows {
        let profile_id = row
            .get("profile_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("active reducer profile lacks profile_id"))?;
        let expected = row
            .get("reducer_profile_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("active reducer profile {profile_id} lacks generated digest"))?;
        let actual = cotest::conformance::reducer_profile_digest(profile_id)?;
        assert_eq!(
            actual, expected,
            "reducer profile digest drift for {profile_id}"
        );
        if profile_id == cotest::conformance::FEDERATION_MINIMAL_PROFILE_ID {
            assert_eq!(
                actual,
                arkret::FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST,
                "Spec, SDK, Soland consumer, and Cotest federation digest must share one generated value"
            );
        }
    }
    Ok(())
}

fn read_json_fixture<T: for<'de> Deserialize<'de>>(name: &str) -> Result<T> {
    let path = manifest_dir().join("e2e").join("fixtures").join(name);
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
