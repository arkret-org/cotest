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

#[derive(Deserialize)]
struct ReducerProfileDigestVectors {
    vectors: Vec<ReducerProfileDigestVector>,
}

#[derive(Deserialize)]
struct ReducerProfileDigestVector {
    profile_id: String,
    expected_digest: String,
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
    let fixture: ReducerProfileDigestVectors =
        read_json_fixture("reducer-profile-digest-vectors.json")?;
    assert!(
        !fixture.vectors.is_empty(),
        "reducer profile digest vector fixture is empty"
    );
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

    let vectors = fixture
        .vectors
        .into_iter()
        .map(|vector| (vector.profile_id, vector.expected_digest))
        .collect::<std::collections::BTreeMap<_, _>>();
    for row in registry
        .get("profiles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|row| row.get("status").and_then(Value::as_str) == Some("active"))
    {
        let profile_id = row
            .get("profile_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("active reducer profile lacks profile_id"))?;
        let expected = vectors
            .get(profile_id)
            .ok_or_else(|| anyhow!("missing reducer digest vector for {profile_id}"))?;
        let actual = cotest::conformance::reducer_profile_digest(profile_id)?;
        assert_eq!(
            actual, *expected,
            "reducer profile digest drift for {profile_id}"
        );
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
