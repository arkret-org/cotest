//! COT-ORG-01 / COT-ORG-02 — `ak.realm.organization` (RealmOrganizationPayload)
//! payload + protocol-semantic regression gate.
//!
//! cotest is the "declared organization != verified organization" regression
//! gate. These tests drive the *shared* arkret-rust-sdk surfaces so cotest
//! never re-implements the organization-side invariants:
//!
//!   * `arkret_schema::payloads` strong [`EventPayloadValidatorCatalog`] dispatches
//!     `ak.realm.organization` to the `realm_organization_payload` def (the singleton `{
//!     organization_ref }` shape is not accepted).
//!   * `arkret_policy::verify_realm_organization_statement` enforces the issuer-role / delegation /
//!     proof / validity-window / scope / revocation invariants, fail-closed.
//!
//! COT-ORG-01 asserts the coverage fixture's active + revoked
//! `RealmOrganizationPayload` shapes validate against the SDK validator and the
//! pre-migration singleton shape is rejected.
//!
//! COT-ORG-02 replays `realm_organization_statement_negative_vectors.json`.
//! Each vector pins the **spec wire error/reason code** the verifier embeds
//! (from the SDK error-code-registry / reason-code-registry), never a
//! project-private error string.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use arkret_models_collaboration::{
    RealmOrganizationControlScope, RealmOrganizationPayload, RealmOrganizationRelationship,
};
use arkret_policy::{
    NoDelegationResolver, RealmOrganizationDelegation, RealmOrganizationDelegationResolver,
    RealmOrganizationVerificationResult, verify_realm_organization_statement,
};
use arkret_schema_conformance::{
    EventPayloadValidatorCatalog, event_payload_validator_catalog_from_configured_spec_artifacts,
};
use arkret_wire::{DidCoreId, ObjectRef, RealmId};
use chrono::{DateTime, Utc};
use serde_json::Value;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn load_spec_fixture(name: &str) -> Result<Value> {
    let path = cotest::conformance::fixture_path(name);
    let raw = fs::read_to_string(&path).with_context(|| format!("read spec fixture {name}"))?;
    serde_json::from_str(&raw).with_context(|| format!("parse spec fixture {name}"))
}

fn load_fixture(name: &str) -> Result<Value> {
    let path = fixtures_dir().join(name);
    let raw = fs::read_to_string(&path).with_context(|| format!("read fixture {name}"))?;
    serde_json::from_str(&raw).with_context(|| format!("parse fixture {name}"))
}

fn strong_catalog() -> EventPayloadValidatorCatalog {
    let catalog = event_payload_validator_catalog_from_configured_spec_artifacts()
        .expect("embedded spec artifacts must build the strong payload validator catalog");
    // Guard against silently falling back to the hand-written shapes: the
    // regression value of these tests depends on the strong schema dispatch.
    assert!(
        catalog.rules[arkret_wire::event_kind_str::REALM_ORGANIZATION]
            .payload_schema_id
            .ends_with("#/$defs/realm_organization_payload"),
        "ak.realm.organization must dispatch to the realm_organization_payload def, got {}",
        catalog.rules[arkret_wire::event_kind_str::REALM_ORGANIZATION].payload_schema_id
    );
    catalog
}

// ── COT-ORG-01 — coverage fixture payloads validate via the SDK ────────────

#[test]
fn coverage_fixture_active_and_revoked_realm_organization_payloads_validate() -> Result<()> {
    // This one is a spec artifact, not a cotest-local vector file. Reading it
    // out of `tests/fixtures` looked for a copy that does not exist, so the
    // suite failed on a missing file rather than on any payload it validates.
    let fixture = load_spec_fixture("event-kind-payload-coverage-fixture.json")?;
    let catalog = strong_catalog();

    let positives = fixture
        .get("positive_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("coverage fixture missing positive_vectors[]"))?;

    let mut active_seen = false;
    let mut revoked_seen = false;
    for vector in positives {
        if vector.get("event_kind").and_then(Value::as_str)
            != Some(arkret_wire::event_kind_str::REALM_ORGANIZATION)
        {
            continue;
        }
        let name = vector
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("organization positive vector missing name"))?;
        let payload = vector
            .get("payload_shape")
            .ok_or_else(|| anyhow!("vector {name} missing payload_shape"))?;

        // Strong schema acceptance.
        catalog
            .validate_payload(arkret_wire::event_kind_str::REALM_ORGANIZATION, payload)
            .with_context(|| format!("strong schema must accept {name}"))?;
        // Strong-typed deserialization round-trip (rejects the singleton shape).
        let _typed: RealmOrganizationPayload = serde_json::from_value(payload.clone())
            .with_context(|| {
                format!("vector {name} must deserialize to RealmOrganizationPayload")
            })?;

        match payload.get("status").and_then(Value::as_str) {
            Some("active") => {
                assert!(
                    payload.get("revokes_statement_id").is_none(),
                    "active vector {name} must not carry revokes_statement_id"
                );
                active_seen = true;
            }
            Some("revoked") => {
                assert!(
                    payload.get("revokes_statement_id").is_some(),
                    "revoked vector {name} must carry revokes_statement_id"
                );
                revoked_seen = true;
            }
            other => bail!("vector {name} unexpected status {other:?}"),
        }
    }

    assert!(
        active_seen,
        "coverage fixture must carry an active organization vector"
    );
    assert!(
        revoked_seen,
        "coverage fixture must carry a revoked organization vector"
    );
    Ok(())
}

#[test]
fn coverage_fixture_rejects_singleton_organization_ref_shape() {
    let catalog = strong_catalog();
    let singleton = serde_json::json!({ "organization_ref": "did:web:org.example" });
    assert!(
        catalog
            .validate_payload(arkret_wire::event_kind_str::REALM_ORGANIZATION, &singleton)
            .is_err(),
        "singleton {{ organization_ref }} shape must be rejected by the strong validator"
    );
    assert!(
        serde_json::from_value::<RealmOrganizationPayload>(singleton).is_err(),
        "singleton {{ organization_ref }} shape must not deserialize to RealmOrganizationPayload"
    );
}

// ── COT-ORG-02 — protocol-semantic negative vectors ────────────────────────

/// Resolver fixtures selected by the vector's `resolver` field. Mirrors the
/// shapes verify_realm_organization_statement distinguishes.
fn organization_id() -> DidCoreId {
    DidCoreId::new("ak:did_core:web:example.test:orgs:01J0000000000000000000000A").unwrap()
}

struct FixedResolver(Option<RealmOrganizationDelegation>);
impl RealmOrganizationDelegationResolver for FixedResolver {
    type Error = std::convert::Infallible;

    fn resolve_delegation(
        &self,
        _delegation_ref: &ObjectRef,
        _organization_id: &DidCoreId,
    ) -> Result<Option<RealmOrganizationDelegation>, Self::Error> {
        Ok(self.0.clone())
    }
}

fn delegation(
    is_live: bool,
    relationships: Vec<RealmOrganizationRelationship>,
    scopes: Vec<RealmOrganizationControlScope>,
) -> RealmOrganizationDelegation {
    RealmOrganizationDelegation {
        organization_id: organization_id(),
        is_live,
        covered_relationships: relationships,
        covered_control_scopes: scopes,
    }
}

fn run_verifier(
    payload: &RealmOrganizationPayload,
    expected_realm_id: &RealmId,
    now: DateTime<Utc>,
    resolver_name: &str,
) -> RealmOrganizationVerificationResult<()> {
    use RealmOrganizationControlScope::*;
    use RealmOrganizationRelationship::*;

    match resolver_name {
        "no_delegation" => verify_realm_organization_statement(
            payload,
            expected_realm_id,
            now,
            &NoDelegationResolver,
        ),
        "delegation_not_live" => verify_realm_organization_statement(
            payload,
            expected_realm_id,
            now,
            &FixedResolver(Some(delegation(
                false,
                vec![Owner],
                vec![OfficialBadge, RealmAdmin],
            ))),
        ),
        "delegation_covers_realm_admin_only" => verify_realm_organization_statement(
            payload,
            expected_realm_id,
            now,
            &FixedResolver(Some(delegation(true, vec![Owner], vec![RealmAdmin]))),
        ),
        "delegation_covers_owner_only" => verify_realm_organization_statement(
            payload,
            expected_realm_id,
            now,
            &FixedResolver(Some(delegation(
                true,
                vec![Owner],
                vec![OfficialBadge, RealmAdmin],
            ))),
        ),
        other => panic!("unknown resolver fixture {other}"),
    }
}

/// Apply a vector's mutation/replace directives to the base statement JSON.
fn build_candidate(base: &Value, vector: &Value) -> Value {
    if let Some(replace) = vector.get("replace") {
        return replace.clone();
    }
    let mut candidate = base.clone();
    let Some(mutation) = vector.get("mutation") else {
        return candidate;
    };
    if let Some(set) = mutation.get("set").and_then(Value::as_object) {
        for (pointer, value) in set {
            set_dotted(&mut candidate, pointer, value.clone());
        }
    }
    if let Some(set_array) = mutation.get("set_array").and_then(Value::as_object) {
        for (pointer, value) in set_array {
            set_dotted(&mut candidate, pointer, value.clone());
        }
    }
    if let Some(remove) = mutation.get("remove").and_then(Value::as_array) {
        for pointer in remove.iter().filter_map(Value::as_str) {
            remove_dotted(&mut candidate, pointer);
        }
    }
    candidate
}

/// Set a value at a dotted path (`a.b.c`) creating intermediate objects.
fn set_dotted(root: &mut Value, dotted: &str, value: Value) {
    let parts: Vec<&str> = dotted.split('.').collect();
    let mut cursor = root;
    for part in &parts[..parts.len() - 1] {
        cursor = cursor
            .as_object_mut()
            .expect("set_dotted intermediate must be object")
            .entry((*part).to_owned())
            .or_insert_with(|| Value::Object(Default::default()));
    }
    cursor
        .as_object_mut()
        .expect("set_dotted leaf parent must be object")
        .insert(parts[parts.len() - 1].to_owned(), value);
}

/// Remove a value at a dotted path; no-op if absent.
fn remove_dotted(root: &mut Value, dotted: &str) {
    let parts: Vec<&str> = dotted.split('.').collect();
    let mut cursor = root;
    for part in &parts[..parts.len() - 1] {
        let Some(next) = cursor.as_object_mut().and_then(|m| m.get_mut(*part)) else {
            return;
        };
        cursor = next;
    }
    if let Some(map) = cursor.as_object_mut() {
        map.remove(parts[parts.len() - 1]);
    }
}

#[test]
fn realm_organization_statement_negative_vectors_match_spec_codes() -> Result<()> {
    let fixture = load_fixture("realm_organization_statement_negative_vectors.json")?;
    let catalog = strong_catalog();

    let expected_realm_id = RealmId::new(
        fixture
            .get("expected_realm_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("fixture missing expected_realm_id"))?,
    )
    .map_err(|err| anyhow!("expected_realm_id invalid: {err}"))?;
    let now: DateTime<Utc> = fixture
        .get("now")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("fixture missing now"))?
        .parse()
        .context("parse fixture.now")?;
    let base = fixture
        .get("base_active_statement")
        .ok_or_else(|| anyhow!("fixture missing base_active_statement"))?;

    // Positive control: the unmutated base statement passes both surfaces.
    catalog
        .validate_payload(arkret_wire::event_kind_str::REALM_ORGANIZATION, base)
        .context("positive control must pass the strong schema")?;
    let base_typed: RealmOrganizationPayload =
        serde_json::from_value(base.clone()).context("positive control must deserialize")?;
    verify_realm_organization_statement(
        &base_typed,
        &expected_realm_id,
        now,
        &NoDelegationResolver,
    )
    .context("positive control must pass the verifier")?;

    let vectors = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("fixture missing negative_vectors[]"))?;
    assert!(
        vectors.len() >= 12,
        "expected a broad negative-vector set, found {}",
        vectors.len()
    );

    let mut schema_cases = 0usize;
    let mut verifier_cases = 0usize;
    for vector in vectors {
        let name = vector
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("negative vector missing name"))?;
        let surface = vector
            .get("surface")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing surface"))?;
        let reason_code = vector
            .pointer("/expected/reason_code")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing expected.reason_code"))?;
        let outcome = vector
            .pointer("/expected/outcome")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing expected.outcome"))?;
        if outcome != "reject" {
            bail!("vector {name} expected.outcome must be reject");
        }

        let candidate = build_candidate(base, vector);

        match surface {
            "schema" => {
                // The strong JSON-schema validator rejects malformed payloads
                // but echoes the schema $id, not the registry reason-code token.
                // For schema-surface vectors we therefore assert rejection only;
                // `expected.reason_code` stays documentary (it classifies the
                // wire failure as schema_violation per the error-code-registry).
                if reason_code != "schema_violation" {
                    bail!(
                        "schema vector {name}: schema-surface failures map to schema_violation, got {reason_code}"
                    );
                }
                if catalog
                    .validate_payload(arkret_wire::event_kind_str::REALM_ORGANIZATION, &candidate)
                    .is_ok()
                {
                    bail!("schema vector {name} unexpectedly validated against the strong schema");
                }
                schema_cases += 1;
            }
            "verifier" => {
                let resolver_name = vector
                    .get("resolver")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("verifier vector {name} missing resolver"))?;
                // The candidate must remain a structurally valid payload so the
                // verifier (not the deserializer) is what rejects it.
                let typed: RealmOrganizationPayload = serde_json::from_value(candidate.clone())
                    .with_context(|| {
                        format!(
                            "verifier vector {name} must deserialize to RealmOrganizationPayload"
                        )
                    })?;
                let err = run_verifier(&typed, &expected_realm_id, now, resolver_name)
                    .err()
                    .ok_or_else(|| anyhow!("verifier vector {name} unexpectedly passed"))?;
                let text = err.to_string();
                if !text.contains(reason_code) {
                    bail!(
                        "verifier vector {name}: error {text:?} does not embed spec code {reason_code}"
                    );
                }
                verifier_cases += 1;
            }
            other => bail!("vector {name} unknown surface {other}"),
        }
    }

    assert!(schema_cases > 0, "expected schema-surface negative vectors");
    assert!(
        verifier_cases > 0,
        "expected verifier-surface negative vectors"
    );
    Ok(())
}
