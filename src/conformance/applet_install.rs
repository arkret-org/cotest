use anyhow::{Context as _, Result, bail};
use arkret_models_collaboration::governance::grant_constraint::GrantConstraint;
use serde_json::{Value, json};

use crate::transcripts::record_vector_event;

const MANAGED_ACTOR_FIXTURE: &str = "applet-managed-actor-fixture.json";
const REGISTRATION_EPOCH_FIXTURE: &str = "applet-registration-epoch-fixture.json";
const MANAGED_ACTOR_ENTRYPOINT: &str = "ak.suite.applet.managed_actor_authority.v1";

/// Execute the registered Realm Actor successor, never the retired Account/PCR model.
/// This is a formal contract regression suite and makes no production SUT claim.
pub fn run_applet_managed_actor_authority_suite() -> Result<()> {
    let fixture = super::load_fixture_value(MANAGED_ACTOR_FIXTURE)?;
    if fixture["runner"]["kind"] != "named_suite"
        || fixture["runner"]["entrypoint"] != MANAGED_ACTOR_ENTRYPOINT
        || fixture["creation_event_kinds"]
            != json!([arkret_wire::event_kind_str::REALM_ACTOR_CREATE])
    {
        bail!("Applet authority fixture does not name the current Realm Actor successor");
    }
    let groups = fixture["acceptance_groups"]
        .as_array()
        .context("Realm Actor acceptance groups")?;
    if groups.is_empty() {
        bail!("Realm Actor authority fixture has no acceptance groups");
    }
    let artifacts = super::spec_artifacts_root();
    let spec = artifacts
        .ancestors()
        .nth(3)
        .context("Spec repository for the registered executor")?;
    if !spec.join("tools/test_realm_actor_contract.py").is_file() {
        bail!("The registered Realm Actor contract executor is unavailable");
    }
    let python =
        std::env::var_os("COTEST_PYTHON_BIN").unwrap_or_else(|| std::ffi::OsString::from("python"));
    let output = std::process::Command::new(python)
        .args(["-B", "-m", "tools.test_realm_actor_contract"])
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .current_dir(spec)
        .output()
        .context("execute the registered Realm Actor contract suite")?;
    let stdout = String::from_utf8(output.stdout).context("Realm Actor suite stdout")?;
    let stderr = String::from_utf8(output.stderr).context("Realm Actor suite stderr")?;
    if !output.status.success() {
        bail!(
            "Realm Actor contract suite failed: {}\n{}\n{}",
            output.status,
            stdout,
            stderr
        );
    }
    let executed = stderr
        .lines()
        .find_map(|line| {
            line.strip_prefix("Ran ")?
                .split_whitespace()
                .next()?
                .parse::<usize>()
                .ok()
        })
        .filter(|count| *count > 0)
        .context("Realm Actor executor must run a nonempty test suite")?;
    record_vector_event(
        "applet.managed_actor.realm_actor_successor",
        &json!({"entrypoint": MANAGED_ACTOR_ENTRYPOINT, "acceptance_groups": groups}),
        &json!({"executor": "tools.test_realm_actor_contract", "nonempty": true}),
        &json!({"executed_tests": executed, "exit_success": true, "production_sut_claim": false}),
    );
    Ok(())
}

pub fn run_applet_install_authoring_suite() -> Result<()> {
    let applet_id = arkret_wire::AppletId::new("ak:applet:01974100-0000-7000-8000-000000000001")?;
    let service_id = arkret_wire::DidCoreId::new("ak:did_core:web:calendar.example")?;
    let registration_epoch = arkret_wire::Hash::new(format!("sha256:{}", "7".repeat(64)))?;
    let constraint = GrantConstraint::applet_authority(
        applet_id.clone(),
        arkret_wire::ActorId::service(service_id.clone()),
        registration_epoch.clone(),
    );
    let canonical = serde_json::to_value(&constraint)?;
    for (field, expected) in [
        ("constraint_kind", "authority_control"),
        ("constraint_subkind", "applet_authority"),
        ("evaluation_class", "grant_local"),
        ("applet_id", applet_id.as_str()),
        ("registration_epoch", registration_epoch.as_str()),
    ] {
        if canonical.get(field).and_then(Value::as_str) != Some(expected) {
            bail!("canonical Applet delegation constraint lost {field}={expected}");
        }
    }
    let executor = serde_json::to_value(arkret_wire::ActorId::service(service_id.clone()))?;
    if canonical.get("executed_by") != Some(&executor) {
        bail!("canonical Applet delegation constraint lost the Service actor executor");
    }
    // Unregistered `constraint_kind` spellings MUST fail closed: only
    // `authority_control` is a registered GrantConstraint kind.
    let mut unregistered_kind = canonical.clone();
    unregistered_kind["constraint_kind"] = json!("applet_delegation_binding");
    if serde_json::from_value::<GrantConstraint>(unregistered_kind).is_ok() {
        bail!("unregistered constraint_kind `applet_delegation_binding` was accepted");
    }

    let realm_resource: arkret_wire::WireResourceSelector = serde_json::from_value(json!({
        "kind": "realm",
        "realm_id": "ak:realm:ATg8FU4syAKnb6AxCmZvnzVYTFe33amlqXfbtAUgi5R3"
    }))?;
    let expected_resource = serde_json::to_value(&realm_resource)?;
    let valid = applet_grant_binding_matches(
        &canonical,
        &expected_resource,
        &expected_resource,
        applet_id.as_str(),
        service_id.as_str(),
        registration_epoch.as_str(),
    );
    if !valid {
        bail!("canonical Applet delegation grant binding was rejected");
    }
    for (name, mutated_constraint, mutated_resource, expected_service, expected_epoch) in [
        (
            "account_executor_with_same_principal",
            mutate(
                &canonical,
                "executed_by",
                serde_json::to_value(arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    service_id.clone(),
                    arkret_wire::DidCoreId::new("ak:did_core:web:station.example")?,
                )))?,
            ),
            expected_resource.clone(),
            service_id.as_str(),
            registration_epoch.as_str(),
        ),
        (
            "wrong_applet",
            mutate(&canonical, "applet_id", json!("ak:applet:wrong")),
            expected_resource.clone(),
            service_id.as_str(),
            registration_epoch.as_str(),
        ),
        (
            "wrong_service",
            canonical.clone(),
            expected_resource.clone(),
            "did:web:wrong.example",
            registration_epoch.as_str(),
        ),
        (
            "wrong_epoch",
            canonical.clone(),
            expected_resource.clone(),
            service_id.as_str(),
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        (
            "widened_resource",
            canonical.clone(),
            json!({
                "kind": "realm",
                "realm_id": "ak:realm:AXxrsUIlJjXTN1WmemivF8XXUgduxtq-nllathYqyddS"
            }),
            service_id.as_str(),
            registration_epoch.as_str(),
        ),
    ] {
        if applet_grant_binding_matches(
            &mutated_constraint,
            &mutated_resource,
            &expected_resource,
            applet_id.as_str(),
            expected_service,
            expected_epoch,
        ) {
            bail!("Applet install mutation {name} widened or rebound the grant");
        }
    }

    let creation = arkret_schema::capability_action_descriptor(
        arkret_wire::CapabilityActionId::AppletGhostProvision,
    );
    if creation.target_event_kinds != [arkret_wire::event_kind_str::REALM_ACTOR_CREATE]
        || creation.approver_capability_action != Some(arkret_wire::CapabilityActionId::RealmAdmin)
    {
        bail!("Ghost creation must use one RealmActor create with explicit Realm admin approval");
    }

    record_vector_event(
        "applet.install.caller_signed_grant_binding",
        &json!({
            "constraint": canonical,
            "resource": expected_resource,
            "creation_event_kinds": creation.target_event_kinds,
        }),
        &json!({
            "canonical_constraint": true,
            "unregistered_constraint_kind_rejected": true,
            "exact_scope_required": true,
            "single_realm_actor_create": true,
        }),
        &json!({
            "canonical_constraint": valid,
            "unregistered_constraint_kind_rejected": true,
            "exact_scope_required": true,
            "single_realm_actor_create": true,
        }),
    );
    Ok(())
}

pub fn run_applet_registration_epoch_kat_suite() -> Result<()> {
    use arkret_models_integration::applet::AppletRegistrationEpochTranscript;

    let fixture = super::load_fixture_value(REGISTRATION_EPOCH_FIXTURE)?;
    let embedded = arkret_schema_conformance::spec_json_artifact(&format!(
        "fixtures/{REGISTRATION_EPOCH_FIXTURE}"
    ))
    .context("embedded Applet registration-epoch fixture")?;
    if fixture != embedded {
        bail!("filesystem and SDK-embedded registration-epoch fixtures drifted");
    }
    if fixture["runner"]["kind"] != "named_suite"
        || fixture["runner"]["entrypoint"] != "ak.suite.applet.registration_epoch.v1"
        || fixture["domain_separator_utf8"].as_str()
            != Some(
                String::from_utf8_lossy(AppletRegistrationEpochTranscript::DOMAIN_SEPARATOR)
                    .as_ref(),
            )
    {
        bail!("Applet registration-epoch suite identity or domain separator drifted");
    }

    let transcript_value = fixture["positive"]["transcript"].clone();
    let transcript_schema = super::schema_validation_fixture::SchemaEnv::load()?
        .compile("schemas/applet-registration-epoch-transcript.schema.json")?;
    if !transcript_schema.is_valid(&transcript_value) {
        bail!("positive registration-epoch transcript fails the authoritative schema");
    }
    let transcript: AppletRegistrationEpochTranscript =
        serde_json::from_value(transcript_value.clone())?;
    transcript.validate_normalized()?;
    let canonical = transcript.canonical_json_bytes()?;
    let frozen_canonical = fixture["positive"]["canonical_bytes_utf8"]
        .as_str()
        .context("registration-epoch canonical bytes")?
        .as_bytes();
    if canonical != frozen_canonical {
        bail!("registration-epoch canonical bytes drifted");
    }
    let expected_epoch = fixture["positive"]["expected_registration_epoch"]
        .as_str()
        .context("expected registration epoch")?;
    if transcript.registration_epoch()?.as_str() != expected_epoch {
        bail!("registration-epoch domain-separated digest drifted");
    }

    let mut unsorted = transcript_value.clone();
    unsorted["accepted_signing_keys"]
        .as_array_mut()
        .context("accepted_signing_keys array")?
        .reverse();
    let unsorted: AppletRegistrationEpochTranscript = serde_json::from_value(unsorted)?;
    if unsorted.validate_normalized().is_ok() {
        bail!("unsorted accepted signing keys entered the digest boundary");
    }

    let mut duplicate = transcript_value.clone();
    let first_key = duplicate["accepted_signing_keys"][0].clone();
    duplicate["accepted_signing_keys"]
        .as_array_mut()
        .context("accepted_signing_keys array")?
        .push(first_key);
    let duplicate: AppletRegistrationEpochTranscript = serde_json::from_value(duplicate)?;
    if duplicate.validate_normalized().is_ok() {
        bail!("duplicate accepted signing key entered the digest boundary");
    }

    let mut optional_null = transcript_value.clone();
    optional_null["service_did_document"]["method_version"]["version_time"] = Value::Null;
    if transcript_schema.is_valid(&optional_null) {
        bail!("authoritative schema accepted an explicit optional null");
    }

    let mut unversioned = transcript_value.clone();
    unversioned["service_did_document"]["method_version"]["unversioned_refetch"] = json!(true);
    if transcript_schema.is_valid(&unversioned) {
        bail!("authoritative schema accepted unversioned evidence with version_id");
    }
    if serde_json::from_value::<AppletRegistrationEpochTranscript>(unversioned).is_ok() {
        bail!("unversioned DID evidence retained a version_id");
    }

    let mut security_change = transcript_value;
    security_change["derived_registration"]["base_url"] = json!("https://other.example/cx");
    let security_change: AppletRegistrationEpochTranscript =
        serde_json::from_value(security_change)?;
    security_change.validate_normalized()?;
    if security_change.registration_epoch()?.as_str() == expected_epoch {
        bail!("security-relevant registration change did not rotate the epoch");
    }
    if arkret_wire::ErrorCode::from_wire("applet_registration_epoch_evidence_deactivated")
        != Some(arkret_wire::ErrorCode::AppletRegistrationEpochEvidenceDeactivated)
    {
        bail!("deactivated DID evidence lost its dedicated registered error code");
    }

    record_vector_event(
        "applet.registration_epoch.kat",
        &json!({
            "entrypoint": "ak.suite.applet.registration_epoch.v1",
            "canonical_bytes": String::from_utf8(canonical)?,
            "expected_registration_epoch": expected_epoch,
        }),
        &json!({
            "positive": true,
            "negative_cases": fixture["negative"],
        }),
        &json!({
            "filesystem_embedded_equal": true,
            "canonical_and_digest_equal": true,
            "negative_count": 6,
        }),
    );
    Ok(())
}

fn mutate(value: &Value, field: &str, replacement: Value) -> Value {
    let mut value = value.clone();
    value[field] = replacement;
    value
}

fn applet_grant_binding_matches(
    constraint: &Value,
    resource: &Value,
    expected_resource: &Value,
    applet_id: &str,
    service_id: &str,
    registration_epoch: &str,
) -> bool {
    let Ok(service_id) = arkret_wire::DidCoreId::new(service_id) else {
        return false;
    };
    let Ok(executor) = serde_json::to_value(arkret_wire::ActorId::service(service_id)) else {
        return false;
    };
    constraint.get("constraint_kind").and_then(Value::as_str) == Some("authority_control")
        && constraint.get("constraint_subkind").and_then(Value::as_str) == Some("applet_authority")
        && constraint.get("evaluation_class").and_then(Value::as_str) == Some("grant_local")
        && constraint.get("applet_id").and_then(Value::as_str) == Some(applet_id)
        && constraint.get("executed_by") == Some(&executor)
        && constraint.get("registration_epoch").and_then(Value::as_str) == Some(registration_epoch)
        && resource == expected_resource
}
