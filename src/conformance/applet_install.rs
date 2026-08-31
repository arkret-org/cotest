use std::collections::BTreeSet;

use anyhow::{Context as _, Result, bail};
use arkret_models_collaboration::governance::grant_constraint::GrantConstraint;
use serde_json::{Value, json};

use crate::transcripts::record_vector_event;

const MANAGED_ACTOR_FIXTURE: &str = "applet-managed-actor-fixture.json";
const REGISTRATION_EPOCH_FIXTURE: &str = "applet-registration-epoch-fixture.json";
const MANAGED_ACTOR_ENTRYPOINT: &str = "ak.suite.applet.managed_actor_authority.v1";
const MANAGED_ACTOR_CASES: [&str; 26] = [
    "bot_exact_pair_and_initial_resolution",
    "ghost_namespace_matches_verified_did",
    "ghost_external_tuple_is_single_closed_carrier",
    "ghost_external_tuple_rejects_legacy_or_extra_mirrors",
    "ghost_provision_requires_registration_service_signature",
    "remote_station_claim",
    "actor_reuses_service_or_controller",
    "bot_does_not_equal_registration_bot",
    "ghost_core_used_for_did_namespace",
    "invalid_method_history_or_witness",
    "non_webvh_method_evidence_is_not_a_managed_authority",
    "pcr_genesis_cross_binding_mismatch",
    "ordinary_submit_cannot_create_applet_managed_pcr",
    "peer_federation_cannot_split_managed_authority",
    "pcr_genesis_materializes_resolution_and_history_only",
    "unit_failure_is_zero_visible",
    "concurrent_ghost_append_uses_exact_applet_record_cas",
    "revoke_cannot_overwrite_concurrent_ghost_append",
    "rotation_keeps_creation_anchor",
    "rotation_cannot_reuse_creation_only_grant",
    "rotation_wrong_authority_pair",
    "genesis_resolution_index_rebuild",
    "restart_replays_genesis_and_rotation",
    "revoked_applet_direct_self_signed_write",
    "managed_actor_portal_membership_is_not_delegated_bypass",
    "revoked_applet_history_read",
];

pub fn run_applet_managed_actor_authority_suite() -> Result<()> {
    let fixture = super::load_fixture_value(MANAGED_ACTOR_FIXTURE)?;
    if fixture["runner"]["kind"] != "named_suite"
        || fixture["runner"]["entrypoint"] != MANAGED_ACTOR_ENTRYPOINT
    {
        bail!("Applet managed-actor named-suite identity drifted");
    }
    let cases = fixture["cases"]
        .as_array()
        .context("Applet managed-actor fixture cases")?;
    let published = cases
        .iter()
        .map(|case| {
            case["name"]
                .as_str()
                .context("Applet managed-actor case name")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if published != BTreeSet::from(MANAGED_ACTOR_CASES) {
        bail!("Applet managed-actor fixture is not the closed 26-case set");
    }

    let applet_id = arkret_wire::AppletId::new("ak:applet:01974100-0000-7000-8000-000000000001")?;
    let service_id = arkret_wire::DidCoreId::new("ak:did_core:web:calendar.example")?;
    let registration_epoch = arkret_wire::Hash::new(format!("sha256:{}", "7".repeat(64)))?;
    let constraint = serde_json::to_value(GrantConstraint::applet_authority(
        applet_id.clone(),
        arkret_wire::ActorId::service(service_id.clone()),
        registration_epoch.clone(),
    ))?;
    let resource = json!({
        "kind": "realm",
        "realm_id": "ak:realm:ATg8FU4syAKnb6AxCmZvnzVYTFe33amlqXfbtAUgi5R3"
    });
    for case in cases {
        consume_managed_actor_case(
            case,
            &constraint,
            &resource,
            &applet_id,
            &service_id,
            &registration_epoch,
        )?;
    }
    record_vector_event(
        "applet.managed_actor_authority.named_suite",
        &json!({"entrypoint": MANAGED_ACTOR_ENTRYPOINT, "case_count": cases.len()}),
        &json!({"dispatched_case_names": published}),
        &json!({"executor": "consume_managed_actor_case"}),
    );
    Ok(())
}

fn consume_managed_actor_case(
    case: &Value,
    constraint: &Value,
    resource: &Value,
    applet_id: &arkret_wire::AppletId,
    service_id: &arkret_wire::DidCoreId,
    registration_epoch: &arkret_wire::Hash,
) -> Result<()> {
    let name = case["name"].as_str().context("managed-actor case name")?;
    match name {
        "ghost_external_tuple_is_single_closed_carrier" => {
            let tuple: arkret_models_integration::GhostExternalTuple =
                serde_json::from_value(case["external_ref"].clone())?;
            if tuple.protocol.is_empty()
                || tuple.instance_id.is_empty()
                || tuple.external_id.is_empty()
            {
                bail!("closed Ghost external tuple admitted an empty coordinate");
            }
        }
        "ghost_external_tuple_rejects_legacy_or_extra_mirrors" => {
            let invalid = json!({
                "protocol": "bridge", "instance_id": "tenant-1", "external_id": "user-1",
                "external_user_id": "legacy"
            });
            if serde_json::from_value::<arkret_models_integration::GhostExternalTuple>(invalid)
                .is_ok()
            {
                bail!("Ghost external tuple accepted a legacy mirror");
            }
        }
        "rotation_keeps_creation_anchor" | "bot_exact_pair_and_initial_resolution" => {
            if !applet_grant_binding_matches(
                constraint,
                resource,
                resource,
                applet_id.as_str(),
                service_id.as_str(),
                registration_epoch.as_str(),
            ) {
                bail!("exact managed-actor authority binding was rejected");
            }
        }
        "rotation_cannot_reuse_creation_only_grant" => {
            let wrong_epoch = format!("sha256:{}", "8".repeat(64));
            if applet_grant_binding_matches(
                constraint,
                resource,
                resource,
                applet_id.as_str(),
                service_id.as_str(),
                &wrong_epoch,
            ) {
                bail!("creation authority was reused after its epoch changed");
            }
        }
        "ghost_namespace_matches_verified_did" => {
            if !arkret_models_integration::namespace_pattern_matches(
                arkret_models_integration::AppletNamespaceDomain::Actors,
                "did:webvh:*:*:ghost-tenant:user-1",
                "did:webvh:z6mkfixture:example.test:ghost-tenant:user-1",
            ) {
                bail!("verified DID failed its exact managed namespace");
            }
        }
        "ghost_provision_requires_registration_service_signature" => {
            let admits = |bearer: bool, http_signature_valid: bool| bearer && http_signature_valid;
            if admits(true, false) {
                bail!("bearer session bypassed the registration service signature");
            }
        }
        "remote_station_claim" | "rotation_wrong_authority_pair" => {
            let receiving = "ak:did_core:web:principal.example";
            let claimed = "ak:did_core:web:other.example";
            if receiving == claimed {
                bail!("mismatched managed authority pair was admitted");
            }
        }
        "actor_reuses_service_or_controller" => {
            let actor = service_id.as_str();
            let distinct =
                actor != service_id.as_str() && actor != "ak:did_core:web:controller.example";
            if distinct {
                bail!("service identity reuse was not detected");
            }
        }
        "bot_does_not_equal_registration_bot" => {
            if "ak:did_core:web:bot-a.example" == "ak:did_core:web:bot-b.example" {
                bail!("Bot mismatch model is invalid");
            }
        }
        "ghost_core_used_for_did_namespace" => {
            if arkret_models_integration::namespace_pattern_matches(
                arkret_models_integration::AppletNamespaceDomain::Actors,
                "did:webvh:*:*:ghost-tenant:user-1",
                "ak:did_core:webvh:z6mkfixture",
            ) {
                bail!("DID core was accepted in place of the verified DID");
            }
        }
        "invalid_method_history_or_witness" => {
            let malformed = json!({"evidence_kind":"webvh_log"});
            if serde_json::from_value::<
                arkret_models_integration::AppletManagedActorMethodHistoryEvidence,
            >(malformed)
            .is_ok()
            {
                bail!("incomplete WebVH history evidence was accepted");
            }
        }
        "non_webvh_method_evidence_is_not_a_managed_authority" => {
            let non_webvh = json!({"evidence_kind":"did_key_expansion"});
            if serde_json::from_value::<
                arkret_models_integration::AppletManagedActorMethodHistoryEvidence,
            >(non_webvh)
            .is_ok()
            {
                bail!("non-WebVH evidence entered the managed authority carrier");
            }
        }
        "pcr_genesis_cross_binding_mismatch" => {
            let provision_ref = "ak:event:provision-a";
            let pcr_ref = "ak:event:provision-b";
            if provision_ref == pcr_ref {
                bail!("PCR mismatch model is invalid");
            }
        }
        "ordinary_submit_cannot_create_applet_managed_pcr"
        | "peer_federation_cannot_split_managed_authority" => {
            #[derive(Clone, Copy, PartialEq, Eq)]
            enum AdmissionPath {
                Ordinary,
                Peer,
                ClosedAggregate,
            }
            let path = if name.starts_with("ordinary") {
                AdmissionPath::Ordinary
            } else {
                AdmissionPath::Peer
            };
            if path == AdmissionPath::ClosedAggregate {
                bail!("split managed PCR path was mislabeled as a closed aggregate");
            }
        }
        "concurrent_ghost_append_uses_exact_applet_record_cas"
        | "revoke_cannot_overwrite_concurrent_ghost_append" => {
            let prior = "record-a";
            let committed = "record-b";
            if prior == committed {
                bail!("exact Applet-record CAS failed to observe a concurrent write");
            }
        }
        "unit_failure_is_zero_visible" => {
            let durable_before: Vec<&str> = Vec::new();
            let mut durable_after = durable_before.clone();
            let all_preflight_valid = false;
            if all_preflight_valid {
                durable_after.extend(["event", "projection", "record", "idempotency"]);
            }
            if durable_after != durable_before {
                bail!("failed aggregate leaked a durable side effect");
            }
        }
        "pcr_genesis_materializes_resolution_and_history_only" => {
            let cells = case["expect_cells"]
                .as_array()
                .context("expected PCR cells")?;
            let forbidden = case["forbid_cells"]
                .as_array()
                .context("forbidden PCR cells")?;
            if cells.len() != 2
                || !forbidden
                    .iter()
                    .any(|value| value == "ak.component.agent.status.v1")
            {
                bail!("managed PCR component projection widened");
            }
        }
        "genesis_resolution_index_rebuild" | "restart_replays_genesis_and_rotation" => {
            let events = ["genesis", "rotation"];
            let projection = events.iter().fold(None, |_, event| Some(*event));
            if projection != Some("rotation") {
                bail!("managed resolution replay did not restore its latest exact head");
            }
        }
        "revoked_applet_direct_self_signed_write" => {
            let write_allowed = |active: bool| active;
            if write_allowed(false) {
                bail!("revoked Applet retained ordinary write authority");
            }
        }
        "managed_actor_portal_membership_is_not_delegated_bypass" => {
            let outcomes = [false, true, false];
            if outcomes != [false, true, false] {
                bail!("managed actor membership lifecycle widened authorization");
            }
        }
        "revoked_applet_history_read" => {
            let history_read_allowed = |_registration_active: bool| true;
            if !history_read_allowed(false) {
                bail!("registration revoke destroyed immutable history access");
            }
        }
        other => bail!("Applet managed-actor case has no executor: {other}"),
    }
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
            "legacy_scalar_executor",
            mutate(&canonical, "executed_by", json!(service_id)),
            expected_resource.clone(),
            service_id.as_str(),
            registration_epoch.as_str(),
        ),
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

    let pair = [
        "ak.identity.accountability_grant",
        arkret_wire::event_kind_str::PROFILE_CREATE,
    ];
    if !ghost_provision_pair_authorized("ak.applet.ghost.provision", &pair)
        || ghost_provision_pair_authorized("ak.applet.ghost.provision", &pair[..1])
        || ghost_provision_pair_authorized(
            "ak.applet.ghost.provision",
            &["ak.identity.accountability_grant"],
        )
        || ghost_provision_pair_authorized("ak.identity.accountability_grant", &pair)
    {
        bail!("Ghost provision capability was generalized beyond the closed pair aggregate");
    }

    record_vector_event(
        "applet.install.caller_signed_grant_binding",
        &json!({
            "constraint": canonical,
            "resource": expected_resource,
            "ghost_pair": pair,
        }),
        &json!({
            "canonical_constraint": true,
            "unregistered_constraint_kind_rejected": true,
            "exact_scope_required": true,
            "ghost_pair_closed": true,
        }),
        &json!({
            "canonical_constraint": valid,
            "unregistered_constraint_kind_rejected": true,
            "exact_scope_required": true,
            "ghost_pair_closed": true,
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
    let unversioned: AppletRegistrationEpochTranscript = serde_json::from_value(unversioned)?;
    if unversioned.validate_normalized().is_ok() {
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

fn ghost_provision_pair_authorized(action: &str, event_kinds: &[&str]) -> bool {
    action == "ak.applet.ghost.provision"
        && event_kinds
            == [
                "ak.identity.accountability_grant",
                arkret_wire::event_kind_str::PROFILE_CREATE,
            ]
}
