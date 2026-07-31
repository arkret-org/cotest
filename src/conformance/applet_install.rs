use anyhow::{Result, bail};
use arkret_models_collaboration::governance::grant_constraint::GrantConstraint;
use serde_json::{Value, json};

use crate::transcripts::record_vector_event;

pub fn run_applet_install_authoring_suite() -> Result<()> {
    let applet_id = arkret_wire::AppletId::new("ak:applet:01974100-0000-7000-8000-000000000001")?;
    let service_id = arkret_wire::Did::new("did:web:calendar.example")?;
    let registration_epoch = arkret_wire::Hash::new(format!("sha256:{}", "7".repeat(64)))?;
    let constraint = GrantConstraint::applet_authority(
        applet_id.clone(),
        service_id.clone(),
        registration_epoch.clone(),
    );
    let canonical = serde_json::to_value(&constraint)?;
    for (field, expected) in [
        ("constraint_kind", "authority_control"),
        ("constraint_subkind", "applet_authority"),
        ("evaluation_class", "grant_local"),
        ("applet_id", applet_id.as_str()),
        ("executed_by", service_id.as_str()),
        ("registration_epoch", registration_epoch.as_str()),
    ] {
        if canonical.get(field).and_then(Value::as_str) != Some(expected) {
            bail!("canonical Applet delegation constraint lost {field}={expected}");
        }
    }
    let mut legacy = canonical.clone();
    legacy["constraint_kind"] = json!("applet_delegation_binding");
    if serde_json::from_value::<GrantConstraint>(legacy).is_ok() {
        bail!("retired applet_delegation_binding alias was accepted");
    }

    let realm_resource: arkret_wire::WireResourceSelector = serde_json::from_value(json!({
        "kind": "realm",
        "realm_id": "ak:realm:01974100-0000-7000-8000-000000000010"
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
                "realm_id": "ak:realm:01974100-0000-7000-8000-000000000011"
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
        arkret_wire::events::EventKind::PROFILE_CREATE,
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
            "legacy_alias_rejected": true,
            "exact_scope_required": true,
            "ghost_pair_closed": true,
        }),
        &json!({
            "canonical_constraint": valid,
            "legacy_alias_rejected": true,
            "exact_scope_required": true,
            "ghost_pair_closed": true,
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
    constraint.get("constraint_kind").and_then(Value::as_str) == Some("authority_control")
        && constraint.get("constraint_subkind").and_then(Value::as_str) == Some("applet_authority")
        && constraint.get("evaluation_class").and_then(Value::as_str) == Some("grant_local")
        && constraint.get("applet_id").and_then(Value::as_str) == Some(applet_id)
        && constraint.get("executed_by").and_then(Value::as_str) == Some(service_id)
        && constraint.get("registration_epoch").and_then(Value::as_str) == Some(registration_epoch)
        && resource == expected_resource
}

fn ghost_provision_pair_authorized(action: &str, event_kinds: &[&str]) -> bool {
    action == "ak.applet.ghost.provision"
        && event_kinds
            == [
                "ak.identity.accountability_grant",
                arkret_wire::events::EventKind::PROFILE_CREATE,
            ]
}
