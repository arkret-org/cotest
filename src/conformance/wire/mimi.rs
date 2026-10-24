//! MIMI component and read-receipt-policy wire-model conformance vectors.

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{emit_vector, load_local_fixture};
use crate::conformance::{required_str, validate_profile};

/// W8 — MIMI Room Policy Component round-trip matrix.
///
/// Spec extensions/mimi-interop.md §9.1 defines the Arkret typed result family
/// ↔ MIMI policy-component mapping; §9.2 defines the criticality ↔ MIMI
/// unknown-handling mapping. The test cross-references each result family
/// against the active event-kind registry's state_writes, asserts that
/// bidirectional vectors carry both legs, and asserts that
/// `direction = arkret_only` vectors declare the private facade media-type so
/// the facade cannot silently impersonate a standard MIMI component.
pub fn run_mimi_components_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("mimi_components_fixture.json")?;
    validate_profile(&fixture, "ak.profile.mimi_components_vectors.v1")?;

    // §9.2 criticality round-trip
    let crit_section = fixture
        .get("criticality_mapping")
        .ok_or_else(|| anyhow!("mimi_components fixture missing criticality_mapping"))?;
    let crit_vectors = crit_section
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("criticality_mapping missing vectors"))?;
    let expected_pairs = [
        ("required", "must_understand"),
        ("optional", "should_understand"),
        ("ignore", "silently_drop"),
    ];
    if crit_vectors.len() != expected_pairs.len() {
        bail!(
            "criticality mapping must cover required / optional / ignore (got {} entries)",
            crit_vectors.len()
        );
    }
    for (vector, (arkret, mimi)) in crit_vectors.iter().zip(expected_pairs.iter()) {
        let actual_arkret = required_str(vector, "arkret")?;
        let actual_mimi = required_str(vector, "mimi_unknown_handling")?;
        if actual_arkret != *arkret || actual_mimi != *mimi {
            bail!(
                "criticality mapping drift: expected ({arkret} <-> {mimi}), got ({actual_arkret} <-> {actual_mimi})"
            );
        }
        if vector.get("round_trip").and_then(Value::as_bool) != Some(true) {
            bail!(
                "criticality mapping {arkret} must declare round_trip=true (no information loss)"
            );
        }
    }

    // §9.1 typed result family round-trip
    let component_section = fixture
        .get("component_mapping")
        .ok_or_else(|| anyhow!("mimi_components fixture missing component_mapping"))?;
    let component_vectors = component_section
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("component_mapping missing vectors"))?;

    let registry = crate::conformance::load_artifact_json("registry/event-kind-registry.json")?;
    let registered = registry["event_kinds"]
        .as_array()
        .ok_or_else(|| anyhow!("event-kind registry missing event_kinds[]"))?;
    let mut bidirectional = 0usize;
    let mut arkret_only = 0usize;
    for vector in component_vectors {
        let component_type = required_str(vector, "arkret_state_family")?;
        let event_kind = required_str(vector, "arkret_kind")?;
        let descriptor = arkret_wire::EventKind::try_new(event_kind)
            .and_then(|kind| kind.descriptor())
            .ok_or_else(|| {
                anyhow!("mimi component vector references unknown event kind {event_kind}")
            })?;
        let writes_component = descriptor.reducer_input
            && registered.iter().any(|row| {
                row["event_kind"].as_str() == Some(event_kind)
                    && row["status"].as_str() == Some("active")
                    && row["state_writes"].as_array().is_some_and(|writes| {
                        writes
                            .iter()
                            .any(|write| write["state_family"].as_str() == Some(component_type))
                    })
            });
        if !writes_component {
            bail!(
                "mimi event kind {event_kind} does not write registered result family {component_type}"
            );
        }
        let direction = required_str(vector, "direction")?;
        match direction {
            "bidirectional" => {
                let _ = required_str(vector, "mimi_path")?;
                bidirectional += 1;
            }
            "arkret_only" => {
                let media = required_str(vector, "facade_media_type")?;
                if media != "application/vnd.arkret.component+json" {
                    bail!(
                        "arkret_only component {component_type} must use the application/vnd.arkret.component+json media type, got {media}"
                    );
                }
                if vector.get("mimi_path").is_some() {
                    bail!(
                        "arkret_only component {component_type} declared a mimi_path (cannot have a standard MIMI mapping)"
                    );
                }
                arkret_only += 1;
            }
            other => {
                bail!("mimi component vector {component_type} unknown direction {other}");
            }
        }
        emit_vector(
            "mimi_components.mapping",
            vector,
            json!({"component_type": component_type, "direction": direction}),
        );
    }

    if bidirectional < 4 {
        bail!(
            "mimi component fixture must cover at least 4 bidirectional mappings, got {bidirectional}"
        );
    }
    if arkret_only < 5 {
        bail!(
            "mimi component fixture must cover at least 5 Arkret-only components, got {arkret_only}"
        );
    }

    Ok(())
}
/// Execute the canonical independent Realm/Circle receipt policy contract.
/// Authentication flags are verifier preconditions, not production evidence.
pub fn run_read_receipt_policy_fixture_suite() -> Result<()> {
    let fixture = crate::conformance::load_fixture_value("read-receipt-scope-policy-fixture.json")?;
    for case in fixture["schema_cases"]
        .as_array()
        .ok_or_else(|| anyhow!("missing schema cases"))?
    {
        let valid = crate::conformance::schema_validation_fixture::schema_validator(required_str(
            case,
            "schema_ref",
        )?)?
        .is_valid(&case["instance"]);
        anyhow::ensure!(
            valid == case["expected_valid"].as_bool().unwrap_or(false),
            "receipt schema case failed: {}",
            case["name"]
        );
        emit_vector(
            "read_receipt.scope_policy.schema",
            case,
            json!({"valid":valid}),
        );
    }
    let cases = fixture["decision_cases"]
        .as_array()
        .ok_or_else(|| anyhow!("missing decision cases"))?;
    anyhow::ensure!(cases.len() >= 30, "scope policy decision coverage missing");
    for case in cases {
        let actual = scope_receipt_decision(&case["input"])?;
        anyhow::ensure!(
            actual == case["expected"],
            "receipt scope decision failed: {}",
            case["name"]
        );
        emit_vector("read_receipt.scope_policy.decision", case, actual);
    }
    for case in fixture["update_cases"]
        .as_array()
        .ok_or_else(|| anyhow!("missing update cases"))?
    {
        let mut seen = true;
        let mut displays = Vec::new();
        for policy in case["writes"]
            .as_array()
            .ok_or_else(|| anyhow!("missing writes"))?
        {
            let mut input = cases[0]["input"].clone();
            input["viewer"] = case["viewer"].clone();
            input["target_author"] = case["target_author"].clone();
            input["policies"][0]["value"] = policy.clone();
            if case["fresh_receipt_each_step"].as_bool() == Some(true) {
                seen = true;
            }
            seen &= scope_receipt_decision(&input)?["display"] == true;
            displays.push(seen);
        }
        anyhow::ensure!(
            json!(displays) == case["expected_display"],
            "receipt display update failed: {}",
            case["name"]
        );
        emit_vector(
            "read_receipt.scope_policy.updates",
            case,
            json!({"display":displays}),
        );
    }
    Ok(())
}

fn scope_receipt_decision(input: &Value) -> Result<Value> {
    let denied = || json!({"send":false,"display":false});
    let scope: arkret_wire::ScopeRef = serde_json::from_value(input["scope_ref"].clone())?;
    if !matches!(
        scope,
        arkret_wire::ScopeRef::Realm { .. } | arkret_wire::ScopeRef::Circle { .. }
    ) || [
        "basis_verified",
        "complete",
        "scope_authorized",
        "target_verified",
    ]
    .iter()
    .any(|key| input[*key] != true)
        || ["signal_scope_ref", "target_scope_ref", "basis_scope_ref"]
            .iter()
            .any(|key| input[*key] != input["scope_ref"])
    {
        return Ok(denied());
    }
    let selector = json!({"kind":"scope_read_receipt_policy","scope_ref":scope});
    let rows = input["policies"]
        .as_array()
        .ok_or_else(|| anyhow!("missing policies"))?
        .iter()
        .filter(|row| row["selector"] == selector)
        .collect::<Vec<_>>();
    let policy = match (input["current_status"].as_str(), rows.as_slice()) {
        (Some("never_written"), []) => {
            arkret_models_collaboration::objects::read_receipts::ReadReceiptPolicy::default()
        }
        (Some("present"), [row]) => {
            let Ok(current) = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::CurrentScopeReadReceiptPolicy,
            >((*row).clone()) else {
                return Ok(denied());
            };
            if current.validate().is_err() {
                return Ok(denied());
            }
            current.value.resolved()
        }
        _ => return Ok(denied()),
    };
    use arkret_models_collaboration::objects::read_receipts::{
        ReadReceiptDisclosure as D, ReadReceiptVisibility as V,
    };
    if policy.disclosure == D::Disabled {
        return Ok(denied());
    }
    let display = input["display_preference"] == true
        && input["viewer_observer"] == true
        && match policy.visibility {
            V::Public => true,
            V::Members => input["viewer_member"] == true,
            V::Private => input["viewer"] == input["target_author"],
        };
    Ok(
        json!({"send":policy.disclosure == D::Required || input["sender_preference"] == true,"display":display}),
    )
}
