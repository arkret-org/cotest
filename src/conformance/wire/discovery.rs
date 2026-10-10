//! Discovery-profile and facet-renderer-query wire-model conformance vectors.

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::emit_vector;
use crate::conformance::required_str;

/// Execute the current profile-discovery fixture through the SDK claim and
/// semantic coverage validators, including inherited requirements and refusals.
pub fn run_discovery_profile_fixture_suite() -> Result<()> {
    use std::collections::BTreeSet;

    use arkret_policy::{
        ProfileClaim, ProfileSemanticSurface, ProfileValidator,
        collect_profile_semantic_requirements, validate_profile_semantic_coverage,
    };
    use arkret_wire::generated::profile_requirements::PROFILE_REQUIREMENTS;

    let fixture = crate::conformance::load_fixture_value("discovery-profile-fixture.json")?;
    if fixture["suite"] != "discovery_profile_fixture"
        || fixture["runner"]["kind"] != "profile_discovery_coverage"
    {
        bail!("discovery profile fixture identity drifted");
    }
    let cases = fixture["cases"]
        .as_array()
        .ok_or_else(|| anyhow!("discovery cases missing"))?;
    let names = cases
        .iter()
        .map(|case| required_str(case, "name"))
        .collect::<Result<BTreeSet<_>>>()?;
    if cases.len() != 4
        || names
            != BTreeSet::from([
                "advertised_profile_closure",
                "surface_tier_does_not_overclaim",
                "unknown_required_profile_fails_closed",
                "optional_unknown_feature_is_not_claimed",
            ])
    {
        bail!("discovery profile fixture case set drifted");
    }

    let mut checked_profiles = 0;
    for profile in PROFILE_REQUIREMENTS.keys() {
        let requirements = collect_profile_semantic_requirements(&[profile])?;
        let surface = ProfileSemanticSurface {
            operation_requirements: requirements.operation_requirements.clone(),
            event_kinds: requirements.required_event_kinds.clone(),
            schemas: requirements.required_schemas.clone(),
            fixtures: requirements.required_fixtures.clone(),
            capability_actions: requirements.required_capability_actions.clone(),
            features: requirements.required_features.clone(),
            constraint_kinds: requirements.required_constraint_kinds.clone(),
        };
        validate_profile_semantic_coverage(&[profile], &surface)?;
        // Every required family is independently removed from the inherited
        // closure. A validator that stops checking any family must fail here.
        for family in 0..7 {
            let mut incomplete = surface.clone();
            let removed = match family {
                0 => incomplete.operation_requirements.pop().is_some(),
                1 => incomplete.event_kinds.pop().is_some(),
                2 => incomplete.schemas.pop().is_some(),
                3 => incomplete.fixtures.pop().is_some(),
                4 => incomplete.capability_actions.pop().is_some(),
                5 => incomplete.features.pop().is_some(),
                _ => incomplete.constraint_kinds.pop().is_some(),
            };
            if removed && validate_profile_semantic_coverage(&[profile], &incomplete).is_ok() {
                bail!("profile {profile} accepted missing requirement family {family}");
            }
        }
        for rejected in requirements.rejected_event_kinds {
            let mut overclaimed = surface.clone();
            overclaimed.event_kinds.push(rejected);
            if validate_profile_semantic_coverage(&[profile], &overclaimed).is_ok() {
                bail!("profile {profile} accepted an excluded Event kind");
            }
        }
        checked_profiles += 1;
    }
    if checked_profiles == 0 {
        bail!("discovery did not exercise any claimable profile requirements");
    }

    let unknown_case = cases
        .iter()
        .find(|case| case["name"] == "unknown_required_profile_fails_closed")
        .ok_or_else(|| anyhow!("unknown required profile case missing"))?;
    let unknown = required_str(&unknown_case["input"], "required_profile")?;
    if collect_profile_semantic_requirements(&[unknown]).is_ok()
        || ProfileValidator::for_client()
            .validate(&[ProfileClaim::self_claimed(unknown)])
            .is_ok()
    {
        bail!("unknown required profile was advertised as supported");
    }
    let optional_case = cases
        .iter()
        .find(|case| case["name"] == "optional_unknown_feature_is_not_claimed")
        .ok_or_else(|| anyhow!("unknown optional feature case missing"))?;
    let optional = required_str(&optional_case["input"], "optional_feature")?;
    for profile in PROFILE_REQUIREMENTS.keys() {
        if collect_profile_semantic_requirements(&[profile])?
            .required_features
            .iter()
            .any(|feature| feature == optional)
        {
            bail!("unknown optional feature was advertised by {profile}");
        }
    }
    // Co-located Station and push-gateway roles cannot borrow each other's
    // operation claims. Validate the real generated role policy in both directions.
    for (kind, forbidden) in [
        (
            arkret_wire::ServiceKind::PushGateway,
            "ak.profile.station.v1",
        ),
        (
            arkret_wire::ServiceKind::Station,
            "ak.profile.push_gateway.v1",
        ),
    ] {
        if ProfileValidator::new(kind)
            .validate(&[ProfileClaim::self_claimed(forbidden)])
            .is_ok()
        {
            bail!("service role accepted excluded profile {forbidden}");
        }
    }
    emit_vector(
        "discovery_profile.requirements",
        &fixture,
        json!({"checked_profiles": checked_profiles, "case_count": cases.len(),
            "executor": "SDK profile claim and semantic coverage validators"}),
    );
    Ok(())
}

/// Facet renderer/query structural guard. The historical fixture was folded
/// into the canonical `view.schema.json`; keep this suite as an executable
/// regression so stale Morph/View query shapes do not silently reappear.
pub fn run_facet_renderer_query_fixture_suite() -> Result<()> {
    let schema = crate::conformance::load_artifact_json("schemas/view.schema.json")?;
    let query_schema = crate::conformance::load_artifact_json("schemas/query.schema.json")?;
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("view schema missing required[]"))?;
    // `id` is deliberately absent: a View is an event-derived kind, so its id
    // comes from its create Event rather than from the authored object, and
    // requiring it here would contradict `object_id_not_event_derived`.
    for field in [
        "schema",
        "realm_id",
        "kind",
        "state",
        "query",
        "created_by",
        "created_at",
    ] {
        if !required.iter().any(|value| value.as_str() == Some(field)) {
            bail!("view schema required[] missing {field}");
        }
    }

    if schema
        .pointer("/$defs/view_renderer/$ref")
        .and_then(Value::as_str)
        != Some("./query.schema.json#/$defs/view_renderer")
    {
        bail!("view schema must reference the canonical query view_renderer definition");
    }
    let renderer_enum = query_schema
        .pointer("/$defs/view_renderer/enum")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("query schema missing $defs.view_renderer.enum"))?;
    for renderer in [
        "board", "list", "table", "timeline", "graph", "document", "custom",
    ] {
        if !renderer_enum
            .iter()
            .any(|value| value.as_str() == Some(renderer))
        {
            bail!("view renderer enum missing {renderer}");
        }
    }

    let query_properties = schema
        .pointer("/$defs/query/properties")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("view schema missing $defs.query.properties"))?;
    for field in [
        "realm_ids",
        "object_kinds",
        "morph_kinds",
        "facets",
        "filters",
        "order_by",
    ] {
        if !query_properties.contains_key(field) {
            bail!("view query properties missing {field}");
        }
    }
    if schema
        .pointer("/$defs/query/additionalProperties")
        .and_then(Value::as_bool)
        != Some(true)
    {
        bail!("view query must preserve forward-compatible additional properties");
    }

    emit_vector(
        "facet_renderer_query.schema",
        &json!({
            "schema": "ak.schema.view.v1",
            "required_query": "query",
            "facet_field": "facets"
        }),
        json!({
            "renderer_count": renderer_enum.len(),
            "query_property_count": query_properties.len()
        }),
    );

    Ok(())
}
