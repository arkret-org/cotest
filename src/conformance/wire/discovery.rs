//! Discovery-profile and facet-renderer-query wire-model conformance vectors.

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{emit_vector, load_local_fixture};
use crate::conformance::{required_str, validate_profile};

/// Round-21 — Discovery profile (`ck.profile.discovery.v1`) black-box
/// vectors covering tier filtering and post-C16 surface naming.
///
/// Spec authority: `registry/operation-registry.json` `surface_groups[]` and
/// `capability_tiers`. The fixture asserts:
///   * core surfaces are implied by claiming `ck.profile.arkret_v1.core` — events_sync /
///     identity_registry / service_discovery MUST appear and the discovery client MAY call ops in
///     those surfaces;
///   * extension surfaces (post-C16 split: blob_storage, realtime_media, moderation_reports) MUST
///     be advertised explicitly — a core-only SUT MUST NOT auto-imply them, and discovery clients
///     MUST gate extension calls on the advertised set;
///   * `interop_bridge` tier surfaces (applet, mimi_interop) MUST be advertised only when the
///     external protocol is supported, and bridge advertisement is INDEPENDENT of core/extension
///     advertisement (no implication via `bridges_to`).
pub fn run_discovery_profile_fixture_suite() -> Result<()> {
    use std::collections::BTreeSet;

    let fixture = load_local_fixture("discovery_profile_fixture.json")?;
    validate_profile(&fixture, "ck.profile.discovery_vectors.v1")?;

    // Cross-check the fixture's surface_catalog against the LIVE operation
    // registry's surface_groups so any spec-side rename is caught here
    // rather than silently passing.
    let op_registry = crate::conformance::load_artifact_json("registry/operation-registry.json")?;
    let mut live_core: BTreeSet<String> = BTreeSet::new();
    let mut live_ext: BTreeSet<String> = BTreeSet::new();
    let mut live_bridge: BTreeSet<String> = BTreeSet::new();
    let mut surface_to_ops: std::collections::BTreeMap<String, BTreeSet<String>> =
        Default::default();
    for group in op_registry
        .get("surface_groups")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("operation-registry.surface_groups missing"))?
    {
        let surface = required_str(group, "surface")?;
        let tier = required_str(group, "tier")?;
        let mut ops: BTreeSet<String> = BTreeSet::new();
        for op in group
            .get("operations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(s) = op.as_str() {
                ops.insert(s.to_owned());
            }
        }
        match tier {
            "core" => {
                live_core.insert(surface.to_owned());
            }
            "extension" => {
                live_ext.insert(surface.to_owned());
            }
            "interop_bridge" => {
                live_bridge.insert(surface.to_owned());
            }
            "deployment_local" => {}
            other => bail!("operation-registry surface {surface} has unknown tier {other}"),
        }
        surface_to_ops.insert(surface.to_owned(), ops);
    }

    let catalog = fixture
        .get("surface_catalog")
        .ok_or_else(|| anyhow!("discovery fixture missing surface_catalog"))?;
    for (key, expected) in [
        ("core", &live_core),
        ("extension", &live_ext),
        ("interop_bridge", &live_bridge),
    ] {
        let declared: BTreeSet<String> = catalog
            .get(key)
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("surface_catalog.{key} missing"))?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        if &declared != expected {
            bail!(
                "discovery fixture surface_catalog.{key} drift vs operation-registry: declared {declared:?} live {expected:?}"
            );
        }
    }
    // Post-C16 surfaces MUST be present under their canonical names.
    for required in ["blob_storage", "realtime_media", "moderation_reports"] {
        if !live_ext.contains(required) {
            bail!("operation-registry surface_groups missing post-C16 surface {required}");
        }
    }

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("discovery fixture missing vectors[]"))?;

    let mut covered_core_only = false;
    let mut covered_ext_blob = false;
    let mut covered_ext_realtime = false;
    let mut covered_ext_moderation = false;
    let mut covered_bridge_mimi = false;
    let mut covered_bridge_applet = false;

    for vector in vectors {
        let name = required_str(vector, "name")?;
        let surfaces: BTreeSet<String> = vector
            .get("advertised_surfaces")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("vector {name} missing advertised_surfaces[]"))?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        // Every advertised surface MUST be a known live surface.
        for s in &surfaces {
            if !live_core.contains(s) && !live_ext.contains(s) && !live_bridge.contains(s) {
                bail!(
                    "vector {name} advertises unknown surface {s} (not in operation-registry surface_groups)"
                );
            }
        }
        let expected = vector
            .get("expected")
            .ok_or_else(|| anyhow!("vector {name} missing expected"))?;
        let core_present = expected
            .get("core_present")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} expected.core_present missing"))?;
        let ext_present = expected
            .get("extension_present")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} expected.extension_present missing"))?;
        let bridge_present = expected
            .get("interop_bridge_present")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} expected.interop_bridge_present missing"))?;

        let actual_core = surfaces.iter().any(|s| live_core.contains(s));
        let actual_ext = surfaces.iter().any(|s| live_ext.contains(s));
        let actual_bridge = surfaces.iter().any(|s| live_bridge.contains(s));
        if actual_core != core_present {
            bail!("vector {name} core_present drift: expected {core_present} got {actual_core}");
        }
        if actual_ext != ext_present {
            bail!("vector {name} extension_present drift: expected {ext_present} got {actual_ext}");
        }
        if actual_bridge != bridge_present {
            bail!(
                "vector {name} interop_bridge_present drift: expected {bridge_present} got {actual_bridge}"
            );
        }

        // Each `client_can_call` op MUST belong to one of the advertised
        // surfaces. Each `client_must_not_call` op MUST NOT belong to any.
        let allowed_ops: BTreeSet<String> = surfaces
            .iter()
            .flat_map(|s| surface_to_ops.get(s).cloned().unwrap_or_default())
            .collect();
        for op in expected
            .get("client_can_call")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str())
        {
            if !allowed_ops.contains(op) {
                bail!(
                    "vector {name} expects client_can_call {op} but op not in any advertised surface"
                );
            }
        }
        for op in expected
            .get("client_must_not_call")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str())
        {
            if allowed_ops.contains(op) {
                bail!(
                    "vector {name} expects client_must_not_call {op} but op IS in advertised surface set"
                );
            }
        }

        // interop_bridge: when surface is mimi_interop / applet the
        // external_protocol_supported field MUST be set.
        if bridge_present {
            let ext = vector
                .get("external_protocol_supported")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    anyhow!(
                        "vector {name} advertises interop_bridge surfaces; external_protocol_supported MUST be a non-null string"
                    )
                })?;
            if ext.is_empty() {
                bail!(
                    "vector {name} external_protocol_supported MUST identify the external protocol"
                );
            }
        }

        match name {
            "core_only_sut_advertises_core_implies_no_extension_or_bridge" => {
                covered_core_only = true
            }
            "extension_advertised_blob_storage_post_c16_split" => covered_ext_blob = true,
            "extension_advertised_realtime_media_alone_does_not_imply_blob" => {
                covered_ext_realtime = true
            }
            "extension_advertised_moderation_reports_post_c16_split" => {
                covered_ext_moderation = true
            }
            "interop_bridge_mimi_advertised_when_supported" => covered_bridge_mimi = true,
            "interop_bridge_applet_advertised_when_third_party_host_supported" => {
                covered_bridge_applet = true
            }
            other => bail!("discovery fixture unexpected positive vector {other}"),
        }
        emit_vector(
            "discovery_profile.advertise",
            vector,
            json!({
                "name": name,
                "advertised_surfaces": surfaces,
                "core_present": actual_core,
                "extension_present": actual_ext,
                "interop_bridge_present": actual_bridge,
            }),
        );
    }
    if !(covered_core_only
        && covered_ext_blob
        && covered_ext_realtime
        && covered_ext_moderation
        && covered_bridge_mimi
        && covered_bridge_applet)
    {
        bail!(
            "discovery fixture must cover (a) core-only, (b) blob_storage / realtime_media / moderation_reports extension advertisement, and (c) mimi_interop + applet bridge advertisement"
        );
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("discovery fixture missing negative_vectors[]"))?;
    let mut neg_bridge_unsupported = false;
    let mut neg_ext_blocked = false;
    let mut neg_bridge_no_implication = false;
    for vector in negatives {
        let name = required_str(vector, "name")?;
        let expected = vector
            .get("expected")
            .ok_or_else(|| anyhow!("negative vector {name} missing expected"))?;
        let outcome = required_str(expected, "outcome")?;
        if outcome != "reject_call" && outcome != "reject_advertisement" {
            bail!(
                "negative vector {name} outcome must be reject_call or reject_advertisement, got {outcome}"
            );
        }
        match name {
            "interop_bridge_mimi_not_advertised_when_external_protocol_unsupported" => {
                if required_str(expected, "rejection_reason")?
                    != "interop_bridge_surface_not_advertised"
                {
                    bail!(
                        "negative vector {name} rejection_reason must be interop_bridge_surface_not_advertised"
                    );
                }
                neg_bridge_unsupported = true;
            }
            "extension_call_blocked_when_surface_not_advertised" => {
                if required_str(expected, "rejection_reason")? != "extension_surface_not_advertised"
                {
                    bail!(
                        "negative vector {name} rejection_reason must be extension_surface_not_advertised"
                    );
                }
                neg_ext_blocked = true;
            }
            "interop_bridge_advertised_does_not_imply_in_spec_bridges_to" => {
                neg_bridge_no_implication = true;
            }
            other => bail!("discovery fixture unexpected negative vector {other}"),
        }
    }
    if !(neg_bridge_unsupported && neg_ext_blocked && neg_bridge_no_implication) {
        bail!(
            "discovery fixture must cover (a) bridge-when-unsupported, (b) extension-not-advertised, and (c) bridge-no-implication"
        );
    }

    Ok(())
}

// ────────────────────────── Round 22 ──────────────────────────
/// Facet renderer/query structural guard. The historical fixture was folded
/// into the canonical `view.schema.json`; keep this suite as an executable
/// regression so stale Morph/View query shapes do not silently reappear.
pub fn run_facet_renderer_query_fixture_suite() -> Result<()> {
    let schema = crate::conformance::load_artifact_json("schemas/view.schema.json")?;
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("view schema missing required[]"))?;
    for field in [
        "id",
        "schema",
        "realm_id",
        "kind",
        "query",
        "created_by",
        "created_at",
    ] {
        if !required.iter().any(|value| value.as_str() == Some(field)) {
            bail!("view schema required[] missing {field}");
        }
    }

    let renderer_enum = schema
        .pointer("/$defs/view_renderer/enum")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("view schema missing $defs.view_renderer.enum"))?;
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
        "object_types",
        "morph_types",
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
            "schema": "ck.schema.view.v1",
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
