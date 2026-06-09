//! OpenAPI / vector lint parity (cotest-side mirrors of the
//! straightforward `check_service_describe_alignment`,
//! `check_policy_check_alignment`, and `check_vector_reference_closure`
//! rules from `cokret-spec/tools/lint_artifacts.py`).
//!
//! Each rule pins a structural invariant the cotest harness can check from
//! canonical artifacts and the conformance prose.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use serde_yaml::Value as YamlValue;

use super::{load_artifact_json, load_artifact_yaml};

/// Mirror of `lint_artifacts.py::check_service_describe_alignment`.
///
/// * ServiceDescribe schema and the OpenAPI component MUST both declare `service_did` +
///   `trust_domain` in `required`.
/// * Every `/server/describe`, `/events/describe`, `/identity/describe`, `/sync/describe`,
///   `/directory/describe`, `/applet/describe` 200 response MUST reference
///   `#/components/schemas/ServiceDescribe`.
pub fn run_service_describe_alignment_check() -> Result<()> {
    let openapi = load_artifact_yaml("openapi/cokret-service-api.openapi.yaml")?;
    let schema = load_artifact_json("schemas/service-describe.schema.json")?;

    let component = openapi
        .get("components")
        .and_then(|c| c.get("schemas"))
        .and_then(|s| s.get("ServiceDescribe"))
        .ok_or_else(|| anyhow!("openapi components.schemas.ServiceDescribe missing"))?;
    let openapi_required: BTreeSet<String> = yaml_string_array(component, "required")?;
    let schema_required: BTreeSet<String> = schema
        .get("required")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    for required_field in ["service_did", "trust_domain"] {
        if !schema_required.contains(required_field) {
            bail!(
                "service-describe.schema.json `required` missing `{required_field}` (lint parity)"
            );
        }
        if !openapi_required.contains(required_field) {
            bail!(
                "openapi components.schemas.ServiceDescribe.required missing `{required_field}` (lint parity)"
            );
        }
    }
    if openapi_required != schema_required {
        bail!(
            "ServiceDescribe required-field drift: \
             openapi_only={:?}, schema_only={:?}",
            openapi_required
                .difference(&schema_required)
                .collect::<Vec<_>>(),
            schema_required
                .difference(&openapi_required)
                .collect::<Vec<_>>(),
        );
    }

    let describe_paths = [
        "/server/describe",
        "/events/describe",
        "/identity/describe",
        "/sync/describe",
        "/directory/describe",
        "/applet/describe",
    ];
    let paths = openapi
        .get("paths")
        .ok_or_else(|| anyhow!("openapi paths section missing"))?;
    for describe_path in describe_paths {
        let Some(node) = paths.get(describe_path) else {
            // Round-4 lint parity is best-effort — a missing describe
            // path is surfaced by the spec-side lint already.
            continue;
        };
        let ref_target = node
            .get("get")
            .and_then(|g| g.get("responses"))
            .and_then(|r| r.get("200"))
            .and_then(|s| s.get("content"))
            .and_then(|c| c.get("application/json"))
            .and_then(|j| j.get("schema"))
            .and_then(|s| s.get("$ref"))
            .and_then(YamlValue::as_str);
        if ref_target != Some("#/components/schemas/ServiceDescribe") {
            bail!(
                "{describe_path} 200 response does not reference ServiceDescribe (got {ref_target:?}) (lint parity)"
            );
        }
    }
    Ok(())
}

/// Mirror of `lint_artifacts.py::check_policy_check_alignment`.
///
/// * `/_cokret/self/policy/check` POST request/response MUST reference `PolicyCheckRequest` /
///   `PolicyCheckResponse` components (thin `$ref` aliases over the
///   `service-operation-dtos.schema.json` `$defs`).
/// * The resolved `PolicyCheckRequest` schema's `required` MUST include `realm_id`.
/// * The resolved `PolicyCheckResponse` schema's `required` MUST include `bound_to`.
pub fn run_policy_check_alignment_check() -> Result<()> {
    let openapi = load_artifact_yaml("openapi/cokret-service-api.openapi.yaml")?;
    let paths = openapi
        .get("paths")
        .ok_or_else(|| anyhow!("openapi paths section missing"))?;
    let post = paths
        .get("/_cokret/self/policy/check")
        .and_then(|p| p.get("post"))
        .ok_or_else(|| anyhow!("/_cokret/self/policy/check POST missing"))?;
    let req_ref = post
        .get("requestBody")
        .and_then(|b| b.get("content"))
        .and_then(|c| c.get("application/json"))
        .and_then(|j| j.get("schema"))
        .and_then(|s| s.get("$ref"))
        .and_then(YamlValue::as_str);
    let resp_ref = post
        .get("responses")
        .and_then(|r| r.get("200"))
        .and_then(|s| s.get("content"))
        .and_then(|c| c.get("application/json"))
        .and_then(|j| j.get("schema"))
        .and_then(|s| s.get("$ref"))
        .and_then(YamlValue::as_str);
    if req_ref != Some("#/components/schemas/PolicyCheckRequest") {
        bail!(
            "/_cokret/self/policy/check requestBody must reference PolicyCheckRequest, got {req_ref:?} (lint parity)"
        );
    }
    if resp_ref != Some("#/components/schemas/PolicyCheckResponse") {
        bail!(
            "/_cokret/self/policy/check 200 response must reference PolicyCheckResponse, got {resp_ref:?} (lint parity)"
        );
    }

    let components = openapi
        .get("components")
        .and_then(|c| c.get("schemas"))
        .ok_or_else(|| anyhow!("openapi components.schemas missing"))?;
    let req_component = resolve_openapi_component_schema(components, "PolicyCheckRequest")?;
    let resp_component = resolve_openapi_component_schema(components, "PolicyCheckResponse")?;
    let req_required = yaml_string_array(&req_component, "required")?;
    if !req_required.contains("realm_id") {
        bail!("PolicyCheckRequest.required must include realm_id (lint parity)");
    }
    let resp_required = yaml_string_array(&resp_component, "required")?;
    if !resp_required.contains("bound_to") {
        bail!("PolicyCheckResponse.required must include bound_to (lint parity)");
    }
    Ok(())
}

/// Resolve an OpenAPI `components.schemas.<name>` node to its concrete schema,
/// following internal (`#/components/schemas/X`) and external
/// (`../schemas/<file>#/$defs/<def>`) `$ref` aliases. Mirrors
/// `lint_artifacts.py::resolve_openapi_component_schema`.
fn resolve_openapi_component_schema(components: &YamlValue, name: &str) -> Result<YamlValue> {
    let mut current = components
        .get(name)
        .cloned()
        .ok_or_else(|| anyhow!("components.schemas.{name} missing"))?;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    loop {
        let Some(ref_str) = current
            .get("$ref")
            .and_then(YamlValue::as_str)
            .map(str::to_owned)
        else {
            return Ok(current);
        };
        if let Some(internal) = ref_str.strip_prefix("#/components/schemas/") {
            if !seen.insert(internal.to_owned()) {
                bail!("cyclic OpenAPI component ref via {name}");
            }
            current = components
                .get(internal)
                .cloned()
                .ok_or_else(|| anyhow!("components.schemas.{internal} missing"))?;
            continue;
        }
        // External ref: `../schemas/<file>#/<json-pointer>`.
        let (file_part, fragment) = ref_str
            .split_once('#')
            .ok_or_else(|| anyhow!("external $ref missing fragment: {ref_str}"))?;
        let relative = file_part.trim_start_matches("../");
        let doc = load_artifact_yaml(relative)?;
        let mut node = &doc;
        for raw_segment in fragment.trim_start_matches('/').split('/') {
            let segment = raw_segment.replace("~1", "/").replace("~0", "~");
            node = node
                .get(&segment)
                .ok_or_else(|| anyhow!("ref fragment {fragment} not found in {relative}"))?;
        }
        return Ok(node.clone());
    }
}

/// Mirror of `lint_artifacts.py::check_vector_reference_closure` — verifies
/// that every `ck.vector.*` id referenced from fixtures, conformance prose, or
/// cotest Rust sources resolves to the canonical `vector-registry.json`.
pub fn run_vector_reference_closure_check() -> Result<()> {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::Path;
    let root = super::spec_artifacts_root();
    let fixtures_dir = root.join("fixtures");
    if !fixtures_dir.is_dir() {
        bail!(
            "artifacts/fixtures dir missing at {}",
            fixtures_dir.display()
        );
    }
    let registry_path = root.join("registry").join("vector-registry.json");
    let registry = load_registry_vector_ids(&registry_path)?;
    if registry.is_empty() {
        bail!(
            "vector registry {} contains no ck.vector.* ids",
            registry_path.display()
        );
    }
    let mut referenced: BTreeSet<String> = BTreeSet::new();
    if let Some(prose_path) = root.parent().map(|spec_v1| {
        spec_v1
            .join("zh")
            .join("conformance")
            .join("conformance-vectors.md")
    }) {
        if prose_path.is_file() {
            let prose = fs::read_to_string(&prose_path)?;
            referenced.extend(extract_vector_tokens(&prose));
        }
    }
    for entry in fs::read_dir(&fixtures_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let raw = fs::read_to_string(&path)?;
        referenced.extend(extract_vector_tokens(&raw));
    }
    collect_rust_source_vector_refs(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut referenced,
    )?;
    collect_rust_source_vector_refs(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests"),
        &mut referenced,
    )?;
    let missing = referenced
        .difference(&registry)
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!(
            "vector_reference_closure: ck.vector.* ids referenced outside canonical vector-registry.json: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

fn load_registry_vector_ids(path: &std::path::Path) -> Result<BTreeSet<String>> {
    let raw = std::fs::read_to_string(path)?;
    let registry: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|error| anyhow!("failed to parse {}: {error}", path.display()))?;
    let vectors = registry
        .get("vectors")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow!("{} missing vectors[]", path.display()))?;
    Ok(vectors
        .iter()
        .filter_map(|item| item.get("vector_id").and_then(serde_json::Value::as_str))
        .filter(|id| id.starts_with("ck.vector."))
        .map(ToOwned::to_owned)
        .collect())
}

fn collect_rust_source_vector_refs(
    path: &std::path::Path,
    out: &mut BTreeSet<String>,
) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if path.is_file() {
        if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            let raw = std::fs::read_to_string(path)?;
            out.extend(extract_vector_tokens(&raw));
        }
        return Ok(());
    }
    for entry in std::fs::read_dir(path)? {
        collect_rust_source_vector_refs(&entry?.path(), out)?;
    }
    Ok(())
}

fn extract_vector_tokens(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = input.as_bytes();
    let needle = b"ck.vector.";
    let mut i = 0usize;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] != needle {
            i += 1;
            continue;
        }
        let mut j = i + needle.len();
        while j < bytes.len() {
            let b = bytes[j];
            if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_') {
                j += 1;
            } else {
                break;
            }
        }
        if j > i + needle.len()
            && let Ok(token) = std::str::from_utf8(&bytes[i..j])
            && is_vector_id_token(token)
        {
            out.push(token.to_string());
        }
        i = j;
    }
    out
}

fn is_vector_id_token(token: &str) -> bool {
    token.rsplit('.').next().is_some_and(|tail| {
        tail.len() > 1 && tail.starts_with('v') && tail[1..].chars().all(|ch| ch.is_ascii_digit())
    })
}

fn yaml_string_array(value: &YamlValue, field: &str) -> Result<BTreeSet<String>> {
    Ok(value
        .get(field)
        .and_then(YamlValue::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(|item| item.as_str().map(str::to_owned))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_describe_alignment_passes() {
        run_service_describe_alignment_check()
            .expect("ServiceDescribe alignment must match round-4 spec");
    }

    #[test]
    fn policy_check_alignment_passes() {
        run_policy_check_alignment_check()
            .expect("PolicyCheck request/response alignment must match round-4 spec");
    }

    #[test]
    fn vector_reference_closure_passes() {
        run_vector_reference_closure_check()
            .expect("vector reference closure best-effort scan must not error");
    }
}
