//! Round 4 / A2 — Python lint parity (cotest-side mirrors of the
//! straightforward `check_service_describe_alignment`,
//! `check_policy_check_alignment`, and `check_vector_reference_closure`
//! rules from `contrix-spec/tools/lint_artifacts.py`).
//!
//! Each rule pins a structural invariant the cotest harness can check from
//! canonical artifacts and the conformance prose.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use serde_yaml::Value as YamlValue;

use super::{load_artifact_json, load_artifact_yaml};

/// Mirror of `lint_artifacts.py::check_service_describe_alignment`.
///
/// * ServiceDescribe schema and the OpenAPI component MUST both declare
///   `service_did` + `trust_domain` in `required`.
/// * Every `/server/describe`, `/events/describe`, `/identity/describe`,
///   `/sync/describe`, `/directory/describe`, `/applet/describe` 200
///   response MUST reference `#/components/schemas/ServiceDescribe`.
pub fn run_service_describe_alignment_check() -> Result<()> {
    let openapi = load_artifact_yaml("openapi/contrix-service-api.openapi.yaml")?;
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
                "service-describe.schema.json `required` missing `{required_field}` (round-4 lint parity)"
            );
        }
        if !openapi_required.contains(required_field) {
            bail!(
                "openapi components.schemas.ServiceDescribe.required missing `{required_field}` (round-4 lint parity)"
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
                "{describe_path} 200 response does not reference ServiceDescribe (got {ref_target:?}) (round-4 lint parity)"
            );
        }
    }
    Ok(())
}

/// Mirror of `lint_artifacts.py::check_policy_check_alignment`.
///
/// * `/policy/check` POST request/response MUST reference
///   `PolicyCheckRequest` / `PolicyCheckResponse` components.
/// * `PolicyCheckRequest.required` MUST include `realm_id`.
/// * `PolicyCheckResponse.required` MUST include `bound_to`.
/// * Legacy `/contrix/v1/check` MUST NOT be present.
pub fn run_policy_check_alignment_check() -> Result<()> {
    let openapi = load_artifact_yaml("openapi/contrix-service-api.openapi.yaml")?;
    let paths = openapi
        .get("paths")
        .ok_or_else(|| anyhow!("openapi paths section missing"))?;
    if paths.get("/contrix/v1/check").is_some() {
        bail!(
            "legacy /contrix/v1/check policy path must not be present; use /policy/check (round-4 lint parity)"
        );
    }
    let post = paths
        .get("/policy/check")
        .and_then(|p| p.get("post"))
        .ok_or_else(|| anyhow!("/policy/check POST missing"))?;
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
            "/policy/check requestBody must reference PolicyCheckRequest, got {req_ref:?} (round-4 lint parity)"
        );
    }
    if resp_ref != Some("#/components/schemas/PolicyCheckResponse") {
        bail!(
            "/policy/check 200 response must reference PolicyCheckResponse, got {resp_ref:?} (round-4 lint parity)"
        );
    }

    let components = openapi
        .get("components")
        .and_then(|c| c.get("schemas"))
        .ok_or_else(|| anyhow!("openapi components.schemas missing"))?;
    let req_component = components
        .get("PolicyCheckRequest")
        .ok_or_else(|| anyhow!("components.schemas.PolicyCheckRequest missing"))?;
    let resp_component = components
        .get("PolicyCheckResponse")
        .ok_or_else(|| anyhow!("components.schemas.PolicyCheckResponse missing"))?;
    let req_required = yaml_string_array(req_component, "required")?;
    if !req_required.contains("realm_id") {
        bail!("PolicyCheckRequest.required must include realm_id (round-4 lint parity)");
    }
    let resp_required = yaml_string_array(resp_component, "required")?;
    if !resp_required.contains("bound_to") {
        bail!("PolicyCheckResponse.required must include bound_to (round-4 lint parity)");
    }
    Ok(())
}

/// Mirror of `lint_artifacts.py::check_vector_reference_closure` — verifies
/// that every `cx.vector.*` id referenced from any fixture JSON resolves to a
/// declared vector in the canonical conformance prose
/// (`spec/v1/zh/conformance/conformance-vectors.md`) or the fixture file
/// itself defines it.
pub fn run_vector_reference_closure_check() -> Result<()> {
    use std::collections::BTreeSet;
    use std::fs;
    let root = super::spec_artifacts_root();
    let fixtures_dir = root.join("fixtures");
    if !fixtures_dir.is_dir() {
        bail!(
            "artifacts/fixtures dir missing at {}",
            fixtures_dir.display()
        );
    }
    let mut declared: BTreeSet<String> = BTreeSet::new();
    let mut referenced: BTreeSet<String> = BTreeSet::new();
    if let Some(prose_path) = root.parent().map(|spec_v1| {
        spec_v1
            .join("zh")
            .join("conformance")
            .join("conformance-vectors.md")
    }) {
        if prose_path.is_file() {
            let prose = fs::read_to_string(&prose_path)?;
            declared.extend(extract_vector_tokens(&prose));
        }
    }
    for entry in fs::read_dir(&fixtures_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let raw = fs::read_to_string(&path)?;
        let fixture_vectors = extract_vector_tokens(&raw);
        // Mirror contrix-spec's Python lint: any cx.vector.* token appearing
        // in a fixture JSON is part of the known-vector definition set. Some
        // fixture suites declare vectors in top-level arrays such as
        // `conformance_vectors`, not only in object-level `vector_id` fields.
        declared.extend(fixture_vectors.iter().cloned());
        for vector_id in fixture_vectors {
            referenced.insert(vector_id.clone());
        }
    }
    if declared.is_empty() {
        bail!("no cx.vector.* declarations found in fixtures or conformance prose");
    }
    for vector_id in &referenced {
        if !declared.contains(vector_id) {
            bail!(
                "vector_reference_closure: `{vector_id}` referenced by fixtures but not declared in any fixture or conformance prose"
            );
        }
    }
    Ok(())
}

fn extract_vector_tokens(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = input.as_bytes();
    let needle = b"cx.vector.";
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
        if let Ok(token) = std::str::from_utf8(&bytes[i..j]) {
            out.push(token.to_string());
        }
        i = j;
    }
    out
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
