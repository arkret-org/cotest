use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{Duration, Utc};
use cotest::harness::{
    ArkretServer, events_frontier_request_body, expect_json, query_method, register_account,
};
use cotest::scenarios::identity_test_support::{
    actor_did_for_service, authorize_device_public_key,
};
use reqwest::Method;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use serial_test::serial;

const MOCK_PARITY_ALICE_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-0000000000a1";
const MOCK_PARITY_ALICE_SIGNING_SEED: [u8; 32] = [0x5f; 32];

#[derive(Debug, Deserialize)]
struct Fixture {
    cases: Vec<ParityCase>,
}

#[derive(Debug, Deserialize)]
struct ParityCase {
    id: String,
    operation_id: String,
    method: String,
    path: String,
    #[serde(default)]
    auth: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: Option<Value>,
    #[serde(default)]
    body_template: Option<String>,
    #[serde(default)]
    live_skip_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OperationRegistryArtifact {
    operations: Vec<RegistryOperation>,
}

#[derive(Debug, Deserialize)]
struct RegistryOperation {
    operation_id: String,
    http: String,
    success_shape_kind: Option<String>,
    request_schema_ref: Option<String>,
    response_schema_ref: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OperationSchemaIndexArtifact {
    operations: Vec<SchemaIndexOperation>,
}

#[derive(Debug, Deserialize)]
struct SchemaIndexOperation {
    operation_id: String,
    success_shape_kind: Option<String>,
    request: Option<SchemaShape>,
    response: Option<SchemaShape>,
}

#[derive(Debug, Deserialize)]
struct SchemaShape {
    schema_kind: Option<String>,
    #[serde(default)]
    required: Vec<String>,
    #[serde(default)]
    properties: Vec<String>,
    #[serde(default)]
    closed: bool,
}

#[derive(Debug, Deserialize)]
struct Allowlist {
    allowed: Vec<AllowedDiff>,
}

#[derive(Debug, Deserialize)]
struct AllowedDiff {
    id: String,
    reason: String,
}

#[derive(Clone, Debug, PartialEq)]
struct HttpSnapshot {
    status: u16,
    body: Value,
}

#[derive(Debug)]
struct CaseResult {
    id: String,
    mock: HttpSnapshot,
    live: HttpSnapshot,
    allowed_reason: Option<String>,
}

struct TemplateContext {
    alice_did: String,
    alice_token: String,
    service_id: String,
    realm_id: String,
    space_id: String,
}

#[tokio::test]
#[serial]
async fn inkson_mock_contract_matches_live_soland_baseline() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture = load_fixture(&root)?;
    let allowlist = load_allowlist(&root)?;
    if allowlist.len() > 5 {
        bail!(
            "mock-parity-allowlist.json must contain at most 5 entries, got {}",
            allowlist.len()
        );
    }

    let server = ArkretServer::spawn("inkson-mock-parity").await?;
    let alice_did = actor_did_for_service(server.service_id(), "alice-mock-parity")?;
    let alice_token = register_account(
        &server,
        &alice_did,
        "@alice-mock-parity",
        MOCK_PARITY_ALICE_DEVICE_ID,
    )
    .await?;
    authorize_device_public_key(
        &server,
        &alice_token,
        &alice_did,
        MOCK_PARITY_ALICE_DEVICE_ID,
        &ed25519_dalek::SigningKey::from_bytes(&MOCK_PARITY_ALICE_SIGNING_SEED),
    )
    .await?;
    let mut ctx = TemplateContext {
        alice_did,
        alice_token,
        service_id: server.service_id().to_owned(),
        realm_id: String::new(),
        space_id: "ak:space:Ad3UlXP6ccWRlthrQ99e2Z3KV4UYm8ko8ct2eE6fdk-9".to_owned(),
    };
    // The parity Realm's id is derived from the genesis Event the setup case
    // submits, so it has to be computed from that batch rather than chosen.
    // Built once, not twice: the batch carries real-clock timestamps inside the
    // digest preimage, so rebuilding it would derive a different Realm id than
    // the one actually submitted.
    let (setup_realm_id, setup_bootstrap_body) = realm_bootstrap_batch(
        &ctx,
        "ak:realm:AeHsC4PtEYSA7Jc0C2kRtZ1V5ZG6aMCG8aL6V5juJvfk",
        "Mock parity setup",
    )?;
    ctx.realm_id = setup_realm_id;

    let contract_path = locate_inkson_contract(&root)?
        .ok_or_else(|| anyhow!("inkson mock contract missing next to {}", root.display()))?;
    assert_mock_contract_format(&contract_path, &fixture, &ctx)?;
    assert_mock_contract_artifact_gate(&root, &contract_path, &fixture, &ctx)?;

    let mut results = Vec::new();
    for case in &fixture.cases {
        if let Some(reason) = &case.live_skip_reason {
            if reason.trim().is_empty() {
                bail!("fixture case `{}` has an empty live_skip_reason", case.id);
            }
            continue;
        }

        let rendered_path = render_str(&case.path, &ctx);
        let rendered_body = render_body(case, &ctx, &setup_bootstrap_body)?;
        let rendered_body =
            prepare_live_publication_body(&server, case, &ctx, rendered_body).await?;
        let mock = normalize_snapshot(
            &case.id,
            call_mock_contract(
                &contract_path,
                case,
                &rendered_path,
                rendered_body.clone(),
                &ctx,
            )?,
        );
        let live = normalize_snapshot(
            &case.id,
            call_live_soland(&server, case, &ctx, &rendered_path, rendered_body).await?,
        );
        let allowed_reason = allowlist.get(&case.id).cloned();
        results.push(CaseResult {
            id: case.id.clone(),
            mock,
            live,
            allowed_reason,
        });
    }

    write_report(&root, &results)?;

    let unexpected: Vec<&CaseResult> = results
        .iter()
        .filter(|result| result.mock != result.live && result.allowed_reason.is_none())
        .collect();
    if !unexpected.is_empty() {
        bail!(
            "unexpected inkson mock parity diffs: {} (see mock-parity.md in the cotest artifact directory)",
            unexpected
                .iter()
                .map(|result| result.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    Ok(())
}

#[test]
fn inkson_mock_contract_format_smoke() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some(contract_path) = locate_inkson_contract(&root)? else {
        if std::env::var_os("COTEST_REQUIRE_INKSON_CONTRACT").is_some() {
            bail!("COTEST_REQUIRE_INKSON_CONTRACT is set but sibling inkson contract is missing");
        }
        eprintln!("skipping inkson mock contract smoke: sibling inkson checkout not found");
        return Ok(());
    };
    let fixture = load_fixture(&root)?;
    let ctx = TemplateContext {
        alice_did: "did:web:alice-mock-parity.example".to_owned(),
        alice_token: "cotest-format-smoke-token".to_owned(),
        service_id: "did:web:soland.mock-parity-smoke.local".to_owned(),
        realm_id: "ak:realm:AeHsC4PtEYSA7Jc0C2kRtZ1V5ZG6aMCG8aL6V5juJvfk".to_owned(),
        space_id: "ak:space:Ad3UlXP6ccWRlthrQ99e2Z3KV4UYm8ko8ct2eE6fdk-9".to_owned(),
    };
    assert_mock_contract_format(&contract_path, &fixture, &ctx)
}

#[test]
fn inkson_mock_contract_matches_operation_schema_artifacts() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some(contract_path) = locate_inkson_contract(&root)? else {
        if std::env::var_os("COTEST_REQUIRE_INKSON_CONTRACT").is_some() {
            bail!("COTEST_REQUIRE_INKSON_CONTRACT is set but sibling inkson contract is missing");
        }
        eprintln!("skipping inkson mock artifact gate: sibling inkson checkout not found");
        return Ok(());
    };
    let fixture = load_fixture(&root)?;
    let ctx = TemplateContext {
        alice_did: "did:web:alice-mock-parity.example".to_owned(),
        alice_token: "cotest-artifact-gate-token".to_owned(),
        service_id: "did:web:soland.mock-parity-gate.local".to_owned(),
        realm_id: "ak:realm:AeHsC4PtEYSA7Jc0C2kRtZ1V5ZG6aMCG8aL6V5juJvfk".to_owned(),
        space_id: "ak:space:Ad3UlXP6ccWRlthrQ99e2Z3KV4UYm8ko8ct2eE6fdk-9".to_owned(),
    };
    assert_mock_contract_artifact_gate(&root, &contract_path, &fixture, &ctx)
}

fn locate_inkson_contract(root: &Path) -> Result<Option<PathBuf>> {
    let path = root
        .parent()
        .ok_or_else(|| anyhow!("cotest root has no parent: {}", root.display()))?
        .join("inkson")
        .join("tests")
        .join("e2e")
        .join("mockArkretContract.ts");
    Ok(path.is_file().then_some(path))
}

fn locate_inkson_mock_api(root: &Path) -> Result<Option<PathBuf>> {
    let path = root
        .parent()
        .ok_or_else(|| anyhow!("cotest root has no parent: {}", root.display()))?
        .join("inkson")
        .join("tests")
        .join("e2e")
        .join("mockArkretApi.ts");
    Ok(path.is_file().then_some(path))
}

fn assert_mock_contract_format(
    contract_path: &Path,
    fixture: &Fixture,
    ctx: &TemplateContext,
) -> Result<()> {
    // Shape-only gates: the batch is never submitted, so a locally built one
    // serves and its derived Realm id does not have to match anything.
    let setup_bootstrap_body = realm_bootstrap_batch(
        ctx,
        "ak:realm:AeHsC4PtEYSA7Jc0C2kRtZ1V5ZG6aMCG8aL6V5juJvfk",
        "Mock parity setup",
    )?
    .1;
    for case in &fixture.cases {
        let rendered_path = render_str(&case.path, ctx);
        let rendered_body = render_body(case, ctx, &setup_bootstrap_body)?;
        let snapshot = call_mock_contract(contract_path, case, &rendered_path, rendered_body, ctx)
            .with_context(|| format!("format smoke for {}", case.id))?;
        if snapshot.status == 599 {
            bail!(
                "inkson mock contract returned undefined for fixture case `{}`; \
                 update tests/fixtures/inkson_mock_parity.json or the contract branch",
                case.id
            );
        }
    }
    Ok(())
}

fn assert_mock_contract_artifact_gate(
    root: &Path,
    contract_path: &Path,
    fixture: &Fixture,
    ctx: &TemplateContext,
) -> Result<()> {
    let artifacts_root = spec_artifacts_root(root);
    let registry = load_operation_registry(&artifacts_root)?;
    let schema_index = load_operation_schema_index(&artifacts_root)?;
    // Shape-only gate: the batch is never submitted, so a locally built one
    // serves and its derived Realm id does not have to match anything.
    let setup_bootstrap_body = realm_bootstrap_batch(
        ctx,
        "ak:realm:AeHsC4PtEYSA7Jc0C2kRtZ1V5ZG6aMCG8aL6V5juJvfk",
        "Mock parity setup",
    )?
    .1;

    let contract_source = fs::read_to_string(contract_path)
        .with_context(|| format!("read {}", contract_path.display()))?;
    assert_contract_branches_have_fixture_cases(&contract_source, fixture, ctx)?;
    assert_supported_operation_literals_registered(
        "mockArkretContract.ts",
        &contract_source,
        &registry,
    )?;
    if let Some(api_path) = locate_inkson_mock_api(root)? {
        let api_source = fs::read_to_string(&api_path)
            .with_context(|| format!("read {}", api_path.display()))?;
        assert_supported_operation_literals_registered("mockArkretApi.ts", &api_source, &registry)?;
    }

    for case in &fixture.cases {
        let operation = registry.get(&case.operation_id).ok_or_else(|| {
            anyhow!(
                "fixture case `{}` references unregistered operation_id {}",
                case.id,
                case.operation_id
            )
        })?;
        let (registered_method, registered_path) = parse_http_binding(&operation.http)
            .with_context(|| format!("parse registry http binding for {}", case.operation_id))?;
        let rendered_path = render_str(&case.path, ctx);
        let (path_only, _) = split_path_query(&rendered_path);
        if registered_method != case.method.to_ascii_uppercase() || registered_path != path_only {
            bail!(
                "fixture case `{}` drifted from operation registry: case {} {}, registry {} {} ({})",
                case.id,
                case.method.to_ascii_uppercase(),
                path_only,
                registered_method,
                registered_path,
                case.operation_id
            );
        }

        let schema = schema_index.get(&case.operation_id);
        if operation.request_schema_ref.is_some() || operation.response_schema_ref.is_some() {
            let schema = schema.ok_or_else(|| {
                anyhow!(
                    "schema index missing fixture operation {} ({})",
                    case.operation_id,
                    case.id
                )
            })?;
            if let (Some(registry_kind), Some(index_kind)) =
                (&operation.success_shape_kind, &schema.success_shape_kind)
                && registry_kind != index_kind
            {
                bail!(
                    "success_shape_kind drift for {}: registry {}, schema index {}",
                    case.operation_id,
                    registry_kind,
                    index_kind
                );
            }
            if operation.request_schema_ref.is_some() {
                let body = render_body(case, ctx, &setup_bootstrap_body)?;
                let request_shape = schema.request.as_ref().ok_or_else(|| {
                    anyhow!(
                        "schema index missing request shape for fixture case `{}` ({})",
                        case.id,
                        case.operation_id
                    )
                })?;
                assert_json_shape_required_fields(case, "request", request_shape, body.as_ref())?;
            }
            if operation.response_schema_ref.is_some() {
                let body = render_body(case, ctx, &setup_bootstrap_body)?;
                let snapshot = call_mock_contract(contract_path, case, &rendered_path, body, ctx)
                    .with_context(|| {
                    format!("mock response for artifact gate case `{}`", case.id)
                })?;
                if !(200..300).contains(&snapshot.status) {
                    bail!(
                        "fixture case `{}` returned non-success mock status {}",
                        case.id,
                        snapshot.status
                    );
                }
                let response_shape = schema.response.as_ref().ok_or_else(|| {
                    anyhow!(
                        "schema index missing response shape for fixture case `{}` ({})",
                        case.id,
                        case.operation_id
                    )
                })?;
                assert_supported_operations_registered(&case.id, &snapshot.body, &registry)?;
                assert_json_shape_required_fields(
                    case,
                    "response",
                    response_shape,
                    Some(&snapshot.body),
                )?;
            }
        } else {
            let body = render_body(case, ctx, &setup_bootstrap_body)?;
            let snapshot = call_mock_contract(contract_path, case, &rendered_path, body, ctx)
                .with_context(|| format!("mock response for artifact gate case `{}`", case.id))?;
            assert_supported_operations_registered(&case.id, &snapshot.body, &registry)?;
        }
    }

    Ok(())
}

fn load_fixture(root: &Path) -> Result<Fixture> {
    let path = root.join("tests/fixtures/inkson_mock_parity.json");
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

fn load_allowlist(root: &Path) -> Result<BTreeMap<String, String>> {
    let path = root.join("mock-parity-allowlist.json");
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let allowlist: Allowlist =
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    Ok(allowlist
        .allowed
        .into_iter()
        .map(|entry| (entry.id, entry.reason))
        .collect())
}

fn spec_artifacts_root(root: &Path) -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ARTIFACTS_ROOT") {
        return PathBuf::from(root);
    }
    if let Some(root) = std::env::var_os("COTEST_SPEC_ROOT") {
        let root = PathBuf::from(root);
        let candidates = [root.clone(), root.join("spec").join("v1").join("artifacts")];
        if let Some(candidate) = candidates
            .into_iter()
            .find(|candidate| candidate.join("registry").is_dir())
        {
            return candidate;
        }
    }
    root.join("..")
        .join("arkret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
}

fn load_operation_registry(root: &Path) -> Result<BTreeMap<String, RegistryOperation>> {
    let path = root.join("registry").join("operation-registry.json");
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let artifact: OperationRegistryArtifact =
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    Ok(artifact
        .operations
        .into_iter()
        .map(|operation| (operation.operation_id.clone(), operation))
        .collect())
}

fn load_operation_schema_index(root: &Path) -> Result<BTreeMap<String, SchemaIndexOperation>> {
    let path = root.join("reports").join("operation-schema-index.json");
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let artifact: OperationSchemaIndexArtifact =
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    Ok(artifact
        .operations
        .into_iter()
        .map(|operation| (operation.operation_id.clone(), operation))
        .collect())
}

fn parse_http_binding(http: &str) -> Result<(String, String)> {
    let mut parts = http.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow!("http binding missing method"))?
        .to_ascii_uppercase();
    let path = parts
        .next()
        .ok_or_else(|| anyhow!("http binding missing path"))?
        .to_owned();
    if parts.next().is_some() {
        bail!("http binding has extra fields: {http}");
    }
    Ok((method, path))
}

fn assert_contract_branches_have_fixture_cases(
    contract_source: &str,
    fixture: &Fixture,
    ctx: &TemplateContext,
) -> Result<()> {
    let branches = extract_contract_branches(contract_source);
    let fixture_branches = fixture
        .cases
        .iter()
        .map(|case| {
            let rendered_path = render_str(&case.path, ctx);
            let (path, _) = split_path_query(&rendered_path);
            (case.method.to_ascii_uppercase(), path.to_owned())
        })
        .collect::<BTreeSet<_>>();
    let missing = branches
        .difference(&fixture_branches)
        .map(|(method, path)| format!("{method} {path}"))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!(
            "inkson mock contract branches missing fixture cases: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

fn extract_contract_branches(source: &str) -> BTreeSet<(String, String)> {
    source
        .lines()
        .filter_map(|line| {
            let method = extract_after(line, "method === \"", "\"")?;
            let path = extract_after(line, "path === \"", "\"")?;
            Some((method.to_ascii_uppercase(), path.to_owned()))
        })
        .collect()
}

fn assert_supported_operation_literals_registered(
    source_name: &str,
    source: &str,
    registry: &BTreeMap<String, RegistryOperation>,
) -> Result<()> {
    let mut rogue = Vec::new();
    for (line, operation_id) in extract_supported_operation_literals(source) {
        if !registry.contains_key(&operation_id) {
            rogue.push(format!("{source_name}:{line}: {operation_id}"));
        }
    }
    if !rogue.is_empty() {
        bail!(
            "mock supported_operations references unregistered operation_id(s): {}",
            rogue.join(", ")
        );
    }
    Ok(())
}

fn assert_supported_operations_registered(
    case_id: &str,
    body: &Value,
    registry: &BTreeMap<String, RegistryOperation>,
) -> Result<()> {
    let Some(operations) = body.get("supported_operations").and_then(Value::as_array) else {
        return Ok(());
    };
    let rogue = operations
        .iter()
        .filter_map(Value::as_str)
        .filter(|operation_id| !registry.contains_key(*operation_id))
        .collect::<Vec<_>>();
    if !rogue.is_empty() {
        bail!(
            "mock case `{case_id}` returned unregistered supported_operations: {}",
            rogue.join(", ")
        );
    }
    Ok(())
}

fn extract_supported_operation_literals(source: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut in_supported_operations = false;
    let mut bracket_depth = 0i32;
    for (line_index, line) in source.lines().enumerate() {
        if !in_supported_operations && line.contains("supported_operations") && line.contains('[') {
            in_supported_operations = true;
            bracket_depth = 0;
        }
        if in_supported_operations {
            for literal in extract_string_literals(line) {
                if literal.starts_with("ak.") {
                    out.push((line_index + 1, literal));
                }
            }
            bracket_depth += line.chars().filter(|ch| *ch == '[').count() as i32;
            bracket_depth -= line.chars().filter(|ch| *ch == ']').count() as i32;
            if bracket_depth <= 0 {
                in_supported_operations = false;
            }
        }
    }
    out
}

fn extract_string_literals(line: &str) -> Vec<String> {
    let bytes = line.as_bytes();
    let mut literals = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let quote = bytes[i];
        if !matches!(quote, b'"' | b'\'' | b'`') {
            i += 1;
            continue;
        }
        i += 1;
        let mut literal = String::new();
        while i < bytes.len() {
            let byte = bytes[i];
            if byte == b'\\' && i + 1 < bytes.len() {
                let next = bytes[i + 1] as char;
                match next {
                    '/' | '"' | '\'' | '`' | '\\' => literal.push(next),
                    'n' => literal.push('\n'),
                    'r' => literal.push('\r'),
                    't' => literal.push('\t'),
                    _ => {
                        literal.push('\\');
                        literal.push(next);
                    }
                }
                i += 2;
                continue;
            }
            if byte == quote {
                break;
            }
            literal.push(byte as char);
            i += 1;
        }
        if i < bytes.len() && bytes[i] == quote {
            literals.push(literal);
            i += 1;
        }
    }
    literals
}

fn assert_json_shape_required_fields(
    case: &ParityCase,
    direction: &str,
    shape: &SchemaShape,
    value: Option<&Value>,
) -> Result<()> {
    if shape.schema_kind.as_deref() != Some("object") {
        return Ok(());
    }
    let value = value.ok_or_else(|| {
        anyhow!(
            "fixture case `{}` missing {direction} body for {}",
            case.id,
            case.operation_id
        )
    })?;
    let object = value.as_object().ok_or_else(|| {
        anyhow!(
            "fixture case `{}` {direction} for {} must be a JSON object",
            case.id,
            case.operation_id
        )
    })?;
    let missing = shape
        .required
        .iter()
        .filter(|field| !object.contains_key(field.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!(
            "fixture case `{}` {} for {} missing required schema field(s): {}",
            case.id,
            direction,
            case.operation_id,
            missing.join(", ")
        );
    }
    if shape.closed {
        let properties = shape
            .properties
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let extra = object
            .keys()
            .filter(|key| !properties.contains(key.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        if !extra.is_empty() {
            bail!(
                "fixture case `{}` {} for {} has field(s) outside schema index: {}",
                case.id,
                direction,
                case.operation_id,
                extra.join(", ")
            );
        }
    }
    Ok(())
}

fn extract_after<'a>(line: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    let start = line.find(prefix)? + prefix.len();
    let rest = &line[start..];
    let end = rest.find(suffix)?;
    Some(&rest[..end])
}

fn render_body(
    case: &ParityCase,
    ctx: &TemplateContext,
    setup_bootstrap_body: &Value,
) -> Result<Option<Value>> {
    Ok(match case.body_template.as_deref() {
        // The setup batch is the one the Realm id in `ctx` was derived from,
        // so it is replayed rather than rebuilt.
        Some("realm_create_event") => Some(setup_bootstrap_body.clone()),
        Some("realm_create_event_2") => Some(realm_create_event(
            ctx,
            "ak:realm:AXkWN4ihjvy_cLRGmk5Rflr6_1olBATMdS32QpUd-BG9",
            "Mock Parity Realm",
        )?),
        Some("realm_create_event_3") => Some(realm_create_event(
            ctx,
            "ak:realm:AU333dfTBLCxKUz6U6KscxDaOSk5lfjH0nb9kR4LyUsL",
            "Mock Parity Space",
        )?),
        Some("typing_signal") => {
            let sent_at = Utc::now();
            // `session` is the class for an ordinary typing signal; its TTL
            // ceiling is 30 seconds (`zh/sync/signal.md` §2).
            let expires_at = sent_at + Duration::seconds(30);
            // The outer envelope carries no product classification beyond
            // `signal_class`: the typing payload type, its Strand target and
            // the sender sequence live inside `encrypted_payload` and are not
            // reconstructible from the header (§1). The ciphertext is opaque
            // to the parity harness on purpose — this case pins the request
            // and response *shape* both implementations must agree on.
            let mut envelope = json!({
                "realm_id": ctx.realm_id,
                "scope_ref": {"kind": "realm", "realm_id": ctx.realm_id},
                "sender_actor_id": ctx.alice_did,
                "sender_device_id": MOCK_PARITY_ALICE_DEVICE_ID,
                "seal_ref": format!("ak:seal:sha256:{}", "a".repeat(64)),
                "signal_class": "session",
                "sent_at": arkret_canonical::format_timestamp_canonical(sent_at),
                "expires_at": arkret_canonical::format_timestamp_canonical(expires_at),
                "encrypted_payload": {
                    "scheme": "ak.signal_exporter_aead.v1",
                    "key_ref": {
                        "algorithm": "MLS-EXPORTER-AEAD",
                        "group_state_ref": "ak:event:AX1Yi6rgOReFnLzM0OwMzoI7WWl1XHT5HWSbeE9LgFyg"
                    },
                    "purpose": "ak.signal.v1",
                    "aead_profile": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
                    "epoch": 1,
                    "nonce": "AAAAAAAAAAAAAAAA",
                    "ciphertext": "Q2lwaGVydGV4dFBsYWNlaG9sZGVy",
                    "aad_digest": format!("sha256:{}", "0".repeat(64))
                },
                "proof": {
                    "kind": "detached_jws",
                    "verification_method": format!(
                        "{}#{MOCK_PARITY_ALICE_DEVICE_ID}",
                        ctx.alice_did
                    ),
                    "envelope_digest": format!("sha256:{}", "0".repeat(64)),
                    "created_at": arkret_canonical::format_timestamp_canonical(sent_at),
                    "jws": "eyJhbGciOiJFZDI1NTE5In0..c2ln"
                }
            });
            cotest::harness::attach_signal_proof_value(
                &mut envelope,
                &ed25519_dalek::SigningKey::from_bytes(&[0x5f; 32]),
            );
            Some(envelope)
        }
        Some(other) => bail!("unknown body_template {other}"),
        None => case.body.as_ref().map(|body| render_value(body, ctx)),
    })
}

fn render_value(value: &Value, ctx: &TemplateContext) -> Value {
    match value {
        Value::String(value) => Value::String(render_str(value, ctx)),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| render_value(value, ctx))
                .collect(),
        ),
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| (key.clone(), render_value(value, ctx)))
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn render_str(value: &str, ctx: &TemplateContext) -> String {
    value
        .replace("${alice_did}", &ctx.alice_did)
        .replace("${service_id}", &ctx.service_id)
        .replace("${realm_id}", &ctx.realm_id)
        .replace("${space_id}", &ctx.space_id)
}

/// The bootstrap batch for a parity Realm, together with the Realm id its
/// genesis Event derives.
///
/// The create payload carries no object id, so the Realm id is a function of
/// the genesis Event and is only knowable once the batch is built. It is
/// deterministic here because the signing seed, title and timestamps are fixed,
/// which is what lets the template context name the Realm before the batch is
/// submitted.
fn realm_bootstrap_batch(
    ctx: &TemplateContext,
    realm_id: &str,
    title: &str,
) -> Result<(String, Value)> {
    let creator = arkret_identifiers::Did::new(ctx.alice_did.clone())?;
    let service_id = arkret_identifiers::Did::new(ctx.service_id.clone())?;
    let mut realm = arkret_models_collaboration::objects::realm::Realm::new(
        arkret_identifiers::RealmId::new(realm_id.to_owned())?,
        title,
        creator,
        arkret_identifiers::TypedTrustDomainId::new(
            "ak:trust_domain:mock-parity.cotest.local".to_owned(),
        )?,
        arkret_wire::CORE_REDUCER_PROFILE,
        arkret_models_collaboration::objects::realm::NotaryProfile::SingleDid,
        arkret_wire::notary::NotaryValue::single_did(service_id),
        arkret::current_capability_action_registry_digest()?,
    );
    realm.summary = Some("created by T-P0-04 parity baseline".to_owned());
    realm.default_discoverability = serde_json::from_value(json!("public"))?;
    realm.default_join_rule = serde_json::from_value(json!("public"))?;
    realm.history_visibility = serde_json::from_value(json!("world_readable"))?;
    realm.security_class = Some(serde_json::from_value(json!("standard"))?);
    realm.federation_policy = Some(serde_json::from_value(json!("open"))?);
    realm.created_at = chrono::DateTime::parse_from_rfc3339("2026-05-22T10:00:00.000Z")?
        .with_timezone(&chrono::Utc);
    // R3.1: the create payload carries no object id.
    realm.id = None;
    let payload = arkret_models_collaboration::events_payloads::RealmCreatePayload::new(realm);
    let (derived_realm_id, events) =
        cotest::harness::realm_bootstrap_event_batch_with_signing_seed(
            &ctx.alice_did,
            payload,
            None,
            MOCK_PARITY_ALICE_SIGNING_SEED,
            &cotest::fixture_did_url(format!("{}#{MOCK_PARITY_ALICE_DEVICE_ID}", ctx.alice_did)),
        )?;
    let request = arkret_wire::EventsSubmitBatchRequestBody {
        events: events
            .into_iter()
            .map(arkret_wire::EventInitialSubmission::online)
            .collect(),
    };
    Ok((derived_realm_id.to_string(), serde_json::to_value(request)?))
}

fn realm_create_event(ctx: &TemplateContext, realm_id: &str, title: &str) -> Result<Value> {
    Ok(realm_bootstrap_batch(ctx, realm_id, title)?.1)
}

fn call_mock_contract(
    contract_path: &Path,
    case: &ParityCase,
    rendered_path: &str,
    body: Option<Value>,
    ctx: &TemplateContext,
) -> Result<HttpSnapshot> {
    let (path_only, query) = split_path_query(rendered_path);
    let request = json!({
        "method": case.method,
        "path": path_only,
        "query": query,
        "headers": case.headers,
        "account": {
            "did": ctx.alice_did,
            "handle": "@alice-mock-parity",
            "display_name": "alice-mock-parity",
            "device_id": MOCK_PARITY_ALICE_DEVICE_ID
        },
        "body": body,
    });
    let script = r#"
const fs = require("node:fs");
const vm = require("node:vm");
const contractPath = process.argv[1];
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const source = fs
  .readFileSync(contractPath, "utf8")
  .replace(/\bexport\s+(?=(function|const|let|var|class))/g, "");
const context = { __input: input, __result: undefined, console };
vm.createContext(context);
vm.runInContext(`${source}
if (typeof mockArkretContract !== "function") {
  throw new Error("mockArkretContract export was not a function after stripping ESM exports");
}
if (typeof canonicalPath !== "function") {
  throw new Error("canonicalPath export was not a function after stripping ESM exports");
}
__result = mockArkretContract(__input);`, context, { filename: contractPath });
process.stdout.write(JSON.stringify(context.__result ?? null));
"#;
    let mut child = Command::new("node")
        .arg("-e")
        .arg(script)
        .arg(contract_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn node for mock contract parity")?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| anyhow!("node stdin unavailable"))?
        .write_all(serde_json::to_vec(&request)?.as_slice())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "node mock contract failed for {}: {}",
            case.id,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let raw: Value = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("parse node mock response for {}", case.id))?;
    if raw.is_null() {
        return Ok(HttpSnapshot {
            status: 599,
            body: json!({"error": "mock_contract_not_handled"}),
        });
    }
    Ok(HttpSnapshot {
        status: raw["status"].as_u64().unwrap_or(200) as u16,
        body: raw.get("body").cloned().unwrap_or(Value::Null),
    })
}

fn split_path_query(path: &str) -> (&str, BTreeMap<String, String>) {
    let Some((path_only, query)) = path.split_once('?') else {
        return (path, BTreeMap::new());
    };
    let parsed = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    (path_only, parsed)
}

async fn call_live_soland(
    server: &ArkretServer,
    case: &ParityCase,
    ctx: &TemplateContext,
    rendered_path: &str,
    body: Option<Value>,
) -> Result<HttpSnapshot> {
    // Nothing left to rewrite per-case: a Signal's Strand target lives inside
    // `encrypted_payload`, so there is no outer field a harness could inject
    // it into.
    let _ = server;
    let method = case
        .method
        .parse::<Method>()
        .with_context(|| format!("invalid method {} for {}", case.method, case.id))?;
    let mut request = server.http().request(method, server.url(rendered_path));
    if case.auth.as_deref() == Some("alice") {
        request = request.bearer_auth(&ctx.alice_token);
    }
    for (key, value) in &case.headers {
        request = request.header(key, value);
    }
    if let Some(body) = body {
        request = match case.operation_id.as_str() {
            "ak.self.events.command.submit" => {
                let typed: arkret_wire::EventsSubmitBatchRequestBody =
                    serde_json::from_value(body)?;
                request
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(arkret_canonical::canonical_json_bytes(&typed)?)
            }
            "ak.self.events.read.scan" => {
                let typed: arkret_models_collaboration::event_query::EventsQueryPostRequestBody =
                    serde_json::from_value(body)?;
                request
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(arkret_canonical::canonical_json_bytes(&typed)?)
            }
            "ak.find.directory.read.search_realms" => {
                let typed: arkret_models_discovery::DirectorySearchRealmsRequestBody =
                    serde_json::from_value(body)?;
                request
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(arkret_canonical::canonical_json_bytes(&typed)?)
            }
            "ak.self.signal.command.send" => {
                let typed: arkret_wire::SignalEnvelope = serde_json::from_value(body)?;
                request
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(arkret_canonical::canonical_json_bytes(&typed)?)
            }
            operation_id => {
                return Err(anyhow!(
                    "live mock-parity request {operation_id} has no SDK request-body binding"
                ));
            }
        };
    }
    let response = request.send().await?;
    let status = response.status().as_u16();
    let text = response.text().await?;
    let body = serde_json::from_str(&text).unwrap_or(Value::String(text));
    Ok(HttpSnapshot { status, body })
}

async fn prepare_live_publication_body(
    server: &ArkretServer,
    case: &ParityCase,
    ctx: &TemplateContext,
    body: Option<Value>,
) -> Result<Option<Value>> {
    if case.body_template.as_deref() == Some("typing_signal") {
        let mut envelope = body.context("Signal template omitted its request body")?;
        let seal_ref = wait_for_realm_seal(server, ctx, &ctx.realm_id).await?;
        envelope["seal_ref"] = Value::String(seal_ref);
        cotest::harness::attach_signal_proof_value(
            &mut envelope,
            &ed25519_dalek::SigningKey::from_bytes(&MOCK_PARITY_ALICE_SIGNING_SEED),
        );
        return Ok(Some(envelope));
    }
    if !matches!(
        case.body_template.as_deref(),
        Some("realm_create_event" | "realm_create_event_2" | "realm_create_event_3")
    ) {
        return Ok(body);
    }
    let body = body.context("Realm bootstrap template omitted its request body")?;
    let events = body
        .get("events")
        .and_then(Value::as_array)
        .context("Realm bootstrap template omitted events")?
        .iter()
        .cloned()
        .map(serde_json::from_value::<arkret_wire::EventInitialSubmission>)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|submission| submission.event)
        .collect::<Vec<_>>();
    let request = arkret_wire::AuthorizationLeaseIssueRequest {
        events: events.clone(),
        intents: Vec::new(),
    };
    let request_digest = arkret_canonical::canonical_sha256(&request)?;
    let value = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/authorization-leases"))
            .bearer_auth(&ctx.alice_token)
            .header("Idempotency-Key", format!("cotest-parity-{request_digest}"))
            .json(&request),
        reqwest::StatusCode::OK,
    )
    .await?;
    let outcome: arkret_wire::AuthorizationLeaseIssueOutcome =
        serde_json::from_value(value).context("decode Realm bootstrap lease outcome")?;
    outcome
        .validate_against_request(&request)
        .context("validate Realm bootstrap lease outcome")?;
    Ok(Some(serde_json::to_value(
        arkret_wire::EventsSubmitBatchRequestBody {
            events: events
                .into_iter()
                .zip(outcome.authorization_leases)
                .map(
                    |(event, authorization_lease)| arkret_wire::EventInitialSubmission {
                        event,
                        authorization_lease: Some(authorization_lease),
                        cba_proof_bundles: Vec::new(),
                        control_proposal_ack: None,
                        membership_compensation_evidence: None,
                    },
                )
                .collect(),
        },
    )?))
}

async fn wait_for_realm_seal(
    server: &ArkretServer,
    ctx: &TemplateContext,
    realm_id: &str,
) -> Result<String> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let response = server
            .http()
            .request(query_method(), server.url("/_arkret/self/events/frontier"))
            .bearer_auth(&ctx.alice_token)
            .json(&events_frontier_request_body(None, Some(realm_id))?)
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::OK {
            let body: Value = response.json().await?;
            if let Some(seal_id) = body
                .pointer("/frontier/seal_id")
                .and_then(Value::as_str)
                .filter(|seal_id| !seal_id.trim().is_empty())
            {
                return Ok(seal_id.to_owned());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("Realm {realm_id} founding Seal was not materialized within 30 seconds");
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

fn normalize_snapshot(case_id: &str, snapshot: HttpSnapshot) -> HttpSnapshot {
    let body = match case_id {
        "server_describe" => normalize_server_describe(snapshot.body),
        "directory_describe" => normalize_directory_describe(snapshot.body),
        "account_profile" => json!({
            "principal_id": normalize_value(
                snapshot
                    .body
                    .get("principal_id")
                    .cloned()
                    .unwrap_or(Value::Null)
            ),
            "state": snapshot.body.get("state").cloned().unwrap_or(Value::Null),
            "devices": snapshot.body.get("devices").is_some_and(Value::is_array),
        }),
        "events_list" => json!({
            "events": snapshot.body.get("events").is_some_and(Value::is_array),
        }),
        "keys_backups" | "keys_backups_did_recovery_filter" => json!({
            "backups": snapshot.body.get("backups").is_some_and(Value::is_array),
        }),
        "directory_search_realms" => {
            // The harness creates a non-deterministic number of realms before
            // this case runs, and the per-item `name`/`description` text is
            // free-form. Collapse to "realms is an array, items expose the
            // expected key set" — that's what callers (inkson UI) bind to.
            let first_keys: Vec<String> = snapshot
                .body
                .get("realms")
                .and_then(Value::as_array)
                .and_then(|realms| realms.first())
                .and_then(Value::as_object)
                .map(|item| item.keys().cloned().collect())
                .unwrap_or_default();
            let mut keys = first_keys;
            keys.sort();
            json!({
                "realms_is_array": snapshot.body.get("realms").is_some_and(Value::is_array),
                "realm_item_keys": keys,
                "next_cursor_present": snapshot.body.get("next_cursor").is_some(),
            })
        }
        "events_submit" | "realm_create" | "space_create" => {
            // Compare the write-receipt's *key set* (after dropping dynamic
            // members), not just `body.status`. The previous normalizer kept
            // only `status`, so a mock or soland that dropped `accepted` /
            // `rejected` / the frontier objects from the EventsSubmitOutcome
            // would still pass. We deliberately compare the remaining top-level
            // key names rather than their values: the frontier objects and the
            // `accepted[]` event ids are per-run (head event ids, freshly minted
            // ids) and `is_dynamic_key` only filters whole members by name, not
            // the dynamic contents nested inside `actor_frontier` /
            // `realm_frontier`. The key-set check keeps the receipt shape honest
            // while staying immune to those per-run values.
            if snapshot.status == 200 || snapshot.status == 201 {
                let mut keys: Vec<String> = snapshot
                    .body
                    .as_object()
                    .map(|object| {
                        object
                            .keys()
                            .filter(|key| !is_dynamic_key(key.as_str()))
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default();
                keys.sort();
                json!({
                    "status": snapshot.body.get("status").cloned().unwrap_or(Value::Null),
                    "receipt_keys": keys,
                })
            } else {
                normalize_value(snapshot.body)
            }
        }
        _ => normalize_value(snapshot.body),
    };
    HttpSnapshot {
        status: snapshot.status,
        body,
    }
}

fn normalize_server_describe(body: Value) -> Value {
    let supported_features =
        body.get("supported_features")
            .and_then(Value::as_array)
            .map(|features| {
                features.iter().filter_map(Value::as_str).any(|feature| {
                    feature == "events.submit" || feature == "directory.search_realms"
                })
            })
            .unwrap_or(false);
    let supported_operations = body
        .get("supported_operations")
        .and_then(Value::as_array)
        .map(|operations| {
            operations
                .iter()
                .filter_map(Value::as_str)
                .any(|operation| operation == "ak.self.events.command.submit")
        })
        .unwrap_or(false);
    json!({
        "protocol_version": body.get("protocol_version").cloned().unwrap_or(Value::Null),
        "service_kind": body.get("service_kind").cloned().unwrap_or(Value::Null),
        "supports_core_events": supported_features || supported_operations,
    })
}

/// Reduce a `/_arkret/find/directory/describe` response to the stable semantic
/// invariants both the inkson mock and a live soland must agree on. The full
/// response carries environment-specific fields (development_mode, trust_domain,
/// per-deployment base_url) and a growing surface inventory (did methods,
/// operations, features) that legitimately differs between a fixed mock and the
/// current server, so — like `normalize_server_describe` — compare only the
/// directory contract invariants.
fn normalize_directory_describe(body: Value) -> Value {
    let supports_describe = body
        .get("supported_operations")
        .and_then(Value::as_array)
        .map(|operations| {
            operations
                .iter()
                .filter_map(Value::as_str)
                .any(|operation| operation == "ak.find.directory.read.describe")
        })
        .unwrap_or(false);
    let accepts_did_web = body
        .get("accepted_did_methods")
        .and_then(Value::as_array)
        .map(|methods| {
            methods
                .iter()
                .filter_map(Value::as_str)
                .any(|method| method == "did:web")
        })
        .unwrap_or(false);
    json!({
        "accept_policy_kind": body.get("accept_policy_kind").cloned().unwrap_or(Value::Null),
        "accepted_resource_kinds": body.get("accepted_resource_kinds").cloned().unwrap_or(Value::Null),
        "discovery_profiles": body.get("discovery_profiles").cloned().unwrap_or(Value::Null),
        "auth_mode": body.pointer("/auth_metadata/mode").cloned().unwrap_or(Value::Null),
        "default_ttl_seconds": body.get("default_ttl_seconds").cloned().unwrap_or(Value::Null),
        "supports_describe": supports_describe,
        "accepts_did_web": accepts_did_web,
    })
}

fn normalize_value(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut normalized = Map::new();
            for (key, value) in object {
                if is_dynamic_key(&key) {
                    continue;
                }
                normalized.insert(key, normalize_value(value));
            }
            Value::Object(normalized)
        }
        Value::Array(values) => {
            let mut normalized: Vec<_> = values.into_iter().map(normalize_value).collect();
            if normalized.iter().all(Value::is_string) {
                normalized.sort_by_key(|value| value.as_str().unwrap_or_default().to_owned());
            }
            Value::Array(normalized)
        }
        Value::String(value) => Value::String(normalize_string(&value)),
        other => other,
    }
}

fn is_dynamic_key(key: &str) -> bool {
    matches!(
        key,
        "event_id"
            | "operation_id"
            | "created_at"
            | "updated_at"
            | "received_at"
            | "server_received_at"
            | "expires_at"
            | "canonical_digest"
            | "sync_token"
            | "cursor"
            | "next_cursor"
            | "hlc"
            | "proofs"
            | "unsigned"
            | "receipt"
            | "challenge_id"
            | "server_signature"
            | "token"
            | "session_credential"
    )
}

fn normalize_string(value: &str) -> String {
    if value.starts_with("ak:space:") {
        "<ak:space>".to_owned()
    } else if value.starts_with("ak:realm:") {
        "<ak:realm>".to_owned()
    } else if value.starts_with("ak:event:") {
        "<ak:event>".to_owned()
    } else if value.starts_with("ak:operation:") {
        "<ak:operation>".to_owned()
    } else if value.starts_with("ak:backup:") {
        "<ak:backup>".to_owned()
    } else if value.starts_with("did:webvh:") {
        "<did:webvh>".to_owned()
    } else if value.starts_with("did:web:") {
        "<did:web>".to_owned()
    } else if value.starts_with("http://127.0.0.1:") {
        "<local-url>".to_owned()
    } else if value.len() >= 20 && value.contains('T') && value.ends_with('Z') {
        "<timestamp>".to_owned()
    } else {
        value.to_owned()
    }
}

fn write_report(root: &Path, results: &[CaseResult]) -> Result<()> {
    // Bare `cargo test` (no COTEST_ARTIFACT_DIR from run-cotest.ps1) lands in
    // the canonical runs/ tree instead of scattering files at artifacts/ root.
    let artifact_dir = std::env::var_os("COTEST_ARTIFACT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("artifacts").join("runs").join("cargo-adhoc"));
    fs::create_dir_all(&artifact_dir)?;
    let path = artifact_dir.join("mock-parity.md");
    let mut out = String::new();
    out.push_str("# inkson mock parity\n\n");
    out.push_str("| case | status | mock HTTP | live HTTP | allowed |\n");
    out.push_str("|---|---:|---:|---:|---|\n");
    for result in results {
        let status = if result.mock == result.live {
            "pass"
        } else if result.allowed_reason.is_some() {
            "allowed-diff"
        } else {
            "diff"
        };
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} |\n",
            result.id,
            status,
            result.mock.status,
            result.live.status,
            result.allowed_reason.as_deref().unwrap_or("")
        ));
    }
    for result in results.iter().filter(|result| result.mock != result.live) {
        out.push_str(&format!("\n## {}\n\n", result.id));
        if let Some(reason) = &result.allowed_reason {
            out.push_str(&format!("Allowed: {reason}\n\n"));
        }
        out.push_str("### mock\n\n```json\n");
        out.push_str(&serde_json::to_string_pretty(&result.mock.body)?);
        out.push_str("\n```\n\n### live\n\n```json\n");
        out.push_str(&serde_json::to_string_pretty(&result.live.body)?);
        out.push_str("\n```\n");
    }
    fs::write(path, out)?;
    Ok(())
}
