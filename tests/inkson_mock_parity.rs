use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{Duration, SecondsFormat, Utc};
use cotest::harness::{CokretServer, register_account};
use reqwest::Method;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use serial_test::serial;

const MOCK_PARITY_ALICE_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-0000000000a1";

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
    service_did: String,
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

    let server = CokretServer::spawn("inkson-mock-parity").await?;
    let alice_token = register_account(
        &server,
        "did:web:alice-mock-parity.example",
        "@alice-mock-parity",
        MOCK_PARITY_ALICE_DEVICE_ID,
    )
    .await?;
    let ctx = TemplateContext {
        alice_did: "did:web:alice-mock-parity.example".to_owned(),
        alice_token,
        service_did: server.service_did().to_owned(),
        realm_id: "ak:realm:01999999-0000-7000-8000-000000000451".to_owned(),
        space_id: "ak:space:01999999-0000-7000-8000-000000000451".to_owned(),
    };

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
        let rendered_body = render_body(case, &ctx);
        let mock = normalize_snapshot(
            &case.id,
            call_mock_contract(&contract_path, case, &rendered_path, rendered_body.clone())?,
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
        service_did: "did:web:soland.mock-parity-smoke.local".to_owned(),
        realm_id: "ak:realm:01999999-0000-7000-8000-000000000451".to_owned(),
        space_id: "ak:space:01999999-0000-7000-8000-000000000451".to_owned(),
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
        service_did: "did:web:soland.mock-parity-gate.local".to_owned(),
        realm_id: "ak:realm:01999999-0000-7000-8000-000000000451".to_owned(),
        space_id: "ak:space:01999999-0000-7000-8000-000000000451".to_owned(),
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
        .join("mockCokretContract.ts");
    Ok(path.is_file().then_some(path))
}

fn locate_inkson_mock_api(root: &Path) -> Result<Option<PathBuf>> {
    let path = root
        .parent()
        .ok_or_else(|| anyhow!("cotest root has no parent: {}", root.display()))?
        .join("inkson")
        .join("tests")
        .join("e2e")
        .join("mockCokretApi.ts");
    Ok(path.is_file().then_some(path))
}

fn assert_mock_contract_format(
    contract_path: &Path,
    fixture: &Fixture,
    ctx: &TemplateContext,
) -> Result<()> {
    for case in &fixture.cases {
        let rendered_path = render_str(&case.path, ctx);
        let rendered_body = render_body(case, ctx);
        let snapshot = call_mock_contract(contract_path, case, &rendered_path, rendered_body)
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

    let contract_source = fs::read_to_string(contract_path)
        .with_context(|| format!("read {}", contract_path.display()))?;
    assert_contract_branches_have_fixture_cases(&contract_source, fixture, ctx)?;
    assert_supported_operation_literals_registered(
        "mockCokretContract.ts",
        &contract_source,
        &registry,
    )?;
    if let Some(api_path) = locate_inkson_mock_api(root)? {
        let api_source = fs::read_to_string(&api_path)
            .with_context(|| format!("read {}", api_path.display()))?;
        assert_supported_operation_literals_registered("mockCokretApi.ts", &api_source, &registry)?;
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
                let body = render_body(case, ctx);
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
                let body = render_body(case, ctx);
                let snapshot = call_mock_contract(contract_path, case, &rendered_path, body)
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
            let body = render_body(case, ctx);
            let snapshot = call_mock_contract(contract_path, case, &rendered_path, body)
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

fn render_body(case: &ParityCase, ctx: &TemplateContext) -> Option<Value> {
    match case.body_template.as_deref() {
        Some("realm_create_event") => Some(realm_create_event(
            ctx,
            "ak:realm:01999999-0000-7000-8000-000000000451",
            "Mock parity setup",
            9_000_000_000_000_451,
        )),
        Some("realm_create_event_2") => Some(realm_create_event(
            ctx,
            "ak:realm:01999999-0000-7000-8000-000000000452",
            "Mock Parity Realm",
            9_000_000_000_000_452,
        )),
        Some("realm_create_event_3") => Some(realm_create_event(
            ctx,
            "ak:realm:01999999-0000-7000-8000-000000000453",
            "Mock Parity Space",
            9_000_000_000_000_453,
        )),
        Some("typing_ephemeral") => {
            let sent_at = Utc::now();
            let expires_at = sent_at + Duration::seconds(30);
            // ephemeral-envelope.schema.json: every broadcast ephemeral kind
            // carries `device_id` and a detached-JWS `proof` bound to
            // `{actor_id}#{device_id}` over the canonical envelope bytes.
            let mut envelope = json!({
                "kind": "ak.typing",
                "realm_id": ctx.realm_id,
                "actor_id": ctx.alice_did,
                "device_id": MOCK_PARITY_ALICE_DEVICE_ID,
                "sent_at": sent_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                "expires_at": expires_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                "payload": {
                    "actor_id": ctx.alice_did,
                    "realm_id": ctx.realm_id,
                    "strand_id": "ak:strand:01999999-0000-7000-8000-000000000451",
                    "track_name": "discussion",
                    "typing": true,
                    "ttl_ms": 30000
                }
            });
            cotest::harness::attach_ephemeral_proof_value(
                &mut envelope,
                &ed25519_dalek::SigningKey::from_bytes(&[0x5f; 32]),
            );
            Some(envelope)
        }
        Some(other) => panic!("unknown body_template {other}"),
        None => case.body.as_ref().map(|body| render_value(body, ctx)),
    }
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
        .replace("${service_did}", &ctx.service_did)
        .replace("${realm_id}", &ctx.realm_id)
        .replace("${space_id}", &ctx.space_id)
}

fn realm_create_event(ctx: &TemplateContext, realm_id: &str, title: &str, actor_seq: u64) -> Value {
    let cell = format!("ak:cell:ck.component.realm.create.v1:{realm_id}");
    let payload = json!({
        "object": {
            "id": realm_id,
            "schema": "ak.schema.realm.v1",
            "title": title,
            "trust_domain": "ak:trust_domain:mock-parity.cotest.local",
            "created_by": ctx.alice_did,
            "schema_refs": ["ak.schema.realm.v1"],
            "summary": "created by T-P0-04 parity baseline",
            "default_discoverability": "public",
            "default_join_rule": "public",
            "history_visibility": "world_readable",
            "encryption_profile": "none",
            "security_class": "standard",
            "federation_policy": "open",
            "notary_profile": "single_did",
            "digest_algorithm": "sha256",
            "notary": {
                "type": "single_did",
                "did": ctx.alice_did,
                "recovery_members": ["did:web:recovery-anchorer.cotest.local"],
                "controller_organization": "did:web:mock-parity.cotest.local",
                "recovery_controller_organizations": ["did:web:recovery-org.cotest.local"]
            },
            "created_at": "2026-05-22T10:00:00Z"
        }
    });
    let event_id = format!(
        "ak:event:{}",
        realm_id
            .strip_prefix("ak:realm:")
            .unwrap_or("01999999-0000-7000-8000-000000000451")
    );
    let mut event = json!({
        "event_id": event_id,
        "kind": "ak.realm.create",
        "realm_id": realm_id,
        "actor_id": ctx.alice_did,
        "actor_seq": actor_seq,
        "created_at": "2026-05-22T10:00:00Z",
        "hlc": format!("01970e589d21-{:04x}-a13f9c2e", actor_seq & 0xffff),
        "prev_refs": [],
        "refs": [],
        "requirements": {
            "schema": ["ak.schema.realm.v1"]
        },
        "payload": payload,
        "preconditions": [{
            "cell": cell,
            "predicate": {
                "op": "head_eq",
                "value": null
            }
        }],
        "effects": [{
            "cell": cell,
            "op": {
                "kind": "set",
                "value": payload["object"]
            }
        }],
        "unsigned": {
            "local_operation_idempotency_alias": format!("ak:operation:{}", realm_id.strip_prefix("ak:realm:").unwrap_or("01999999-0000-7000-8000-000000000451")),
            "local_target_ref": realm_id
        },
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": format!("{}#device", ctx.alice_did),
            "event_digest": "",
            "created_at": "2026-05-22T10:00:00Z",
            "jws": "placeholder"
        }]
    });
    cotest::harness::refresh_event_proof(&mut event);
    event
}

fn call_mock_contract(
    contract_path: &Path,
    case: &ParityCase,
    rendered_path: &str,
    body: Option<Value>,
) -> Result<HttpSnapshot> {
    let (path_only, query) = split_path_query(rendered_path);
    let request = json!({
        "method": case.method,
        "path": path_only,
        "query": query,
        "headers": case.headers,
        "account": {
            "did": "did:web:alice-mock-parity.example",
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
if (typeof mockCokretContract !== "function") {
  throw new Error("mockCokretContract export was not a function after stripping ESM exports");
}
if (typeof canonicalPath !== "function") {
  throw new Error("canonicalPath export was not a function after stripping ESM exports");
}
__result = mockCokretContract(__input);`, context, { filename: contractPath });
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
    server: &CokretServer,
    case: &ParityCase,
    ctx: &TemplateContext,
    rendered_path: &str,
    body: Option<Value>,
) -> Result<HttpSnapshot> {
    let body = if case.id == "ephemeral" {
        inject_live_default_strand_id(server, ctx, body).await?
    } else {
        body
    };
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
        request = request.json(&body);
    }
    let response = request.send().await?;
    let status = response.status().as_u16();
    let text = response.text().await?;
    let body = serde_json::from_str(&text).unwrap_or(Value::String(text));
    Ok(HttpSnapshot { status, body })
}

async fn inject_live_default_strand_id(
    server: &CokretServer,
    ctx: &TemplateContext,
    body: Option<Value>,
) -> Result<Option<Value>> {
    let Some(mut body) = body else {
        return Ok(None);
    };
    // soland does not auto-create a Strand on realm create and does not expose
    // `default_strand_id` on the realm lifecycle view; the realm's conversation
    // Strand id is derived from the realm id (ck:realm:<uuid> -> ck:strand:<uuid>),
    // which is the same id the message/typing envelopes target.
    let _ = server;
    let strand_id = ctx.realm_id.replace("ak:realm:", "ak:strand:");
    if let Some(payload) = body.get_mut("payload").and_then(Value::as_object_mut) {
        payload.insert("strand_id".to_owned(), Value::String(strand_id));
    }
    // The strand_id injection changed the canonical envelope bytes — re-sign
    // the broadcast proof so proof.event_digest matches what soland recomputes.
    if body.get("proof").is_some() {
        cotest::harness::attach_ephemeral_proof_value(
            &mut body,
            &ed25519_dalek::SigningKey::from_bytes(&[0x5f; 32]),
        );
    }
    Ok(Some(body))
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
        "service_type": body.get("service_type").cloned().unwrap_or(Value::Null),
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
                .any(|operation| operation == "ak.find.directory.query.describe")
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
        "<ck:space>".to_owned()
    } else if value.starts_with("ak:realm:") {
        "<ck:realm>".to_owned()
    } else if value.starts_with("ak:event:") {
        "<ck:event>".to_owned()
    } else if value.starts_with("ak:operation:") {
        "<ck:operation>".to_owned()
    } else if value.starts_with("ak:backup:") {
        "<ck:backup>".to_owned()
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
