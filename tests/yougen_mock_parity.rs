use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{Duration, SecondsFormat, Utc};
use cotest::harness::{ContrixServer, register_account};
use reqwest::Method;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use serial_test::serial;
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
struct Fixture {
    cases: Vec<ParityCase>,
}

#[derive(Debug, Deserialize)]
struct ParityCase {
    id: String,
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
struct Snapshot {
    status: u16,
    body: Value,
}

#[derive(Debug)]
struct CaseResult {
    id: String,
    mock: Snapshot,
    live: Snapshot,
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
async fn yougen_mock_contract_matches_live_soland_baseline() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture = load_fixture(&root)?;
    let allowlist = load_allowlist(&root)?;
    if allowlist.len() > 5 {
        bail!(
            "mock-parity-allowlist.json must contain at most 5 entries, got {}",
            allowlist.len()
        );
    }

    let server = ContrixServer::spawn("yougen-mock-parity").await?;
    let alice_token = register_account(
        &server,
        "did:web:alice-mock-parity.example",
        "@alice-mock-parity",
        "dev_alice_mock_parity",
    )
    .await?;
    let ctx = TemplateContext {
        alice_did: "did:web:alice-mock-parity.example".to_owned(),
        alice_token,
        service_did: server.service_did().to_owned(),
        realm_id: "cx:realm:01999999-0000-7000-8000-000000000451".to_owned(),
        space_id: "cx:space:01999999-0000-7000-8000-000000000451".to_owned(),
    };

    let contract_path = root
        .parent()
        .ok_or_else(|| anyhow!("cotest root has no parent: {}", root.display()))?
        .join("yougen")
        .join("tests")
        .join("e2e")
        .join("mockContrixContract.ts");
    if !contract_path.is_file() {
        bail!(
            "yougen mock contract missing at {}",
            contract_path.display()
        );
    }

    let mut results = Vec::new();
    for case in &fixture.cases {
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
            "unexpected yougen mock parity diffs: {} (see mock-parity.md in the cotest artifact directory)",
            unexpected
                .iter()
                .map(|result| result.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    Ok(())
}

fn load_fixture(root: &Path) -> Result<Fixture> {
    let path = root.join("tests/fixtures/yougen_mock_parity.json");
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

fn render_body(case: &ParityCase, ctx: &TemplateContext) -> Option<Value> {
    match case.body_template.as_deref() {
        Some("realm_create_event") => Some(realm_create_event(
            ctx,
            "cx:realm:01999999-0000-7000-8000-000000000451",
            "Mock parity setup",
            9_000_000_000_000_451,
        )),
        Some("realm_create_event_2") => Some(realm_create_event(
            ctx,
            "cx:realm:01999999-0000-7000-8000-000000000452",
            "Mock Parity Realm",
            9_000_000_000_000_452,
        )),
        Some("realm_create_event_3") => Some(realm_create_event(
            ctx,
            "cx:realm:01999999-0000-7000-8000-000000000453",
            "Mock Parity Space",
            9_000_000_000_000_453,
        )),
        Some("typing_ephemeral") => {
            let sent_at = Utc::now();
            let expires_at = sent_at + Duration::seconds(30);
            // EphemeralEnvelope's `device_id` is typed as `DeviceId` in the SDK
            // and must match the `cx:device:<ULID>` shape. `dev_alice_mock_parity`
            // is a dev-login identifier accepted by `/auth/dev-login`, but it
            // would make this envelope fail salvo's deserializer with
            // `bad_request`. Drop the optional field so the typing surface is
            // what's actually under test.
            Some(json!({
                "kind": "cx.typing",
                "realm_id": ctx.realm_id,
                "actor_id": ctx.alice_did,
                "sent_at": sent_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                "expires_at": expires_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                "payload": {
                    "actor_id": ctx.alice_did,
                    "actor_did": ctx.alice_did,
                    "realm_id": ctx.realm_id,
                    "scope_id": ctx.space_id,
                    "typing": true,
                    "ttl_ms": 30000
                }
            }))
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
    let cell = format!("cx:cell:cx.component.realm.create.v1:{realm_id}");
    let payload = json!({
        "object": {
            "id": realm_id,
            "schema": "cx.schema.realm.v1",
            "title": title,
            "trust_domain": "cx:trust_domain:mock-parity.cotest.local",
            "created_by": ctx.alice_did,
            "schema_refs": ["cx.schema.realm.v1"],
            "summary": "created by T-P0-04 parity baseline",
            "default_discoverability": "public",
            "default_join_rule": "public",
            "history_visibility": "world_readable",
            "encryption_profile": "none",
            "security_class": "standard",
            "federation_policy": "open",
            "anchor_profile": "single_did",
            "digest_algorithm": "sha256",
            "anchorer": {
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
        "cx:event:{}",
        realm_id
            .strip_prefix("cx:realm:")
            .unwrap_or("01999999-0000-7000-8000-000000000451")
    );
    json!({
        "event_id": event_id,
        "kind": "cx.realm.create",
        "realm_id": realm_id,
        "actor_id": ctx.alice_did,
        "actor_seq": actor_seq,
        "created_at": "2026-05-22T10:00:00Z",
        "prev_refs": [],
        "refs": [],
        "requirements": {
            "schema": ["cx.schema.realm.v1"],
            "critical_extensions": []
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
            "local_operation_idempotency_alias": format!("cx:operation:{}", realm_id.strip_prefix("cx:realm:").unwrap_or("01999999-0000-7000-8000-000000000451")),
            "local_target_ref": realm_id
        },
        "proofs": [{
            "type": "dev-proof",
            "verification_method": format!("{}#device", ctx.alice_did),
            "payload_digest": format!("sha256:{}", sha256_canonical_json(&payload))
        }]
    })
}

fn call_mock_contract(
    contract_path: &Path,
    case: &ParityCase,
    rendered_path: &str,
    body: Option<Value>,
) -> Result<Snapshot> {
    let path_only = rendered_path
        .split_once('?')
        .map_or(rendered_path, |(path, _)| path);
    let request = json!({
        "method": case.method,
        "path": path_only,
        "headers": case.headers,
        "account": {
            "did": "did:web:alice-mock-parity.example",
            "handle": "@alice-mock-parity",
            "display_name": "alice-mock-parity",
            "device_id": "dev_alice_mock_parity"
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
vm.runInContext(`${source}\n__result = mockContrixContract(__input);`, context, { filename: contractPath });
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
        return Ok(Snapshot {
            status: 599,
            body: json!({"error": "mock_contract_not_handled"}),
        });
    }
    Ok(Snapshot {
        status: raw["status"].as_u64().unwrap_or(200) as u16,
        body: raw.get("body").cloned().unwrap_or(Value::Null),
    })
}

async fn call_live_soland(
    server: &ContrixServer,
    case: &ParityCase,
    ctx: &TemplateContext,
    rendered_path: &str,
    body: Option<Value>,
) -> Result<Snapshot> {
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
    Ok(Snapshot { status, body })
}

fn normalize_snapshot(case_id: &str, snapshot: Snapshot) -> Snapshot {
    let body = match case_id {
        "server_describe" => normalize_server_describe(snapshot.body),
        "account_profile" => json!({
            "did": normalize_value(snapshot.body.get("did").cloned().unwrap_or(Value::Null)),
        }),
        "events_list" => json!({
            "events": snapshot.body.get("events").is_some_and(Value::is_array),
        }),
        "keys_backups" => json!({
            "backups": snapshot.body.get("backups").is_some_and(Value::is_array),
        }),
        "devices_pairing_challenge" => json!({
            "device_id": normalize_value(snapshot.body.get("device_id").cloned().unwrap_or(Value::Null)),
        }),
        "directory_search_realms" => {
            // The harness creates a non-deterministic number of realms before
            // this case runs, and the per-item `name`/`description` text is
            // free-form. Collapse to "results is an array, items expose the
            // expected key set" — that's what callers (yougen UI) bind to.
            let first_keys: Vec<String> = snapshot
                .body
                .get("results")
                .and_then(Value::as_array)
                .and_then(|results| results.first())
                .and_then(Value::as_object)
                .map(|item| item.keys().cloned().collect())
                .unwrap_or_default();
            let mut keys = first_keys;
            keys.sort();
            json!({
                "results_is_array": snapshot.body.get("results").is_some_and(Value::is_array),
                "result_item_keys": keys,
                "next_cursor_present": snapshot.body.get("next_cursor").is_some(),
            })
        }
        "events_submit" | "realm_create" | "space_create" => {
            if snapshot.status == 200 || snapshot.status == 201 {
                json!({
                    "status": snapshot.body.get("status").cloned().unwrap_or(Value::Null),
                })
            } else {
                normalize_value(snapshot.body)
            }
        }
        _ => normalize_value(snapshot.body),
    };
    Snapshot {
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
                .any(|operation| operation == "cx.events.submit")
        })
        .unwrap_or(false);
    json!({
        "protocol_version": body.get("protocol_version").cloned().unwrap_or(Value::Null),
        "service_type": body.get("service_type").cloned().unwrap_or(Value::Null),
        "supports_core_events": supported_features || supported_operations,
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

fn sha256_canonical_json(value: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_json(value).as_bytes());
    format!("{:x}", hasher.finalize())
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => value.to_string(),
        Value::Array(values) => {
            let parts = values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{parts}]")
        }
        Value::Object(object) => {
            let parts = object
                .iter()
                .map(|(key, value)| {
                    format!("{}:{}", Value::String(key.clone()), canonical_json(value))
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{parts}}}")
        }
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
            | "session_token"
    )
}

fn normalize_string(value: &str) -> String {
    if value.starts_with("cx:space:") {
        "<cx:space>".to_owned()
    } else if value.starts_with("cx:realm:") {
        "<cx:realm>".to_owned()
    } else if value.starts_with("cx:event:") {
        "<cx:event>".to_owned()
    } else if value.starts_with("cx:operation:") {
        "<cx:operation>".to_owned()
    } else if value.starts_with("cx:backup:") {
        "<cx:backup>".to_owned()
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
    let artifact_dir = std::env::var_os("COTEST_ARTIFACT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("artifacts"));
    fs::create_dir_all(&artifact_dir)?;
    let path = artifact_dir.join("mock-parity.md");
    let mut out = String::new();
    out.push_str("# yougen mock parity\n\n");
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
