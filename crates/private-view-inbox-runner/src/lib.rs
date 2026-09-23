//! Executable private-View and notification-inbox Account Data conformance.
//!
//! The runner drives the production SDK's typed key parsers, View validators,
//! and notification-inbox merge primitive. Only the opaque encrypted-value
//! boundary and the server-side physical-delete CAS register are modeled here.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use arkret_models_collaboration::events_payloads::{
    AccountDataSetPayload, ViewCreatePayload, ViewDefinition, ViewUpdatePayload,
    notification_inbox_account_data_key_notification_id, private_view_account_data_key_view_id,
};
use arkret_models_collaboration::objects::productivity::validate_private_account_data_key;
use arkret_models_collaboration::objects::queries::View;
use arkret_models_collaboration::objects::read_receipts::NotificationInboxValue;
use serde::Deserialize;
use serde_json::{Map, Value, json};

pub const PRIVATE_VIEW_INBOX_ENTRYPOINT: &str =
    "ak.suite.account_data.private_view_inbox_binding.v1";
pub const FIXTURE: &str = "private-view-inbox-account-data-fixture.json";

const VECTOR_ID: &str = "ak.vector.account_data.private_view_inbox_binding.v1";
const DEFAULT_HLC: &str = "01970e589d21-0001-a13f9c2e";
const DEFAULT_DEVICE: &str = "ak:device:0196419b-0000-7000-8000-000000000001";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRoot {
    profile: String,
    version: String,
    suite: String,
    runner: Runner,
    covers_vectors: Vec<String>,
    cases: Vec<Value>,
    minimum_independent_runners: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Runner {
    kind: String,
    entrypoint: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateViewInboxExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
}

fn spec_artifacts_root() -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ARTIFACTS_ROOT") {
        return PathBuf::from(root);
    }
    if let Some(root) = std::env::var_os("COTEST_SPEC_ROOT") {
        let root = PathBuf::from(root);
        for candidate in [root.clone(), root.join("spec").join("v1").join("artifacts")] {
            if candidate.join("fixtures").is_dir() {
                return candidate;
            }
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("arkret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
}

fn load_fixture() -> Result<FixtureRoot> {
    let path = spec_artifacts_root().join("fixtures").join(FIXTURE);
    serde_json::from_slice(&std::fs::read(&path)?)
        .with_context(|| format!("parse fixture {}", path.display()))
}

fn required<'a>(value: &'a Value, field: &str) -> Result<&'a Value> {
    value
        .get(field)
        .with_context(|| format!("missing field {field}"))
}

fn object<'a>(value: &'a Value, field: &str) -> Result<&'a Map<String, Value>> {
    required(value, field)?
        .as_object()
        .with_context(|| format!("{field} is not an object"))
}

fn array<'a>(value: &'a Value, field: &str) -> Result<&'a [Value]> {
    required(value, field)?
        .as_array()
        .map(Vec::as_slice)
        .with_context(|| format!("{field} is not an array"))
}

fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    required(value, field)?
        .as_str()
        .with_context(|| format!("{field} is not a string"))
}

fn strings<'a>(value: &'a Value, field: &str) -> Result<Vec<&'a str>> {
    array(value, field)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .with_context(|| format!("{field} entries must be strings"))
        })
        .collect()
}

fn key_patterns(case: &Value) -> Result<CaseExecutionResult> {
    let accepted = strings(case, "accepted_keys")?;
    let rejected = strings(case, "rejected_keys")?;
    for key in &accepted {
        validate_private_account_data_key(key)
            .with_context(|| format!("registered private key rejected: {key}"))?;
        let parsed = private_view_account_data_key_view_id(key).is_some()
            || notification_inbox_account_data_key_notification_id(key).is_some();
        ensure!(parsed, "accepted key has no typed namespace parser: {key}");
    }
    for key in &rejected {
        ensure!(
            validate_private_account_data_key(key).is_err(),
            "invalid key accepted: {key}"
        );
    }
    let expected = object(case, "expected")?;
    ensure!(expected["rejected_error"] == "param_invalid");
    ensure!(expected["bare_namespace_is_not_a_writable_key"] == true);
    ensure!(expected["unregistered_key_fallback_unreachable"] == true);
    Ok(CaseExecutionResult {
        case_id: string(case, "name")?.to_owned(),
        assertions: accepted.len() * 2 + rejected.len() + 3,
    })
}

fn storage_is_encrypted(case: &Value) -> Result<CaseExecutionResult> {
    let key = string(case, "account_data_key")?;
    validate_private_account_data_key(key)?;
    let mut accepted = BTreeSet::new();
    let mut rejected = BTreeSet::new();
    for request in array(case, "requests")? {
        let id = string(request, "id")?;
        let content = required(request, "content")?;
        let payload: AccountDataSetPayload = serde_json::from_value(json!({
            "key": key,
            "expected_server_revision": required(request, "expected_server_revision")?,
            "body": content,
        }))?;
        payload.validate()?;
        if content.as_str() == Some("encrypted_account_data_envelope") {
            accepted.insert(id);
        } else {
            rejected.insert(id);
        }
    }
    let expected = object(case, "expected")?;
    ensure!(
        accepted
            == strings(&Value::Object(expected.clone()), "accepted")?
                .into_iter()
                .collect()
    );
    ensure!(
        rejected
            == strings(&Value::Object(expected.clone()), "rejected")?
                .into_iter()
                .collect()
    );
    ensure!(expected["rejected_error"] == "param_invalid");
    ensure!(expected["envelope_aad_binds"] == json!(["actor_id", "account_data_key"]));
    ensure!(expected["server_reads_plaintext"] == false);
    Ok(CaseExecutionResult {
        case_id: string(case, "name")?.to_owned(),
        assertions: 8,
    })
}

fn merge_object(base: &Map<String, Value>, overlay: &Map<String, Value>) -> Map<String, Value> {
    let mut merged = base.clone();
    merged.remove("name");
    merged.remove("accepted");
    for (key, value) in overlay {
        if key != "name" && key != "accepted" {
            merged.insert(key.clone(), value.clone());
        }
    }
    merged
}

fn production_view(mut value: Map<String, Value>) -> Result<View> {
    let realm_id = value
        .get("realm_id")
        .cloned()
        .context("View realm_id missing")?;
    if value.get("query").is_some_and(|query| query == &json!({})) {
        value.insert("query".to_owned(), json!({"realm_ids": [realm_id]}));
    }
    serde_json::from_value(Value::Object(value)).context("decode production View")
}

fn private_view_plaintext(case: &Value) -> Result<CaseExecutionResult> {
    let key = string(case, "account_data_key")?;
    let candidates = array(case, "decrypted_plaintext_cases")?;
    let base = candidates
        .first()
        .and_then(Value::as_object)
        .context("accepted private View base missing")?;
    let mut assertions = 0;
    for candidate in candidates {
        let candidate = candidate
            .as_object()
            .context("View case is not an object")?;
        let expected = candidate
            .get("accepted")
            .and_then(Value::as_bool)
            .context("View case accepted missing")?;
        let result = production_view(merge_object(base, candidate))
            .and_then(|view| view.validate_private_account_data(key).map_err(Into::into));
        let actual = result.is_ok();
        ensure!(
            actual == expected,
            "private View case {} binding result drifted: {:?}",
            candidate
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unnamed"),
            result.err()
        );
        assertions += 1;
    }
    let expected = object(case, "expected")?;
    ensure!(expected["enforcement_point"] == "holder_client");
    ensure!(expected["server_can_recheck"] == false);
    Ok(CaseExecutionResult {
        case_id: string(case, "name")?.to_owned(),
        assertions: assertions + 2,
    })
}

fn shared_view_surfaces(case: &Value, private_view_case: &Value) -> Result<CaseExecutionResult> {
    let private_base = array(private_view_case, "decrypted_plaintext_cases")?
        .first()
        .and_then(Value::as_object)
        .context("private View base missing")?;
    let mut create_object = private_base.clone();
    // A shared Event authors only `view_definition`. The private Account Data
    // fixture is a materialized View, so discard reducer-owned members before
    // crossing the typed authoring boundary.
    for field in [
        "name",
        "accepted",
        "id",
        "type",
        "schema",
        "realm_id",
        "state",
        "state_changed_at",
        "created_by",
        "created_at",
        "updated_by",
        "updated_at",
    ] {
        create_object.remove(field);
    }
    let definition: ViewDefinition = serde_json::from_value(Value::Object(create_object))?;
    definition.validate()?;
    let view_id = private_base
        .get("id")
        .cloned()
        .context("private View id missing")?;
    let mut assertions = 0;
    for request in array(case, "requests")? {
        ensure!(string(request, "visibility")? == "private");
        let error = match string(request, "surface")? {
            "ak.view.create" => ViewCreatePayload {
                object: definition.clone(),
            }
            .validate()
            .expect_err("shared View create accepted private visibility")
            .to_string(),
            "ak.view.update" => {
                let payload = json!({"view_id": view_id, "patch": {"visibility": "private"}});
                match serde_json::from_value::<ViewUpdatePayload>(payload) {
                    Ok(payload) => payload
                        .validate()
                        .expect_err("shared View update accepted private visibility")
                        .to_string(),
                    Err(error) => error.to_string(),
                }
            }
            surface => bail!("unexpected shared View surface {surface}"),
        };
        ensure!(
            error.contains("private_view_requires_account_data"),
            "shared View private rejection reason drifted: {error}"
        );
        assertions += 3;
    }
    let expected = object(case, "expected")?;
    ensure!(expected["all_rejected"] == true);
    ensure!(expected["error"] == "schema_violation");
    ensure!(expected["reason_code"] == "private_view_requires_account_data");
    ensure!(expected["shared_view_query_visibility"] == json!(["shared"]));
    ensure!(expected["private_definition_in_shared_realm_result"] == false);
    Ok(CaseExecutionResult {
        case_id: string(case, "name")?.to_owned(),
        assertions: assertions + 5,
    })
}

fn inbox_value(key: &str, overlay: &Map<String, Value>) -> Result<NotificationInboxValue> {
    let notification_id = notification_inbox_account_data_key_notification_id(key)
        .context("notification key did not parse")?;
    let mut value = json!({
        "notification_id": notification_id.as_str(),
        "state": "dismissed",
        "updated_hlc": DEFAULT_HLC,
        "origin_device_id": DEFAULT_DEVICE,
    });
    let object = value.as_object_mut().expect("literal is an object");
    for (field, value) in overlay {
        if field != "name" && field != "accepted" && field != "id" {
            object.insert(field.clone(), value.clone());
        }
    }
    NotificationInboxValue::from_account_data(key, &value).map_err(Into::into)
}

fn inbox_state(case: &Value) -> Result<CaseExecutionResult> {
    let key = string(case, "account_data_key")?;
    let candidates = array(case, "decrypted_plaintext_cases")?;
    for candidate in candidates {
        let candidate = candidate
            .as_object()
            .context("Inbox case is not an object")?;
        let expected = candidate["accepted"]
            .as_bool()
            .context("Inbox accepted missing")?;
        let actual = inbox_value(key, candidate).is_ok();
        ensure!(actual == expected, "Inbox state acceptance drifted");
    }
    let expected = object(case, "expected")?;
    ensure!(
        expected["value_binds"]
            == json!([
                "notification_id",
                "state",
                "updated_hlc",
                "origin_device_id"
            ])
    );
    ensure!(expected["read_state_source"] == "read_cursor");
    Ok(CaseExecutionResult {
        case_id: string(case, "name")?.to_owned(),
        assertions: candidates.len() + 2,
    })
}

fn winner<'a>(
    left: &'a NotificationInboxValue,
    right: &'a NotificationInboxValue,
) -> Result<&'a NotificationInboxValue> {
    Ok(if left.compare_precedence(right)? == Ordering::Less {
        right
    } else {
        left
    })
}

fn inbox_merge(case: &Value) -> Result<CaseExecutionResult> {
    let key = string(case, "account_data_key")?;
    let values = array(case, "values")?;
    let mut decoded = BTreeMap::new();
    for value in values {
        let id = string(value, "id")?.to_owned();
        let object = value
            .as_object()
            .context("Inbox merge value is not an object")?;
        decoded.insert(id, inbox_value(key, object)?);
    }
    let a = decoded.get("device_a").context("device_a missing")?;
    let newer = decoded
        .get("device_b_newer_hlc")
        .context("newer value missing")?;
    let equal = decoded
        .get("device_b_equal_hlc")
        .context("equal-HLC value missing")?;
    ensure!(std::ptr::eq(winner(a, newer)?, newer));
    ensure!(std::ptr::eq(winner(a, equal)?, equal));
    let orders = [
        [a, newer, equal],
        [a, equal, newer],
        [newer, a, equal],
        [newer, equal, a],
        [equal, a, newer],
        [equal, newer, a],
    ];
    for order in orders {
        let selected = winner(winner(order[0], order[1])?, order[2])?;
        ensure!(
            std::ptr::eq(selected, newer),
            "delivery order changed Inbox winner"
        );
    }
    let expected = object(case, "expected")?;
    ensure!(expected["newer_hlc_winner"] == "device_b_newer_hlc");
    ensure!(expected["equal_hlc_winner"] == "device_b_equal_hlc");
    ensure!(expected["all_delivery_orders_equal"] == true);
    ensure!(expected["merge_runs_on"] == "client_plaintext");
    Ok(CaseExecutionResult {
        case_id: string(case, "name")?.to_owned(),
        assertions: 12,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Register {
    revision: u64,
    content: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteOutcome {
    Accepted,
    Conflict { current_revision: u64 },
}

fn apply(
    register: &mut Register,
    operation: &str,
    expected_revision: u64,
    content: Option<&str>,
) -> WriteOutcome {
    if register.revision != expected_revision {
        return WriteOutcome::Conflict {
            current_revision: register.revision,
        };
    }
    register.revision += 1;
    register.content = (operation == "replace")
        .then(|| content.map(str::to_owned))
        .flatten();
    WriteOutcome::Accepted
}

fn deletion(case: &Value) -> Result<CaseExecutionResult> {
    for key in strings(case, "account_data_keys")? {
        validate_private_account_data_key(key)?;
    }
    let requests = array(case, "requests")?;
    let delete = requests.first().context("delete request missing")?;
    let stale = requests.get(1).context("stale request missing")?;
    let mut register = Register {
        revision: 4,
        content: Some("encrypted_account_data_envelope".to_owned()),
    };
    ensure!(
        apply(
            &mut register,
            string(delete, "operation")?,
            required(delete, "expected_server_revision")?
                .as_u64()
                .context("delete revision invalid")?,
            None,
        ) == WriteOutcome::Accepted
    );
    ensure!(register.revision == 5 && register.content.is_none());
    ensure!(
        apply(
            &mut register,
            string(stale, "operation")?,
            required(stale, "expected_server_revision")?
                .as_u64()
                .context("stale revision invalid")?,
            required(stale, "content")?.as_str(),
        ) == WriteOutcome::Conflict {
            current_revision: 5
        }
    );
    ensure!(register.revision == 5 && register.content.is_none());
    let expected = object(case, "expected")?;
    ensure!(expected["physical_delete"] == "accepted");
    ensure!(expected["final_revision"] == 5);
    ensure!(expected["resource_get"] == "not_found");
    ensure!(expected["not_found_current_revision"] == 5);
    ensure!(expected["offline_stale_rewrite"] == "cas_conflict");
    ensure!(expected["revival_allowed"] == false);
    Ok(CaseExecutionResult {
        case_id: string(case, "name")?.to_owned(),
        assertions: 12,
    })
}

fn run_case(case: &Value, cases: &[Value]) -> Result<CaseExecutionResult> {
    match string(case, "name")? {
        "key_patterns_require_a_full_typed_id_tail" => key_patterns(case),
        "storage_is_encrypted_account_data" => storage_is_encrypted(case),
        "private_view_plaintext_binds_its_own_key" => private_view_plaintext(case),
        "shared_view_surfaces_never_carry_private" => shared_view_surfaces(
            case,
            cases
                .get(2)
                .context("private View plaintext case must precede shared surfaces")?,
        ),
        "inbox_state_is_closed_to_dismissed_and_archived" => inbox_state(case),
        "inbox_merge_is_hlc_then_device_tie_break" => inbox_merge(case),
        "deletion_mode_is_physical_delete" => deletion(case),
        other => bail!("unknown private View / Inbox case {other}"),
    }
}

pub fn run_private_view_inbox_suite() -> Result<PrivateViewInboxExecution> {
    let fixture = load_fixture()?;
    ensure!(fixture.profile == "ak.profile.full_client.v1");
    ensure!(fixture.version == "2026-08-01");
    ensure!(fixture.suite == "private_view_inbox_account_data");
    ensure!(fixture.runner.kind == "named_suite");
    ensure!(fixture.runner.entrypoint == PRIVATE_VIEW_INBOX_ENTRYPOINT);
    ensure!(fixture.covers_vectors == [VECTOR_ID]);
    ensure!(fixture.minimum_independent_runners >= 2);
    let cases = fixture
        .cases
        .iter()
        .map(|case| run_case(case, &fixture.cases))
        .collect::<Result<Vec<_>>>()?;
    Ok(PrivateViewInboxExecution {
        entrypoint: PRIVATE_VIEW_INBOX_ENTRYPOINT,
        fixture: FIXTURE,
        cases,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executes_every_private_view_and_inbox_case() {
        let execution = run_private_view_inbox_suite().unwrap();
        assert_eq!(execution.cases.len(), 7);
        assert!(execution.cases.iter().all(|case| case.assertions > 0));
    }

    #[test]
    fn typed_key_parsers_reject_bare_and_wrong_id_tails() {
        for key in [
            "ak.views.private",
            "ak.views.private.quarterly-plan",
            "ak.notifications.inbox.ak:view:AQwfxZZieb7Udz28u8Z_wXvR3hFpZzHl4sWKOICaiKC6",
        ] {
            assert!(validate_private_account_data_key(key).is_err());
        }
    }

    #[test]
    fn inbox_merge_is_commutative() {
        let fixture = load_fixture().unwrap();
        let case = &fixture.cases[5];
        let key = string(case, "account_data_key").unwrap();
        let values = array(case, "values").unwrap();
        let left = inbox_value(key, values[0].as_object().unwrap()).unwrap();
        let right = inbox_value(key, values[2].as_object().unwrap()).unwrap();
        assert_eq!(
            winner(&left, &right).unwrap(),
            winner(&right, &left).unwrap()
        );
    }
}
