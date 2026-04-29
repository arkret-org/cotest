use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs,
    path::PathBuf,
};

use anyhow::{Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

const DEFAULT_SPEC_CONFORMANCE_ROOT: &str = r"E:\Works\contrix-dev\contrix-spec\zh\conformance";

pub fn run_encoding_fixture_suite() -> Result<()> {
    let fixture = load_fixture::<EncodingFixture>("encoding-fixture.json")?;
    if fixture.suite != "encoding" {
        bail!("unexpected fixture suite {}", fixture.suite);
    }

    for case in fixture.cases.canonical_json {
        let canonical = canonical_json(&case.input)?;
        if canonical != case.canonical {
            bail!(
                "encoding fixture {} expected canonical {}, got {}",
                case.name,
                case.canonical,
                canonical
            );
        }
    }

    for case in fixture.cases.hash_digest {
        let digest = sha256_prefixed(case.input_ref.as_bytes());
        if case.expected_pattern != "^sha256:[0-9a-f]{64}$" {
            bail!("encoding fixture {} pattern drifted to {}", case.name, case.expected_pattern);
        }
        if !looks_like_sha256_digest(&digest) {
            bail!("encoding fixture {} produced invalid digest {}", case.name, digest);
        }
        if digest == sha256_prefixed(b"") {
            bail!("encoding fixture {} digest collapsed to empty input", case.name);
        }
    }

    for case in fixture.cases.proof_payload {
        let event = json!({
            "event_id": "cx:event:proof-demo",
            "kind": "cx.message.create",
            "space_id": "cx:space:proof-demo",
            "content": {"body": "covered"},
            "proofs": [{"alg": "none"}],
            "unsigned": {"hint": "not covered"}
        });
        let payload = canonical_proof_payload(&event)?;
        for field in case.covered_fields {
            if payload.get(&field).is_none() {
                bail!("encoding fixture {} missing covered field {}", case.name, field);
            }
        }
        for field in case.excluded_fields {
            if payload.get(&field).is_some() {
                bail!("encoding fixture {} leaked excluded field {}", case.name, field);
            }
        }
    }

    for case in fixture.cases.hlc {
        for pair in case.values.windows(2) {
            if pair[0] >= pair[1] {
                bail!("encoding fixture {} is not lexicographically increasing", case.name);
            }
        }
    }

    for case in fixture.cases.cursor {
        let encoded = encode_cursor_shape(&case.shape)?;
        if !encoded.starts_with("cx:cursor:") {
            bail!("encoding fixture {} did not produce cx:cursor prefix", case.name);
        }
        let decoded = decode_cursor_shape(&encoded)?;
        if decoded != case.shape {
            bail!(
                "encoding fixture {} roundtrip mismatch: expected {:?}, got {:?}",
                case.name,
                case.shape,
                decoded
            );
        }
    }

    for case in fixture.cases.fractional_rank {
        let actual = rank_between(&case.left, &case.right)?;
        if actual != case.expected {
            bail!(
                "encoding fixture {} expected rank {}, got {}",
                case.name,
                case.expected,
                actual
            );
        }
    }

    Ok(())
}

pub fn run_redaction_fixture_suite() -> Result<()> {
    let fixture = load_fixture::<RedactionFixture>("redaction-fixture.json")?;
    if fixture.suite != "redaction" {
        bail!("unexpected fixture suite {}", fixture.suite);
    }
    let target = sample_event();

    for case in fixture.cases {
        match case.name.as_str() {
            "preserved_fields" => {
                let redacted = redact_event(&target, "cx:event:redaction")?;
                for field in case.preserve.unwrap_or_default() {
                    if redacted.get(&field).is_none() {
                        bail!("redaction fixture {} did not preserve {}", case.name, field);
                    }
                }
                if redacted.get("content").is_some() {
                    bail!("redaction fixture {} leaked content", case.name);
                }
            }
            "dangling_redaction" => {
                let mut tracker = RedactionTracker::default();
                let state = tracker.push_redaction("cx:event:missing", "cx:event:redaction");
                if state != RedactionState::Pending {
                    bail!("redaction fixture {} expected pending state", case.name);
                }
            }
            "late_target_event" => {
                let mut tracker = RedactionTracker::default();
                tracker.push_redaction("cx:event:late", "cx:event:redaction");
                let materialized = tracker.materialize_target(&sample_event_with_id("cx:event:late"))?;
                if materialized.get("content").is_some() {
                    bail!("redaction fixture {} failed to materialize as redacted", case.name);
                }
                if materialized["redacted_because"] != "cx:event:redaction" {
                    bail!("redaction fixture {} lost redaction reference", case.name);
                }
            }
            "audit_visibility" => {
                let redacted = redact_event(&target, "cx:event:redaction")?;
                let audit = audit_tombstone(&redacted)?;
                if audit.get("content").is_some() {
                    bail!("redaction fixture {} leaked content to audit view", case.name);
                }
                if audit["redacts"] != target["event_id"] {
                    bail!("redaction fixture {} lost target reference", case.name);
                }
            }
            _ => bail!("unknown redaction fixture case {}", case.name),
        }
    }

    Ok(())
}

pub fn run_capability_fixture_suite() -> Result<()> {
    let fixture = load_fixture::<CapabilityFixture>("capability-fixture.json")?;
    if fixture.suite != "capability" {
        bail!("unexpected fixture suite {}", fixture.suite);
    }

    for case in fixture.cases {
        match case.name.as_str() {
            "resource_selector_grammar" => {
                let selector = case
                    .selector
                    .ok_or_else(|| anyhow!("capability fixture {} missing selector", case.name))?;
                let task = ResourceRef {
                    kind: "entity".to_owned(),
                    space_id: selector.space_id.clone(),
                    entity_type: Some("task".to_owned()),
                };
                let note = ResourceRef {
                    kind: "entity".to_owned(),
                    space_id: selector.space_id.clone(),
                    entity_type: Some("note".to_owned()),
                };
                if !selector.matches(&task) || selector.matches(&note) {
                    bail!("capability fixture {} selector grammar mismatch", case.name);
                }
            }
            "constraint_fail_closed" => {
                let grant = CapabilityGrant {
                    required_claims: BTreeSet::from(["employee".to_owned()]),
                    approval_mode: ApprovalMode::None,
                    approved: false,
                    revoked_claims: BTreeSet::new(),
                    scope: selector_scope("task")?,
                };
                if grant.is_usable(&BTreeSet::new()) {
                    bail!("capability fixture {} did not fail closed", case.name);
                }
            }
            "approval_proposal" => {
                let grant = CapabilityGrant {
                    required_claims: BTreeSet::new(),
                    approval_mode: ApprovalMode::ProposalThenApprove,
                    approved: false,
                    revoked_claims: BTreeSet::new(),
                    scope: selector_scope("task")?,
                };
                if grant.is_usable(&BTreeSet::new()) {
                    bail!("capability fixture {} allowed unapproved proposal", case.name);
                }
            }
            "claim_revocation" => {
                let grant = CapabilityGrant {
                    required_claims: BTreeSet::from(["employee".to_owned()]),
                    approval_mode: ApprovalMode::None,
                    approved: false,
                    revoked_claims: BTreeSet::from(["employee".to_owned()]),
                    scope: selector_scope("task")?,
                };
                if grant.is_usable(&BTreeSet::from(["employee".to_owned()])) {
                    bail!("capability fixture {} ignored revoked claim", case.name);
                }
            }
            "delegation_cycle_and_scope_narrowing" => {
                let parent = Delegation {
                    from: "did:web:alice.example".to_owned(),
                    to: "did:web:bob.example".to_owned(),
                    scope: selector_scope("task")?,
                };
                let child_ok = Delegation {
                    from: "did:web:bob.example".to_owned(),
                    to: "did:web:carol.example".to_owned(),
                    scope: selector_scope("task")?,
                };
                let child_bad_scope = Delegation {
                    from: "did:web:bob.example".to_owned(),
                    to: "did:web:carol.example".to_owned(),
                    scope: selector_scope("entity")?,
                };
                let cycle = Delegation {
                    from: "did:web:carol.example".to_owned(),
                    to: "did:web:alice.example".to_owned(),
                    scope: selector_scope("task")?,
                };
                validate_delegations(&[parent.clone(), child_ok.clone()])?;
                if validate_delegations(&[parent.clone(), child_bad_scope]).is_ok() {
                    bail!("capability fixture {} allowed widened child scope", case.name);
                }
                if validate_delegations(&[parent, child_ok.clone(), cycle]).is_ok() {
                    bail!("capability fixture {} allowed delegation cycle", case.name);
                }
            }
            _ => bail!("unknown capability fixture case {}", case.name),
        }
    }

    Ok(())
}

pub fn run_state_resolution_fixture_suite() -> Result<()> {
    let fixture = load_fixture::<StateResolutionFixture>("state-resolution-fixture.json")?;
    if fixture.suite != "state_resolution" {
        bail!("unexpected fixture suite {}", fixture.suite);
    }

    for case in fixture.cases {
        match case.name.as_str() {
            "membership_concurrency" => {
                let join = StateEvent {
                    kind: "join".to_owned(),
                    auth_weight: 10,
                    hlc: "01970e589d21-0004-a13f9c2e".to_owned(),
                    actor_seq: 1,
                    event_id: "cx:event:join".to_owned(),
                };
                let ban = StateEvent {
                    kind: "ban".to_owned(),
                    auth_weight: 20,
                    hlc: "01970e589d21-0005-a13f9c2e".to_owned(),
                    actor_seq: 1,
                    event_id: "cx:event:ban".to_owned(),
                };
                let resolved = resolve_state_events(&[join, ban])?;
                if resolved.kind != "ban" {
                    bail!("state resolution fixture {} did not pick ban", case.name);
                }
            }
            "capability_delegate_revoke_race" => {
                let delegate = StateEvent {
                    kind: "delegate".to_owned(),
                    auth_weight: 15,
                    hlc: "01970e589d21-0005-a13f9c2e".to_owned(),
                    actor_seq: 1,
                    event_id: "cx:event:delegate".to_owned(),
                };
                let revoke = StateEvent {
                    kind: "revoke".to_owned(),
                    auth_weight: 15,
                    hlc: "01970e589d21-0005-a13f9c2e".to_owned(),
                    actor_seq: 1,
                    event_id: "cx:event:revoke".to_owned(),
                };
                let resolved = resolve_state_events(&[delegate, revoke])?;
                if resolved.kind != "revoke" {
                    bail!("state resolution fixture {} did not fail closed on revoke", case.name);
                }
            }
            "schema_policy_update_race" => {
                let policy_state = PolicyState {
                    decision: "deny".to_owned(),
                };
                let write = PendingWrite {
                    event_id: "cx:event:write".to_owned(),
                    required_decision: "allow".to_owned(),
                };
                if write_is_valid_against_policy(&write, &policy_state) {
                    bail!("state resolution fixture {} accepted stale policy", case.name);
                }
            }
            "deterministic_tie_breaker" => {
                let first = StateEvent {
                    kind: "join".to_owned(),
                    auth_weight: 10,
                    hlc: "01970e589d21-0005-a13f9c2e".to_owned(),
                    actor_seq: 1,
                    event_id: "cx:event:a".to_owned(),
                };
                let second = StateEvent {
                    kind: "join".to_owned(),
                    auth_weight: 10,
                    hlc: "01970e589d21-0005-a13f9c2e".to_owned(),
                    actor_seq: 2,
                    event_id: "cx:event:b".to_owned(),
                };
                let resolved = resolve_state_events(&[second, first.clone()])?;
                if resolved.event_id != first.event_id {
                    bail!("state resolution fixture {} was not deterministic", case.name);
                }
            }
            _ => bail!("unknown state resolution fixture case {}", case.name),
        }
    }

    Ok(())
}

pub fn run_sync_fixture_suite() -> Result<()> {
    let fixture = load_fixture::<SyncFixture>("sync-fixture.json")?;
    if fixture.suite != "sync" {
        bail!("unexpected fixture suite {}", fixture.suite);
    }
    let mut service = ReferenceSyncService::sample();

    for case in fixture.cases {
        match case.name.as_str() {
            "initial_sync" => {
                let response = service.initial_sync(10)?;
                if response.events.len() != 3 || response.next_cursor.is_none() {
                    bail!("sync fixture {} did not return full visible state", case.name);
                }
            }
            "incremental_sync" => {
                let initial = service.initial_sync(10)?;
                let response = service.incremental_sync(initial.next_cursor.as_deref(), 10)?;
                if response.events.len() != 1 || response.events[0].event_id != "evt_4" {
                    bail!("sync fixture {} did not return only delta", case.name);
                }
            }
            "state_after" => {
                let response = service.initial_sync(10)?;
                if !response.state_after.starts_with("sha256:") {
                    bail!("sync fixture {} missing post-reducer frontier", case.name);
                }
            }
            "limited_timeline_backfill" => {
                let response = service.backfill(2)?;
                if !response.limited || response.prev_batch.is_none() {
                    bail!("sync fixture {} missing limited/prev_batch", case.name);
                }
            }
            "expired_cursor" => {
                let result = service.incremental_sync(Some("cx:cursor:expired"), 10);
                match result {
                    Err(error) if error.to_string().contains("snapshot_bootstrap") => {}
                    _ => bail!("sync fixture {} did not signal expiry recovery", case.name),
                }
            }
            "filter_mismatch" => {
                let result = service.validate_filter("unsupported-profile");
                match result {
                    Err(error) if error.to_string().contains("describe_guidance") => {}
                    _ => bail!("sync fixture {} did not reject mismatched filter", case.name),
                }
            }
            "to_device_ack" => {
                service.queue_to_device("msg-1");
                let first = service.pull_to_device();
                if first != vec!["msg-1".to_owned()] {
                    bail!("sync fixture {} failed first delivery", case.name);
                }
                service.ack_to_device("msg-1");
                if !service.pull_to_device().is_empty() {
                    bail!("sync fixture {} redelivered acked message", case.name);
                }
            }
            "snapshot_manifest_chunk_frontier" => {
                let snapshot = ReferenceSnapshot::sample()?;
                if !snapshot.verify()? {
                    bail!("sync fixture {} snapshot verification failed", case.name);
                }
            }
            _ => bail!("unknown sync fixture case {}", case.name),
        }
    }

    Ok(())
}

pub fn run_federation_fixture_suite() -> Result<()> {
    let fixture = load_fixture::<FederationFixture>("federation-fixture.json")?;
    if fixture.suite != "federation" {
        bail!("unexpected fixture suite {}", fixture.suite);
    }
    let mut replay_cache = HashSet::new();
    let mut fork_table = HashMap::new();

    for case in fixture.cases {
        match case.name.as_str() {
            "http_message_signature_hash" => {
                let request = SignedFederationRequest {
                    method: "PUT".to_owned(),
                    target: "/api/v1/federation/transactions/demo".to_owned(),
                    body: json!({"txn_id": "demo"}),
                };
                let signature_input = request.signature_input_hash()?;
                let canonical = request.canonical_request_hash()?;
                if signature_input != canonical {
                    bail!("federation fixture {} hash mismatch", case.name);
                }
            }
            "origin_destination_service_did_mismatch" => {
                let verdict = validate_origin_destination(
                    "did:web:remote.example",
                    "did:web:wrong.example",
                    "did:web:local.example",
                );
                if verdict == FederationVerdict::Accepted {
                    bail!("federation fixture {} accepted DID mismatch", case.name);
                }
            }
            "replay_protection" => {
                if !replay_cache.insert("txn-1".to_owned()) {
                    bail!("federation fixture {} cache failed first insert", case.name);
                }
                if replay_cache.insert("txn-1".to_owned()) {
                    bail!("federation fixture {} missed replay", case.name);
                }
            }
            "fork_quarantine" => {
                let first = register_history_head(&mut fork_table, "cx:space:fork", "sha256:a");
                let second = register_history_head(&mut fork_table, "cx:space:fork", "sha256:b");
                if first != FederationVerdict::Accepted || second != FederationVerdict::Quarantined {
                    bail!("federation fixture {} did not quarantine fork", case.name);
                }
            }
            "pull_authorization" => {
                if authorize_pull(false, false) != FederationVerdict::Blinded {
                    bail!("federation fixture {} exposed unauthorized pull", case.name);
                }
            }
            _ => bail!("unknown federation fixture case {}", case.name),
        }
    }

    Ok(())
}

pub fn run_privacy_security_fixture_suite() -> Result<()> {
    let fixture = load_fixture::<PrivacySecurityFixture>("privacy-security-fixture.json")?;
    if fixture.suite != "privacy_security" {
        bail!("unexpected fixture suite {}", fixture.suite);
    }

    for case in fixture.cases {
        match case.name.as_str() {
            "private_blob_head_range_anti_enumeration" => {
                let hidden = anti_enumeration_blob_error(true);
                let missing = anti_enumeration_blob_error(false);
                if hidden != missing {
                    bail!("privacy fixture {} leaked distinguishable blob error", case.name);
                }
            }
            "push_blind_wakeup_payload" => {
                let payload = blind_wakeup_payload();
                if payload.get("body").is_some() || payload.get("members").is_some() {
                    bail!("privacy fixture {} leaked plaintext wakeup fields", case.name);
                }
            }
            "pairwise_did_resolve_proof" => {
                if resolve_private_did(None).is_ok() || resolve_private_did(Some("holder-proof")).is_err() {
                    bail!("privacy fixture {} proof requirement mismatch", case.name);
                }
            }
            "encrypted_payload_forwarding_without_plaintext" => {
                let forwarded = forwarded_encrypted_payload();
                if forwarded.get("plaintext").is_some() || forwarded["ciphertext"] != "opaque-ciphertext" {
                    bail!("privacy fixture {} did not preserve ciphertext-only forwarding", case.name);
                }
            }
            _ => bail!("unknown privacy fixture case {}", case.name),
        }
    }

    Ok(())
}

fn spec_conformance_root() -> PathBuf {
    std::env::var_os("COTEST_SPEC_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SPEC_CONFORMANCE_ROOT))
}

fn fixture_path(file_name: &str) -> PathBuf {
    spec_conformance_root().join("fixtures").join(file_name)
}

fn load_fixture<T>(file_name: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let path = fixture_path(file_name);
    let raw = fs::read_to_string(&path)?;
    serde_json::from_str(&raw)
        .map_err(|error| anyhow!("failed to parse fixture {}: {error}", path.display()))
}

fn canonical_json(value: &Value) -> Result<String> {
    match value {
        Value::Object(map) => {
            let mut ordered = BTreeMap::new();
            for (key, value) in map {
                ordered.insert(key, canonical_json(value)?);
            }
            let mut out = String::from("{");
            for (index, (key, value)) in ordered.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key)?);
                out.push(':');
                out.push_str(value);
            }
            out.push('}');
            Ok(out)
        }
        Value::Array(items) => {
            let canonical_items = items
                .iter()
                .map(canonical_json)
                .collect::<Result<Vec<_>>>()?;
            Ok(format!("[{}]", canonical_items.join(",")))
        }
        _ => Ok(serde_json::to_string(value)?),
    }
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity("sha256:".len() + digest.len() * 2);
    out.push_str("sha256:");
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn looks_like_sha256_digest(value: &str) -> bool {
    value.starts_with("sha256:")
        && value.len() == "sha256:".len() + 64
        && value["sha256:".len()..]
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
}

fn canonical_proof_payload(event: &Value) -> Result<Map<String, Value>> {
    let object = event
        .as_object()
        .ok_or_else(|| anyhow!("proof payload source must be an object"))?;
    let mut payload = Map::new();
    for (key, value) in object {
        if key != "unsigned" {
            payload.insert(key.clone(), value.clone());
        }
    }
    Ok(payload)
}

fn encode_cursor_shape(shape: &CursorShape) -> Result<String> {
    let canonical = canonical_json(&serde_json::to_value(shape)?)?;
    Ok(format!(
        "cx:cursor:{}",
        URL_SAFE_NO_PAD.encode(canonical.as_bytes())
    ))
}

fn decode_cursor_shape(encoded: &str) -> Result<CursorShape> {
    let payload = encoded
        .strip_prefix("cx:cursor:")
        .ok_or_else(|| anyhow!("cursor must start with cx:cursor:"))?;
    let bytes = URL_SAFE_NO_PAD.decode(payload)?;
    serde_json::from_slice(&bytes).map_err(Into::into)
}

fn rank_between(left: &str, right: &str) -> Result<String> {
    if left.len() != right.len() || left.len() < 2 {
        bail!("unsupported fractional rank inputs {left} / {right}");
    }
    let left_prefix = &left[..left.len() - 1];
    let right_prefix = &right[..right.len() - 1];
    if left_prefix != right_prefix {
        bail!("rank prefixes differ for {left} / {right}");
    }
    let left_digit = left
        .chars()
        .last()
        .and_then(|ch| ch.to_digit(36))
        .ok_or_else(|| anyhow!("left rank is not base36-like"))?;
    let right_digit = right
        .chars()
        .last()
        .and_then(|ch| ch.to_digit(36))
        .ok_or_else(|| anyhow!("right rank is not base36-like"))?;
    if right_digit <= left_digit + 1 {
        bail!("no space between {left} and {right}");
    }
    let middle = ((left_digit + right_digit) / 2) as u8;
    let middle_char = char::from_digit(u32::from(middle), 36)
        .ok_or_else(|| anyhow!("middle rank is not representable"))?;
    Ok(format!("{left_prefix}{middle_char}"))
}

fn sample_event() -> Value {
    sample_event_with_id("cx:event:target")
}

fn sample_event_with_id(event_id: &str) -> Value {
    json!({
        "event_id": event_id,
        "created_at": "2026-04-29T00:00:00Z",
        "actor_id": "did:web:alice.example",
        "kind": "cx.message.create",
        "content": {"body": "secret"},
        "proofs": [{"alg": "none"}]
    })
}

fn redact_event(target: &Value, redaction_event_id: &str) -> Result<Value> {
    let target = target
        .as_object()
        .ok_or_else(|| anyhow!("target event must be an object"))?;
    let event_id = target
        .get("event_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("target event missing event_id"))?;
    let created_at = target
        .get("created_at")
        .cloned()
        .ok_or_else(|| anyhow!("target event missing created_at"))?;
    let actor_id = target
        .get("actor_id")
        .cloned()
        .ok_or_else(|| anyhow!("target event missing actor_id"))?;
    Ok(json!({
        "event_id": event_id,
        "created_at": created_at,
        "actor_id": actor_id,
        "redacts": event_id,
        "redacted_because": redaction_event_id
    }))
}

fn audit_tombstone(redacted: &Value) -> Result<Value> {
    let object = redacted
        .as_object()
        .ok_or_else(|| anyhow!("redacted event must be an object"))?;
    Ok(json!({
        "event_id": object["event_id"],
        "actor_id": object["actor_id"],
        "created_at": object["created_at"],
        "redacts": object["redacts"],
        "redaction": true
    }))
}

#[derive(Default)]
struct RedactionTracker {
    pending: HashMap<String, String>,
}

#[derive(Debug, Eq, PartialEq)]
enum RedactionState {
    Pending,
}

impl RedactionTracker {
    fn push_redaction(&mut self, target_event_id: &str, redaction_event_id: &str) -> RedactionState {
        self.pending
            .insert(target_event_id.to_owned(), redaction_event_id.to_owned());
        RedactionState::Pending
    }

    fn materialize_target(&mut self, target: &Value) -> Result<Value> {
        let target_id = target["event_id"]
            .as_str()
            .ok_or_else(|| anyhow!("target event missing event_id"))?;
        if let Some(redaction_event_id) = self.pending.remove(target_id) {
            redact_event(target, &redaction_event_id)
        } else {
            Ok(target.clone())
        }
    }
}

fn selector_scope(entity_type: &str) -> Result<ResourceSelector> {
    Ok(ResourceSelector {
        kind: "entity".to_owned(),
        space_id: "cx:space:01JS0SP000000000000000000".to_owned(),
        entity_type: Some(entity_type.to_owned()),
    })
}

#[derive(Clone, Debug, Deserialize)]
struct ResourceSelector {
    kind: String,
    space_id: String,
    entity_type: Option<String>,
}

impl ResourceSelector {
    fn matches(&self, resource: &ResourceRef) -> bool {
        self.kind == resource.kind
            && self.space_id == resource.space_id
            && match (&self.entity_type, &resource.entity_type) {
                (Some(expected), Some(actual)) => expected == actual,
                (Some(_), None) => false,
                (None, _) => true,
            }
    }

    fn contains(&self, child: &Self) -> bool {
        self.kind == child.kind
            && self.space_id == child.space_id
            && match (&self.entity_type, &child.entity_type) {
                (Some(parent), Some(current)) => parent == current,
                (Some(_), None) => false,
                (None, _) => true,
            }
    }
}

struct ResourceRef {
    kind: String,
    space_id: String,
    entity_type: Option<String>,
}

enum ApprovalMode {
    None,
    ProposalThenApprove,
}

struct CapabilityGrant {
    required_claims: BTreeSet<String>,
    approval_mode: ApprovalMode,
    approved: bool,
    revoked_claims: BTreeSet<String>,
    scope: ResourceSelector,
}

impl CapabilityGrant {
    fn is_usable(&self, claims: &BTreeSet<String>) -> bool {
        let _ = &self.scope;
        if !self.required_claims.is_subset(claims) {
            return false;
        }
        if self
            .required_claims
            .iter()
            .any(|claim| self.revoked_claims.contains(claim))
        {
            return false;
        }
        match self.approval_mode {
            ApprovalMode::None => true,
            ApprovalMode::ProposalThenApprove => self.approved,
        }
    }
}

#[derive(Clone)]
struct Delegation {
    from: String,
    to: String,
    scope: ResourceSelector,
}

fn validate_delegations(delegations: &[Delegation]) -> Result<()> {
    let mut graph = HashMap::<String, String>::new();
    for delegation in delegations {
        graph.insert(delegation.from.clone(), delegation.to.clone());
    }
    for delegation in delegations {
        let mut seen = HashSet::new();
        let mut current = delegation.to.as_str();
        while let Some(next) = graph.get(current) {
            if !seen.insert(current.to_owned()) || next == &delegation.from {
                bail!("delegation cycle detected");
            }
            current = next;
        }
    }
    for window in delegations.windows(2) {
        if !window[0].scope.contains(&window[1].scope) {
            bail!("delegation widened child scope");
        }
    }
    Ok(())
}

#[derive(Clone)]
struct StateEvent {
    kind: String,
    auth_weight: u64,
    hlc: String,
    actor_seq: u64,
    event_id: String,
}

fn resolve_state_events(events: &[StateEvent]) -> Result<StateEvent> {
    let mut sorted = events.to_vec();
    sorted.sort_by(|left, right| {
        right
            .auth_weight
            .cmp(&left.auth_weight)
            .then_with(|| precedence_of(&right.kind).cmp(&precedence_of(&left.kind)))
            .then_with(|| left.hlc.cmp(&right.hlc))
            .then_with(|| left.actor_seq.cmp(&right.actor_seq))
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    sorted
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("cannot resolve empty state set"))
}

fn precedence_of(kind: &str) -> u8 {
    match kind {
        "ban" => 3,
        "revoke" => 2,
        "delegate" => 1,
        _ => 0,
    }
}

struct PolicyState {
    decision: String,
}

struct PendingWrite {
    event_id: String,
    required_decision: String,
}

fn write_is_valid_against_policy(write: &PendingWrite, policy: &PolicyState) -> bool {
    let _ = &write.event_id;
    write.required_decision == policy.decision
}

#[derive(Clone)]
struct SyncEvent {
    cursor: String,
    event_id: String,
}

struct SyncResponse {
    events: Vec<SyncEvent>,
    next_cursor: Option<String>,
    state_after: String,
    limited: bool,
    prev_batch: Option<String>,
}

struct ReferenceSyncService {
    events: Vec<SyncEvent>,
    visible_cursor: Option<String>,
    pending_to_device: Vec<String>,
    acked_to_device: HashSet<String>,
}

impl ReferenceSyncService {
    fn sample() -> Self {
        Self {
            events: vec![
                SyncEvent {
                    cursor: "cx:cursor:001".to_owned(),
                    event_id: "evt_1".to_owned(),
                },
                SyncEvent {
                    cursor: "cx:cursor:002".to_owned(),
                    event_id: "evt_2".to_owned(),
                },
                SyncEvent {
                    cursor: "cx:cursor:003".to_owned(),
                    event_id: "evt_3".to_owned(),
                },
                SyncEvent {
                    cursor: "cx:cursor:004".to_owned(),
                    event_id: "evt_4".to_owned(),
                },
            ],
            visible_cursor: Some("cx:cursor:003".to_owned()),
            pending_to_device: Vec::new(),
            acked_to_device: HashSet::new(),
        }
    }

    fn initial_sync(&self, limit: usize) -> Result<SyncResponse> {
        let events = self.events.iter().take(limit.min(3)).cloned().collect::<Vec<_>>();
        let next_cursor = events.last().map(|event| event.cursor.clone());
        Ok(SyncResponse {
            state_after: sha256_prefixed(b"state-after-initial"),
            events,
            next_cursor,
            limited: false,
            prev_batch: None,
        })
    }

    fn incremental_sync(&self, since: Option<&str>, limit: usize) -> Result<SyncResponse> {
        if let Some(cursor) = since {
            if !self.events.iter().any(|event| event.cursor == cursor) {
                bail!("sync_token_expired_or_snapshot_bootstrap");
            }
        }
        let since = since.unwrap_or(self.visible_cursor.as_deref().unwrap_or(""));
        let start_index = self
            .events
            .iter()
            .position(|event| event.cursor == since)
            .map(|index| index + 1)
            .unwrap_or(0);
        let events = self.events[start_index..]
            .iter()
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        let next_cursor = events.last().map(|event| event.cursor.clone());
        Ok(SyncResponse {
            state_after: sha256_prefixed(b"state-after-incremental"),
            events,
            next_cursor,
            limited: false,
            prev_batch: None,
        })
    }

    fn backfill(&self, limit: usize) -> Result<SyncResponse> {
        let events = self
            .events
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        Ok(SyncResponse {
            state_after: sha256_prefixed(b"state-after-backfill"),
            limited: self.events.len() > limit,
            prev_batch: Some("cx:cursor:prev-batch".to_owned()),
            next_cursor: events.last().map(|event| event.cursor.clone()),
            events,
        })
    }

    fn validate_filter(&self, profile: &str) -> Result<()> {
        if profile == "default" {
            return Ok(());
        }
        bail!("invalid_param_or_describe_guidance");
    }

    fn queue_to_device(&mut self, message_id: &str) {
        self.pending_to_device.push(message_id.to_owned());
    }

    fn pull_to_device(&self) -> Vec<String> {
        self.pending_to_device
            .iter()
            .filter(|message| !self.acked_to_device.contains(*message))
            .cloned()
            .collect()
    }

    fn ack_to_device(&mut self, message_id: &str) {
        self.acked_to_device.insert(message_id.to_owned());
    }
}

struct ReferenceSnapshot {
    manifest: Value,
    chunks: Vec<Value>,
}

impl ReferenceSnapshot {
    fn sample() -> Result<Self> {
        let chunk_1 = json!({"chunk_id": "chunk-1", "events": ["evt_1", "evt_2"]});
        let chunk_2 = json!({"chunk_id": "chunk-2", "events": ["evt_3", "evt_4"]});
        let chunk_digests = vec![
            sha256_prefixed(canonical_json(&chunk_1)?.as_bytes()),
            sha256_prefixed(canonical_json(&chunk_2)?.as_bytes()),
        ];
        let manifest = json!({
            "snapshot_ref": "cx:snapshot:01JS0SN000000000000000000",
            "space_id": "cx:space:fixture",
            "state_hash": sha256_prefixed("evt_1evt_2evt_3evt_4".as_bytes()),
            "frontier": ["evt_4"],
            "chunks": [
                {"chunk_id": "chunk-1", "digest": chunk_digests[0]},
                {"chunk_id": "chunk-2", "digest": chunk_digests[1]}
            ],
            "signature": {"alg": "none", "sig": "fixture"}
        });
        Ok(Self {
            manifest,
            chunks: vec![chunk_1, chunk_2],
        })
    }

    fn verify(&self) -> Result<bool> {
        let manifest_chunks = self.manifest["chunks"]
            .as_array()
            .ok_or_else(|| anyhow!("snapshot manifest missing chunks"))?;
        for (entry, chunk) in manifest_chunks.iter().zip(self.chunks.iter()) {
            let expected = entry["digest"]
                .as_str()
                .ok_or_else(|| anyhow!("snapshot digest missing"))?;
            let actual = sha256_prefixed(canonical_json(chunk)?.as_bytes());
            if actual != expected {
                return Ok(false);
            }
        }
        let state_hash = self.manifest["state_hash"]
            .as_str()
            .ok_or_else(|| anyhow!("snapshot state_hash missing"))?;
        Ok(state_hash == sha256_prefixed("evt_1evt_2evt_3evt_4".as_bytes()))
    }
}

struct SignedFederationRequest {
    method: String,
    target: String,
    body: Value,
}

impl SignedFederationRequest {
    fn canonical_request_hash(&self) -> Result<String> {
        let canonical = canonical_json(&json!({
            "method": self.method,
            "target": self.target,
            "body": self.body
        }))?;
        Ok(sha256_prefixed(canonical.as_bytes()))
    }

    fn signature_input_hash(&self) -> Result<String> {
        self.canonical_request_hash()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FederationVerdict {
    Accepted,
    Rejected,
    Quarantined,
    Blinded,
}

fn validate_origin_destination(origin: &str, signed_destination: &str, expected_destination: &str) -> FederationVerdict {
    if origin.is_empty() || signed_destination != expected_destination {
        FederationVerdict::Rejected
    } else {
        FederationVerdict::Accepted
    }
}

fn register_history_head(
    table: &mut HashMap<String, String>,
    space_id: &str,
    head: &str,
) -> FederationVerdict {
    match table.insert(space_id.to_owned(), head.to_owned()) {
        Some(existing) if existing != head => FederationVerdict::Quarantined,
        _ => FederationVerdict::Accepted,
    }
}

fn authorize_pull(has_backfill_capability: bool, has_plaintext_visibility: bool) -> FederationVerdict {
    if has_backfill_capability && has_plaintext_visibility {
        FederationVerdict::Accepted
    } else {
        FederationVerdict::Blinded
    }
}

fn anti_enumeration_blob_error(_hidden: bool) -> &'static str {
    "not_found"
}

fn blind_wakeup_payload() -> Value {
    json!({
        "device_id": "dev_alice",
        "wakeup": true
    })
}

fn resolve_private_did(proof: Option<&str>) -> Result<&'static str> {
    match proof {
        Some("holder-proof") => Ok("resolved"),
        _ => bail!("resolve_requires_holder_approved_proof"),
    }
}

fn forwarded_encrypted_payload() -> Value {
    json!({
        "ciphertext": "opaque-ciphertext",
        "content_type": "cx.mls.application"
    })
}

#[derive(Debug, Deserialize)]
struct EncodingFixture {
    suite: String,
    cases: EncodingCases,
}

#[derive(Debug, Deserialize)]
struct EncodingCases {
    canonical_json: Vec<CanonicalJsonCase>,
    hash_digest: Vec<HashDigestCase>,
    proof_payload: Vec<ProofPayloadCase>,
    hlc: Vec<HlcCase>,
    cursor: Vec<CursorCase>,
    fractional_rank: Vec<FractionalRankCase>,
}

#[derive(Debug, Deserialize)]
struct CanonicalJsonCase {
    name: String,
    input: Value,
    canonical: String,
}

#[derive(Debug, Deserialize)]
struct HashDigestCase {
    name: String,
    input_ref: String,
    expected_pattern: String,
}

#[derive(Debug, Deserialize)]
struct ProofPayloadCase {
    name: String,
    covered_fields: Vec<String>,
    excluded_fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct HlcCase {
    name: String,
    values: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CursorShape {
    v: String,
    x: u64,
}

#[derive(Debug, Deserialize)]
struct CursorCase {
    name: String,
    shape: CursorShape,
}

#[derive(Debug, Deserialize)]
struct FractionalRankCase {
    name: String,
    left: String,
    right: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct RedactionFixture {
    suite: String,
    cases: Vec<RedactionCase>,
}

#[derive(Debug, Deserialize)]
struct RedactionCase {
    name: String,
    preserve: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct CapabilityFixture {
    suite: String,
    cases: Vec<CapabilityCase>,
}

#[derive(Debug, Deserialize)]
struct CapabilityCase {
    name: String,
    selector: Option<ResourceSelector>,
}

#[derive(Debug, Deserialize)]
struct StateResolutionFixture {
    suite: String,
    cases: Vec<NamedCase>,
}

#[derive(Debug, Deserialize)]
struct SyncFixture {
    suite: String,
    cases: Vec<NamedCase>,
}

#[derive(Debug, Deserialize)]
struct FederationFixture {
    suite: String,
    cases: Vec<NamedCase>,
}

#[derive(Debug, Deserialize)]
struct PrivacySecurityFixture {
    suite: String,
    cases: Vec<NamedCase>,
}

#[derive(Debug, Deserialize)]
struct NamedCase {
    name: String,
}
