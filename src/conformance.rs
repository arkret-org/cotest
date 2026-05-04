use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs,
    path::PathBuf,
};

use anyhow::{Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

const ARTIFACT_REGISTRY_DIR: &str = "registry";
const ARTIFACT_FIXTURES_DIR: &str = "fixtures";

#[derive(Clone, Debug)]
struct RegistryManifestEntry {
    kind: String,
    source_role: String,
    source_of_truth: bool,
    generated_from: Option<String>,
}

pub fn run_artifact_registry_suite() -> Result<()> {
    let root = spec_artifacts_root();
    let registry_manifest = load_artifact_json("registry/registry-manifest.json")?;
    let schema_registry = load_artifact_json("registry/schema-registry.json")?;
    let event_kind_registry = load_artifact_json("registry/event-kind-registry.json")?;
    let operation_registry = load_artifact_json("registry/operation-registry.json")?;
    let id_kind_registry = load_artifact_json("registry/id-kind-registry.json")?;
    let conformance_profiles = load_artifact_json("profiles/conformance-profiles.json")?;
    let openapi = load_artifact_yaml("openapi/contrix-service-api.openapi.yaml")?;
    let non_http_bindings = load_artifact_yaml("bindings/non-http-bindings.yaml")?;
    let registry_entries = validate_registry_manifest(&root, &registry_manifest)?;

    let schema_ids = validate_schema_registry(
        &root,
        &schema_registry,
        registry_manifest_entry(&registry_entries, "registry/schema-registry.json")?,
    )?;
    let event_kinds = validate_event_kind_registry(
        &root,
        &event_kind_registry,
        registry_manifest_entry(&registry_entries, "registry/event-kind-registry.json")?,
    )?;
    let operation_ids = validate_operation_registry(
        &operation_registry,
        registry_manifest_entry(&registry_entries, "registry/operation-registry.json")?,
    )?;
    let id_kinds = validate_id_kind_registry(
        &id_kind_registry,
        registry_manifest_entry(&registry_entries, "registry/id-kind-registry.json")?,
    )?;
    let profiles = validate_profile_registry(&conformance_profiles)?;
    validate_profile_requirements(
        &root,
        &conformance_profiles,
        &profiles,
        &event_kinds,
        &operation_ids,
        &schema_ids,
    )?;
    validate_openapi_operation_refs(&openapi, &operation_ids)?;
    validate_non_http_binding_refs(&non_http_bindings, &operation_ids)?;

    validate_fixture_artifact_refs(
        &root,
        &profiles,
        &event_kinds,
        &operation_ids,
        &id_kinds,
        &schema_ids,
    )?;

    Ok(())
}

pub fn run_encoding_fixture_suite() -> Result<()> {
    let value = load_fixture_value("encoding-fixture.json")?;
    if value.get("suite").is_none() {
        return run_encoding_artifact_suite(&value);
    }
    let fixture: EncodingFixture = parse_fixture_value("encoding-fixture.json", value)?;
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
            bail!(
                "encoding fixture {} pattern drifted to {}",
                case.name,
                case.expected_pattern
            );
        }
        if !looks_like_sha256_digest(&digest) {
            bail!(
                "encoding fixture {} produced invalid digest {}",
                case.name,
                digest
            );
        }
        if digest == sha256_prefixed(b"") {
            bail!(
                "encoding fixture {} digest collapsed to empty input",
                case.name
            );
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
                bail!(
                    "encoding fixture {} missing covered field {}",
                    case.name,
                    field
                );
            }
        }
        for field in case.excluded_fields {
            if payload.get(&field).is_some() {
                bail!(
                    "encoding fixture {} leaked excluded field {}",
                    case.name,
                    field
                );
            }
        }
    }

    for case in fixture.cases.hlc {
        for pair in case.values.windows(2) {
            if pair[0] >= pair[1] {
                bail!(
                    "encoding fixture {} is not lexicographically increasing",
                    case.name
                );
            }
        }
    }

    for case in fixture.cases.cursor {
        let encoded = encode_cursor_shape(&case.shape)?;
        if !encoded.starts_with("cx:cursor:") {
            bail!(
                "encoding fixture {} did not produce cx:cursor prefix",
                case.name
            );
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
        match case.name.as_str() {
            "rank_between"
            | "rank_between_start"
            | "rank_between_end"
            | "rank_dense_insert_extends" => {
                let expected = case.expected.as_deref().ok_or_else(|| {
                    anyhow!("encoding fixture {} missing expected rank", case.name)
                })?;
                let actual = rank_between(case.left.as_deref(), case.right.as_deref())?;
                if actual != expected {
                    bail!(
                        "encoding fixture {} expected rank {}, got {}",
                        case.name,
                        expected,
                        actual
                    );
                }
            }
            "rebalance_assignments_three_items" => {
                let edges = case.ordered_edges.as_deref().ok_or_else(|| {
                    anyhow!("encoding fixture {} missing ordered_edges", case.name)
                })?;
                let expected = case.expected_assignments.as_deref().ok_or_else(|| {
                    anyhow!(
                        "encoding fixture {} missing expected_assignments",
                        case.name
                    )
                })?;
                let actual = rebalance_assignments(edges)?;
                if actual != expected {
                    bail!(
                        "encoding fixture {} rank rebalance assignments differed",
                        case.name
                    );
                }
            }
            "rebalance_reject_partial_assignment" => {
                let active = case.active_edge_count.ok_or_else(|| {
                    anyhow!("encoding fixture {} missing active_edge_count", case.name)
                })?;
                let assignments = case.assignment_count.ok_or_else(|| {
                    anyhow!("encoding fixture {} missing assignment_count", case.name)
                })?;
                if validate_rebalance_assignment_count(active, assignments).is_ok() {
                    bail!(
                        "encoding fixture {} accepted partial rebalance assignment",
                        case.name
                    );
                }
            }
            "rank_reject_invalid_character" => {
                let input = case
                    .input
                    .as_deref()
                    .ok_or_else(|| anyhow!("encoding fixture {} missing input", case.name))?;
                if validate_rank(input, RANK_MAX_LENGTH).is_ok() {
                    bail!(
                        "encoding fixture {} accepted invalid rank character",
                        case.name
                    );
                }
            }
            "rank_reject_too_long" => {
                let max_length = case
                    .max_length
                    .ok_or_else(|| anyhow!("encoding fixture {} missing max_length", case.name))?;
                let too_long = "0".repeat(max_length + 1);
                if validate_rank(&too_long, max_length).is_ok() {
                    bail!("encoding fixture {} accepted overlong rank", case.name);
                }
            }
            _ => bail!("unknown fractional rank fixture case {}", case.name),
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
                let materialized =
                    tracker.materialize_target(&sample_event_with_id("cx:event:late"))?;
                if materialized.get("content").is_some() {
                    bail!(
                        "redaction fixture {} failed to materialize as redacted",
                        case.name
                    );
                }
                if materialized["redacted_because"] != "cx:event:redaction" {
                    bail!("redaction fixture {} lost redaction reference", case.name);
                }
            }
            "audit_visibility" => {
                let redacted = redact_event(&target, "cx:event:redaction")?;
                let audit = audit_tombstone(&redacted)?;
                if audit.get("content").is_some() {
                    bail!(
                        "redaction fixture {} leaked content to audit view",
                        case.name
                    );
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
    let value = load_fixture_value("capability-fixture.json")?;
    if value.get("suite").is_none() {
        return run_capability_artifact_suite(&value);
    }
    let fixture: CapabilityFixture = parse_fixture_value("capability-fixture.json", value)?;
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
                    bail!(
                        "capability fixture {} allowed unapproved proposal",
                        case.name
                    );
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
                    bail!(
                        "capability fixture {} allowed widened child scope",
                        case.name
                    );
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

pub fn run_event_envelope_fixture_suite() -> Result<()> {
    let event_kind_registry = load_artifact_json("registry/event-kind-registry.json")?;
    let event_kinds = event_kind_metadata(&event_kind_registry)?;

    let crypto_fixture = load_fixture_value("crypto-signature-fixture.json")?;
    validate_profile(&crypto_fixture, "cx.profile.crypto_signature_vectors.v1")?;
    for vector in crypto_fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("crypto signature fixture missing vectors"))?
    {
        validate_crypto_signature_event_vector(vector, &event_kinds)?;
    }

    let negative_fixture = load_fixture_value("event-envelope-negative-fixture.json")?;
    for case in negative_fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event envelope negative fixture missing cases"))?
    {
        validate_event_envelope_negative_case(case, &event_kinds)?;
    }
    validate_synthetic_event_envelope_negatives(&event_kinds)?;

    Ok(())
}

pub fn run_deprecated_event_alias_suite() -> Result<()> {
    let event_kind_registry = load_artifact_json("registry/event-kind-registry.json")?;
    let event_kinds = event_kind_metadata(&event_kind_registry)?;
    let alias = event_kinds
        .get("cx.marker.read")
        .ok_or_else(|| anyhow!("event registry missing deprecated cx.marker.read alias"))?;
    if alias.status != "deprecated"
        || alias.wire_scope != "deprecated_alias"
        || alias.replaced_by.as_deref() != Some("cx.read.marker")
    {
        bail!("deprecated read marker alias metadata drifted");
    }

    if canonical_event_kind_for_consumer("cx.marker.read", &event_kinds) != Some("cx.read.marker") {
        bail!("consumer compatibility failed to map cx.marker.read to cx.read.marker");
    }
    if canonical_event_kind_for_consumer("cx.read.marker", &event_kinds) != Some("cx.read.marker") {
        bail!("canonical read marker kind was not stable");
    }

    let event = sample_envelope_event(
        "cx.marker.read",
        1,
        "01970e589d21-0001-a13f9c2e",
        "2026-05-02T00:00:00Z",
        json!({"event_id": "cx:event:01k9na00000000000000000000"}),
    );
    let decision = validate_event_envelope(
        &event,
        &event_kinds,
        &EventEnvelopeContext::default_for_durable_history(),
    )?;
    assert_event_decision(
        &decision,
        "reject",
        Some("schema_violation"),
        "deprecated_alias",
    )
}

pub fn run_capability_facet_fixture_suite() -> Result<()> {
    let grant = FacetGrant {
        allowed_entity_facets: BTreeSet::from(["rankable".to_owned(), "stateful".to_owned()]),
        critical: true,
    };
    let matching = EntityTarget {
        entity_type: "task".to_owned(),
        facets: Some(BTreeSet::from([
            "rankable".to_owned(),
            "renderable".to_owned(),
            "stateful".to_owned(),
        ])),
    };
    if !grant.allows(&matching) {
        bail!("capability facet suite rejected matching entity facets");
    }

    let missing_facets = EntityTarget {
        entity_type: "task".to_owned(),
        facets: None,
    };
    if grant.allows(&missing_facets) {
        bail!("capability facet suite did not fail closed for missing critical facets");
    }

    let compatibility_label_only = EntityTarget {
        entity_type: "rankable_stateful_task".to_owned(),
        facets: Some(BTreeSet::from(["renderable".to_owned()])),
    };
    if grant.allows(&compatibility_label_only) {
        bail!("capability facet suite allowed entity_type labels to satisfy facet constraints");
    }

    Ok(())
}

pub fn run_facet_renderer_query_fixture_suite() -> Result<()> {
    let request = json!({
        "projection": "collection",
        "preset": "kanban",
        "renderer": "board",
        "view_id": "cx:view:01js0vw0000000000000000000",
        "facets": ["stateful", "rankable"],
        "limit": 50
    });
    validate_query_renderer(&request)?;
    let required_facets = request_facets(&request)?;
    let entities = vec![
        json!({
            "id": "cx:entity:01js0ta0000000000000000000",
            "entity_type": "task",
            "facets": ["stateful", "rankable", "renderable"],
            "title": "Rankable task"
        }),
        json!({
            "id": "cx:entity:01js0na0000000000000000000",
            "entity_type": "note",
            "facets": ["stateful", "renderable"],
            "title": "State-only note"
        }),
    ];
    let visible = filter_entities_by_facets(&entities, &required_facets)?;
    if visible.len() != 1
        || value_field_str(&visible[0], "id")? != "cx:entity:01js0ta0000000000000000000"
    {
        bail!("facet renderer query suite did not filter by requested facets");
    }

    let response = json!({
        "projection": "collection",
        "preset": "kanban",
        "view_id": "cx:view:01js0vw0000000000000000000",
        "frontier": {"state_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "groups": [{
            "key": "todo",
            "title": "Todo",
            "source": {"model": "field_value", "field": "fields.status", "value": "todo"},
            "items": [{
                "entity": visible[0].clone(),
                "position": {"model": "field_value", "container_id": "todo", "rank": "F"}
            }],
            "next_cursor": null,
            "limited": false
        }]
    });
    validate_response_entities_against_request_facets(&response, &request, "facet_renderer_query")?;

    let invalid_renderer = json!({
        "projection": "collection",
        "preset": "kanban",
        "renderer": "table",
        "view_id": "cx:view:01js0vw0000000000000000000",
        "facets": ["stateful", "rankable"]
    });
    if validate_query_renderer(&invalid_renderer).is_ok() {
        bail!("facet renderer query suite accepted mismatched renderer");
    }

    Ok(())
}

pub fn run_projection_position_discriminator_fixture_suite() -> Result<()> {
    let positions = [
        json!({
            "model": "field_value",
            "container_id": "todo",
            "rank": "F"
        }),
        json!({
            "model": "relation_container",
            "scope_container_id": "cx:entity:01js0bd0000000000000000000",
            "container_id": "cx:entity:01js0c10000000000000000000",
            "relation_kind": "contains",
            "relation_id": "cx:relation:01js0r1000000000000000000",
            "rank": "V"
        }),
        json!({
            "model": "time_bucket",
            "start_field": "fields.starts_at",
            "bucket": "week",
            "timezone": "UTC",
            "bucket_start": "2026-04-27T00:00:00Z",
            "rank": "k"
        }),
        json!({
            "model": "matrix_cell",
            "rows_by": "fields.assignee",
            "columns_by": "fields.status",
            "row_key": "did:web:alice.example",
            "column_key": "todo",
            "rank": "F"
        }),
    ];
    for position in positions {
        validate_projection_position(&position)?;
    }

    let invalid = json!({
        "model": "relation_container",
        "container_id": "cx:entity:01js0c10000000000000000000",
        "relation_kind": "contains",
        "rank": "F"
    });
    if validate_projection_position(&invalid).is_ok() {
        bail!("projection position suite accepted incomplete relation_container position");
    }

    Ok(())
}

pub fn run_state_resolution_fixture_suite() -> Result<()> {
    let value = load_fixture_value("state-resolution-fixture.json")?;
    if value.get("suite").is_none() {
        return run_state_resolution_artifact_suite(&value);
    }
    let fixture: StateResolutionFixture =
        parse_fixture_value("state-resolution-fixture.json", value)?;
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
                    bail!(
                        "state resolution fixture {} did not fail closed on revoke",
                        case.name
                    );
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
                    bail!(
                        "state resolution fixture {} accepted stale policy",
                        case.name
                    );
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
                    bail!(
                        "state resolution fixture {} was not deterministic",
                        case.name
                    );
                }
            }
            "kanban_concurrent_card_move" | "board_concurrent_item_move" => {
                validate_container_move_resolution(&case)?
            }
            "kanban_atomic_task_move" | "board_atomic_field_position_move" => {
                validate_field_position_resolution(&case)?
            }
            "relation_rebalance_assignment" | "container_rebalance_assignment" => {
                validate_state_rebalance_assignment(&case)?
            }
            "relation_rebalance_cas_conflict" | "container_rebalance_cas_conflict" => {
                validate_state_rebalance_cas_conflict(&case)?
            }
            _ => bail!("unknown state resolution fixture case {}", case.name),
        }
    }

    Ok(())
}

pub fn run_sync_fixture_suite() -> Result<()> {
    let value = load_fixture_value("sync-fixture.json")?;
    if value.get("suite").is_none() {
        return run_sync_artifact_suite(&value);
    }
    let fixture: SyncFixture = parse_fixture_value("sync-fixture.json", value)?;
    if fixture.suite != "sync" {
        bail!("unexpected fixture suite {}", fixture.suite);
    }
    let mut service = ReferenceSyncService::sample();

    for case in fixture.cases {
        match case.name.as_str() {
            "initial_sync" => {
                let response = service.initial_sync(10)?;
                if response.events.len() != 3 || response.next_cursor.is_none() {
                    bail!(
                        "sync fixture {} did not return full visible state",
                        case.name
                    );
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
                    _ => bail!(
                        "sync fixture {} did not reject mismatched filter",
                        case.name
                    ),
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
            "kanban_projection_column_pagination" | "board_projection_group_pagination" => {
                validate_kanban_column_pagination(&case)?
            }
            "kanban_projection_hidden_counts" | "board_projection_hidden_counts" => {
                validate_kanban_hidden_counts(&case)?
            }
            "row_projection_contract" => {
                validate_projection_contract(&case, "collection", "table")?
            }
            "timeline_projection_contract" => {
                validate_projection_contract(&case, "timeline", "chat")?
            }
            "graph_projection_contract" => validate_projection_contract(&case, "graph", "graph")?,
            "document_projection_contract" => {
                validate_projection_contract(&case, "document", "document")?
            }
            "composite_projection_contract" => {
                validate_projection_contract(&case, "composite", "dashboard")?
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
                if first != FederationVerdict::Accepted || second != FederationVerdict::Quarantined
                {
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
    let value = load_fixture_value("privacy-security-fixture.json")?;
    let fixture: PrivacySecurityFixture =
        parse_fixture_value("privacy-security-fixture.json", value)?;
    if fixture.suite != "privacy_security" {
        bail!("unexpected fixture suite {}", fixture.suite);
    }

    for case in fixture.cases {
        match case.name.as_str() {
            "private_blob_head_range_anti_enumeration" => {
                let hidden = anti_enumeration_blob_error(true);
                let missing = anti_enumeration_blob_error(false);
                if hidden != missing {
                    bail!(
                        "privacy fixture {} leaked distinguishable blob error",
                        case.name
                    );
                }
            }
            "push_blind_wakeup_payload" => {
                let payload = blind_wakeup_payload();
                if payload.get("body").is_some() || payload.get("members").is_some() {
                    bail!(
                        "privacy fixture {} leaked plaintext wakeup fields",
                        case.name
                    );
                }
            }
            "hidden_space_resolve_indistinguishable" => {
                if case.operation_id.as_deref() != Some("cx.directory.resolve_space")
                    || case
                        .expected
                        .as_ref()
                        .and_then(|expected| expected.get("same_http_status"))
                        .and_then(Value::as_u64)
                        != Some(404)
                {
                    bail!(
                        "privacy fixture {} no longer proves indistinguishable resolve errors",
                        case.name
                    );
                }
            }
            "private_contact_discovery_padding_and_cardinality" => {
                let input = case
                    .input
                    .as_ref()
                    .ok_or_else(|| anyhow!("privacy fixture {} missing input", case.name))?;
                let contact_count = input
                    .get("contacts")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                let target_batch_size = input
                    .pointer("/padding/target_batch_size")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("privacy fixture {} missing target batch", case.name))?;
                if target_batch_size <= contact_count as u64 {
                    bail!(
                        "privacy fixture {} does not pad contact discovery",
                        case.name
                    );
                }
            }
            "plaintext_visible_service_required_for_private_body_processing" => {
                let expected = case
                    .expected
                    .as_ref()
                    .ok_or_else(|| anyhow!("privacy fixture {} missing expected", case.name))?;
                if expected.get("decision").and_then(Value::as_str) != Some("deny")
                    || expected
                        .get("must_not_forward_plaintext")
                        .and_then(Value::as_bool)
                        != Some(true)
                {
                    bail!(
                        "privacy fixture {} no longer denies unauthorized plaintext processing",
                        case.name
                    );
                }
            }
            "pairwise_did_resolve_proof" => {
                if resolve_private_did(None).is_ok()
                    || resolve_private_did(Some("holder-proof")).is_err()
                {
                    bail!("privacy fixture {} proof requirement mismatch", case.name);
                }
            }
            "encrypted_payload_forwarding_without_plaintext" => {
                let forwarded = forwarded_encrypted_payload();
                if forwarded.get("plaintext").is_some()
                    || forwarded["ciphertext"] != "opaque-ciphertext"
                {
                    bail!(
                        "privacy fixture {} did not preserve ciphertext-only forwarding",
                        case.name
                    );
                }
            }
            _ => bail!("unknown privacy fixture case {}", case.name),
        }
    }

    Ok(())
}

fn spec_artifacts_root() -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ARTIFACTS_ROOT") {
        return PathBuf::from(root);
    }

    if let Some(root) = std::env::var_os("COTEST_SPEC_ROOT") {
        let root = PathBuf::from(root);
        if root.join(ARTIFACT_REGISTRY_DIR).is_dir() {
            return root;
        }
        if root.join("artifacts").join(ARTIFACT_REGISTRY_DIR).is_dir() {
            return root.join("artifacts");
        }
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("contrix-spec")
        .join("artifacts")
}

fn fixture_path(file_name: &str) -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ROOT") {
        let root = PathBuf::from(root);
        let candidate = if root.join(ARTIFACT_FIXTURES_DIR).is_dir() {
            root.join(ARTIFACT_FIXTURES_DIR).join(file_name)
        } else {
            root.join("artifacts")
                .join(ARTIFACT_FIXTURES_DIR)
                .join(file_name)
        };
        if candidate.is_file() {
            return candidate;
        }
        let legacy = root.join("fixtures").join(file_name);
        if legacy.is_file() {
            return legacy;
        }
    }

    spec_artifacts_root()
        .join(ARTIFACT_FIXTURES_DIR)
        .join(file_name)
}

fn load_fixture<T>(file_name: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    parse_fixture_value(file_name, load_fixture_value(file_name)?)
}

fn load_fixture_value(file_name: &str) -> Result<Value> {
    let path = fixture_path(file_name);
    let raw = fs::read_to_string(&path)?;
    serde_json::from_str(&raw)
        .map_err(|error| anyhow!("failed to parse fixture {}: {error}", path.display()))
}

fn parse_fixture_value<T>(file_name: &str, value: Value) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(value)
        .map_err(|error| anyhow!("failed to parse fixture {file_name}: {error}"))
}

fn load_artifact_json(relative_path: &str) -> Result<Value> {
    let path = spec_artifacts_root().join(relative_path);
    let raw = fs::read_to_string(&path)?;
    serde_json::from_str(&raw)
        .map_err(|error| anyhow!("failed to parse artifact {}: {error}", path.display()))
}

fn load_artifact_yaml(relative_path: &str) -> Result<serde_yaml::Value> {
    let path = spec_artifacts_root().join(relative_path);
    let raw = fs::read_to_string(&path)?;
    serde_yaml::from_str(&raw)
        .map_err(|error| anyhow!("failed to parse artifact {}: {error}", path.display()))
}

fn validate_registry_manifest(
    root: &std::path::Path,
    manifest: &Value,
) -> Result<HashMap<String, RegistryManifestEntry>> {
    if manifest.get("source_of_truth").and_then(Value::as_bool) != Some(true) {
        bail!("registry-manifest must declare source_of_truth=true");
    }
    let registries = manifest
        .get("registries")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("registry-manifest missing registries"))?;
    let mut entries = HashMap::new();
    for entry in registries {
        let file = required_str(entry, "file")?;
        if !root.join(file).is_file() {
            bail!("registry-manifest references missing file {file}");
        }
        let kind = required_str(entry, "kind")?;
        let source_role = required_str(entry, "source_role")?;
        let source_of_truth = entry
            .get("source_of_truth")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("registry-manifest entry {file} missing source_of_truth"))?;
        let generated_from = entry
            .get("generated_from")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        match source_role {
            "canonical" => {
                if !source_of_truth {
                    bail!("registry-manifest canonical entry {file} must declare source_of_truth=true");
                }
                if generated_from.is_some() {
                    bail!("registry-manifest canonical entry {file} must not declare generated_from");
                }
            }
            "generated" => {
                if source_of_truth {
                    bail!("registry-manifest generated entry {file} must declare source_of_truth=false");
                }
                let generated_from = generated_from.as_deref().ok_or_else(|| {
                    anyhow!("registry-manifest generated entry {file} missing generated_from")
                })?;
                if !root.join(generated_from).is_file() {
                    bail!("registry-manifest generated entry {file} references missing source {generated_from}");
                }
            }
            other => bail!("registry-manifest entry {file} has invalid source_role {other}"),
        }
        if entries
            .insert(
                file.to_owned(),
                RegistryManifestEntry {
                    kind: kind.to_owned(),
                    source_role: source_role.to_owned(),
                    source_of_truth,
                    generated_from,
                },
            )
            .is_some()
        {
            bail!("registry-manifest duplicate file entry {file}");
        }
    }
    Ok(entries)
}

fn registry_manifest_entry<'a>(
    entries: &'a HashMap<String, RegistryManifestEntry>,
    file: &str,
) -> Result<&'a RegistryManifestEntry> {
    entries
        .get(file)
        .ok_or_else(|| anyhow!("registry-manifest missing {file}"))
}

fn validate_registry_metadata(
    registry_name: &str,
    registry: &Value,
    expected_kind: &str,
    manifest_entry: &RegistryManifestEntry,
) -> Result<()> {
    if manifest_entry.kind != expected_kind {
        bail!(
            "{registry_name} kind drifted: expected {expected_kind}, got {}",
            manifest_entry.kind
        );
    }
    let source_of_truth = registry
        .get("source_of_truth")
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("{registry_name} missing source_of_truth"))?;
    if source_of_truth != manifest_entry.source_of_truth {
        bail!(
            "{registry_name} source_of_truth drifted: expected {}, got {}",
            manifest_entry.source_of_truth,
            source_of_truth
        );
    }
    match manifest_entry.source_role.as_str() {
        "canonical" => {
            if registry.get("generated_from").is_some() {
                bail!("{registry_name} canonical registry must not declare generated_from");
            }
        }
        "generated" => {
            let generated_from = required_str(registry, "generated_from")?;
            if Some(generated_from) != manifest_entry.generated_from.as_deref() {
                bail!(
                    "{registry_name} generated_from drifted: expected {:?}, got {generated_from}",
                    manifest_entry.generated_from
                );
            }
        }
        other => bail!("{registry_name} manifest source_role drifted to {other}"),
    }
    Ok(())
}

fn validate_schema_registry(
    root: &std::path::Path,
    registry: &Value,
    manifest_entry: &RegistryManifestEntry,
) -> Result<BTreeSet<String>> {
    validate_registry_metadata("schema registry", registry, "schema_registry", manifest_entry)?;
    let schemas = registry
        .get("schemas")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("schema registry missing schemas"))?;
    let mut ids = BTreeSet::new();
    for schema in schemas {
        let schema_id = required_str(schema, "schema_id")?;
        if !schema_id.starts_with("cx.schema.") {
            bail!("schema registry contains non-standard id {schema_id}");
        }
        if !ids.insert(schema_id.to_owned()) {
            bail!("duplicate schema id {schema_id}");
        }
        let file = required_str(schema, "file")?;
        let path = root.join(file);
        if !path.is_file() {
            bail!(
                "schema registry file missing for {schema_id}: {}",
                path.display()
            );
        }
        let raw = fs::read_to_string(&path)?;
        serde_json::from_str::<Value>(&raw)
            .map_err(|error| anyhow!("schema file {} is not JSON: {error}", path.display()))?;
    }
    for required in ["cx.schema.event.v1", "cx.schema.event_payload.v1"] {
        if !ids.contains(required) {
            bail!("schema registry missing required {required}");
        }
    }
    Ok(ids)
}

fn validate_event_kind_registry(
    root: &std::path::Path,
    registry: &Value,
    manifest_entry: &RegistryManifestEntry,
) -> Result<BTreeSet<String>> {
    validate_registry_metadata(
        "event-kind registry",
        registry,
        "event_kind_registry",
        manifest_entry,
    )?;
    let envelope_schema = registry
        .pointer("/payload_schema_contract/event_envelope_schema")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("event-kind registry missing event envelope schema ref"))?;
    if !root.join(envelope_schema).is_file() {
        bail!("event envelope schema ref missing: {envelope_schema}");
    }

    let event_kinds = registry
        .get("event_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event-kind registry missing event_kinds"))?;
    let mut ids = BTreeSet::new();
    let mut deprecated = BTreeSet::new();
    for entry in event_kinds {
        let event_kind = required_str(entry, "event_kind")?;
        if !event_kind.starts_with("cx.") {
            bail!("event kind must use cx.* namespace: {event_kind}");
        }
        if !ids.insert(event_kind.to_owned()) {
            bail!("duplicate event kind {event_kind}");
        }
        let status = required_str(entry, "status")?;
        let wire_scope = required_str(entry, "wire_scope")?;
        if status == "active" && wire_scope == "deprecated_alias" {
            bail!("active event kind {event_kind} cannot be deprecated_alias");
        }
        if status == "deprecated" || wire_scope == "deprecated_alias" {
            deprecated.insert(event_kind.to_owned());
            if entry.get("replaced_by").and_then(Value::as_str).is_none() {
                bail!("deprecated event kind {event_kind} missing replaced_by");
            }
        }
    }
    for alias in deprecated {
        if !ids.contains(&alias) {
            bail!("deprecated alias set drift for {alias}");
        }
    }
    Ok(ids)
}

fn validate_operation_registry(
    registry: &Value,
    manifest_entry: &RegistryManifestEntry,
) -> Result<BTreeSet<String>> {
    validate_registry_metadata(
        "operation registry",
        registry,
        "operation_registry",
        manifest_entry,
    )?;
    let operations = registry
        .get("operations")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("operation registry missing operations"))?;
    let mut ids = BTreeSet::new();
    for entry in operations {
        let operation_id = required_str(entry, "operation_id")?;
        if !operation_id.starts_with("cx.") {
            bail!("operation id must use cx.* namespace: {operation_id}");
        }
        if !ids.insert(operation_id.to_owned()) {
            bail!("duplicate operation id {operation_id}");
        }
        for field in ["http", "grpc", "mq"] {
            required_str(entry, field)?;
        }
    }
    for required in [
        "cx.events.describe",
        "cx.events.submit",
        "cx.sync.client_sync",
    ] {
        if !ids.contains(required) {
            bail!("operation registry missing required {required}");
        }
    }
    Ok(ids)
}

fn validate_id_kind_registry(
    registry: &Value,
    manifest_entry: &RegistryManifestEntry,
) -> Result<BTreeSet<String>> {
    validate_registry_metadata(
        "id-kind registry",
        registry,
        "id_kind_registry",
        manifest_entry,
    )?;
    let mut special_kinds = BTreeSet::new();
    for form in registry
        .get("special_forms")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let kind = required_str(form, "kind")?;
        if !special_kinds.insert(kind.to_owned()) {
            bail!("duplicate special id kind {kind}");
        }
    }
    let mut regular_kinds = BTreeSet::new();
    for kind in registry
        .get("id_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("id-kind registry missing id_kinds"))?
    {
        let id_kind = required_str(kind, "kind")?;
        if !regular_kinds.insert(id_kind.to_owned()) {
            bail!("duplicate id kind {id_kind}");
        }
        let wire_form = required_str(kind, "wire_form")?;
        if !wire_form.starts_with(&format!("cx:{id_kind}:")) {
            bail!("id kind {id_kind} wire_form drifted: {wire_form}");
        }
    }
    let mut kinds = regular_kinds;
    kinds.extend(special_kinds);
    if !kinds.contains("event") {
        bail!("id-kind registry missing event");
    }
    Ok(kinds)
}

fn validate_profile_registry(registry: &Value) -> Result<BTreeSet<String>> {
    let mut profiles = BTreeSet::new();
    for field in [
        "implementation_profiles",
        "deployment_profiles",
        "hardening_profiles",
        "vector_profiles",
    ] {
        for profile in registry
            .get(field)
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("conformance profiles missing {field}"))?
        {
            let profile = profile
                .as_str()
                .ok_or_else(|| anyhow!("conformance profile entry in {field} is not a string"))?;
            if !profile.starts_with("cx.profile.") {
                bail!("invalid profile id {profile}");
            }
            profiles.insert(profile.to_owned());
        }
    }
    for required in [
        "cx.profile.core_event_store.v1",
        "cx.profile.chat_mvp.v1",
        "cx.profile.kanban_mvp.v1",
        "cx.profile.push_gateway.v1",
    ] {
        if !profiles.contains(required) {
            bail!("conformance profiles missing required {required}");
        }
    }
    Ok(profiles)
}

fn validate_profile_requirements(
    root: &std::path::Path,
    registry: &Value,
    profiles: &BTreeSet<String>,
    event_kinds: &BTreeSet<String>,
    operation_ids: &BTreeSet<String>,
    schema_ids: &BTreeSet<String>,
) -> Result<()> {
    let requirements = registry
        .get("profile_requirements")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("conformance profiles missing profile_requirements"))?;

    for profile in profiles {
        if !requirements.contains_key(profile) {
            bail!("conformance profile {profile} missing profile_requirements entry");
        }
    }

    for (profile, requirement) in requirements {
        if !profiles.contains(profile) {
            bail!("profile_requirements references unregistered profile {profile}");
        }

        for inherited in string_array_field(requirement, "inherits")? {
            if !profiles.contains(inherited) {
                bail!("{profile} inherits unknown profile {inherited}");
            }
        }
        for endpoint in string_array_field(requirement, "required_endpoints")? {
            if !operation_ids.contains(endpoint) {
                bail!("{profile} requires unknown endpoint operation {endpoint}");
            }
        }
        for event_kind in string_array_field(requirement, "required_event_kinds")? {
            if !event_kinds.contains(event_kind) {
                bail!("{profile} requires unknown event kind {event_kind}");
            }
        }
        for rejected in string_array_field(requirement, "rejected_event_kinds")? {
            if rejected.starts_with("wire_scope:") {
                continue;
            }
            if !event_kinds.contains(rejected) {
                bail!("{profile} rejects unknown event kind {rejected}");
            }
        }
        for schema_id in string_array_field(requirement, "required_schemas")? {
            if !schema_ids.contains(schema_id) {
                bail!("{profile} requires unknown schema {schema_id}");
            }
        }
        for fixture in string_array_field(requirement, "required_fixtures")? {
            if !root.join(ARTIFACT_FIXTURES_DIR).join(fixture).is_file() {
                bail!("{profile} requires missing fixture {fixture}");
            }
        }
        for extension in string_array_field(requirement, "optional_extensions")? {
            if extension.starts_with("cx.profile.") && !profiles.contains(extension) {
                bail!("{profile} references unknown optional profile {extension}");
            }
        }
        if requirement
            .pointer("/feature_discovery/required")
            .and_then(Value::as_array)
            .is_none()
        {
            bail!("{profile} missing feature_discovery.required");
        }
    }

    Ok(())
}

fn validate_openapi_operation_refs(
    openapi: &serde_yaml::Value,
    operation_ids: &BTreeSet<String>,
) -> Result<()> {
    let mut discovered = BTreeSet::new();
    collect_yaml_values_for_key(openapi, "operationId", &mut discovered);
    if discovered.is_empty() {
        bail!("OpenAPI artifact did not expose any operationId values");
    }
    for operation_id in &discovered {
        if !operation_ids.contains(operation_id) {
            bail!("OpenAPI references unknown operation id {operation_id}");
        }
    }
    for operation_id in operation_ids {
        if !discovered.contains(operation_id) {
            bail!("operation registry {operation_id} missing from OpenAPI artifact");
        }
    }
    Ok(())
}

fn validate_non_http_binding_refs(
    bindings: &serde_yaml::Value,
    operation_ids: &BTreeSet<String>,
) -> Result<()> {
    let mut discovered = BTreeSet::new();
    collect_yaml_operation_like_values(bindings, &mut discovered);
    if discovered.is_empty() {
        bail!("non-HTTP binding artifact did not expose operation refs");
    }
    for operation_id in discovered {
        if !operation_ids.contains(&operation_id) {
            bail!("non-HTTP binding references unknown operation id {operation_id}");
        }
    }
    Ok(())
}

fn collect_yaml_values_for_key(
    value: &serde_yaml::Value,
    wanted_key: &str,
    values: &mut BTreeSet<String>,
) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (key, child) in map {
                if key.as_str() == Some(wanted_key) {
                    if let Some(value) = child.as_str() {
                        values.insert(value.to_owned());
                    }
                }
                collect_yaml_values_for_key(child, wanted_key, values);
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for item in items {
                collect_yaml_values_for_key(item, wanted_key, values);
            }
        }
        _ => {}
    }
}

fn collect_yaml_operation_like_values(value: &serde_yaml::Value, values: &mut BTreeSet<String>) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            for child in map.values() {
                collect_yaml_operation_like_values(child, values);
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for item in items {
                collect_yaml_operation_like_values(item, values);
            }
        }
        serde_yaml::Value::String(text) if text.starts_with("cx.") => {
            values.insert(text.to_owned());
        }
        _ => {}
    }
}

fn string_array_field<'a>(value: &'a Value, field: &str) -> Result<Vec<&'a str>> {
    Ok(value
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| anyhow!("{field} entry must be a string"))
        })
        .collect::<Result<Vec<_>>>()?)
}

fn validate_fixture_artifact_refs(
    root: &std::path::Path,
    profiles: &BTreeSet<String>,
    event_kinds: &BTreeSet<String>,
    operation_ids: &BTreeSet<String>,
    id_kinds: &BTreeSet<String>,
    schema_ids: &BTreeSet<String>,
) -> Result<()> {
    let fixture_root = root.join(ARTIFACT_FIXTURES_DIR);
    for entry in fs::read_dir(&fixture_root)? {
        let path = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let raw = fs::read_to_string(&path)?;
        let value: Value = serde_json::from_str(&raw)
            .map_err(|error| anyhow!("fixture {} is not JSON: {error}", path.display()))?;
        if let Some(profile) = value.get("profile").and_then(Value::as_str) {
            if !profiles.contains(profile) {
                bail!(
                    "fixture {} references unknown profile {profile}",
                    path.display()
                );
            }
        }
        validate_value_refs(
            &value,
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("fixture"),
            event_kinds,
            operation_ids,
            id_kinds,
            schema_ids,
        )?;
    }
    Ok(())
}

fn validate_value_refs(
    value: &Value,
    context: &str,
    event_kinds: &BTreeSet<String>,
    operation_ids: &BTreeSet<String>,
    id_kinds: &BTreeSet<String>,
    schema_ids: &BTreeSet<String>,
) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                match (key.as_str(), child.as_str()) {
                    ("operation_id", Some(operation_id)) => {
                        if !operation_ids.contains(operation_id) {
                            bail!("{context} references unknown operation id {operation_id}");
                        }
                    }
                    ("event_kind", Some(event_kind)) => {
                        if !event_kinds.contains(event_kind) {
                            bail!("{context} references unknown event kind {event_kind}");
                        }
                    }
                    ("kind", Some(kind)) if kind.starts_with("cx.") => {
                        if !event_kinds.contains(kind) {
                            bail!("{context} references unknown event kind {kind}");
                        }
                    }
                    ("schema_id", Some(schema_id)) => {
                        if !schema_ids.contains(schema_id) {
                            bail!("{context} references unknown schema id {schema_id}");
                        }
                    }
                    _ => {}
                }
                validate_value_refs(
                    child,
                    context,
                    event_kinds,
                    operation_ids,
                    id_kinds,
                    schema_ids,
                )?;
            }
        }
        Value::Array(items) => {
            for child in items {
                validate_value_refs(
                    child,
                    context,
                    event_kinds,
                    operation_ids,
                    id_kinds,
                    schema_ids,
                )?;
            }
        }
        Value::String(text) => validate_typed_id_ref(text, context, id_kinds)?,
        _ => {}
    }
    Ok(())
}

fn validate_typed_id_ref(value: &str, context: &str, id_kinds: &BTreeSet<String>) -> Result<()> {
    let Some(rest) = value.strip_prefix("cx:") else {
        return Ok(());
    };
    let Some((kind, _tail)) = rest.split_once(':') else {
        return Ok(());
    };
    if !id_kinds.contains(kind) {
        bail!("{context} references unknown typed id kind {kind}: {value}");
    }
    Ok(())
}

fn run_encoding_artifact_suite(value: &Value) -> Result<()> {
    validate_profile(value, "cx.profile.encoding_vectors.v1")?;
    let rank_order = value
        .get("rank_order")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("encoding artifact missing rank_order"))?;
    let expected = value
        .get("expected_order")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("encoding artifact missing expected_order"))?;
    let mut sorted = rank_order.clone();
    sorted.sort_by(|left, right| {
        left.get("rank")
            .and_then(Value::as_str)
            .cmp(&right.get("rank").and_then(Value::as_str))
    });
    let actual = sorted
        .iter()
        .map(rank_order_entry_id)
        .collect::<Result<Vec<_>>>()?;
    let expected = expected
        .iter()
        .map(|entry| entry.as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    if actual != expected {
        bail!("encoding rank_order did not match expected_order");
    }
    Ok(())
}

fn rank_order_entry_id(entry: &Value) -> Result<String> {
    if let Some(value) = entry.get("flow_id").and_then(Value::as_str) {
        return Ok(value.to_owned());
    }
    bail!("encoding rank_order entry missing flow_id");
}

fn run_capability_artifact_suite(value: &Value) -> Result<()> {
    validate_profile(value, "cx.profile.capability_vectors.v1")?;
    let fixtures = value
        .get("fixtures")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("capability artifact missing fixtures"))?;
    for fixture in fixtures {
        let name = required_str(fixture, "name")?;
        if fixture.get("expected").is_none() && fixture.get("requests").is_none() {
            bail!("capability fixture {name} missing expected outcome");
        }
        if name == "approval_constraint_requires_controller_approval" {
            let requests = fixture
                .get("requests")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("approval fixture missing requests"))?;
            if !requests.iter().any(|request| {
                request
                    .pointer("/expected/decision")
                    .and_then(Value::as_str)
                    == Some("require_review")
            }) {
                bail!("approval fixture no longer requires review without proof");
            }
        }
        if name == "revoked_grant_denies_later_write"
            && fixture
                .pointer("/expected/decision")
                .and_then(Value::as_str)
                != Some("deny")
        {
            bail!("revoked grant fixture no longer denies later write");
        }
    }
    Ok(())
}

fn run_state_resolution_artifact_suite(value: &Value) -> Result<()> {
    validate_profile(value, "cx.profile.state_resolution_vectors.v1")?;
    let vectors = value
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("state resolution artifact missing vectors"))?;
    for vector in vectors {
        let name = required_str(vector, "name")?;
        if let Some(candidates) = vector.get("candidates").and_then(Value::as_array) {
            let expected = vector
                .pointer("/expected/winner_event_id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("state vector {name} missing winner_event_id"))?;
            let actual = select_state_resolution_candidate(candidates)
                .ok_or_else(|| anyhow!("state vector {name} has no selectable candidate"))?;
            if actual != expected {
                bail!("state vector {name} winner drifted: expected {expected}, got {actual}");
            }
        }
        if name == "offline_write_concurrent_with_revoke_soft_fails_when_order_unknown"
            && vector.pointer("/expected/decision").and_then(Value::as_str) != Some("soft_fail")
        {
            bail!("state vector {name} no longer soft-fails unknown revoke ordering");
        }
    }
    Ok(())
}

fn select_state_resolution_candidate(candidates: &[Value]) -> Option<&str> {
    candidates
        .iter()
        .filter(|candidate| {
            candidate.get("policy_result").and_then(Value::as_str) != Some("hard_deny")
        })
        .max_by(|left, right| compare_state_candidates(left, right))
        .and_then(|candidate| candidate.get("event_id").and_then(Value::as_str))
}

fn compare_state_candidates(left: &Value, right: &Value) -> Ordering {
    let left_weight = left
        .get("auth_weight")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    let right_weight = right
        .get("auth_weight")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    left_weight
        .cmp(&right_weight)
        .then_with(|| {
            left.get("hlc")
                .and_then(Value::as_str)
                .cmp(&right.get("hlc").and_then(Value::as_str))
        })
        .then_with(|| {
            left.get("event_id")
                .and_then(Value::as_str)
                .cmp(&right.get("event_id").and_then(Value::as_str))
        })
}

fn run_sync_artifact_suite(value: &Value) -> Result<()> {
    validate_profile(value, "cx.profile.sync_vectors.v1")?;
    if value
        .pointer("/collection_projection/frontier/state_hash")
        .and_then(Value::as_str)
        .is_none_or(|hash| !looks_like_sha256_digest(hash))
    {
        bail!("sync artifact collection projection missing state_hash");
    }
    if value
        .pointer("/room_timeline/next_cursor")
        .and_then(Value::as_str)
        .is_none_or(|cursor| !cursor.starts_with("cx:cursor:"))
    {
        bail!("sync artifact room timeline missing cursor");
    }
    if value
        .pointer("/snapshot_frontier_recovery/event_set_commitment/root")
        .and_then(Value::as_str)
        .is_none_or(|root| !looks_like_sha256_digest(root))
    {
        bail!("sync artifact snapshot commitment missing digest root");
    }
    if value
        .pointer("/e2ee_decryption_pending/must_not_drop_timeline_entry")
        .and_then(Value::as_bool)
        != Some(true)
    {
        bail!("sync artifact no longer requires keeping pending E2EE entries");
    }
    Ok(())
}

fn validate_profile(value: &Value, expected: &str) -> Result<()> {
    let profile = value
        .get("profile")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("fixture artifact missing profile"))?;
    if profile != expected {
        bail!("fixture profile drifted: expected {expected}, got {profile}");
    }
    Ok(())
}

fn validate_crypto_signature_event_vector(
    vector: &Value,
    event_kinds: &HashMap<String, EventKindInfo>,
) -> Result<()> {
    let name = required_str(vector, "name")?;
    let event_without_proofs = required_field(vector, "event_without_proofs")?;
    let canonical = canonical_event_payload(event_without_proofs)?;
    let expected_canonical = required_str(vector, "canonical_event_payload")?;
    if canonical != expected_canonical {
        bail!("crypto vector {name} canonical event payload drifted");
    }
    let payload_hash = sha256_prefixed(canonical.as_bytes());
    let expected_payload_hash = required_str(vector, "payload_hash")?;
    if payload_hash != expected_payload_hash {
        bail!(
            "crypto vector {name} payload hash drifted: expected {expected_payload_hash}, got {payload_hash}"
        );
    }

    let binding = required_field(vector, "binding_object")?;
    let canonical_binding = canonical_json(binding)?;
    if canonical_binding != required_str(vector, "canonical_binding_payload")? {
        bail!("crypto vector {name} canonical binding payload drifted");
    }
    if sha256_prefixed(canonical_binding.as_bytes()) != required_str(vector, "binding_hash")? {
        bail!("crypto vector {name} binding hash drifted");
    }

    let event_with_proof = required_field(vector, "event_with_proof")?;
    let mut context = EventEnvelopeContext::default_for_durable_history();
    context
        .supported_features
        .extend(event_feature_ids(event_with_proof)?);
    let decision = validate_event_envelope(event_with_proof, event_kinds, &context)?;
    assert_event_decision(&decision, "accept", None, name)?;
    let digest = canonical_event_digest(event_with_proof)?;
    if !looks_like_sha256_digest(&digest) {
        bail!("crypto vector {name} canonical event digest was invalid");
    }

    Ok(())
}

fn validate_event_envelope_negative_case(
    case: &Value,
    event_kinds: &HashMap<String, EventKindInfo>,
) -> Result<()> {
    let name = required_str(case, "name")?;
    let input = required_field(case, "input")?;
    let expected = required_field(case, "expected")?;

    if let (Some(stored), Some(incoming)) = (
        input.get("stored_event").and_then(Value::as_object),
        input.get("incoming_event").and_then(Value::as_object),
    ) {
        let stored_id = stored
            .get("event_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("negative vector {name} stored_event missing event_id"))?;
        let incoming_id = incoming
            .get("event_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("negative vector {name} incoming_event missing event_id"))?;
        let stored_hash = stored
            .get("canonical_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("negative vector {name} stored_event missing canonical_hash"))?;
        let incoming_hash = incoming
            .get("canonical_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                anyhow!("negative vector {name} incoming_event missing canonical_hash")
            })?;
        let decision = if stored_id == incoming_id && stored_hash != incoming_hash {
            EventEnvelopeDecision::quarantine(
                "duplicate_conflict",
                "same event_id different canonical bytes",
            )
        } else {
            EventEnvelopeDecision::accept()
        };
        return assert_event_decision(
            &decision,
            required_str(expected, "decision")?,
            expected.get("error_code").and_then(Value::as_str),
            name,
        );
    }

    let event = required_field(input, "event")?;
    let mut context = EventEnvelopeContext::default_for_durable_history();
    if let Some(scope) = input.get("wire_scope").and_then(Value::as_str) {
        context.durable_history = scope == "durable_history";
    }
    if let Some(features) = input.get("supported_features").and_then(Value::as_array) {
        context.supported_features = features
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect();
    }
    if let Some(frontier) = input.get("actor_frontier") {
        context.actor_frontier = Some(ActorFrontier {
            actor_id: required_str(frontier, "actor_id")?.to_owned(),
            actor_seq: value_field_u64(frontier, "actor_seq")?,
        });
    }

    let decision = validate_event_envelope(event, event_kinds, &context)?;
    assert_event_decision(
        &decision,
        required_str(expected, "decision")?,
        expected.get("error_code").and_then(Value::as_str),
        name,
    )
}

fn validate_synthetic_event_envelope_negatives(
    event_kinds: &HashMap<String, EventKindInfo>,
) -> Result<()> {
    let base = sample_envelope_event(
        "cx.message.create",
        1,
        "01970e589d21-0001-a13f9c2e",
        "2026-05-02T00:00:00Z",
        json!({
            "flow_id": "cx:flow:01k9rm00000000000000000000",
            "body": "hello",
            "noncritical_future_field": {"preserve": true}
        }),
    );
    let context = EventEnvelopeContext::default_for_durable_history();
    let accepted = validate_event_envelope(&base, event_kinds, &context)?;
    assert_event_decision(
        &accepted,
        "accept",
        None,
        "unknown_noncritical_preservation",
    )?;
    let canonical = canonical_event_payload(&base)?;
    if !canonical.contains("noncritical_future_field") {
        bail!("event envelope suite dropped unknown non-critical content from canonical bytes");
    }

    let duplicate_a = sample_envelope_event(
        "cx.message.create",
        2,
        "01970e589d22-0001-a13f9c2e",
        "2026-05-02T00:00:01Z",
        json!({"flow_id": "cx:flow:01k9rm00000000000000000000", "body": "a"}),
    );
    let duplicate_b = sample_envelope_event(
        "cx.message.create",
        2,
        "01970e589d22-0001-a13f9c2e",
        "2026-05-02T00:00:01Z",
        json!({"flow_id": "cx:flow:01k9rm00000000000000000000", "body": "b"}),
    );
    if value_field_str(&duplicate_a, "event_id")? != value_field_str(&duplicate_b, "event_id")? {
        bail!("synthetic duplicate fixture did not use the same event_id");
    }
    if canonical_event_digest(&duplicate_a)? == canonical_event_digest(&duplicate_b)? {
        bail!("same event_id different canonical bytes did not produce distinct digests");
    }

    let mut future_context = EventEnvelopeContext::default_for_durable_history();
    future_context.now_hlc_ms = Some(0x01970e589d21);
    let future = sample_envelope_event(
        "cx.message.create",
        3,
        "01970e700000-0001-a13f9c2e",
        "2026-05-02T00:30:00Z",
        json!({"flow_id": "cx:flow:01k9rm00000000000000000000", "body": "future"}),
    );
    let future_decision = validate_event_envelope(&future, event_kinds, &future_context)?;
    assert_event_decision(
        &future_decision,
        "reject",
        Some("invalid_timestamp"),
        "hlc_future_drift",
    )?;

    let mut revoked_context = EventEnvelopeContext::default_for_durable_history();
    revoked_context.revoked_at_by_actor.insert(
        "did:web:alice.example".to_owned(),
        "2026-05-02T00:05:00Z".to_owned(),
    );
    let backdated = sample_envelope_event(
        "cx.message.create",
        4,
        "01970e589d23-0001-a13f9c2e",
        "2026-05-02T00:00:02Z",
        json!({"flow_id": "cx:flow:01k9rm00000000000000000000", "body": "backdated"}),
    );
    let backdated_decision = validate_event_envelope(&backdated, event_kinds, &revoked_context)?;
    assert_event_decision(
        &backdated_decision,
        "reject",
        Some("authorization_denied"),
        "backdated_event_after_revoke",
    )?;

    Ok(())
}

fn validate_event_envelope(
    event: &Value,
    event_kinds: &HashMap<String, EventKindInfo>,
    context: &EventEnvelopeContext,
) -> Result<EventEnvelopeDecision> {
    if !event.is_object() {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "event envelope must be an object",
        ));
    }

    let kind = match event.get("kind").and_then(Value::as_str) {
        Some(kind) if kind.starts_with("cx.") => kind,
        Some(_) | None => {
            return Ok(EventEnvelopeDecision::reject(
                "schema_violation",
                "Event.kind MUST use registered cx.* spelling",
            ));
        }
    };

    let Some(kind_info) = event_kinds.get(kind) else {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "Event.kind is not registered",
        ));
    };
    if kind_info.status != "active" || kind_info.wire_scope == "deprecated_alias" {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "deprecated_alias producers MUST emit replaced_by",
        ));
    }
    if context.durable_history && kind_info.wire_scope != "durable_event" {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "non-durable event kind submitted to durable Event history",
        ));
    }

    for field in [
        "event_id",
        "space_id",
        "space_version",
        "actor_id",
        "actor_seq",
        "created_at",
        "hlc",
        "prev_refs",
        "auth_refs",
        "content",
        "proofs",
    ] {
        if event.get(field).is_none() {
            return Ok(EventEnvelopeDecision::reject(
                "schema_violation",
                format!("missing required Event field {field}"),
            ));
        }
    }
    if event
        .get("schema")
        .and_then(Value::as_str)
        .unwrap_or("cx.schema.event.v1")
        != "cx.schema.event.v1"
    {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "Event.schema must be cx.schema.event.v1",
        ));
    }
    if !value_field_str(event, "event_id")?.starts_with("cx:event:") {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "invalid event_id",
        ));
    }
    if !value_field_str(event, "space_id")?.starts_with("cx:space:") {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "invalid space_id",
        ));
    }
    if !value_field_str(event, "actor_id")?.starts_with("did:") {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "invalid actor_id",
        ));
    }
    let actor_seq = value_field_u64(event, "actor_seq")?;
    let prev_refs = value_array(required_field(event, "prev_refs")?, "event.prev_refs")?;
    let auth_refs = value_array(required_field(event, "auth_refs")?, "event.auth_refs")?;
    let content = required_field(event, "content")?;
    if !content.is_object() {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "Event.content must be an object",
        ));
    }
    value_array(required_field(event, "proofs")?, "event.proofs")?;

    if event
        .get("prev_ref_count")
        .and_then(Value::as_u64)
        .unwrap_or(prev_refs.len() as u64)
        > context.max_prev_refs as u64
    {
        return Ok(EventEnvelopeDecision::reject(
            "payload_too_large",
            "prev_refs <= 128",
        ));
    }
    let event_id = value_field_str(event, "event_id")?;
    if auth_refs.iter().any(|value| {
        value
            .as_str()
            .is_none_or(|event_ref| !event_ref.starts_with("cx:event:"))
    }) || prev_refs.iter().any(|value| {
        value
            .as_str()
            .is_none_or(|event_ref| !event_ref.starts_with("cx:event:"))
    }) {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "prev_refs and auth_refs must contain event refs",
        ));
    }
    if prev_refs.iter().any(|value| value.as_str() == Some(event_id)) {
        return Ok(EventEnvelopeDecision::reject(
            "causal_conflict",
            "prev_refs MUST NOT contain the event's own event_id",
        ));
    }

    if let Some(frontier) = &context.actor_frontier {
        if frontier.actor_id == value_field_str(event, "actor_id")?
            && actor_seq <= frontier.actor_seq
        {
            return Ok(EventEnvelopeDecision::reject(
                "causal_conflict",
                "actor_seq must monotonically advance actor frontier",
            ));
        }
    }

    if let Some(now_hlc_ms) = context.now_hlc_ms {
        let event_hlc_ms = parse_hlc_millis(value_field_str(event, "hlc")?)?;
        if event_hlc_ms > now_hlc_ms + context.max_future_drift_ms {
            return Ok(EventEnvelopeDecision::reject(
                "invalid_timestamp",
                "HLC future drift exceeded limit",
            ));
        }
    }

    if let Some(revoked_at) = context
        .revoked_at_by_actor
        .get(value_field_str(event, "actor_id")?)
    {
        if value_field_str(event, "created_at")? <= revoked_at.as_str() {
            return Ok(EventEnvelopeDecision::reject(
                "authorization_denied",
                "backdated event after revoke",
            ));
        }
    }

    if let Some(critical_extensions) = event.get("critical_extensions").and_then(Value::as_array) {
        for extension in critical_extensions {
            let id = required_str(extension, "id")?;
            if extension.get("fail_closed").and_then(Value::as_bool) != Some(true)
                || !context.supported_features.contains(id)
            {
                return Ok(EventEnvelopeDecision::reject(
                    "unsupported_feature",
                    "unknown critical extension must fail closed",
                ));
            }
        }
    }

    if let Some(error) = validate_event_payload(kind, content) {
        return Ok(EventEnvelopeDecision::reject("schema_violation", error));
    }

    for proof in event
        .get("proofs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if proof.get("payload_hash").and_then(Value::as_str)
            != Some(canonical_event_payload_hash(event)?.as_str())
        {
            return Ok(EventEnvelopeDecision::reject(
                "invalid_signature",
                "proof.payload_hash does not match canonical Event bytes without proofs",
            ));
        }
    }

    Ok(EventEnvelopeDecision::accept())
}

fn validate_event_payload(kind: &str, content: &Value) -> Option<String> {
    match kind {
        "cx.message.create" => {
            if content.get("flow_id").and_then(Value::as_str).is_none() {
                return Some("message create content missing flow_id".to_owned());
            }
            if !["body", "blocks", "encrypted_payload", "blob_refs"]
                .iter()
                .any(|field| content.get(*field).is_some())
            {
                return Some(
                    "message create content missing body/blocks/encrypted_payload/blob_refs"
                        .to_owned(),
                );
            }
            None
        }
        "cx.flow.move" => {
            missing_payload_fields(content, &["board_id", "flow_id", "to_list_id", "rank"])
        }
        "cx.flow.reorder" => {
            missing_payload_fields(content, &["board_id", "flow_id", "list_id", "rank"])
        }
        "cx.container.rebalance" => {
            missing_payload_fields(content, &["board_id", "list_id", "rank"])
        }
        "cx.member.state" => missing_payload_fields(content, &["membership"]),
        _ => None,
    }
}

fn missing_payload_fields(content: &Value, fields: &[&str]) -> Option<String> {
    fields
        .iter()
        .find(|field| content.get(**field).is_none())
        .map(|field| format!("payload content missing {field}"))
}

fn canonical_event_payload(event: &Value) -> Result<String> {
    canonical_json(&event_without_proofs(event)?)
}

fn canonical_event_payload_hash(event: &Value) -> Result<String> {
    Ok(sha256_prefixed(canonical_event_payload(event)?.as_bytes()))
}

fn canonical_event_digest(event: &Value) -> Result<String> {
    Ok(sha256_prefixed(canonical_json(event)?.as_bytes()))
}

fn event_without_proofs(event: &Value) -> Result<Value> {
    let object = value_object(event, "event")?;
    let mut payload = Map::new();
    for (key, value) in object {
        if key != "proofs" && key != "unsigned" {
            payload.insert(key.clone(), value.clone());
        }
    }
    Ok(Value::Object(payload))
}

fn event_feature_ids(event: &Value) -> Result<BTreeSet<String>> {
    let mut ids = BTreeSet::new();
    for field in ["required_features", "critical_extensions"] {
        for value in event
            .get(field)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(id) = value
                .as_str()
                .or_else(|| value.get("id").and_then(Value::as_str))
            {
                ids.insert(id.to_owned());
            }
        }
    }
    Ok(ids)
}

fn event_kind_metadata(registry: &Value) -> Result<HashMap<String, EventKindInfo>> {
    let mut event_kinds = HashMap::new();
    for entry in registry
        .get("event_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event-kind registry missing event_kinds"))?
    {
        let event_kind = required_str(entry, "event_kind")?;
        event_kinds.insert(
            event_kind.to_owned(),
            EventKindInfo {
                status: required_str(entry, "status")?.to_owned(),
                wire_scope: required_str(entry, "wire_scope")?.to_owned(),
                replaced_by: entry
                    .get("replaced_by")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
            },
        );
    }
    Ok(event_kinds)
}

fn canonical_event_kind_for_consumer<'a>(
    kind: &'a str,
    event_kinds: &'a HashMap<String, EventKindInfo>,
) -> Option<&'a str> {
    let info = event_kinds.get(kind)?;
    if info.wire_scope == "deprecated_alias" {
        info.replaced_by.as_deref()
    } else {
        Some(kind)
    }
}

fn sample_envelope_event(
    kind: &str,
    actor_seq: u64,
    hlc: &str,
    created_at: &str,
    content: Value,
) -> Value {
    json!({
        "schema": "cx.schema.event.v1",
        "event_id": "cx:event:01k9nh00000000000000000000",
        "kind": kind,
        "space_id": "cx:space:01k9sp00000000000000000000",
        "space_version": "1",
        "actor_id": "did:web:alice.example",
        "actor_seq": actor_seq,
        "created_at": created_at,
        "hlc": hlc,
        "prev_refs": [],
        "auth_refs": ["cx:event:01k9au00000000000000000000"],
        "content": content,
        "proofs": []
    })
}

fn parse_hlc_millis(hlc: &str) -> Result<u64> {
    let millis = hlc
        .split_once('-')
        .map(|(millis, _)| millis)
        .ok_or_else(|| anyhow!("invalid HLC shape"))?;
    u64::from_str_radix(millis, 16).map_err(|error| anyhow!("invalid HLC millis: {error}"))
}

fn assert_event_decision(
    actual: &EventEnvelopeDecision,
    expected_decision: &str,
    expected_error_code: Option<&str>,
    context: &str,
) -> Result<()> {
    if actual.decision != expected_decision {
        bail!(
            "event envelope {context} expected decision {expected_decision}, got {} ({:?})",
            actual.decision,
            actual.error_code
        );
    }
    if let Some(expected_error_code) = expected_error_code {
        if actual.error_code.as_deref() != Some(expected_error_code) {
            bail!(
                "event envelope {context} expected error {expected_error_code}, got {:?} ({})",
                actual.error_code,
                actual.reason
            );
        }
    }
    Ok(())
}

#[derive(Clone)]
struct EventKindInfo {
    status: String,
    wire_scope: String,
    replaced_by: Option<String>,
}

struct EventEnvelopeContext {
    durable_history: bool,
    supported_features: BTreeSet<String>,
    actor_frontier: Option<ActorFrontier>,
    revoked_at_by_actor: BTreeMap<String, String>,
    max_prev_refs: usize,
    now_hlc_ms: Option<u64>,
    max_future_drift_ms: u64,
}

impl EventEnvelopeContext {
    fn default_for_durable_history() -> Self {
        Self {
            durable_history: true,
            supported_features: BTreeSet::new(),
            actor_frontier: None,
            revoked_at_by_actor: BTreeMap::new(),
            max_prev_refs: 128,
            now_hlc_ms: None,
            max_future_drift_ms: 5 * 60 * 1000,
        }
    }
}

struct ActorFrontier {
    actor_id: String,
    actor_seq: u64,
}

struct EventEnvelopeDecision {
    decision: &'static str,
    error_code: Option<&'static str>,
    reason: String,
}

impl EventEnvelopeDecision {
    fn accept() -> Self {
        Self {
            decision: "accept",
            error_code: None,
            reason: String::new(),
        }
    }

    fn reject(error_code: &'static str, reason: impl Into<String>) -> Self {
        Self {
            decision: "reject",
            error_code: Some(error_code),
            reason: reason.into(),
        }
    }

    fn quarantine(error_code: &'static str, reason: impl Into<String>) -> Self {
        Self {
            decision: "quarantine",
            error_code: Some(error_code),
            reason: reason.into(),
        }
    }
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {field}"))
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

const RANK_ALPHABET: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const RANK_MAX_LENGTH: usize = 128;

fn rank_between(left: Option<&str>, right: Option<&str>) -> Result<String> {
    if let Some(rank) = left {
        validate_rank(rank, RANK_MAX_LENGTH)?;
    }
    if let Some(rank) = right {
        validate_rank(rank, RANK_MAX_LENGTH)?;
    }

    match (left, right) {
        (Some(left), Some(right)) if left >= right => {
            bail!("left rank must be lower than right rank");
        }
        (Some(left), Some(right)) if right.starts_with(left) => {
            let candidate = format!("{left}0");
            if candidate.as_str() < right {
                return Ok(candidate);
            }
            bail!("no dense rank between {left} and {right}");
        }
        (Some(left), Some(right)) if left.len() == right.len() && left.len() >= 2 => {
            let left_prefix = &left[..left.len() - 1];
            let right_prefix = &right[..right.len() - 1];
            if left_prefix != right_prefix {
                bail!("rank prefixes differ for {left} / {right}");
            }
            let left_digit = rank_char_index(left.chars().last().unwrap())?;
            let right_digit = rank_char_index(right.chars().last().unwrap())?;
            if right_digit <= left_digit + 1 {
                bail!("no space between {left} and {right}");
            }
            let middle = (left_digit + right_digit) / 2;
            Ok(format!("{left_prefix}{}", rank_char_at(middle)?))
        }
        (left, right) => {
            let lower = match left {
                Some(rank) if rank.len() == 1 => rank_char_index(rank.chars().next().unwrap())?,
                Some(rank) => bail!("unsupported lower boundary rank {rank}"),
                None => -1,
            };
            let upper = match right {
                Some(rank) if rank.len() == 1 => rank_char_index(rank.chars().next().unwrap())?,
                Some(rank) => bail!("unsupported upper boundary rank {rank}"),
                None => RANK_ALPHABET.len() as i32,
            };
            if upper <= lower + 1 {
                bail!("no rank available between boundaries");
            }
            let middle = (lower + upper) / 2;
            Ok(rank_char_at(middle)?.to_string())
        }
    }
}

fn validate_rank(rank: &str, max_length: usize) -> Result<()> {
    if rank.is_empty() || rank.len() > max_length {
        bail!("invalid_rank");
    }
    if !rank.chars().all(|ch| RANK_ALPHABET.contains(ch)) {
        bail!("invalid_rank");
    }
    Ok(())
}

fn rank_char_index(ch: char) -> Result<i32> {
    RANK_ALPHABET
        .chars()
        .position(|candidate| candidate == ch)
        .map(|index| index as i32)
        .ok_or_else(|| anyhow!("invalid_rank"))
}

fn rank_char_at(index: i32) -> Result<char> {
    if index < 0 {
        bail!("invalid_rank");
    }
    RANK_ALPHABET
        .chars()
        .nth(index as usize)
        .ok_or_else(|| anyhow!("invalid_rank"))
}

fn rebalance_assignments(edges: &[RankEdge]) -> Result<Vec<RankAssignment>> {
    let count = edges.len();
    validate_rebalance_assignment_count(count, count)?;
    let alphabet_span = (RANK_ALPHABET.len() + 1) as f64;
    let denominator = (count + 1) as f64;
    edges
        .iter()
        .enumerate()
        .map(|(index, edge)| {
            let rank_index =
                (-1.0 + (((index + 1) as f64 * alphabet_span) / denominator)).round() as i32;
            Ok(RankAssignment {
                relation_id: edge.relation_id.clone(),
                entity_id: edge.entity_id.clone(),
                rank: rank_char_at(rank_index)?.to_string(),
            })
        })
        .collect()
}

fn validate_rebalance_assignment_count(
    active_edge_count: usize,
    assignment_count: usize,
) -> Result<()> {
    if active_edge_count != assignment_count {
        bail!("invalid_rebalance_assignment");
    }
    Ok(())
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
    fn push_redaction(
        &mut self,
        target_event_id: &str,
        redaction_event_id: &str,
    ) -> RedactionState {
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

struct FacetGrant {
    allowed_entity_facets: BTreeSet<String>,
    critical: bool,
}

struct EntityTarget {
    entity_type: String,
    facets: Option<BTreeSet<String>>,
}

impl FacetGrant {
    fn allows(&self, target: &EntityTarget) -> bool {
        let _ = &target.entity_type;
        match &target.facets {
            Some(facets) => self.allowed_entity_facets.is_subset(facets),
            None => !self.critical && self.allowed_entity_facets.is_empty(),
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
        let events = self
            .events
            .iter()
            .take(limit.min(3))
            .cloned()
            .collect::<Vec<_>>();
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

fn validate_container_move_resolution(case: &StateResolutionCase) -> Result<()> {
    let input = required_case_input(case)?;
    let base_state = value_object(required_field(input, "base_state")?, "input.base_state")?;
    let candidates = value_array(required_field(input, "candidates")?, "input.candidates")?;
    let expected = required_case_expected(case)?;
    let winner = choose_operation_winner(candidates)?;
    let winner_id = value_field_str(winner, "operation_id")?;
    let content = required_field(winner, "content")?;
    if value_field_str(winner, "kind")? != "cx.container.move_item" {
        bail!(
            "state fixture {} winner was not canonical container move",
            case.name
        );
    }

    let resolved_position = json!({
        "scope_container_id": required_field(content, "scope_container_id")?.clone(),
        "relation_kind": required_field(content, "relation_kind")?.clone(),
        "entity_id": required_field(content, "entity_id")?.clone(),
        "container_id": required_field(content, "to_container_id")?.clone(),
        "rank": required_field(content, "rank")?.clone(),
        "source_operation_id": winner_id
    });
    assert_json_eq(
        &resolved_position,
        required_field(expected, "resolved_position")?,
        &case.name,
        "resolved_position",
    )?;

    let state_key = format!(
        "{}|{}|{}",
        value_field_str(content, "scope_container_id")?,
        value_field_str(content, "relation_kind")?,
        value_field_str(content, "entity_id")?
    );
    let active_registers = json!([{
        "state_key": state_key,
        "container_id": required_field(content, "to_container_id")?.clone(),
        "rank": required_field(content, "rank")?.clone(),
        "source_operation_id": winner_id
    }]);
    assert_json_eq(
        &active_registers,
        required_field(expected, "active_position_registers")?,
        &case.name,
        "active_position_registers",
    )?;

    let loser_ids = operation_ids_except(candidates, winner_id)?;
    let mut inactive_ids = Vec::with_capacity(loser_ids.len() + 1);
    inactive_ids.push(
        base_state
            .get("source_operation_id")
            .cloned()
            .ok_or_else(|| anyhow!("state fixture {} missing base source operation", case.name))?,
    );
    inactive_ids.extend(loser_ids.iter().map(|operation_id| json!(operation_id)));
    assert_json_eq(
        &Value::Array(inactive_ids),
        required_field(expected, "inactive_source_operation_ids")?,
        &case.name,
        "inactive_source_operation_ids",
    )?;

    let expected_conflicts = required_field(expected, "conflict_records")?;
    let conflict = json!([{
        "conflict_type": "exclusive_position",
        "state_key": active_registers[0]["state_key"].clone(),
        "winner": winner_id,
        "losers": loser_ids,
        "reason": expected_conflicts[0]["reason"].clone()
    }]);
    assert_json_eq(
        &conflict,
        expected_conflicts,
        &case.name,
        "conflict_records",
    )
}

fn validate_field_position_resolution(case: &StateResolutionCase) -> Result<()> {
    let input = required_case_input(case)?;
    let candidates = value_array(required_field(input, "candidates")?, "input.candidates")?;
    let expected = required_case_expected(case)?;
    let winner = choose_operation_winner(candidates)?;
    let winner_id = value_field_str(winner, "operation_id")?;
    let content = required_field(winner, "content")?;
    if value_field_str(winner, "kind")? != "cx.field_position.move" {
        bail!(
            "state fixture {} winner was not canonical field-position move",
            case.name
        );
    }

    let resolved_position = json!({
        "view_id": required_field(content, "view_id")?.clone(),
        "entity_id": required_field(content, "entity_id")?.clone(),
        "group_by": required_field(content, "group_by")?.clone(),
        "value": required_field(content, "to_value")?.clone(),
        "rank": required_field(content, "rank")?.clone(),
        "source_operation_id": winner_id
    });
    assert_json_eq(
        &resolved_position,
        required_field(expected, "resolved_position")?,
        &case.name,
        "resolved_position",
    )?;

    let loser_ids = operation_ids_except(candidates, winner_id)?;
    let expected_conflicts = required_field(expected, "conflict_records")?;
    let conflict = json!([{
        "conflict_type": "atomic_position_register",
        "state_key": format!(
            "{}|{}|{}",
            value_field_str(content, "view_id")?,
            value_field_str(content, "entity_id")?,
            value_field_str(content, "group_by")?
        ),
        "winner": winner_id,
        "losers": loser_ids,
        "reason": expected_conflicts[0]["reason"].clone()
    }]);
    assert_json_eq(
        &conflict,
        expected_conflicts,
        &case.name,
        "conflict_records",
    )
}

fn validate_state_rebalance_assignment(case: &StateResolutionCase) -> Result<()> {
    let input = required_case_input(case)?;
    let active_edges =
        serde_json::from_value::<Vec<RankEdge>>(required_field(input, "active_edges")?.clone())?;
    let state_hash = value_field_str(input, "state_hash")?;
    let expected_state_hash = value_field_str(input, "expected_state_hash")?;
    if state_hash != expected_state_hash {
        bail!(
            "state fixture {} attempted rebalance from stale state hash",
            case.name
        );
    }
    let actual = rebalance_assignments(&active_edges)?;
    let expected = case
        .expected_assignments
        .as_deref()
        .ok_or_else(|| anyhow!("state fixture {} missing expected_assignments", case.name))?;
    if actual != expected {
        bail!("state fixture {} rebalance assignments differed", case.name);
    }
    Ok(())
}

fn validate_state_rebalance_cas_conflict(case: &StateResolutionCase) -> Result<()> {
    let input = required_case_input(case)?;
    let state_hash = value_field_str(input, "state_hash")?;
    let expected_state_hash = value_field_str(input, "expected_state_hash")?;
    let expected = case
        .expected
        .as_ref()
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("state fixture {} missing string expected", case.name))?;
    if expected != "reject_without_partial_assignment" {
        bail!(
            "state fixture {} expected CAS rejection semantics drifted",
            case.name
        );
    }
    if state_hash == expected_state_hash {
        bail!(
            "state fixture {} did not model a stale state hash",
            case.name
        );
    }
    Ok(())
}

fn validate_kanban_column_pagination(case: &SyncCase) -> Result<()> {
    let initial_request = required_sync_field(case, "initial_request")?;
    let initial_response = required_sync_field(case, "initial_response")?;
    validate_projection_pair(
        case,
        initial_request,
        initial_response,
        "collection",
        "kanban",
    )?;

    let groups = value_array(
        required_field(initial_response, "groups")?,
        "initial_response.groups",
    )?;
    let todo = find_group(groups, "todo")?;
    let done = find_group(groups, "done")?;
    if !value_field_bool(todo, "limited")? || required_field(todo, "next_cursor")?.is_null() {
        bail!(
            "sync fixture {} todo column was not limited with cursor",
            case.name
        );
    }
    if value_field_bool(done, "limited")? || !required_field(done, "next_cursor")?.is_null() {
        bail!(
            "sync fixture {} done column pagination leaked cursor",
            case.name
        );
    }
    validate_kanban_group_positions(todo, &case.name)?;
    validate_kanban_group_positions(done, &case.name)?;

    let followup_request = required_sync_field(case, "followup_request")?;
    let expected_followup = required_sync_field(case, "expected_followup_response")?;
    let followup_cursor = value_field_str(followup_request, "cursor")?;
    if followup_cursor != value_field_str(todo, "next_cursor")? {
        bail!(
            "sync fixture {} followup cursor did not resume todo column",
            case.name
        );
    }
    validate_projection_pair(
        case,
        followup_request,
        expected_followup,
        "collection",
        "kanban",
    )?;
    let followup_groups = value_array(
        required_field(expected_followup, "groups")?,
        "expected_followup_response.groups",
    )?;
    if followup_groups.len() != 1 || value_field_str(&followup_groups[0], "key")? != "todo" {
        bail!(
            "sync fixture {} followup did not isolate todo column",
            case.name
        );
    }
    validate_kanban_group_positions(&followup_groups[0], &case.name)
}

fn validate_kanban_hidden_counts(case: &SyncCase) -> Result<()> {
    let input = required_sync_field(case, "input")?;
    let visible_entities = value_array(
        required_field(
            required_field(input, "actor_visibility")?,
            "visible_entities",
        )?,
        "input.actor_visibility.visible_entities",
    )?
    .iter()
    .map(|value| {
        value
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("sync fixture {} visible entity must be string", case.name))
    })
    .collect::<Result<BTreeSet<_>>>()?;

    let policy_cases = value_array(required_sync_field(case, "policy_cases")?, "policy_cases")?;
    for policy_case in policy_cases {
        let policy_name = value_field_str(policy_case, "name")?;
        let allowed = required_field(policy_case, "allowed_response")?;
        validate_projection_response(allowed, "collection", "kanban", &case.name)?;
        let groups = value_array(
            required_field(allowed, "groups")?,
            "allowed_response.groups",
        )?;
        for group in groups {
            let visible_count = assert_group_items_visible(group, &visible_entities, &case.name)?;
            match policy_name {
                "omit" if group.get("total_estimate").is_some() => {
                    bail!(
                        "sync fixture {} omit policy exposed total_estimate",
                        case.name
                    );
                }
                "authorized_estimate" | "authorized_exact" => {
                    if value_field_u64(group, "total_estimate")? != visible_count as u64 {
                        bail!(
                            "sync fixture {} count policy was not visibility-trimmed",
                            case.name
                        );
                    }
                }
                "omit" => {}
                other => bail!(
                    "sync fixture {} unknown hidden count policy {other}",
                    case.name
                ),
            }
        }
    }
    Ok(())
}

fn validate_projection_contract(case: &SyncCase, projection: &str, preset: &str) -> Result<()> {
    let request = required_sync_field(case, "request")?;
    let response = required_sync_field(case, "response")?;
    validate_projection_pair(case, request, response, projection, preset)?;
    validate_projection_shape(response, projection, &case.name)
}

fn validate_projection_pair(
    case: &SyncCase,
    request: &Value,
    response: &Value,
    projection: &str,
    preset: &str,
) -> Result<()> {
    if value_field_str(request, "projection")? != projection
        || value_field_str(response, "projection")? != projection
    {
        bail!(
            "sync fixture {} projection discriminator mismatch",
            case.name
        );
    }
    if let Some(request_preset) = request.get("preset").and_then(Value::as_str) {
        if request_preset != preset {
            bail!("sync fixture {} request preset mismatch", case.name);
        }
    }
    if let Some(response_preset) = response.get("preset").and_then(Value::as_str) {
        if response_preset != preset {
            bail!("sync fixture {} response preset mismatch", case.name);
        }
    }
    if let Some(request_view_id) = request.get("view_id").and_then(Value::as_str) {
        if value_field_str(response, "view_id")? != request_view_id {
            bail!("sync fixture {} response view_id drifted", case.name);
        }
    }
    if request.get("renderer").is_some() {
        validate_query_renderer(request)?;
    }
    validate_projection_response(response, projection, preset, &case.name)?;
    validate_response_entities_against_request_facets(response, request, &case.name)
}

fn validate_projection_response(
    response: &Value,
    projection: &str,
    preset: &str,
    case_name: &str,
) -> Result<()> {
    if value_field_str(response, "projection")? != projection {
        bail!("sync fixture {case_name} response discriminator mismatch");
    }
    if let Some(response_preset) = response.get("preset").and_then(Value::as_str) {
        if response_preset != preset {
            bail!("sync fixture {case_name} response preset mismatch");
        }
    }
    let frontier = required_field(response, "frontier")?;
    let state_hash = value_field_str(frontier, "state_hash")?;
    if !looks_like_sha256_digest(state_hash) {
        bail!("sync fixture {case_name} response frontier hash was invalid");
    }
    validate_optional_cursor(response.get("next_cursor"), case_name)?;
    Ok(())
}

fn validate_projection_shape(response: &Value, projection: &str, case_name: &str) -> Result<()> {
    match projection {
        "collection" => {
            let items = required_field(response, "items")?;
            if value_array(items, "response.items")?.is_empty() {
                bail!("sync fixture {case_name} collection projection had no items");
            }
            for item in value_array(items, "response.items")? {
                validate_entity(required_field(item, "entity")?, &BTreeSet::new(), case_name)?;
                if required_field(item, "position")?
                    .as_object()
                    .map_or(true, Map::is_empty)
                {
                    bail!(
                        "sync fixture {case_name} collection item missing position discriminator"
                    );
                }
            }
        }
        "timeline" => {
            let entries = value_array(required_field(response, "entries")?, "response.entries")?;
            for entry in entries {
                if !value_field_str(entry, "sort_key")?.contains('|') {
                    bail!("sync fixture {case_name} timeline entry missing stable sort key");
                }
                validate_entity(
                    required_field(entry, "entity")?,
                    &BTreeSet::new(),
                    case_name,
                )?;
            }
        }
        "graph" => {
            if value_array(required_field(response, "nodes")?, "response.nodes")?.is_empty() {
                bail!("sync fixture {case_name} graph projection had no nodes");
            }
            for node in value_array(required_field(response, "nodes")?, "response.nodes")? {
                validate_entity(required_field(node, "entity")?, &BTreeSet::new(), case_name)?;
            }
            for edge in value_array(required_field(response, "edges")?, "response.edges")? {
                if !value_field_str(edge, "relation_id")?.starts_with("cx:relation:") {
                    bail!("sync fixture {case_name} graph edge relation id was invalid");
                }
            }
        }
        "document" => {
            for section in value_array(required_field(response, "sections")?, "response.sections")?
            {
                if value_field_str(section, "sort_key")?.is_empty() {
                    bail!("sync fixture {case_name} document section missing sort key");
                }
                validate_entity(
                    required_field(section, "entity")?,
                    &BTreeSet::new(),
                    case_name,
                )?;
            }
        }
        "composite" => {
            for widget in value_array(required_field(response, "widgets")?, "response.widgets")? {
                if widget.get("frontier").is_none() || widget.get("projection").is_none() {
                    bail!("sync fixture {case_name} composite widget missing projection frontier");
                }
            }
        }
        other => bail!("sync fixture {case_name} unsupported projection {other}"),
    }
    Ok(())
}

fn validate_kanban_group_positions(group: &Value, case_name: &str) -> Result<()> {
    let source = required_field(group, "source")?;
    if value_field_str(source, "model")? != "field_value" {
        bail!("sync fixture {case_name} kanban group was not field-value sourced");
    }
    for item in value_array(required_field(group, "items")?, "group.items")? {
        let position = required_field(item, "position")?;
        validate_projection_position(position)?;
        if value_field_str(position, "model")? != "field_value" {
            bail!("sync fixture {case_name} kanban item position discriminator mismatch");
        }
    }
    Ok(())
}

fn validate_query_renderer(request: &Value) -> Result<()> {
    let projection = value_field_str(request, "projection")?;
    let renderer = value_field_str(request, "renderer")?;
    let preset = request
        .get("preset")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| infer_preset_from_renderer(projection, renderer).map(ToOwned::to_owned))
        .ok_or_else(|| {
            anyhow!("unsupported projection/renderer mapping {projection}/{renderer}")
        })?;
    let expected = expected_renderer(projection, &preset).ok_or_else(|| {
        anyhow!("unsupported projection/preset renderer mapping {projection}/{preset}")
    })?;
    if renderer != expected {
        bail!("renderer {renderer} does not match {projection}/{preset}; expected {expected}");
    }
    Ok(())
}

fn infer_preset_from_renderer(projection: &str, renderer: &str) -> Option<&'static str> {
    match (projection, renderer) {
        ("collection", "board") => Some("kanban"),
        ("collection", "table") => Some("table"),
        ("collection", "calendar") => Some("calendar"),
        ("collection", "gantt") => Some("gantt"),
        ("timeline", "chat") => Some("chat"),
        ("timeline", "timeline") => Some("timeline"),
        ("graph", "graph") => Some("graph"),
        ("graph", "tree") => Some("tree"),
        ("document", "document") => Some("document"),
        ("composite", "dashboard") => Some("dashboard"),
        _ => None,
    }
}

fn expected_renderer(projection: &str, preset: &str) -> Option<&'static str> {
    match (projection, preset) {
        ("collection", "kanban") => Some("board"),
        ("collection", "table") => Some("table"),
        ("collection", "calendar") => Some("calendar"),
        ("collection", "gantt") => Some("gantt"),
        ("collection", "matrix") => Some("table"),
        ("timeline", "chat") => Some("chat"),
        ("timeline", "timeline") => Some("timeline"),
        ("graph", "graph") => Some("graph"),
        ("graph", "tree") => Some("tree"),
        ("document", "document") => Some("document"),
        ("composite", "dashboard") => Some("dashboard"),
        _ => None,
    }
}

fn validate_projection_position(position: &Value) -> Result<()> {
    match value_field_str(position, "model")? {
        "field_value" => {
            require_position_field(position, "container_id")?;
            require_rank(position)?;
        }
        "relation_container" => {
            require_position_field(position, "scope_container_id")?;
            require_position_field(position, "container_id")?;
            require_position_field(position, "relation_kind")?;
            let relation_id = require_position_field(position, "relation_id")?;
            if !relation_id.starts_with("cx:relation:") {
                bail!("relation_container position relation_id was invalid");
            }
            require_rank(position)?;
        }
        "time_bucket" => {
            require_position_field(position, "start_field")?;
            require_position_field(position, "bucket")?;
            require_position_field(position, "timezone")?;
            let bucket_start = require_position_field(position, "bucket_start")?;
            if !bucket_start.ends_with('Z') {
                bail!("time_bucket position bucket_start must be UTC timestamp");
            }
            require_rank(position)?;
        }
        "matrix_cell" => {
            require_position_field(position, "rows_by")?;
            require_position_field(position, "columns_by")?;
            require_position_field(position, "row_key")?;
            require_position_field(position, "column_key")?;
            require_rank(position)?;
        }
        other => bail!("unknown projection position model {other}"),
    }
    Ok(())
}

fn require_position_field<'a>(position: &'a Value, field: &str) -> Result<&'a str> {
    let value = value_field_str(position, field)?;
    if value.is_empty() {
        bail!("projection position field {field} must not be empty");
    }
    Ok(value)
}

fn require_rank(position: &Value) -> Result<()> {
    validate_rank(require_position_field(position, "rank")?, RANK_MAX_LENGTH)
}

fn validate_response_entities_against_request_facets(
    response: &Value,
    request: &Value,
    case_name: &str,
) -> Result<()> {
    let required_facets = request_facets(request)?;
    validate_nested_entities(response, &required_facets, case_name)
}

fn request_facets(request: &Value) -> Result<BTreeSet<String>> {
    request
        .get("facets")
        .and_then(Value::as_array)
        .map(|facets| {
            facets
                .iter()
                .map(|facet| {
                    facet
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| anyhow!("query facet must be a string"))
                })
                .collect::<Result<BTreeSet<_>>>()
        })
        .unwrap_or_else(|| Ok(BTreeSet::new()))
}

fn filter_entities_by_facets(
    entities: &[Value],
    required_facets: &BTreeSet<String>,
) -> Result<Vec<Value>> {
    let mut filtered = Vec::new();
    for entity in entities {
        let facets = entity_facets(entity)?;
        if required_facets.is_subset(&facets) {
            filtered.push(entity.clone());
        }
    }
    Ok(filtered)
}

fn validate_nested_entities(
    value: &Value,
    required_facets: &BTreeSet<String>,
    case_name: &str,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            if object.contains_key("entity_type") && object.contains_key("facets") {
                validate_entity(value, required_facets, case_name)?;
            }
            for child in object.values() {
                validate_nested_entities(child, required_facets, case_name)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                validate_nested_entities(item, required_facets, case_name)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_entity(
    entity: &Value,
    required_facets: &BTreeSet<String>,
    case_name: &str,
) -> Result<()> {
    if !value_field_str(entity, "id")?.starts_with("cx:entity:") {
        bail!("sync fixture {case_name} entity id was invalid");
    }
    let facets = entity_facets(entity)?;
    if !required_facets.is_subset(&facets) {
        bail!("sync fixture {case_name} entity did not satisfy requested facets");
    }
    Ok(())
}

fn entity_facets(entity: &Value) -> Result<BTreeSet<String>> {
    value_array(required_field(entity, "facets")?, "entity.facets")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("entity facet was not string"))
        })
        .collect()
}

fn assert_group_items_visible(
    group: &Value,
    visible_entities: &BTreeSet<String>,
    case_name: &str,
) -> Result<usize> {
    let mut visible_count = 0;
    for item in value_array(required_field(group, "items")?, "group.items")? {
        let entity_id = value_field_str(required_field(item, "entity")?, "id")?;
        if !visible_entities.contains(entity_id) {
            bail!("sync fixture {case_name} leaked hidden entity in group response");
        }
        visible_count += 1;
    }
    Ok(visible_count)
}

fn find_group<'a>(groups: &'a [Value], key: &str) -> Result<&'a Value> {
    groups
        .iter()
        .find(|group| group.get("key").and_then(Value::as_str) == Some(key))
        .ok_or_else(|| anyhow!("missing projection group {key}"))
}

fn validate_optional_cursor(value: Option<&Value>, case_name: &str) -> Result<()> {
    match value {
        Some(Value::Null) | None => Ok(()),
        Some(Value::String(cursor)) if cursor.starts_with("cx:cursor:") => Ok(()),
        _ => bail!("sync fixture {case_name} invalid cursor shape"),
    }
}

fn choose_operation_winner(candidates: &[Value]) -> Result<&Value> {
    let mut winner = candidates
        .first()
        .ok_or_else(|| anyhow!("cannot resolve empty operation candidate set"))?;
    for candidate in &candidates[1..] {
        if operation_order(candidate, winner)? == Ordering::Greater {
            winner = candidate;
        }
    }
    Ok(winner)
}

fn operation_order(left: &Value, right: &Value) -> Result<Ordering> {
    let left_weight = value_field_u64(left, "auth_weight")?;
    let right_weight = value_field_u64(right, "auth_weight")?;
    let left_hlc = value_field_str(left, "hlc")?;
    let right_hlc = value_field_str(right, "hlc")?;
    let left_operation_id = value_field_str(left, "operation_id")?;
    let right_operation_id = value_field_str(right, "operation_id")?;
    Ok(left_weight
        .cmp(&right_weight)
        .then_with(|| left_hlc.cmp(right_hlc))
        .then_with(|| left_operation_id.cmp(right_operation_id)))
}

fn operation_ids_except(candidates: &[Value], winner_id: &str) -> Result<Vec<String>> {
    let mut operation_ids = Vec::new();
    for candidate in candidates {
        let operation_id = value_field_str(candidate, "operation_id")?;
        if operation_id != winner_id {
            operation_ids.push(operation_id.to_owned());
        }
    }
    Ok(operation_ids)
}

fn required_case_input(case: &StateResolutionCase) -> Result<&Value> {
    case.input
        .as_ref()
        .ok_or_else(|| anyhow!("state fixture {} missing input", case.name))
}

fn required_case_expected(case: &StateResolutionCase) -> Result<&Value> {
    case.expected
        .as_ref()
        .ok_or_else(|| anyhow!("state fixture {} missing expected object", case.name))
}

fn required_sync_field<'a>(case: &'a SyncCase, key: &str) -> Result<&'a Value> {
    case.fields
        .get(key)
        .ok_or_else(|| anyhow!("sync fixture {} missing {key}", case.name))
}

fn required_field<'a>(value: &'a Value, field: &str) -> Result<&'a Value> {
    value
        .as_object()
        .and_then(|object| object.get(field))
        .ok_or_else(|| anyhow!("missing object field {field}"))
}

fn value_object<'a>(value: &'a Value, context: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| anyhow!("{context} must be an object"))
}

fn value_array<'a>(value: &'a Value, context: &str) -> Result<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| anyhow!("{context} must be an array"))
}

fn value_field_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    required_field(value, field)?
        .as_str()
        .ok_or_else(|| anyhow!("object field {field} must be a string"))
}

fn value_field_bool(value: &Value, field: &str) -> Result<bool> {
    required_field(value, field)?
        .as_bool()
        .ok_or_else(|| anyhow!("object field {field} must be a bool"))
}

fn value_field_u64(value: &Value, field: &str) -> Result<u64> {
    required_field(value, field)?
        .as_u64()
        .ok_or_else(|| anyhow!("object field {field} must be an unsigned integer"))
}

fn assert_json_eq(actual: &Value, expected: &Value, case_name: &str, field: &str) -> Result<()> {
    if actual != expected {
        bail!("fixture {case_name} {field} mismatch: expected {expected}, got {actual}");
    }
    Ok(())
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

fn validate_origin_destination(
    origin: &str,
    signed_destination: &str,
    expected_destination: &str,
) -> FederationVerdict {
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

fn authorize_pull(
    has_backfill_capability: bool,
    has_plaintext_visibility: bool,
) -> FederationVerdict {
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
    left: Option<String>,
    right: Option<String>,
    expected: Option<String>,
    input: Option<String>,
    max_length: Option<usize>,
    active_edge_count: Option<usize>,
    assignment_count: Option<usize>,
    ordered_edges: Option<Vec<RankEdge>>,
    expected_assignments: Option<Vec<RankAssignment>>,
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
    cases: Vec<StateResolutionCase>,
}

#[derive(Debug, Deserialize)]
struct SyncFixture {
    suite: String,
    cases: Vec<SyncCase>,
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
    operation_id: Option<String>,
    input: Option<Value>,
    expected: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct StateResolutionCase {
    name: String,
    input: Option<Value>,
    expected: Option<Value>,
    expected_assignments: Option<Vec<RankAssignment>>,
}

#[derive(Debug, Deserialize)]
struct SyncCase {
    name: String,
    #[serde(flatten)]
    fields: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize)]
struct RankEdge {
    relation_id: String,
    entity_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct RankAssignment {
    relation_id: String,
    entity_id: String,
    rank: String,
}
