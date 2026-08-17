use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{
    canonical_json, load_artifact_json, load_fixture_value, looks_like_sha256_digest,
    required_field, required_str, sha256_prefixed, validate_profile, value_array, value_field_str,
    value_field_u64,
};
use crate::transcripts::record_vector_event;

pub fn run_event_envelope_fixture_suite() -> Result<()> {
    let event_kind_registry = load_artifact_json("registry/event-kind-registry.json")?;
    let event_kinds = event_kind_metadata(&event_kind_registry)?;

    let crypto_fixture = load_fixture_value("crypto-signature-fixture.json")?;
    validate_profile(&crypto_fixture, "ak.vector_group.crypto_signature.v1")?;
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

pub fn run_container_realm_control_payload_suite() -> Result<()> {
    let vectors = [
        (
            "ak.cotest_vector.container.move_item.accept.v1",
            "ak.container.move_item",
            json!({
                "item_ref": "ak:morph:AXh0mpVGb536xVxbSPfM4Wc_1WuXAxTYgmtXEncKM9T0",
                "container_ref": "ak:morph:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z",
                "relation_kind": "contains",
                "rank": "A"
            }),
            true,
        ),
        (
            "ak.cotest_vector.container.move_item.unregistered_fields_rejected.v1",
            "ak.container.move_item",
            json!({
                "object_ref": "ak:morph:AXh0mpVGb536xVxbSPfM4Wc_1WuXAxTYgmtXEncKM9T0",
                "to_container_id": "ak:morph:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z",
                "relation_kind": "contains",
                "rank": "A"
            }),
            false,
        ),
        (
            "ak.cotest_vector.container.rebalance.accept.v1",
            "ak.container.rebalance",
            json!({
                "container_ref": "ak:morph:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z",
                "relation_kind": "contains",
                "positions": [
                    {"item_ref": "ak:morph:AXh0mpVGb536xVxbSPfM4Wc_1WuXAxTYgmtXEncKM9T0", "rank": "A"},
                    {"item_ref": "ak:morph:AaIJHtxd23N3TkS66mYyI4XGESjS7Gjt_fonMdJe9inQ", "rank": "B"}
                ],
                "expected_order_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }),
            true,
        ),
        (
            "ak.cotest_vector.container.rebalance.duplicate_rank_rejected.v1",
            "ak.container.rebalance",
            json!({
                "container_ref": "ak:morph:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z",
                "relation_kind": "contains",
                "positions": [
                    {"item_ref": "ak:morph:AXh0mpVGb536xVxbSPfM4Wc_1WuXAxTYgmtXEncKM9T0", "rank": "A"},
                    {"item_ref": "ak:morph:AaIJHtxd23N3TkS66mYyI4XGESjS7Gjt_fonMdJe9inQ", "rank": "A"}
                ],
                "expected_order_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }),
            false,
        ),
        (
            "ak.cotest_vector.realm.notary.accept.v1",
            "ak.realm.notary",
            json!({
                "realm_id": "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
                "notary": {"kind": "single_did", "actor_id": "ak:did_core:web:notary.example"}
            }),
            true,
        ),
        (
            "ak.cotest_vector.realm.digest_transition.accept.v1",
            "ak.realm.digest_suite_transition",
            json!({
                "from_digest_algorithm": "sha256",
                "to_digest_algorithm": "blake3",
                "transition_snapshot_ref": "ak:snapshot:01904100-0000-7000-8000-000000000301",
                "snapshot_commitment": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }),
            true,
        ),
        (
            "ak.cotest_vector.realm.digest_transition.downgrade_rejected.v1",
            "ak.realm.digest_suite_transition",
            json!({
                "from_digest_algorithm": "blake3",
                "to_digest_algorithm": "sha256",
                "transition_snapshot_ref": "ak:snapshot:01904100-0000-7000-8000-000000000302",
                "snapshot_commitment": "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }),
            false,
        ),
        (
            "ak.cotest_vector.realm.digest_transition.noop_rejected.v1",
            "ak.realm.digest_suite_transition",
            json!({
                "from_digest_algorithm": "sha256",
                "to_digest_algorithm": "sha256",
                "transition_snapshot_ref": "ak:snapshot:01904100-0000-7000-8000-000000000303",
                "snapshot_commitment": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            }),
            false,
        ),
    ];

    for (id, kind, payload, expected_accept) in vectors {
        let accepted = validate_event_payload(kind, &payload).is_none();
        if accepted != expected_accept {
            bail!("{id} expected accept={expected_accept}, got accept={accepted}");
        }
        record_vector_event(
            id,
            &json!({"kind": kind, "payload": payload}),
            &json!({"accept": expected_accept}),
            &json!({"accept": accepted}),
        );
    }
    Ok(())
}

// ── Internal validation functions ───────────────────────────────────────────

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
    if vector.get("payload_digest").is_some() {
        bail!("crypto vector {name} carries retired Event proof field payload_digest");
    }
    let event_digest = sha256_prefixed(canonical.as_bytes());
    let expected_event_digest = required_str(vector, "event_digest")?;
    if event_digest != expected_event_digest {
        bail!(
            "crypto vector {name} event hash drifted: expected {expected_event_digest}, got {event_digest}"
        );
    }

    let binding = required_field(vector, "binding_object")?;
    let canonical_binding = canonical_json(binding)?;
    if canonical_binding != required_str(vector, "canonical_binding_payload")? {
        bail!("crypto vector {name} canonical binding payload drifted");
    }
    if sha256_prefixed(canonical_binding.as_bytes()) != required_str(vector, "binding_digest")? {
        bail!("crypto vector {name} binding digest drifted");
    }

    if let Some(event_with_proof) = vector.get("event_with_proof") {
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
    } else {
        let proof_kind = required_str(vector, "proof_kind")?;
        if proof_kind != "raw_detached_signature" {
            bail!("crypto vector {name} missing event_with_proof for proof_kind {proof_kind}");
        }
        let signature_algorithm = required_str(vector, "signature_algorithm")?;
        if signature_algorithm.is_empty() {
            bail!("crypto vector {name} missing signature algorithm");
        }
        let signature = required_str(vector, "signature_b64u")?;
        if signature.is_empty() {
            bail!("crypto vector {name} missing raw detached signature");
        }
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
        let stored_digest = stored
            .get("canonical_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                anyhow!("negative vector {name} stored_event missing canonical_digest")
            })?;
        let incoming_digest = incoming
            .get("canonical_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                anyhow!("negative vector {name} incoming_event missing canonical_digest")
            })?;
        let decision = if stored_id == incoming_id && stored_digest != incoming_digest {
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

    let generated_event;
    let event = if let Some(generator) = input.get("generator") {
        generated_event = generate_negative_envelope_event(generator)?;
        &generated_event
    } else {
        required_field(input, "event")?
    };
    let mut context = EventEnvelopeContext::default_for_durable_history();
    if let Some(scope) = input.get("wire_scope").and_then(Value::as_str) {
        context.durable_history = matches!(scope, "durable_event" | "durable_history");
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

fn generate_negative_envelope_event(generator: &Value) -> Result<Value> {
    let kind = required_str(generator, "kind")?;
    let target_canonical_bytes = value_field_u64(generator, "target_canonical_bytes")? as usize;
    let filler_json_pointer = required_str(generator, "filler_json_pointer")?;
    let filler_char = required_str(generator, "filler_char")?;
    if filler_char.len() != 1 || !filler_char.is_ascii() {
        bail!("generator filler_char must be one ASCII byte");
    }
    let base_event = required_field(generator, "base_event")?;

    let mut low = 0usize;
    let mut high = target_canonical_bytes + 1024;
    while low < high {
        let mid = low + (high - low) / 2;
        let candidate = apply_negative_envelope_filler(
            base_event,
            kind,
            filler_json_pointer,
            filler_char,
            mid,
        )?;
        if canonical_json(&candidate)?.len() >= target_canonical_bytes {
            high = mid;
        } else {
            low = mid + 1;
        }
    }

    let event =
        apply_negative_envelope_filler(base_event, kind, filler_json_pointer, filler_char, low)?;
    let canonical_len = canonical_json(&event)?.len();
    if canonical_len < target_canonical_bytes {
        bail!(
            "generator {kind} produced {canonical_len} canonical bytes, below target {target_canonical_bytes}"
        );
    }
    Ok(event)
}

fn apply_negative_envelope_filler(
    base_event: &Value,
    kind: &str,
    pointer: &str,
    filler_char: &str,
    repeat: usize,
) -> Result<Value> {
    let mut event = base_event.clone();
    let filler = filler_char.repeat(repeat);
    match kind {
        "oversize_envelope" | "long_string_value" => {
            let target = event
                .pointer_mut(pointer)
                .ok_or_else(|| anyhow!("generator pointer {pointer} did not resolve"))?;
            if !target.is_string() {
                bail!("generator pointer {pointer} must target a string");
            }
            *target = Value::String(filler);
        }
        "long_object_key" => {
            let target = event
                .pointer_mut(pointer)
                .and_then(Value::as_object_mut)
                .ok_or_else(|| anyhow!("generator pointer {pointer} must target an object"))?;
            target.insert(filler, json!(1));
        }
        _ => bail!("unknown event envelope negative generator kind {kind}"),
    }
    Ok(event)
}

fn validate_synthetic_event_envelope_negatives(
    event_kinds: &HashMap<String, EventKindInfo>,
) -> Result<()> {
    let base = sample_envelope_event(
        "ak.message.create",
        1,
        "01970e589d21-0001-a13f9c2e",
        "2026-05-02T00:00:00.000Z",
        json!({
            "strand_id": "ak:strand:AXYlSrZyrvLo7DtDjCwS6u7unEkJVXS12FTvdJM5AlGa",
            "content": {
                "kind": "ak.content.text",
                "body": "hello"
            },
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
        "ak.message.create",
        2,
        "01970e589d22-0001-a13f9c2e",
        "2026-05-02T00:00:01.000Z",
        json!({
            "strand_id": "ak:strand:AXYlSrZyrvLo7DtDjCwS6u7unEkJVXS12FTvdJM5AlGa",
            "content": {
                "kind": "ak.content.text",
                "body": "a"
            }
        }),
    );
    let duplicate_b = sample_envelope_event(
        "ak.message.create",
        2,
        "01970e589d22-0001-a13f9c2e",
        "2026-05-02T00:00:01.000Z",
        json!({
            "strand_id": "ak:strand:AXYlSrZyrvLo7DtDjCwS6u7unEkJVXS12FTvdJM5AlGa",
            "content": {
                "kind": "ak.content.text",
                "body": "b"
            }
        }),
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
        "ak.message.create",
        3,
        "01970e700000-0001-a13f9c2e",
        "2026-05-02T00:30:00.000Z",
        json!({
            "strand_id": "ak:strand:AXYlSrZyrvLo7DtDjCwS6u7unEkJVXS12FTvdJM5AlGa",
            "content": {
                "kind": "ak.content.text",
                "body": "future"
            }
        }),
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
        "ak:did_core:web:alice.example".to_owned(),
        "2026-05-02T00:05:00.000Z".to_owned(),
    );
    let backdated = sample_envelope_event(
        "ak.message.create",
        4,
        "01970e589d23-0001-a13f9c2e",
        "2026-05-02T00:00:02.000Z",
        json!({
            "strand_id": "ak:strand:AXYlSrZyrvLo7DtDjCwS6u7unEkJVXS12FTvdJM5AlGa",
            "content": {
                "kind": "ak.content.text",
                "body": "backdated"
            }
        }),
    );
    let backdated_decision = validate_event_envelope(&backdated, event_kinds, &revoked_context)?;
    assert_event_decision(
        &backdated_decision,
        "reject",
        Some("authorization_denied"),
        "backdated_event_after_revoke",
    )?;

    // Unknown top-level field MUST be rejected (envelope root is
    // `additionalProperties:false`). Inject an unregistered field
    // (`space_id`) onto an otherwise-valid event and assert hard rejection.
    let mut unknown_field_event = sample_envelope_event(
        "ak.message.create",
        5,
        "01970e589d24-0001-a13f9c2e",
        "2026-05-02T00:00:03.000Z",
        json!({
            "strand_id": "ak:strand:AXYlSrZyrvLo7DtDjCwS6u7unEkJVXS12FTvdJM5AlGa",
            "content": {
                "kind": "ak.content.text",
                "body": "unregistered field"
            }
        }),
    );
    unknown_field_event["space_id"] =
        json!("ak:space:AafktYXx8-v8PgfMovcpfbkFAJzUiT8l2GHJJ9UmF3fP");
    let unknown_field_decision =
        validate_event_envelope(&unknown_field_event, event_kinds, &context)?;
    assert_event_decision(
        &unknown_field_decision,
        "reject",
        Some("schema_violation"),
        "unknown_top_level_field_rejected",
    )?;

    Ok(())
}

fn validate_event_envelope(
    event: &Value,
    event_kinds: &HashMap<String, EventKindInfo>,
    context: &EventEnvelopeContext,
) -> Result<EventEnvelopeDecision> {
    let Some(event_object) = event.as_object() else {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "event envelope must be an object",
        ));
    };
    let canonical_len = canonical_json(event)?.len();
    if canonical_len > context.max_canonical_bytes {
        return Ok(EventEnvelopeDecision::reject(
            "payload_too_large",
            "canonical Event envelope exceeds byte cap",
        ));
    }

    // event-envelope.schema.json roots `additionalProperties:false`: any
    // top-level field outside this set MUST be rejected. This is the hard
    // guard against unregistered/forbidden envelope fields (`schema`,
    // `schema_id`, `space_id`, …) reaching the wire.
    const ALLOWED_TOP_LEVEL_FIELDS: &[&str] = &[
        "event_id",
        "kind",
        "realm_id",
        "scope_ref",
        "actor_id",
        "principal_server_id",
        "executed_by",
        "authorization_ref",
        "applet_id",
        "external_ref",
        "actor_kind",
        "actor_seq",
        "created_at",
        "hlc",
        "prev_refs",
        "refs",
        "causal_refs",
        "preconditions",
        "seal_ref",
        "auth_context",
        "seal_basis",
        "payload",
        "redacts",
        "unsigned",
        "proofs",
        "requirements",
    ];
    if let Some(unknown) = event_object
        .keys()
        .find(|key| !ALLOWED_TOP_LEVEL_FIELDS.contains(&key.as_str()))
    {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            format!("unknown top-level Event field: {unknown}"),
        ));
    }

    let kind = match event.get("kind").and_then(Value::as_str) {
        Some(kind) if kind.starts_with("ak.") => kind,
        Some(_) | None => {
            return Ok(EventEnvelopeDecision::reject(
                "schema_violation",
                "Event.kind MUST use registered ak.* spelling",
            ));
        }
    };

    let Some(kind_info) = event_kinds.get(kind) else {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "Event.kind is not registered",
        ));
    };
    if kind_info.status != "active" {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "Event.kind is not an active registry entry",
        ));
    }
    if context.durable_history && kind_info.wire_scope != "durable_event" {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "non-durable event kind submitted to durable Event history",
        ));
    }

    // Spec event-envelope.schema.json required fields:
    //   event_id, kind, realm_id, actor_id, principal_server_id, actor_seq, created_at,
    //   prev_refs, refs, payload, proofs
    // `refs` MUST be present per spec — negative fixture
    // `reject_missing_refs[role=authorized_by]` exercises this. `prev_refs`
    // is also required.
    for field in [
        "event_id",
        "realm_id",
        "actor_id",
        "principal_server_id",
        "actor_seq",
        "created_at",
        "prev_refs",
        "refs",
        "payload",
        "proofs",
    ] {
        if event.get(field).is_none() {
            return Ok(EventEnvelopeDecision::reject(
                "schema_violation",
                format!("missing required Event field {field}"),
            ));
        }
    }
    if !value_field_str(event, "event_id")?.starts_with("ak:event:") {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "invalid event_id",
        ));
    }
    if !value_field_str(event, "realm_id")?.starts_with("ak:realm:") {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "invalid realm_id",
        ));
    }
    if !value_field_str(event, "actor_id")?.starts_with("ak:did_core:") {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "invalid actor_id",
        ));
    }
    if arkret_identifiers::DidCoreId::new(value_field_str(event, "principal_server_id")?).is_err() {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "invalid principal_server_id",
        ));
    }
    let actor_seq = value_field_u64(event, "actor_seq")?;
    let prev_refs = value_array(
        event
            .get("prev_refs")
            .ok_or_else(|| anyhow!("event.prev_refs missing after required-field check"))?,
        "event.prev_refs",
    )?;
    let extra_refs = value_array(
        event
            .get("refs")
            .ok_or_else(|| anyhow!("event.refs missing after required-field check"))?,
        "event.refs",
    )?;
    let content = event
        .get("payload")
        .ok_or_else(|| anyhow!("event.payload missing after required-field check"))?;
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
            "schema_violation",
            "prev_refs_too_large",
        ));
    }
    let event_id = value_field_str(event, "event_id")?;
    // Spec post-2026-05-08: `refs[]` entries MUST be typed-ref objects
    // `{id: "ak:<kind>:<ulid>", role, critical, ...}`. v1 is unreleased,
    // so no dual-pattern accommodation: bare string entries fail loudly.
    // `prev_refs[]` is a bare-string list of `ak:event:` ids per spec
    // §refs.
    let valid_ref = |s: &str| s.starts_with("ak:");
    let extra_refs_invalid = extra_refs.iter().any(|value| {
        value
            .get("id")
            .and_then(Value::as_str)
            .is_none_or(|id| !valid_ref(id))
    });
    let prev_refs_invalid = prev_refs.iter().any(|value| {
        value
            .as_str()
            .is_none_or(|event_ref| !event_ref.starts_with("ak:event:"))
    });
    if extra_refs_invalid || prev_refs_invalid {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "prev_refs / refs must contain typed ak: refs",
        ));
    }
    if extra_refs.iter().any(|reference| {
        reference.get("role").and_then(Value::as_str) == Some("authorized_by")
            && reference
                .get("id")
                .and_then(Value::as_str)
                .is_none_or(|id| !id.starts_with("ak:grant:"))
    }) {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "refs[role=authorized_by] must contain immutable ak:grant: ids",
        ));
    }
    if prev_refs
        .iter()
        .any(|value| value.as_str() == Some(event_id))
    {
        return Ok(EventEnvelopeDecision::reject(
            "causal_conflict",
            "prev_refs MUST NOT contain the event's own event_id",
        ));
    }

    if let Some(frontier) = &context.actor_frontier
        && frontier.actor_id == value_field_str(event, "actor_id")?
        && actor_seq <= frontier.actor_seq
    {
        return Ok(EventEnvelopeDecision::reject(
            "causal_conflict",
            "actor_seq must monotonically advance actor frontier",
        ));
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
        && value_field_str(event, "created_at")? <= revoked_at.as_str()
    {
        return Ok(EventEnvelopeDecision::reject(
            "authorization_denied",
            "backdated event after revoke",
        ));
    }

    // Check critical_extensions in both event.critical_extensions and
    // event.requirements.critical_extensions
    let critical_extensions_iter = event
        .get("critical_extensions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            event
                .get("requirements")
                .and_then(|r| r.get("critical_extensions"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        );
    for extension in critical_extensions_iter {
        let id = required_str(extension, "id")?;
        if extension.get("fail_closed").and_then(Value::as_bool) == Some(true)
            && !context.supported_features.contains(id)
        {
            return Ok(EventEnvelopeDecision::reject(
                "unsupported_feature",
                "unknown critical extension must fail closed",
            ));
        }
    }

    if let Some(error) = validate_event_payload(kind, content) {
        return Ok(EventEnvelopeDecision::reject("schema_violation", error));
    }

    // Per spec encoding.md §1.6/§4 and the canonical `event_proof` schema
    // (`additionalProperties:false`, `required` includes `event_digest`):
    // the Event content fingerprint is carried by `proof.event_digest ≡
    // canonical_digest(event_without_proofs_unsigned)`. There is no
    // proof-level `payload_digest` for Event proofs. `domain`/`audience` are
    // optional binding context folded into the signed JWS bytes, but they do
    // NOT change `event_digest`: it MUST always equal the canonical Event
    // digest. (The negative vector `reject_signature_event_digest_mismatch`
    // carries `domain` yet still expects rejection on digest mismatch — so the
    // comparison is unconditional.) Real JWS signature verification (Ed25519
    // signing-key check) happens at proof-verify time and is out of scope for
    // the envelope-shape validator.
    let computed_canonical = canonical_event_payload_digest(event)?;
    let zero_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    for proof in event
        .get("proofs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let proof_hash = proof.get("event_digest").and_then(Value::as_str);
        let Some(proof_hash) = proof_hash else {
            return Ok(EventEnvelopeDecision::reject(
                "signature_invalid",
                "proof.event_digest missing",
            ));
        };
        if !looks_like_sha256_digest(proof_hash) {
            return Ok(EventEnvelopeDecision::reject(
                "signature_invalid",
                "proof.event_digest must be sha256:<hex>",
            ));
        }
        // Sentinel zero-hash always rejects — used by negative fixtures to
        // simulate tamper / mismatch without exercising real JWS crypto.
        if proof_hash == zero_digest {
            return Ok(EventEnvelopeDecision::reject(
                "signature_invalid",
                "proof.event_digest is the zero sentinel — tampered envelope",
            ));
        }
        if proof_hash != computed_canonical.as_str() {
            return Ok(EventEnvelopeDecision::reject(
                "signature_invalid",
                "proof.event_digest does not match canonical Event bytes without proofs",
            ));
        }
    }

    Ok(EventEnvelopeDecision::accept())
}

fn validate_event_payload(kind: &str, content: &Value) -> Option<String> {
    match kind {
        "ak.message.create" => {
            if content.get("strand_id").and_then(Value::as_str).is_none() {
                return Some("message create content missing strand_id".to_owned());
            }
            // Check for v1 message body/encryption fields at the payload level.
            let has_body = ["content", "encrypted_content", "blob_refs"]
                .iter()
                .any(|field| content.get(*field).is_some());
            let has_nested_body = content
                .get("content")
                .map(|c| {
                    ["kind", "body", "parts"]
                        .iter()
                        .any(|field| c.get(*field).is_some())
                })
                .unwrap_or(false);
            if !has_body && !has_nested_body {
                return Some(
                    "message create content missing content/encrypted_content/blob_refs".to_owned(),
                );
            }
            None
        }
        "ak.strand.move" => {
            missing_payload_fields(content, &["board_id", "strand_id", "to_list_id", "rank"])
        }
        "ak.strand.reorder" => {
            missing_payload_fields(content, &["board_id", "strand_id", "list_id", "rank"])
        }
        "ak.container.move_item" => serde_json::from_value::<
            arkret_models_collaboration::events_payloads::ContainerMoveItemPayload,
        >(content.clone())
        .map_err(|error| error.to_string())
        .and_then(|payload| payload.validate().map_err(|error| error.to_string()))
        .err(),
        "ak.container.rebalance" => serde_json::from_value::<
            arkret_models_collaboration::events_payloads::ContainerRebalancePayload,
        >(content.clone())
        .map_err(|error| error.to_string())
        .and_then(|payload| payload.validate().map_err(|error| error.to_string()))
        .err(),
        "ak.realm.notary" => serde_json::from_value::<
            arkret_models_collaboration::events_payloads::RealmNotaryPayload,
        >(content.clone())
        .map_err(|error| error.to_string())
        .and_then(|payload| payload.validate().map_err(|error| error.to_string()))
        .err(),
        "ak.realm.digest_suite_transition" => serde_json::from_value::<
            arkret_models_collaboration::events_payloads::RealmDigestSuiteTransitionPayload,
        >(content.clone())
        .map_err(|error| error.to_string())
        .and_then(|payload| payload.validate().map_err(|error| error.to_string()))
        .err(),
        "ak.member.state" => {
            if let Some(err) = missing_payload_fields(content, &["membership"]) {
                return Some(err);
            }
            // Spec 0a5ab85 (`membership_payload` conditional required):
            // `membership=join` ⇒ `actor_id` + `delivery_status` required;
            // `delivery_status=routable` ⇒ `delivery_binding` required.
            if content.get("membership").and_then(Value::as_str) == Some("join") {
                if let Some(err) = missing_payload_fields(content, &["actor_id", "delivery_status"])
                {
                    return Some(err);
                }
                if content.get("delivery_status").and_then(Value::as_str) == Some("routable")
                    && content.get("delivery_binding").is_none()
                {
                    return Some(
                        "payload content missing delivery_binding (delivery_status=routable)"
                            .to_owned(),
                    );
                }
            }
            None
        }
        _ => None,
    }
}

fn missing_payload_fields(content: &Value, fields: &[&str]) -> Option<String> {
    fields
        .iter()
        .find(|field| content.get(**field).is_none())
        .map(|field| format!("payload content missing {field}"))
}

// ── Internal types ──────────────────────────────────────────────────────────

#[derive(Clone)]
pub(crate) struct EventKindInfo {
    pub(crate) status: String,
    pub(crate) wire_scope: String,
}

pub(crate) fn event_kind_metadata(registry: &Value) -> Result<HashMap<String, EventKindInfo>> {
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
            },
        );
    }
    Ok(event_kinds)
}

pub(crate) fn event_without_proofs(event: &Value) -> Result<Value> {
    arkret_wire::event_digest_preimage(event).map_err(Into::into)
}

pub(crate) fn canonical_event_payload(event: &Value) -> Result<String> {
    super::canonical_json(&event_without_proofs(event)?)
}

pub(crate) fn canonical_event_payload_digest(event: &Value) -> Result<String> {
    Ok(super::sha256_prefixed(
        canonical_event_payload(event)?.as_bytes(),
    ))
}

pub(crate) fn canonical_event_digest(event: &Value) -> Result<String> {
    Ok(super::sha256_prefixed(
        super::canonical_json(event)?.as_bytes(),
    ))
}

pub(crate) fn event_feature_ids(event: &Value) -> Result<BTreeSet<String>> {
    let mut ids = BTreeSet::new();
    // Check both top-level and requirements-level feature fields
    let sources: Vec<&Value> = vec![event]
        .into_iter()
        .chain(event.get("requirements"))
        .collect();
    for source in &sources {
        for field in ["required_features", "critical_extensions"] {
            for value in source
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
    }
    Ok(ids)
}

struct EventEnvelopeContext {
    durable_history: bool,
    supported_features: BTreeSet<String>,
    actor_frontier: Option<ActorFrontier>,
    revoked_at_by_actor: BTreeMap<String, String>,
    max_canonical_bytes: usize,
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
            max_canonical_bytes: 1_048_576,
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

fn sample_envelope_event(
    kind: &str,
    actor_seq: u64,
    hlc: &str,
    created_at: &str,
    content: Value,
) -> Value {
    // Synthetic events emit the active spec shape directly (top-level fields
    // restricted to the canonical envelope property set — no `schema`).
    let mut event = json!({
        "event_id": "ak:event:AbmZo_Q7CHRfJYVqari3NAaEZm6tfSbZppTL7IsJJ7Gl",
        "kind": kind,
        "realm_id": "ak:realm:AXvhSdy6b-PYcJNuFcYsp-gKHjg-PECuUtuV08YJYwhK",
        "actor_id": "ak:did_core:web:alice.example",
        "principal_server_id": "ak:did_core:web:principal.example",
        "actor_seq": actor_seq,
        "created_at": created_at,
        "hlc": hlc,
        "prev_refs": [],
        "refs": [{
            "id": "ak:event:AVkkQ3SRXwZhSvXw0hnu-AeFeMX_3g54oqAZWM4qri4H",
            "role": "reply_to",
            "critical": false
        }],
        "payload": content,
        // Synthetic placeholder proof. `event_digest` is filled below with the
        // real canonical Event digest so the envelope-shape validator's
        // `event_digest == canonical(event_without_proofs_unsigned)` check
        // passes. Real Ed25519 verify happens elsewhere.
        "proofs": [{
            "kind": "detached_jws",
            "verification_method": "did:web:alice.example#k1",
            "event_digest": "",
            "created_at": created_at,
            "domain": "arkret-event-v1",
            "jws": "eyJhbGciOiJFZDI1NTE5In0..synthetic_placeholder_signature_bytes"
        }]
    });
    let digest =
        canonical_event_payload_digest(&event).expect("synthetic event is canonicalizable");
    event["proofs"][0]["event_digest"] = Value::String(digest);
    event
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
    if let Some(expected_error_code) = expected_error_code
        && actual.error_code != Some(expected_error_code)
    {
        bail!(
            "event envelope {context} expected error {expected_error_code}, got {:?} ({})",
            actual.error_code,
            actual.reason
        );
    }
    Ok(())
}
