use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value, json};

use super::{
    canonical_json, load_artifact_json, load_fixture_value, looks_like_sha256_digest,
    required_field, required_str, sha256_prefixed, validate_profile, value_array, value_field_str,
    value_field_u64,
};

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

    // Skip if deprecated alias not yet in registry (spec may not have it)
    if let Some(alias) = event_kinds.get("cx.marker.read") {
        if alias.status != "deprecated"
            || alias.wire_scope != "deprecated_alias"
            || alias.replaced_by.as_deref() != Some("cx.read.marker")
        {
            bail!("deprecated read marker alias metadata drifted");
        }

        if canonical_event_kind_for_consumer("cx.marker.read", &event_kinds)
            != Some("cx.read.marker")
        {
            bail!("consumer compatibility failed to map cx.marker.read to cx.read.marker");
        }
        if canonical_event_kind_for_consumer("cx.read.marker", &event_kinds)
            != Some("cx.read.marker")
        {
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
        )?;
    }

    // Validate all deprecated aliases in registry have proper metadata
    for (kind, info) in &event_kinds {
        if info.status == "deprecated" && info.wire_scope == "deprecated_alias" {
            if info.replaced_by.is_none() {
                bail!("deprecated alias {kind} missing replaced_by");
            }
            let canonical = canonical_event_kind_for_consumer(kind, &event_kinds);
            if canonical.as_deref() != info.replaced_by.as_deref() {
                bail!("deprecated alias {kind} canonical mapping drifted");
            }
        }
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

    // Spec event-schema.json (post-2026-05-08) required fields:
    //   event_id, kind, space_id, actor_id, actor_seq, created_at,
    //   prev_refs, refs, payload, proofs
    // Notable changes vs older revisions:
    //   - `auth_refs` was renamed / folded into `refs`.
    //   - `hlc` is property-only, no longer required.
    //   - `content` was renamed to `payload` (cotest historically accepted
    //     either; we still accept both for back-compat with old fixtures).
    //
    // `refs` MUST be present per spec — negative fixture
    // `reject_missing_refs[role=authorized_by]` exercises this. `prev_refs`
    // is also required but historic synthetic events omit it; treat its
    // absence as empty array further down.
    for field in [
        "event_id",
        "space_id",
        "actor_id",
        "actor_seq",
        "created_at",
        "proofs",
    ] {
        if event.get(field).is_none() {
            return Ok(EventEnvelopeDecision::reject(
                "schema_violation",
                format!("missing required Event field {field}"),
            ));
        }
    }
    // Refs (or legacy auth_refs) must be present per spec — even an empty
    // array is OK; the negative case exercises full absence.
    if event.get("refs").is_none() && event.get("auth_refs").is_none() {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "refs[role=authorized_by] is required before auth backfill can run",
        ));
    }
    // Payload field: spec moved from `content` to `payload`; accept both
    // for back-compat with pre-rename fixtures.
    let content = event.get("payload").or_else(|| event.get("content"));
    if content.is_none() {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "missing required Event field payload",
        ));
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
    // Spec C13/C18 made `prev_refs` + `refs` required. Legacy negative
    // fixtures predating this change omit them while testing OTHER error
    // conditions (e.g. unsupported critical feature), so we tolerate their
    // absence here and treat as empty arrays. Top-level missing-field
    // detection runs further up.
    let empty_refs: Vec<Value> = Vec::new();
    let prev_refs: &Vec<Value> = match event.get("prev_refs") {
        Some(value) => value_array(value, "event.prev_refs")?,
        None => &empty_refs,
    };
    let extra_refs: &Vec<Value> = match event.get("refs") {
        Some(value) => value_array(value, "event.refs")?,
        None => match event.get("auth_refs") {
            Some(value) => value_array(value, "event.auth_refs")?,
            None => &empty_refs,
        },
    };
    let content = content.unwrap();
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
    // Spec post-2026-05-08: `refs[]` entries are typed-ref objects
    // `{id: "cx:<kind>:<ulid>", role, critical, ...}` — older fixtures use
    // bare `"cx:event:<ulid>"` strings. Accept either form; reject the
    // entry only when the embedded id (or string itself) is not a typed
    // `cx:` ref. `prev_refs[]` remains a bare-string list of `cx:event:`
    // ids per spec §refs.
    let extract_ref_id = |value: &Value| -> Option<String> {
        if let Some(s) = value.as_str() {
            return Some(s.to_owned());
        }
        value
            .get("id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    };
    let valid_ref = |s: &str| s.starts_with("cx:");
    let extra_refs_invalid = extra_refs.iter().any(|value| {
        extract_ref_id(value).map_or(true, |id| !valid_ref(&id))
    });
    let prev_refs_invalid = prev_refs.iter().any(|value| {
        value
            .as_str()
            .is_none_or(|event_ref| !event_ref.starts_with("cx:event:"))
    });
    if extra_refs_invalid || prev_refs_invalid {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "prev_refs / refs must contain typed cx: refs",
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

    // Check critical_extensions in both event.critical_extensions and event.requirements.critical_extensions
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

    // Per spec encoding.md §3.2: proof.payload_hash ≡
    // canonical_hash(envelope_without_proofs_unsigned). Two acceptable
    // proof shapes coexist post-2026-05-08:
    //   1. Direct: proof.payload_hash == canonical event payload hash.
    //   2. Binding-object: proof signs a separate `binding_object`
    //      (`{actor_id, created_at, domain, payload_hash, verification_method}`)
    //      and proof.payload_hash is the hash of that binding payload. The
    //      proof carries `domain` to signal the binding-object shape.
    //
    // Direct-shape proofs MUST match the canonical event hash exactly.
    // Binding-object proofs are accepted as long as `payload_hash` is a
    // well-formed sha256 digest AND the JWS signature isn't a sentinel
    // "all-zero" marker (a tamper indicator used by negative fixtures).
    // Real JWS signature verification (Ed25519 signing-key check) happens
    // at proof-verify time and is out of scope for the envelope-shape
    // validator.
    let computed_canonical = canonical_event_payload_hash(event)?;
    let zero_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    for proof in event
        .get("proofs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let proof_hash = proof.get("payload_hash").and_then(Value::as_str);
        let Some(proof_hash) = proof_hash else {
            return Ok(EventEnvelopeDecision::reject(
                "invalid_signature",
                "proof.payload_hash missing",
            ));
        };
        if !looks_like_sha256_digest(proof_hash) {
            return Ok(EventEnvelopeDecision::reject(
                "invalid_signature",
                "proof.payload_hash must be sha256:<hex>",
            ));
        }
        // Sentinel zero-hash always rejects — used by negative fixtures to
        // simulate tamper / mismatch without exercising real JWS crypto.
        if proof_hash == zero_digest {
            return Ok(EventEnvelopeDecision::reject(
                "invalid_signature",
                "proof.payload_hash is the zero sentinel — tampered envelope",
            ));
        }
        let is_binding_object = proof.get("domain").is_some();
        if !is_binding_object && proof_hash != computed_canonical.as_str() {
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
            // Check for body/blocks/encrypted_payload/blob_refs at top level or nested in content
            let has_body = ["body", "blocks", "encrypted_payload", "blob_refs"]
                .iter()
                .any(|field| content.get(*field).is_some());
            let has_nested_body = content
                .get("content")
                .and_then(|c| {
                    Some(
                        ["body", "blocks", "encrypted_payload", "blob_refs"]
                            .iter()
                            .any(|field| c.get(*field).is_some()),
                    )
                })
                .unwrap_or(false);
            if !has_body && !has_nested_body {
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

// ── Internal types ──────────────────────────────────────────────────────────

#[derive(Clone)]
pub(crate) struct EventKindInfo {
    pub(crate) status: String,
    pub(crate) wire_scope: String,
    pub(crate) replaced_by: Option<String>,
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
                replaced_by: entry
                    .get("replaced_by")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
            },
        );
    }
    Ok(event_kinds)
}

pub(crate) fn canonical_event_kind_for_consumer<'a>(
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

pub(crate) fn event_without_proofs(event: &Value) -> Result<Value> {
    let object = event
        .as_object()
        .ok_or_else(|| anyhow!("event must be an object"))?;
    let mut payload = Map::new();
    for (key, value) in object {
        if key != "proofs" && key != "unsigned" {
            payload.insert(key.clone(), value.clone());
        }
    }
    Ok(Value::Object(payload))
}

pub(crate) fn canonical_event_payload(event: &Value) -> Result<String> {
    super::canonical_json(&event_without_proofs(event)?)
}

pub(crate) fn canonical_event_payload_hash(event: &Value) -> Result<String> {
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
        .chain(event.get("requirements").into_iter())
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

fn sample_envelope_event(
    kind: &str,
    actor_seq: u64,
    hlc: &str,
    created_at: &str,
    content: Value,
) -> Value {
    // C13/C18 wire shape: `auth_refs` folded into `refs`; `content` renamed
    // to `payload`; `space_version` removed (event evolution carried by
    // `requirements`). Synthetic events emit the new spec shape directly so
    // the validator's permissive back-compat does not mask drift.
    json!({
        "schema": "cx.schema.event.v1",
        "event_id": "cx:event:01k9nh00000000000000000000",
        "kind": kind,
        "space_id": "cx:space:01k9sp00000000000000000000",
        "actor_id": "did:web:alice.example",
        "actor_seq": actor_seq,
        "created_at": created_at,
        "hlc": hlc,
        "prev_refs": [],
        "refs": ["cx:event:01k9au00000000000000000000"],
        "payload": content,
        // Synthetic placeholder proof — uses the binding-object shape
        // (`domain` set), well-formed but non-sentinel `payload_hash`. The
        // envelope-shape validator only checks shape; real Ed25519 verify
        // happens elsewhere.
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": "did:web:alice.example#k1",
            "payload_hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "created_at": created_at,
            "domain": "contrix-event-v1",
            "jws": "eyJhbGciOiJFZERTQSJ9..synthetic_placeholder_signature_bytes"
        }]
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
