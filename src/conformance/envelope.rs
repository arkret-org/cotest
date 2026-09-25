use std::collections::{BTreeSet, HashMap};

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{
    canonical_json, load_artifact_json, load_fixture_value, looks_like_sha256_digest,
    required_field, required_str, validate_profile, value_array, value_field_str,
};
use crate::transcripts::record_vector_event;

pub fn run_event_envelope_fixture_suite() -> Result<()> {
    let event_kind_registry = load_artifact_json("registry/event-kind-registry.json")?;
    let event_kinds = event_kind_metadata(&event_kind_registry)?;

    let crypto_fixture = load_fixture_value("crypto-signature-fixture.json")?;
    validate_profile(&crypto_fixture, "ak.vector_group.crypto_signature.v1")?;
    super::crypto_signature::run_crypto_signature_fixture(&crypto_fixture)?;
    validate_synthetic_event_envelope_negatives(&event_kinds)?;

    Ok(())
}

// ── Internal validation functions ───────────────────────────────────────────

fn validate_synthetic_event_envelope_negatives(
    event_kinds: &HashMap<String, EventKindInfo>,
) -> Result<()> {
    let base = sample_envelope_event(
        "ak.message.create",
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

    // Unknown top-level field MUST be rejected (envelope root is
    // `additionalProperties:false`). Inject an unregistered field
    // (`space_id`) onto an otherwise-valid event and assert hard rejection.
    let mut unknown_field_event = sample_envelope_event(
        "ak.message.create",
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

/// The closed top-level field set of an Event envelope, read from the schema
/// that declares it.
fn registered_event_envelope_fields() -> Result<&'static BTreeSet<String>> {
    static FIELDS: std::sync::OnceLock<BTreeSet<String>> = std::sync::OnceLock::new();
    if let Some(fields) = FIELDS.get() {
        return Ok(fields);
    }
    let schema = load_artifact_json("schemas/event-envelope.schema.json")?;
    if schema.get("additionalProperties") != Some(&Value::Bool(false)) {
        bail!("the Event envelope schema root stopped being a closed object");
    }
    let fields = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("event-envelope.schema.json declares no root properties"))?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    Ok(FIELDS.get_or_init(|| fields))
}

fn registered_event_envelope_required() -> Result<&'static Vec<String>> {
    static REQUIRED: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    if let Some(required) = REQUIRED.get() {
        return Ok(required);
    }
    let schema = load_artifact_json("schemas/event-envelope.schema.json")?;
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event-envelope.schema.json declares no required set"))?
        .iter()
        .map(|field| {
            field
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("required Event field must be a string"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(REQUIRED.get_or_init(|| required))
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

    // `event-envelope.schema.json` roots `additionalProperties: false`, so the
    // registered property set *is* the allow-list. It is read from the artifact
    // rather than restated here: a hand-copied list is a second spelling of a
    // published set, and this one went stale the moment `data_basis` was
    // registered -- rejecting a field the schema allows, on every Event that
    // carries it.
    let allowed = registered_event_envelope_fields()?;
    if let Some(unknown) = event_object
        .keys()
        .find(|key| !allowed.contains(key.as_str()))
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
        // An unregistered kind the Event itself declares as a fail-closed
        // critical extension is an unsupported *declared capability*, not a
        // malformed envelope: api-conventions.md §5.1 binds
        // `requirements.critical_extensions[]` to `unsupported_feature` and
        // forbids substituting the two codes for one another.
        if declares_unsupported_critical_extension(event, context)? {
            return Ok(EventEnvelopeDecision::reject(
                "unsupported_feature",
                "unknown critical extension must fail closed",
            ));
        }
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

    // The required set is read from event-envelope.schema.json, like the
    // closed property set above.
    for field in registered_event_envelope_required()? {
        if event.get(field.as_str()).is_none() {
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
    if event
        .get("realm_id")
        .and_then(Value::as_str)
        .is_some_and(|realm| !realm.starts_with("ak:realm:"))
    {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "invalid realm_id",
        ));
    }
    let actor_id = match super::value_field_actor(event, "actor_id") {
        Ok(actor) => actor,
        Err(_) => {
            return Ok(EventEnvelopeDecision::reject(
                "schema_violation",
                "invalid actor_id",
            ));
        }
    };
    let extra_refs: &[Value] = if let Some(refs) = event.get("semantic_refs") {
        let refs = value_array(refs, "event.semantic_refs")?;
        if refs.is_empty() {
            return Ok(EventEnvelopeDecision::reject(
                "schema_violation",
                "event.semantic_refs must be omitted when empty",
            ));
        }
        refs
    } else {
        &[]
    };
    if let Some(causal_refs) = event.get("causal_refs") {
        let causal_refs = value_array(causal_refs, "event.causal_refs")?;
        if causal_refs.is_empty() {
            return Ok(EventEnvelopeDecision::reject(
                "schema_violation",
                "event.causal_refs must be omitted when empty",
            ));
        }
    }
    let content = event
        .get("payload")
        .ok_or_else(|| anyhow!("event.payload missing after required-field check"))?;
    if !content.is_object() {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "Event.content must be an object",
        ));
    }
    if !required_field(event, "producer_proof")?.is_object() {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "event.producer_proof must be an object",
        ));
    }

    // `semantic_refs[]` entries MUST be typed-ref objects
    // `{id: "ak:<kind>:<ulid>", role, critical, ...}`. v1 is unreleased,
    // so no dual-pattern accommodation: bare string entries fail loudly.
    let valid_ref = |s: &str| s.starts_with("ak:");
    let extra_refs_invalid = extra_refs.iter().any(|value| {
        value
            .get("id")
            .and_then(Value::as_str)
            .is_none_or(|id| !valid_ref(id))
    });
    if extra_refs_invalid {
        return Ok(EventEnvelopeDecision::reject(
            "schema_violation",
            "semantic_refs must contain typed ak: refs",
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
            "semantic_refs[role=authorized_by] must contain immutable ak:grant: ids",
        ));
    }
    if declares_unsupported_critical_extension(event, context)? {
        return Ok(EventEnvelopeDecision::reject(
            "unsupported_feature",
            "unknown critical extension must fail closed",
        ));
    }

    if let Some(error) = validate_event_payload(kind, content) {
        return Ok(EventEnvelopeDecision::reject("schema_violation", error));
    }

    // key-management.md 4.1: a non-bootstrap `ak.device.authorize` lives in the
    // owning principal's Principal Control Realm. A service actor has no
    // principal device directory, so it can never be authoring inside one --
    // the envelope alone settles that direction of the rule.
    if kind == "ak.device.authorize"
        && content.get("authorized_by").is_some()
        && !matches!(actor_id, arkret_wire::ActorId::Account { .. })
    {
        return Ok(EventEnvelopeDecision::reject(
            "failed_precondition",
            "ak.device.authorize was authored outside a Principal Control Realm",
        ));
    }

    // Per spec encoding.md §1.6/§4 and the canonical `event_proof` schema
    // (`additionalProperties:false`, `required` includes `event_digest`):
    // the Event content fingerprint is carried by `proof.event_digest ≡
    // canonical_digest(event_without_producer_proof_unsigned)`. There is no
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
    let Some(proof) = event.get("producer_proof").and_then(Value::as_object) else {
        return Ok(EventEnvelopeDecision::reject(
            "signature_invalid",
            "producer_proof missing",
        ));
    };
    let proof_hash = proof.get("event_digest").and_then(Value::as_str);
    let Some(proof_hash) = proof_hash else {
        return Ok(EventEnvelopeDecision::reject(
            "signature_invalid",
            "producer_proof.event_digest missing",
        ));
    };
    if !looks_like_sha256_digest(proof_hash) {
        return Ok(EventEnvelopeDecision::reject(
            "signature_invalid",
            "producer_proof.event_digest must be sha256:<hex>",
        ));
    }
    // Sentinel zero-hash always rejects — used by negative fixtures to
    // simulate tamper / mismatch without exercising real JWS crypto.
    if proof_hash == zero_digest {
        return Ok(EventEnvelopeDecision::reject(
            "signature_invalid",
            "producer_proof.event_digest is the zero sentinel — tampered envelope",
        ));
    }
    if proof_hash != computed_canonical.as_str() {
        return Ok(EventEnvelopeDecision::reject(
            "signature_invalid",
            "producer_proof.event_digest does not match canonical Event bytes without producer_proof",
        ));
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
        "ak.member.state" => {
            if let Some(err) = missing_payload_fields(content, &["member_id", "membership"]) {
                return Some(err);
            }
            // A joining member is an exact ActorId. Its AccountId or hosted
            // Station component is the route truth; no delivery sidecar exists.
            if content.get("membership").and_then(Value::as_str) == Some("join")
                && let Some(err) = missing_payload_fields(content, &["realm_id"])
            {
                return Some(err);
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

pub(crate) fn event_without_producer_proof(event: &Value) -> Result<Value> {
    arkret_wire::event_digest_preimage(event).map_err(Into::into)
}

pub(crate) fn canonical_event_payload(event: &Value) -> Result<String> {
    super::canonical_json(&event_without_producer_proof(event)?)
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

struct EventEnvelopeContext {
    durable_history: bool,
    supported_features: BTreeSet<String>,
    max_canonical_bytes: usize,
}

impl EventEnvelopeContext {
    fn default_for_durable_history() -> Self {
        Self {
            durable_history: true,
            supported_features: BTreeSet::new(),
            max_canonical_bytes: 1_048_576,
        }
    }
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
}

fn sample_envelope_event(kind: &str, created_at: &str, content: Value) -> Value {
    // Synthetic events emit the active spec shape directly (top-level fields
    // restricted to the canonical envelope property set — no `schema`).
    let mut event = json!({
        "event_id": "ak:event:AbmZo_Q7CHRfJYVqari3NAaEZm6tfSbZppTL7IsJJ7Gl",
        "kind": kind,
        "realm_id": "ak:realm:AXvhSdy6b-PYcJNuFcYsp-gKHjg-PECuUtuV08YJYwhK",
        "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AXvhSdy6b-PYcJNuFcYsp-gKHjg-PECuUtuV08YJYwhK"},
        "actor_id": {"kind":"account", "account_id":{"principal_id":"ak:did_core:web:alice.example", "station_id":"ak:did_core:web:principal.example"}},
        "created_at": created_at,
        "semantic_refs": [{
            "id": "ak:event:AVkkQ3SRXwZhSvXw0hnu-AeFeMX_3g54oqAZWM4qri4H",
            "role": "reply_to",
            "critical": false
        }],
        "payload": content,
        // Synthetic placeholder proof. `event_digest` is filled below with the
        // real canonical Event digest so the envelope-shape validator's
        // `event_digest == canonical(event_without_producer_proof_unsigned)` check
        // passes. Real Ed25519 verify happens elsewhere.
        "producer_proof": {
            "kind": "detached_jws",
            "verification_method": "did:web:alice.example#k1",
            "event_digest": "",
            "created_at": created_at,
            "domain": "arkret-event-v1",
            "jws": "eyJhbGciOiJFZDI1NTE5In0..synthetic_placeholder_signature_bytes"
        }
    });
    let digest =
        canonical_event_payload_digest(&event).expect("synthetic event is canonicalizable");
    event["producer_proof"]["event_digest"] = Value::String(digest);
    event
}

/// Whether the Event declares a fail-closed critical extension this receiver
/// has not advertised. `requirements.critical_extensions` is the only carrier.
fn declares_unsupported_critical_extension(
    event: &Value,
    context: &EventEnvelopeContext,
) -> Result<bool> {
    let declared = event
        .get("requirements")
        .and_then(|requirements| requirements.get("critical_extensions"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten();
    for extension in declared {
        let id = required_str(extension, "id")?;
        if extension.get("fail_closed").and_then(Value::as_bool) == Some(true)
            && !context.supported_features.contains(id)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn assert_event_decision(
    actual: &EventEnvelopeDecision,
    expected_decision: &str,
    expected_error_code: Option<&str>,
    context: &str,
) -> Result<()> {
    if actual.decision != expected_decision {
        bail!(
            "event envelope {context} expected decision {expected_decision}, got {} ({:?}): {}",
            actual.decision,
            actual.error_code,
            actual.reason
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
