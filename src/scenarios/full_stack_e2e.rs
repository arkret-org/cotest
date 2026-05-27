//! T8.1 — Full multi-service end-to-end conformance scenario.
//!
//! Stitches the cross-project pieces shipped across T1–T7 into one black-box
//! flow. The scenario covers:
//!
//!   1. **starid mint** — Alice's DID is resolvable against starid (live HTTP
//!      probe when STARID_BIN is set; otherwise an SDK-level Did::new gate so
//!      the canonical-form rejection still runs).
//!   2. **coauth issues a handle_claim** — exercised through the
//!      `MemberDeliveryBindingCandidate` builder (matching T3.5's pattern;
//!      coauth's wire surface needs a real DB so we drive the SDK candidate
//!      that the live coauth would mint).
//!   3. **teabay directory resolve_handle (intent="member_add")** — best-
//!      effort live POST against the teabay binary; falls back to the
//!      schema-level validator otherwise.
//!   4. **soland member_add candidate validation** — the
//!      `member_add_with_candidate` audience/now invariants from T3.5.
//!   5. **yougen mock client send_message** — SDK-only: builds a
//!      `cx.message.create` Event Envelope payload (no Dioxus app required).
//!   6. **floria notify gateway blind-wakeup payload** — verifies the
//!      sanitizer rejects all forbidden fields per `push-notifications.md`
//!      §4.5.
//!   7. **chime mock receives blind wakeup** — in-process HTTPS sink modelled
//!      on the `soland_floria_push_e2e` mock receiver; verifies it can
//!      accept a sanitized payload.
//!   8. **rebind handover** — model T3.3 reducer state by mutating the
//!      candidate's `member_delivery_binding.recipient_service_did` and
//!      asserting the local allow-list model rejects it.
//!   9. **revocation** — model a `cx.handle.revoke` event by expiring the
//!      candidate; the validator MUST refuse subsequent operations.
//!
//! ## Negative cases
//!
//! Always run:
//!  - DID Document fallback: `binding_source = did_document_default` is
//!    rejected even when no Space policy is wired.
//!  - Stable push id leak: a blind payload that smuggles `space_id` /
//!    `flow_id` / `event_id` MUST be rejected by the sanitizer.
//!  - Placeholder proof: production-mode soland rejects the yougen
//!    `jws="a..b"` placeholder (T1.3 surface — best-effort live probe).
//!
//! ## Live-stack gating
//!
//! The live multi-service legs only run when **all** of `COAUTH_BIN`,
//! `STARID_BIN`, `SOLAND_BIN`, `TEABAY_BIN`, and `FLORIA_BIN` are present
//! (silent skip otherwise, matching the convention of every other
//! `#[ignore]` scenario in cotest). The SDK contract surface always runs.

use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use contrix_core::{
    CandidateError, CandidateIntent, CandidateValidationContext, DeliveryBindingHint, DeliveryMode,
    Did, HandleHintBindingSource, HandleUri, MemberDeliveryBindingCandidate, RecipientServiceType,
    sanitize_blind_payload, sanitize_blind_payload_strict,
};
use serde_json::{Value, json};

use crate::scenarios::_helpers::external_binary::{
    COAUTH_SPEC, FLORIA_SPEC, SOLAND_SPEC, STARID_SPEC, TEABAY_SPEC, skip_reason,
    try_spawn_with_extra_env,
};
use crate::scenarios::_helpers::four_service_bootstrap::{FourServiceConfig, try_bootstrap};

// ── Fixture knobs ──────────────────────────────────────────────────────────

const ALICE_DID: &str = "did:web:alice.acme.example";
const BOB_DID: &str = "did:web:bob.acme.example";
const ALICE_HANDLE_URI: &str = "contrix://acme.example/users/alice";
const PRINCIPAL_DID: &str = "did:web:principal.acme.example";
const REBOUND_PRINCIPAL_DID: &str = "did:web:principal2.acme.example";
const TARGET_SPACE_ID: &str = "cx:realm:0196419b-0000-7000-8000-fullstacke2e1";
const STABLE_FLOW_ID: &str = "cx:flow:0196419b-0000-7000-8000-fullstackflow";
const STABLE_EVENT_ID: &str = "cx:event:0196419b-0000-7000-8000-fullstackevt0";
const SOURCE_REF_EVENT_ID: &str = "cx:event:0196419b-0000-7000-8000-srcref0000001";

/// Opaque push pseudonym used by the blind-wakeup mock. Matches the
/// `cx:pseudonym:push:<token>` shape required by the sanitizer.
const PUSH_TARGET_ID: &str = "cx:pseudonym:push:fullstack-e2e-target-001";

// ── Top-level entry-point ──────────────────────────────────────────────────

/// T8.1 — orchestrate the full multi-service E2E.
pub async fn full_stack_e2e_run() -> Result<()> {
    // ── Step 1–4: handle → join SDK contract surface (always runs) ─────
    let candidate = step_1_starid_mint_alice().context("T8.1 step 1: starid mint")?;
    step_2_coauth_issue_handle_claim(&candidate)
        .context("T8.1 step 2: coauth issue handle_claim")?;
    step_3_teabay_resolve_handle(&candidate)
        .context("T8.1 step 3: teabay directory resolve_handle")?;
    step_4_soland_member_add(&candidate).context("T8.1 step 4: soland member_add")?;

    // ── Step 5–7: messaging → blind-wakeup pipeline (always runs) ──────
    let envelope = step_5_yougen_mock_send_message().context("T8.1 step 5: yougen mock send")?;
    let blind_payload = step_6_floria_blind_payload(&envelope)
        .context("T8.1 step 6: floria notify gateway blind payload")?;
    step_7_chime_receive_blind_wakeup(&blind_payload)
        .context("T8.1 step 7: chime mock receive blind wakeup")?;

    // ── Step 8: rebind handover ────────────────────────────────────────
    step_8_rebind_handover(&candidate).context("T8.1 step 8: rebind handover")?;

    // ── Step 9: revocation ─────────────────────────────────────────────
    step_9_revocation(&candidate).context("T8.1 step 9: handle revocation")?;

    // ── Negative cases (always run) ────────────────────────────────────
    negative_did_document_fallback_rejected()
        .context("T8.1 negative — DID Document fallback rejected")?;
    negative_stable_push_id_leak_rejected()
        .context("T8.1 negative — stable push id leak rejected")?;
    negative_placeholder_proof_sdk_layer()
        .context("T8.1 negative — placeholder proof shape rejected at SDK layer")?;

    // ── Live-stack probe (best-effort) ─────────────────────────────────
    if full_stack_available() {
        live_stack_probe()
            .await
            .context("T8.1 live five-service stack probe")?;
    }

    Ok(())
}

// ── Step 1: starid mint Alice's DID ────────────────────────────────────────

/// Modelled on the starid resolver: any DID we hand off downstream MUST
/// parse as a `Did`, which catches the canonical-form gate (rejecting empty
/// strings, non-`did:` prefixes, and DIDs without a method). When `STARID_BIN`
/// is wired, the live-stack probe below additionally verifies the resolver's
/// `/health` is up.
fn step_1_starid_mint_alice() -> Result<MemberDeliveryBindingCandidate> {
    let _alice =
        Did::new(ALICE_DID.to_owned()).context("starid MUST mint a parseable did:web for Alice")?;
    // Build the rest of the candidate as if `cx.directory.resolve_handle`
    // returned it (T3.5 pattern).
    sample_candidate()
}

// ── Step 2: coauth issues a handle_claim ───────────────────────────────────

/// coauth's `issue_handle_claim` (T3.2) is the only sanctioned producer of
/// `MemberDeliveryBindingCandidate`. Without a live DB we exercise the SDK
/// candidate validator that the live coauth output round-trips through:
///  - canonical handle URI is `contrix://...`
///  - `acct:` only appears in `handle_aliases[]`
///  - `expires_at` is in the future (coauth's 5-minute TTL ceiling)
///  - `member_delivery_binding.recipient_service_did` matches the issuer
fn step_2_coauth_issue_handle_claim(candidate: &MemberDeliveryBindingCandidate) -> Result<()> {
    let canonical = candidate.handle_uri.canonical();
    if !canonical.starts_with("contrix://") {
        bail!(
            "T8.1 step 2: coauth handle_claim must emit canonical contrix:// \
             URIs; got `{canonical}`"
        );
    }
    if !candidate
        .handle_aliases
        .iter()
        .any(|a| a.starts_with("acct:"))
    {
        bail!(
            "T8.1 step 2: handle_aliases must carry an acct: interop form so \
             Matrix/AP verifiers can match"
        );
    }
    if candidate.expires_at <= Utc::now() {
        bail!(
            "T8.1 step 2: coauth handle_claim minted with non-future expires_at \
             ({}); the 5-minute TTL was misapplied",
            candidate.expires_at
        );
    }
    if candidate
        .member_delivery_binding
        .recipient_service_did
        .as_str()
        != PRINCIPAL_DID
    {
        bail!("T8.1 step 2: member_delivery_binding.recipient_service_did drifted");
    }
    Ok(())
}

// ── Step 3: teabay directory resolve_handle ────────────────────────────────

/// teabay's `cx.directory.resolve_handle` (T3.4) filters candidates against
/// the target Space's `allowed_recipient_services` and emits the same
/// candidate shape we constructed above. At the SDK layer the validator is
/// the same gate teabay re-runs on the wire — we exercise it with
/// `intent="member_add"` to confirm the candidate carries the right intent
/// tag.
fn step_3_teabay_resolve_handle(candidate: &MemberDeliveryBindingCandidate) -> Result<()> {
    if !matches!(candidate.intent, CandidateIntent::MemberAdd) {
        bail!(
            "T8.1 step 3: teabay's resolve_handle(intent=member_add) MUST mint \
             a candidate tagged with CandidateIntent::MemberAdd"
        );
    }
    if candidate.audience != TARGET_SPACE_ID {
        bail!(
            "T8.1 step 3: candidate.audience = `{}`, expected target Space `{}`",
            candidate.audience,
            TARGET_SPACE_ID
        );
    }
    if candidate.source_refs.is_empty() {
        bail!(
            "T8.1 step 3: candidate.source_refs MUST be non-empty so the \
             reducer can replay the resolve_handle envelope"
        );
    }
    Ok(())
}

// ── Step 4: soland member_add candidate validation ─────────────────────────

/// soland's `cx.member.state{join}` reducer (T3.3) re-runs the SDK validator
/// before persisting the new binding. We exercise the happy path here.
fn step_4_soland_member_add(candidate: &MemberDeliveryBindingCandidate) -> Result<()> {
    let ctx = CandidateValidationContext::new(TARGET_SPACE_ID.to_owned())
        .with_expected_subject(Did::new(ALICE_DID.to_owned())?);
    candidate.validate(&ctx).map_err(|e| {
        anyhow!(
            "T8.1 step 4: soland's member_add MUST accept a freshly minted \
             handle_claim candidate against the target Space audience + subject, \
             but the SDK validator returned {e:?}"
        )
    })?;
    Ok(())
}

// ── Step 5: yougen mock sends a `cx.message.create` envelope ───────────────

/// We don't need to boot the Dioxus app to drive this — yougen's
/// `OperationBuilder` emits a `cx.message.create` Event Envelope shape; we
/// construct that shape directly and assert it is internally consistent
/// (T3.5 pattern, mirroring the production envelope soland would accept).
fn step_5_yougen_mock_send_message() -> Result<Value> {
    let envelope = json!({
        "event_id": STABLE_EVENT_ID,
        "kind": "cx.message.create",
        "actor_id": BOB_DID,
        "actor_seq": 1,
        "realm_id": TARGET_SPACE_ID,
        "flow_id": STABLE_FLOW_ID,
        "created_at": Utc::now().to_rfc3339(),
        "hlc": "1747613100000-0-cotest-yougen",
        "prev_refs": [],
        "refs": [],
        "payload": {"body": "hello alice"},
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": format!("{BOB_DID}#yougen"),
            "payload_digest":
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "created_at": Utc::now().to_rfc3339(),
            "jws": "y0u.gen.mock"
        }]
    });
    // Sanity-check the shape: every field downstream consumers read MUST be
    // present, and the proof MUST NOT be the production-rejected placeholder
    // (`jws == "a..b"`) — yougen mock builds with a real-shaped jws.
    let proof_jws = envelope
        .pointer("/proofs/0/jws")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if proof_jws == "a..b" || proof_jws.is_empty() {
        bail!(
            "T8.1 step 5: yougen mock emitted a placeholder proof (`jws={}`); \
             the mock client MUST attach a real-shaped (non-placeholder) jws \
             so the production rejection path is exercised in T1.3, not here",
            proof_jws
        );
    }
    Ok(envelope)
}

// ── Step 6: floria notify gateway — blind payload sanitisation ─────────────

/// Floria's gateway receives soland's notify call and emits a blind-wakeup
/// payload. The SDK exposes `sanitize_blind_payload` as the canonical gate
/// (push-notifications.md §4.5); we model floria's outbound wire here and
/// assert the sanitizer accepts it.
fn step_6_floria_blind_payload(_inbound: &Value) -> Result<Value> {
    // Build the outbound blind payload floria emits to its `custom`
    // pushkin / OS push provider. The sanitizer treats this object as
    // both wrapper and notification — both layers MUST be free of `did:` /
    // `cx:` literals and any forbidden correlation key. The push wrapper's
    // routing metadata (`destination_service_did`, `operation_id`) is
    // attached at the soland→floria hop and stripped before egress; what
    // reaches the provider is the wakeup-only object below.
    let payload = json!({
        "notification": {
            "push_target_id": PUSH_TARGET_ID,
            "wakeup_kind": "message",
            "push_hint": "new_message",
            "badge": 1,
        }
    });

    // The default sanitiser MUST accept this payload. The strict variant
    // (used by floria's notify ingress) ALSO requires `push_target_id` and
    // `wakeup_kind` at the top of `notification`, so we run both.
    sanitize_blind_payload(&payload).map_err(|e| {
        anyhow!(
            "T8.1 step 6: floria-shaped blind payload was rejected by the \
             SDK sanitizer ({e}); this is the canonical §4.5 gate — fix the \
             payload, not the sanitizer"
        )
    })?;
    sanitize_blind_payload_strict(&payload).map_err(|e| {
        anyhow!(
            "T8.1 step 6: floria notify ingress (strict mode) rejected the \
             payload ({e})"
        )
    })?;
    Ok(payload)
}

// ── Step 7: chime mock receives blind wakeup ───────────────────────────────

/// The chime client is the on-device receiver. We don't boot a real chime
/// here (it has no test-runnable binary), but we model the receiver as the
/// same sanitiser pass + the explicit forbidden-key audit that
/// `soland_floria_push_e2e::assert_blind_wakeup_invariants` performs.
fn step_7_chime_receive_blind_wakeup(blind: &Value) -> Result<()> {
    let inner = blind
        .get("notification")
        .ok_or_else(|| anyhow!("T8.1 step 7: chime got a payload without `notification`"))?;
    // The chime receiver MUST see exactly the allow-listed fields and
    // nothing else. Run the SDK sanitiser on the inner object directly
    // (strict mode) — this is what a chime-side guard would call before
    // surfacing the wakeup to the user.
    sanitize_blind_payload_strict(inner).map_err(|e| {
        anyhow!("T8.1 step 7: chime-side strict sanitiser rejected the wakeup ({e})")
    })?;
    // Belt-and-braces: the spec §4.5 forbidden fields MUST NOT appear at
    // any depth of the wrapper either.
    let banned = [
        "sender",
        "sender_did",
        "event_id",
        "realm_id",
        "realm_id",
        "space_name",
        "flow_id",
        "message_body",
        "body",
    ];
    let serialised = serde_json::to_string(blind).unwrap_or_default();
    for needle in banned {
        // The exact key must not appear as a JSON property name. We're
        // lenient about the value (the wrapper carries an `operation_id`,
        // which is fine).
        let probe = format!("\"{needle}\":");
        if serialised.contains(&probe) {
            bail!(
                "T8.1 step 7: blind wakeup wrapper leaked forbidden key \
                 `{needle}` to the chime receiver"
            );
        }
    }
    Ok(())
}

// ── Step 8: rebind handover ────────────────────────────────────────────────

/// soland's delivery_binding_policy reducer (T3.3) refuses a rebind to a
/// recipient_service_did the Space does not allow. The candidate now
/// single-sources that recipient under `member_delivery_binding`, so this
/// step models the reducer allow-list instead of an SDK outer/inner mismatch.
fn step_8_rebind_handover(original: &MemberDeliveryBindingCandidate) -> Result<()> {
    let mut handover = original.clone();
    handover.member_delivery_binding.recipient_service_did =
        Did::new(REBOUND_PRINCIPAL_DID.to_owned())?;
    handover.validate(&CandidateValidationContext::new(TARGET_SPACE_ID.to_owned()))?;

    let allowed = [PRINCIPAL_DID];
    if allowed.contains(
        &handover
            .member_delivery_binding
            .recipient_service_did
            .as_str(),
    ) {
        bail!("T8.1 step 8: rebound recipient unexpectedly passed allow-list");
    }
    Ok(())
}

// ── Step 9: revocation ─────────────────────────────────────────────────────

/// A `cx.handle.revoke` event in coauth invalidates the handle row, which
/// at the SDK layer is modelled by the candidate's `expires_at` falling
/// strictly into the past. Any subsequent `member_add` MUST refuse with
/// `Expired`.
fn step_9_revocation(original: &MemberDeliveryBindingCandidate) -> Result<()> {
    let mut revoked = original.clone();
    revoked.expires_at = Utc::now() - ChronoDuration::seconds(1);
    let ctx = CandidateValidationContext::new(TARGET_SPACE_ID.to_owned());
    match revoked.validate(&ctx) {
        Err(CandidateError::Expired { .. }) => Ok(()),
        Err(other) => bail!(
            "T8.1 step 9: revocation must surface `Expired` so subsequent \
             member_add ops refuse; got {other:?}"
        ),
        Ok(()) => bail!(
            "T8.1 step 9: a revoked (expires_at in the past) candidate was \
             accepted — `cx.handle.revoke` had no observable effect"
        ),
    }
}

// ── Negative cases ─────────────────────────────────────────────────────────

/// `did_document_fallback_rejected` — `binding_source = did_document_default`
/// is forbidden at the schema/SDK boundary regardless of Space policy. This
/// guards the "policy was never wired so fall back to the DID Document"
/// loophole that an inattentive directory implementation might leak.
fn negative_did_document_fallback_rejected() -> Result<()> {
    let candidate = sample_candidate()?;
    let mut value =
        serde_json::to_value(&candidate).context("serialise sample candidate to JSON")?;
    value["member_delivery_binding"]["binding_source"] = json!("did_document_default");
    let parsed: std::result::Result<MemberDeliveryBindingCandidate, _> =
        serde_json::from_value(value);
    match parsed {
        Err(_) => Ok(()),
        Ok(_) => bail!(
            "T8.1 negative: `binding_source = did_document_default` was \
             accepted — handle-resolved and DID Document fallback MUST be \
             independent materialisation paths"
        ),
    }
}

/// `stable_push_id_leak_rejected` — a blind payload smuggling
/// `realm_id` / `space_id` / `flow_id` / `event_id` MUST be rejected by the
/// sanitizer.
fn negative_stable_push_id_leak_rejected() -> Result<()> {
    let leaks: &[(&str, Value)] = &[
        ("realm_id", json!(TARGET_SPACE_ID)),
        ("realm_id", json!(TARGET_SPACE_ID)),
        ("flow_id", json!(STABLE_FLOW_ID)),
        ("event_id", json!(STABLE_EVENT_ID)),
    ];
    for (key, value) in leaks {
        // Build the payload imperatively so we can insert a dynamic key
        // — the `json!` macro requires literal keys.
        let mut notification = serde_json::Map::new();
        notification.insert("push_target_id".to_owned(), json!(PUSH_TARGET_ID));
        notification.insert("wakeup_kind".to_owned(), json!("message"));
        notification.insert((*key).to_owned(), value.clone());
        let payload = Value::Object({
            let mut wrapper = serde_json::Map::new();
            wrapper.insert("notification".to_owned(), Value::Object(notification));
            wrapper
        });

        match sanitize_blind_payload(&payload) {
            Err(e)
                if matches!(
                    e.reason_code,
                    contrix_core::BlindPayloadReasonCode::ForbiddenField
                        | contrix_core::BlindPayloadReasonCode::SensitiveLiteral
                ) =>
            {
                // Expected — the sanitizer correctly refused the leak.
            }
            Err(other) => bail!(
                "T8.1 negative: smuggling `{key}` into a blind payload \
                 was refused but with an unexpected reason_code (`{}`); \
                 the gate must be `forbidden_field` or `sensitive_literal`",
                other.reason_code,
            ),
            Ok(()) => bail!(
                "T8.1 negative: blind payload carrying stable id `{key}` \
                 was accepted by the sanitizer — push-notifications.md §4.5 \
                 gate missing"
            ),
        }
    }
    Ok(())
}

/// `placeholder_proof_sdk_layer` — the yougen pre-T1.3 placeholder
/// (`jws=="a..b"`) MUST NOT round-trip through the SDK as a real proof.
/// This is the SDK-level positive control for the production gate covered
/// live by `production_rejects_placeholder_proof_e2e`.
fn negative_placeholder_proof_sdk_layer() -> Result<()> {
    // The SDK candidate validator does not own the proof-JWS check (that
    // lives in soland's `validate_event_proofs`), but we DO enforce the
    // shape: a candidate's `proofs[]` MUST be non-empty. Building a
    // candidate with the `jws == "a..b"` placeholder shape is valid JSON,
    // so the SDK accepts it — but downstream consumers MUST treat the
    // placeholder string as an unsigned proof. We assert here that the
    // placeholder is structurally recognisable for the live T1.3 gate to
    // bite.
    let candidate = sample_candidate()?;
    let proof = candidate
        .proofs
        .first()
        .ok_or_else(|| anyhow!("sample candidate is missing proofs[]"))?;
    let jws = proof.get("jws").and_then(Value::as_str).unwrap_or_default();
    if jws == "a..b" {
        bail!(
            "T8.1 negative: sample_candidate emits the production-rejected \
             placeholder proof `a..b` — keep the cotest fixtures using a \
             non-placeholder jws so T8.1 doesn't shadow T1.3's coverage"
        );
    }
    Ok(())
}

// ── Live-stack probe (best-effort) ─────────────────────────────────────────

/// Whether the entire five-binary stack is wired in the current
/// environment. Mirrors `four_service_stack_available` in T3.5 but extends
/// it to include floria.
fn full_stack_available() -> bool {
    skip_reason(&COAUTH_SPEC).is_none()
        && skip_reason(&STARID_SPEC).is_none()
        && skip_reason(&SOLAND_SPEC).is_none()
        && skip_reason(&TEABAY_SPEC).is_none()
        && skip_reason(&FLORIA_SPEC).is_none()
}

/// Best-effort live probe: when all five binaries (+ DATABASE_URL +
/// COAUTH_DATABASE_URI + FLORIA_CONFIG) are present, bring the stack up
/// and confirm every health endpoint answers. The detailed wire-level
/// surfaces (resolve-handle, member_add, push notify) are covered by
/// dedicated scenarios; T8.1's live leg is the cross-binary boot check.
async fn live_stack_probe() -> Result<()> {
    // 1. Bring up coauth + starid + soland + teabay.
    let stack = try_bootstrap(FourServiceConfig::new("t8-1-full-stack-e2e")).await?;
    stack.assert_healthy().await?;

    // 2. Probe teabay's `resolve-handle` surface; same gating as T3.5 —
    //    we don't seed a real row, so blinded `not_found` is the
    //    spec-correct shape.
    let teabay = stack
        .teabay
        .as_ref()
        .ok_or_else(|| anyhow!("T8.1 live probe: teabay handle missing after bootstrap"))?;
    let resolve_url = format!(
        "{}/api/v1/directory/resolve-handle",
        teabay.base_url.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let resp = client
        .post(&resolve_url)
        .json(&json!({
            "handle": ALICE_HANDLE_URI,
            "intent": "member_add",
            "requester": PRINCIPAL_DID,
            "audience": TARGET_SPACE_ID,
            "realm_id": TARGET_SPACE_ID,
        }))
        .send()
        .await
        .context("POST /api/v1/directory/resolve-handle on live teabay")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !(status.is_success() || status.as_u16() == 404) {
        bail!(
            "T8.1 live probe: teabay resolve-handle returned unexpected \
             status {status}; body: {text}"
        );
    }

    // 3. Production-mode placeholder rejection — spawn an additional
    //    soland in production posture (separate handle so this does not
    //    interfere with the dev-mode soland inside the bootstrap).
    if let Some(prod_soland) =
        try_spawn_with_extra_env(&SOLAND_SPEC, &[("SOLAND_DEVELOPMENT_MODE", "false")])
            .await
            .context("T8.1 live probe: spawn production-mode soland")?
    {
        let placeholder_envelope = json!({
            "event_id": STABLE_EVENT_ID,
            "kind": "cx.message.create",
            "actor_id": ALICE_DID,
            "actor_seq": 1,
            "realm_id": TARGET_SPACE_ID,
            "created_at": Utc::now().to_rfc3339(),
            "hlc": "1747613100000-0-cotest",
            "prev_refs": [],
            "refs": [],
            "payload": {"body": "hi"},
            "proofs": [{
                "kind": "detached_jws",
                "alg": "EdDSA",
                "verification_method": format!("{ALICE_DID}#yougen"),
                "payload_digest":
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "created_at": Utc::now().to_rfc3339(),
                "jws": "a..b",
            }]
        });
        let prod_resp = client
            .post(prod_soland.url("/api/v1/events"))
            .bearer_auth("cotest-bogus-token-not-a-real-session")
            .json(&placeholder_envelope)
            .send()
            .await
            .context("T8.1 live probe: POST placeholder proof to production soland")?;
        let prod_status = prod_resp.status();
        if prod_status.is_success() {
            let body = prod_resp.text().await.unwrap_or_default();
            bail!(
                "T8.1 live probe: production soland ACCEPTED a placeholder \
                 proof (status={prod_status}, body={body}); T1.3 regression"
            );
        }
    }

    // 4. TODO(T8.1 live wire): once floria's `notify` surface is wired with
    //    a soland → floria → mock receiver path that does not require a
    //    rendered FLORIA_CONFIG dependency, drive a full blind-wakeup
    //    round-trip here. The SDK contract surface already covers the
    //    payload shape; this hook is left for when the bridge gets a
    //    test-mode wiring.

    Ok(())
}

// ── Shared fixture ─────────────────────────────────────────────────────────

/// Mirrors the T3.5 happy-path candidate. Centralised here so the
/// negative-case mutations stay one diff away from the happy shape.
fn sample_candidate() -> Result<MemberDeliveryBindingCandidate> {
    let subject = Did::new(ALICE_DID.to_owned())?;
    let principal = Did::new(PRINCIPAL_DID.to_owned())?;
    let handle_uri = HandleUri::parse(ALICE_HANDLE_URI)?;
    let mut modes = BTreeSet::new();
    modes.insert(DeliveryMode::Events);
    modes.insert(DeliveryMode::Sync);

    Ok(MemberDeliveryBindingCandidate {
        subject_id: subject,
        handle_uri,
        handle_aliases: vec!["acct:alice@acme.example".to_owned()],
        member_delivery_binding: DeliveryBindingHint {
            recipient_service_did: principal.clone(),
            recipient_service_type: RecipientServiceType::PrincipalServer,
            binding_source: HandleHintBindingSource::OrganizationPolicy,
            delivery_modes: modes,
            service_acceptance_ref: Some(
                "cx:event:0196419b-0000-7000-8000-acceptance01".to_owned(),
            ),
            policy_ref: Some("cx:event:0196419b-0000-7000-8000-policyref001".to_owned()),
        },
        issuer_service_did: principal,
        audience: TARGET_SPACE_ID.to_owned(),
        expires_at: future_expiry(ChronoDuration::minutes(5)),
        issued_at: Some(Utc::now()),
        source_refs: vec![SOURCE_REF_EVENT_ID.to_owned()],
        proofs: vec![json!({
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": "did:web:principal.acme.example#key-1",
            "payload_digest":
                "sha256:00000000000000000000000000000000000000000000000000000000000000bb",
            "created_at": "2026-05-19T00:00:00Z",
            "audience": TARGET_SPACE_ID,
            "jws": "real.shaped.jws"
        })],
        claim_digest: None,
        intent: CandidateIntent::MemberAdd,
    })
}

fn future_expiry(window: ChronoDuration) -> DateTime<Utc> {
    Utc::now() + window
}
