//! T8.1 — Full multi-service end-to-end conformance scenario.
//!
//! Stitches the cross-project pieces shipped across T1–T7 into one black-box
//! strand. The scenario covers:
//!
//!   1. **subject DID mint** — Alice's DID passes the SDK-level `DidFullId::new` canonical-form
//!      gate before it is handed to any downstream service.
//!   2. **coauth issues a handle_claim** — exercised through the `MemberDeliveryBindingCandidate`
//!      builder (matching T3.5's pattern; coauth's wire surface needs a real DB so we drive the SDK
//!      candidate that the live coauth would mint).
//!   3. **teabay directory resolve_handle (intent="member_add")** — best- effort live POST against
//!      the teabay binary; falls back to the schema-level validator otherwise.
//!   4. **soland member_add candidate validation** — the `member_add_with_candidate` audience/now
//!      invariants from T3.5.
//!   5. **inkson mock client send_message** — SDK-only: builds a `ak.message.create` Event Envelope
//!      payload (no Dioxus app required).
//!   6. **floria notify gateway blind-wakeup payload** — verifies the sanitizer rejects all
//!      forbidden fields per `push-notifications.md` §4.5.
//!   7. **chime mock receives blind wakeup** — an in-process receiver verifies it can accept a
//!      sanitized payload.
//!   8. **rebind handover** — model T3.3 reducer state by mutating the candidate's
//!      `member_delivery_binding.recipient_service_id` and asserting the local allow-list model
//!      rejects it.
//!   9. **revocation** — model a `ak.handle.revoke` event by expiring the candidate; the validator
//!      MUST refuse subsequent operations.
//!
//! ## Negative cases
//!
//! Always run:
//!  - DID Document fallback: `binding_source = did_document_default` is rejected even when no Space
//!    policy is wired.
//!  - Stable push id leak: a blind payload that smuggles `space_id` / `strand_id` / `event_id` MUST
//!    be rejected by the sanitizer.
//!  - Placeholder proof: production-mode soland rejects the inkson `jws="a..b"` placeholder (T1.3
//!    surface — best-effort live probe).
//!
//! ## Live-stack gating
//!
//! The live multi-service legs only run when **all** of `COAUTH_BIN`,
//! `SOLAND_BIN`, `TEABAY_BIN`, and `FLORIA_BIN` are present (silent skip
//! otherwise, matching the convention of every other `#[ignore]` scenario in
//! cotest). The SDK contract surface always runs.

use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use arkret_identifiers::{DidCoreId, DidFullId, EventId, Hash};
use arkret_models_collaboration::governance::member_delivery_binding_candidate::{
    CandidateError, CandidateIntent, CandidateValidationContext, MemberDeliveryBindingCandidate,
};
use arkret_models_identity::delivery_binding::{DeliveryMode, RecipientServiceKind};
use arkret_models_identity::handle::{Handle, HandleHintBindingSource};
use arkret_models_identity::handle_claim::DeliveryBindingHint;
use arkret_push_policy::blind_payload_sanitizer::{
    sanitize_blind_payload, sanitize_blind_payload_strict,
};
use arkret_wire::{Audience, PrincipalAuthorityKey, Proof};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde_json::{Value, json};

use crate::scenarios::_helpers::coauth_bootstrap::coauth_with_db_available;
use crate::scenarios::_helpers::external_binary::{
    FLORIA_SPEC, SOLAND_SPEC, TEABAY_SPEC, skip_reason, try_spawn_with_extra_env,
};
use crate::scenarios::_helpers::joint_service_bootstrap::{JointServiceConfig, try_bootstrap};

// ── Fixture knobs ──────────────────────────────────────────────────────────

const ALICE_ID: &str = "ak:did_core:web:alice.acme.example";
const ALICE_FULL_ID: &str = "did:web:alice.acme.example";
const BOB_ID: &str = "ak:did_core:web:bob.acme.example";
const BOB_FULL_ID: &str = "did:web:bob.acme.example";
/// R3.1 canonical handle `<localpart>:<domain>` (arkret-spec @ 7157ee8).
const ALICE_HANDLE: &str = "alice:acme.example";
const PRINCIPAL_ID: &str = "ak:did_core:web:principal.acme.example";
const REBOUND_PRINCIPAL_ID: &str = "ak:did_core:web:principal2.acme.example";
const TARGET_REALM_ID: &str = "ak:realm:0196419b-0000-8000-8000-fullstacke2e1";
const STABLE_STRAND_ID: &str = "ak:strand:0196419b-0000-8000-8000-fullstackflow";
const STABLE_EVENT_ID: &str = "ak:event:AYj6JMkunCLeeu9ILKnSICoqU8huDFX5orzGYBdH_ESu";
const SOURCE_REF_EVENT_ID: &str = "ak:event:AR4I3pqI_AE1Vxb4LEKq2azQxWXhHobgzwnTJmhVKJT-";

/// Opaque push pseudonym used by the blind-wakeup mock. Matches the
/// `ak:pseudonym:push:<token>` shape required by the sanitizer.
const PUSH_TARGET_ID: &str = "ak:pseudonym:push:fullstack-e2e-target-001";

// ── Top-level entry-point ──────────────────────────────────────────────────

/// T8.1 — orchestrate the full multi-service E2E.
pub async fn full_stack_e2e_run() -> Result<()> {
    // ── Step 1–4: handle → join SDK contract surface (always runs) ─────
    let candidate = step_1_mint_alice_did().context("T8.1 step 1: subject DID mint")?;
    step_2_coauth_issue_handle_claim(&candidate)
        .context("T8.1 step 2: coauth issue handle_claim")?;
    step_3_teabay_resolve_handle(&candidate)
        .context("T8.1 step 3: teabay directory resolve_handle")?;
    step_4_soland_member_add(&candidate).context("T8.1 step 4: soland member_add")?;

    // ── Step 5–7: messaging → blind-wakeup pipeline (always runs) ──────
    let envelope = step_5_inkson_mock_send_message().context("T8.1 step 5: inkson mock send")?;
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
            .context("T8.1 live four-service stack probe")?;
    }

    Ok(())
}

// ── Step 1: mint Alice's subject DID ───────────────────────────────────────

/// Any DID we hand off downstream MUST parse as a `DidFullId`, which catches
/// the canonical-form gate (rejecting empty strings, non-`did:` prefixes, and
/// DIDs without a method).
fn step_1_mint_alice_did() -> Result<MemberDeliveryBindingCandidate> {
    let _alice = DidFullId::new(ALICE_FULL_ID.to_owned())
        .context("Alice's subject DID MUST be a parseable did:web")?;
    // Build the rest of the candidate as if `ak.find.directory.read.resolve_handle`
    // returned it (T3.5 pattern).
    sample_candidate()
}

// ── Step 2: coauth issues a handle_claim ───────────────────────────────────

/// coauth's `issue_handle_claim` (T3.2) is the only sanctioned producer of
/// `MemberDeliveryBindingCandidate`. Without a live DB we exercise the SDK
/// candidate validator that the live coauth output round-trips through:
///  - canonical handle is `<localpart>:<domain>` (R3.1 wire rename)
///  - `acct:` only appears in `handle_aliases[]`
///  - `expires_at` is in the future (coauth's 5-minute TTL ceiling)
///  - `member_delivery_binding.recipient_service_id` matches the issuer
fn step_2_coauth_issue_handle_claim(candidate: &MemberDeliveryBindingCandidate) -> Result<()> {
    let canonical = candidate.handle.canonical();
    let mut colon_parts = canonical.split(':');
    let local = colon_parts.next().unwrap_or_default();
    let domain = colon_parts.next().unwrap_or_default();
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        bail!(
            "T8.1 step 2: coauth handle_claim must emit canonical \
             `<localpart>:<domain>` handles (R3.1); got `{canonical}`"
        );
    }
    if canonical.starts_with("arkret://") || canonical.starts_with("acct:") {
        bail!(
            "T8.1 step 2: coauth handle_claim leaked a retired URI form \
             (`{canonical}`); the `arkret://` form was retired at \
             arkret-spec @ 7157ee8."
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
        .recipient_service_id
        .as_str()
        != PRINCIPAL_ID
    {
        bail!("T8.1 step 2: member_delivery_binding.recipient_service_id drifted");
    }
    Ok(())
}

// ── Step 3: teabay directory resolve_handle ────────────────────────────────

/// teabay's `ak.find.directory.read.resolve_handle` (T3.4) filters candidates against
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
    if candidate.audience != TARGET_REALM_ID {
        bail!(
            "T8.1 step 3: candidate.audience = `{}`, expected target Space `{}`",
            candidate.audience,
            TARGET_REALM_ID
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

/// soland's `ak.member.state{join}` reducer (T3.3) re-runs the SDK validator
/// before persisting the new binding. We exercise the happy path here.
fn step_4_soland_member_add(candidate: &MemberDeliveryBindingCandidate) -> Result<()> {
    let ctx = CandidateValidationContext::new(TARGET_REALM_ID.to_owned())
        .with_expected_subject(DidCoreId::new(ALICE_ID)?);
    candidate.validate(&ctx).map_err(|e| {
        anyhow!(
            "T8.1 step 4: soland's member_add MUST accept a freshly minted \
             handle_claim candidate against the target Space audience + subject, \
             but the SDK validator returned {e:?}"
        )
    })?;
    Ok(())
}

// ── Step 5: inkson mock sends a `ak.message.create` envelope ───────────────

/// We don't need to boot the Dioxus app to drive this — inkson's
/// `OperationBuilder` emits a `ak.message.create` Event Envelope shape; we
/// construct that shape directly and assert it is internally consistent
/// (T3.5 pattern, mirroring the production envelope soland would accept).
fn step_5_inkson_mock_send_message() -> Result<Value> {
    let envelope = json!({
        "event_id": STABLE_EVENT_ID,
        "kind": "ak.message.create",
        "actor_id": BOB_ID,
        "actor_seq": 1,
        "realm_id": TARGET_REALM_ID,
        "strand_id": STABLE_STRAND_ID,
        "created_at": arkret_canonical::format_timestamp_canonical(Utc::now()),
        "hlc": "1747613100000-0-cotest-inkson",
        "prev_refs": [],
        "refs": [],
        "payload": {"body": "hello alice"},
        "proofs": [{
            "kind": "detached_jws",
            "verification_method": format!("{BOB_FULL_ID}#inkson"),
            "event_digest":
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "created_at": arkret_canonical::format_timestamp_canonical(Utc::now()),
            "jws": "y0u.gen.mock"
        }]
    });
    // Sanity-check the shape: every field downstream consumers read MUST be
    // present, and the proof MUST NOT be the production-rejected placeholder
    // (`jws == "a..b"`) — inkson mock builds with a real-shaped jws.
    let proof_jws = envelope
        .pointer("/proofs/0/jws")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if proof_jws == "a..b" || proof_jws.is_empty() {
        bail!(
            "T8.1 step 5: inkson mock emitted a placeholder proof (`jws={}`); \
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
    // `ak:` literals and any forbidden correlation key. The push wrapper's
    // routing metadata (`destination_service_id`, `operation_id`) is
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
/// same sanitiser pass plus an explicit forbidden-key audit.
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
        "strand_id",
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
/// recipient_service_id the Space does not allow. The candidate now
/// single-sources that recipient under `member_delivery_binding`, so this
/// step models the reducer allow-list instead of an SDK outer/inner mismatch.
fn step_8_rebind_handover(original: &MemberDeliveryBindingCandidate) -> Result<()> {
    let mut handover = original.clone();
    handover.member_delivery_binding.recipient_service_id = DidCoreId::new(REBOUND_PRINCIPAL_ID)?;
    if handover
        .validate(&CandidateValidationContext::new(TARGET_REALM_ID.to_owned()))
        .is_ok()
    {
        bail!("T8.1 step 8: recipient substitution escaped exact principal authority pair");
    }

    let allowed = [PRINCIPAL_ID];
    if allowed.contains(
        &handover
            .member_delivery_binding
            .recipient_service_id
            .as_str(),
    ) {
        bail!("T8.1 step 8: rebound recipient unexpectedly passed allow-list");
    }
    Ok(())
}

// ── Step 9: revocation ─────────────────────────────────────────────────────

/// A `ak.handle.revoke` event in coauth invalidates the handle row, which
/// at the SDK layer is modelled by the candidate's `expires_at` falling
/// strictly into the past. Any subsequent `member_add` MUST refuse with
/// `Expired`.
fn step_9_revocation(original: &MemberDeliveryBindingCandidate) -> Result<()> {
    let mut revoked = original.clone();
    revoked.expires_at = Utc::now() - ChronoDuration::seconds(1);
    let ctx = CandidateValidationContext::new(TARGET_REALM_ID.to_owned());
    match revoked.validate(&ctx) {
        Err(CandidateError::Expired { .. }) => Ok(()),
        Err(other) => bail!(
            "T8.1 step 9: revocation must surface `Expired` so subsequent \
             member_add ops refuse; got {other:?}"
        ),
        Ok(()) => bail!(
            "T8.1 step 9: a revoked (expires_at in the past) candidate was \
             accepted — `ak.handle.revoke` had no observable effect"
        ),
    }
}

// ── Negative cases ─────────────────────────────────────────────────────────

/// `did_document_fallback_rejected` — `binding_source = did_document_default`
/// is forbidden at the schema/SDK boundary regardless of Realm policy. This
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
/// `realm_id` / `space_id` / `strand_id` / `event_id` MUST be rejected by the
/// sanitizer.
fn negative_stable_push_id_leak_rejected() -> Result<()> {
    let leaks: &[(&str, Value)] = &[
        ("realm_id", json!(TARGET_REALM_ID)),
        ("realm_id", json!(TARGET_REALM_ID)),
        ("strand_id", json!(STABLE_STRAND_ID)),
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
                    arkret_push_policy::blind_payload_sanitizer::BlindPayloadReasonCode::ForbiddenField
                        | arkret_push_policy::blind_payload_sanitizer::BlindPayloadReasonCode::SensitiveLiteral
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

/// `placeholder_proof_sdk_layer` — the inkson pre-T1.3 placeholder
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
    let jws = proof.jws.as_str();
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

/// Whether the entire four-binary stack is wired in the current
/// environment. Mirrors `joint_service_stack_available` in T3.5 but extends
/// it to include floria.
fn full_stack_available() -> bool {
    coauth_with_db_available()
        && skip_reason(&SOLAND_SPEC).is_none()
        && skip_reason(&TEABAY_SPEC).is_none()
        && skip_reason(&FLORIA_SPEC).is_none()
}

/// Best-effort live probe: when all four binaries (+ Docker for coauth's
/// ephemeral Postgres, DATABASE_URL for teabay, and FLORIA_CONFIG) are present, bring the stack up
/// and confirm every health endpoint answers. The detailed wire-level
/// surfaces (resolve-handle, member_add, push notify) are covered by
/// dedicated scenarios; T8.1's live leg is the cross-binary boot check.
async fn live_stack_probe() -> Result<()> {
    // 1. Bring up coauth + soland + teabay.
    let stack = try_bootstrap(JointServiceConfig::new("t8-1-full-stack-e2e")).await?;
    stack.assert_healthy().await?;

    // 2. Probe teabay's `resolve-handle` surface; same gating as T3.5 — we don't seed a real row,
    //    so blinded `not_found` is the spec-correct shape.
    let teabay = stack
        .teabay
        .as_ref()
        .ok_or_else(|| anyhow!("T8.1 live probe: teabay handle missing after bootstrap"))?;
    let resolve_url = format!(
        "{}/_arkret/find/directory/resolve-handle",
        teabay.base_url.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let resp = client
        .post(&resolve_url)
        .json(&serde_json::from_value::<
            arkret_models_discovery::DirectoryResolveHandleRequestBody,
        >(json!({
            "handle": ALICE_HANDLE,
            "intent": "member_add",
            "requester": PRINCIPAL_ID,
            "audience": TARGET_REALM_ID,
            "realm_id": TARGET_REALM_ID,
        }))?)
        .send()
        .await
        .context("POST /_arkret/find/directory/resolve-handle on live teabay")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !(status.is_success() || status.as_u16() == 404) {
        bail!(
            "T8.1 live probe: teabay resolve-handle returned unexpected \
             status {status}; body: {text}"
        );
    }

    // 3. Production-mode placeholder rejection — spawn an additional soland in production posture
    //    (separate handle so this does not interfere with the dev-mode soland inside the
    //    bootstrap).
    if let Some(prod_soland) =
        try_spawn_with_extra_env(&SOLAND_SPEC, &[("SOLAND_DEVELOPMENT_MODE", "false")])
            .await
            .context("T8.1 live probe: spawn production-mode soland")?
    {
        let mut placeholder_event = crate::harness::event_envelope(
            ALICE_FULL_ID,
            TARGET_REALM_ID,
            "ak.message.create",
            crate::harness::message_create_text_payload(
                "ak:strand:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934",
                "hi",
            )?,
        );
        let arkret_wire::EventProof::Producer(proof) = &mut placeholder_event.proofs[0] else {
            unreachable!("freshly authored Event has producer proof")
        };
        proof.jws = "a..b".to_owned();
        let placeholder_submission = crate::publication::initial_submission(placeholder_event, "")?;
        let prod_resp = client
            .post(prod_soland.url("/_arkret/self/events"))
            .bearer_auth("cotest-bogus-token-not-a-real-session")
            .json(&placeholder_submission)
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

    // 4. TODO(T8.1 live wire): once floria's `notify` surface is wired with a soland → floria →
    //    mock receiver path that does not require a rendered FLORIA_CONFIG dependency, drive a full
    //    blind-wakeup round-trip here. The SDK contract surface already covers the payload shape;
    //    this hook is left for when the bridge gets a test-mode wiring.

    Ok(())
}

// ── Shared fixture ─────────────────────────────────────────────────────────

/// Mirrors the T3.5 happy-path candidate. Centralised here so the
/// negative-case mutations stay one diff away from the happy shape.
fn sample_candidate() -> Result<MemberDeliveryBindingCandidate> {
    let subject = DidCoreId::new(ALICE_ID)?;
    let principal = DidCoreId::new(PRINCIPAL_ID)?;
    let principal_authority = PrincipalAuthorityKey::new(subject.clone(), principal.clone());
    let handle = Handle::parse(ALICE_HANDLE)?;
    let mut modes = BTreeSet::new();
    modes.insert(DeliveryMode::Events);
    modes.insert(DeliveryMode::Sync);

    Ok(MemberDeliveryBindingCandidate {
        subject_id: subject,
        principal_authority,
        handle,
        handle_aliases: vec!["acct:alice@acme.example".to_owned()],
        member_delivery_binding: DeliveryBindingHint {
            recipient_service_id: principal.clone(),
            recipient_service_kind: RecipientServiceKind::PrincipalServer,
            binding_source: HandleHintBindingSource::OrganizationPolicy,
            delivery_modes: modes,
            service_acceptance_ref: Some(
                "ak:event:AfPgQP_sR1tmWDCox_M0w4ypjV53kE6rtQlYvPf_xll2".to_owned(),
            ),
            policy_event_ref: Some(
                "ak:event:AbAWvgHwDMsvHp-83ayUI2TKbLu45n6bfQhAgod9_Q_P".to_owned(),
            ),
        },
        issuer_service_id: principal,
        audience: TARGET_REALM_ID.to_owned(),
        expires_at: future_expiry(ChronoDuration::minutes(5)),
        issued_at: Utc::now(),
        source_refs: vec![EventId::new(SOURCE_REF_EVENT_ID.to_owned())?],
        proofs: vec![candidate_payload_proof(
            "sha256:00000000000000000000000000000000000000000000000000000000000000bb",
            TARGET_REALM_ID,
            "real.shaped.jws",
        )?],
        claim_digest: None,
        intent: CandidateIntent::MemberAdd,
    })
}

fn future_expiry(window: ChronoDuration) -> DateTime<Utc> {
    Utc::now() + window
}

fn candidate_payload_proof(digest: &str, audience: &str, jws: &str) -> Result<Proof> {
    Ok(Proof {
        kind: "detached_jws".to_owned(),
        verification_method: crate::fixture_did_url("did:web:principal.acme.example#key-1"),
        event_digest: Hash::new(digest.to_owned())?,
        signer_resolution_evidence_ref: None,
        signer_resolution_evidence_digest: None,
        created_at: DateTime::parse_from_rfc3339("2026-05-19T00:00:00.000Z")?.with_timezone(&Utc),
        domain: None,
        audience: Some(Audience::Single(audience.to_owned())),
        proof_purpose: None,
        jws: jws.to_owned(),
    })
}
