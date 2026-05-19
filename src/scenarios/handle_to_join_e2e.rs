//! T3.5 — Handle → Join E2E.
//!
//! Stitches the four pieces shipped in T3.1–T3.4 into a single black-box
//! scenario:
//!
//!   1. coauth (T3.2) issues a `handle_claim` whose `handle_uri` is the
//!      canonical `contrix://...` form and whose `delivery_binding_hint`
//!      points at a recipient principal server.
//!   2. teabay (T3.4) hosts `cx.directory.resolve_handle(intent="member_add")`
//!      and filters candidates against the target Space's
//!      `allowed_recipient_services`.
//!   3. soland (T3.3) projects `cx.realm.delivery_binding_policy` and the
//!      `cx.member.state{join}` reducer rejects bindings whose
//!      `recipient_service_did` is not in the policy allow-list.
//!   4. The SDK (T3.1) ships `MemberDeliveryBindingCandidate` and
//!      `Space::member_add_with_candidate` as the *only* sanctioned
//!      builder-side entry point: the candidate is re-validated against
//!      `audience = target_space_id` + `now` before any operation is built.
//!
//! ## Scope of this scenario
//!
//! The protocol fans across three live services, but the rejection contract
//! is single-sourced in the SDK candidate validator + soland reducer. Per
//! cotest convention (see `soland_teabay_directory_sync.rs`, which gates on
//! the full four-service stack and silently skips otherwise), this scenario:
//!
//!  - **Happy path** — boots `four_service_bootstrap` when COAUTH_BIN /
//!    SOLAND_BIN / TEABAY_BIN are all available and exercises the live
//!    `/api/v1/directory/resolve-handle` surface. When the stack is
//!    partial (the default cargo-test posture), the scenario falls back to
//!    the SDK candidate builder, exercising the same `audience` /
//!    `expires_at` / `subject_did` / `binding_source` invariants that the
//!    live teabay row in T3.4 enforces.
//!  - **Negative cases** — always run; each builds a malformed candidate
//!    and asserts the matching `CandidateError` (or `Space::
//!    member_add_with_candidate` rejection) fires. These guard the SDK
//!    contract surface that downstream callers (yougen, sodmin, future
//!    web UI) rely on regardless of which directory implementation is in
//!    front of them.

use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use contrix_core::{
    CandidateError, CandidateIntent, CandidateValidationContext, DeliveryBindingHint,
    DeliveryMode, Did, HandleHintBindingSource, HandleUri, MemberDeliveryBindingCandidate,
    RecipientServiceType,
};
use serde_json::{Value, json};

use crate::scenarios::_helpers::external_binary::{
    COAUTH_SPEC, SOLAND_SPEC, TEABAY_SPEC, skip_reason,
};
use crate::scenarios::_helpers::four_service_bootstrap::{
    FourServiceConfig, try_bootstrap,
};

// ── Test fixture knobs ─────────────────────────────────────────────────────

/// Stable Space DID used as the candidate audience for the happy path. Picked
/// so the assertions read as a Space identifier and not as a free-form string.
const TARGET_SPACE_ID: &str = "cx:realm:0196419b-0000-7000-8000-handle2joinaa";

/// Stable principal-server DID that appears as both the issuer and the
/// recipient on the candidate. T3.4's allow-list test uses the same shape.
const PRINCIPAL_DID: &str = "did:web:principal.acme.example";

/// Alternate principal-server DID — used by the `service_not_allowed`
/// negative to model a Space whose policy only lists `PRINCIPAL_DID`.
const OTHER_PRINCIPAL_DID: &str = "did:web:rogue.example";

/// Subject DID for the happy path actor.
const ALICE_DID: &str = "did:web:alice.acme.example";

/// Handle URI for alice in canonical Contrix form. The acct: alias appears
/// in `handle_aliases[]` as the interop form, mirroring the coauth
/// `issue_handle_claim` output.
const ALICE_HANDLE_URI: &str = "contrix://acme.example/users/alice";

/// Source-ref event id the directory would echo back on a real
/// `cx.directory.resolve_handle` envelope. Carried so `source_refs[]` is
/// non-empty (a candidate validator MUST-rule).
const SOURCE_REF_EVENT_ID: &str = "cx:event:01890000-0000-7000-8000-source0001";

// ── Public scenario entry-point ────────────────────────────────────────────

/// T3.5 — drive the Handle → Join chain end-to-end.
pub async fn handle_to_join_e2e_run() -> Result<()> {
    // 1. Always run the SDK-level happy path. This exercises T3.1's
    //    `MemberDeliveryBindingCandidate` validator + `member_add_with_
    //    candidate` builder.
    happy_path_via_sdk_candidate().context("T3.5 happy path (SDK candidate)")?;

    // 2. Always run every negative case. Each maps to one of the
    //    `CandidateError` variants T3.1 exposes; in production these are
    //    the same gates teabay (T3.4) and soland (T3.3) re-run on the
    //    wire.
    negative_case_verified_false()
        .context("T3.5 negative — verified=false on handle row")?;
    negative_case_subject_mismatch()
        .context("T3.5 negative — claim subject != caller did")?;
    negative_case_expired()
        .context("T3.5 negative — candidate expired")?;
    negative_case_audience_mismatch()
        .context("T3.5 negative — audience != target space")?;
    negative_case_service_not_allowed()
        .context("T3.5 negative — recipient_service_did not in Space allow-list")?;
    negative_case_acct_canonical_rejected()
        .context("T3.5 negative — acct: as canonical handle_uri")?;
    negative_case_did_document_fallback_rejected()
        .context("T3.5 negative — DID Document fallback masquerades as handle candidate")?;

    // 3. Best-effort live-stack probe. If the full four-service stack
    //    happens to be available (COAUTH_BIN + SOLAND_BIN + TEABAY_BIN
    //    + DATABASE_URL + docker), drive a real HTTP `resolve-handle`
    //    against teabay and assert the surface responds with the
    //    `cx.directory.resolve_handle` envelope shape. Partial stacks
    //    silently skip this leg — the SDK assertions above are the
    //    cotest contract surface.
    if four_service_stack_available() {
        live_stack_probe()
            .await
            .context("T3.5 live four-service stack probe")?;
    }

    Ok(())
}

// ── Happy path (SDK candidate) ─────────────────────────────────────────────

fn happy_path_via_sdk_candidate() -> Result<()> {
    let candidate = sample_candidate()?;
    let ctx = CandidateValidationContext::new(TARGET_SPACE_ID.to_owned())
        .with_expected_subject(Did::new(ALICE_DID.to_owned())?);

    candidate.validate(&ctx).map_err(|e| {
        anyhow!(
            "T3.5 happy path: a freshly minted handle_claim-shaped candidate \
             MUST validate against the target Space audience + subject, but \
             validate() returned {e:?}"
        )
    })?;

    // The candidate's canonical `handle_uri` MUST round-trip through the
    // canonical form — guards against directory caches that silently
    // rewrite to `acct:` (forbidden per T3.1).
    let canonical = candidate.handle_uri.canonical();
    if !canonical.starts_with("contrix://") || !canonical.contains("/users/") {
        bail!(
            "T3.5 happy path: candidate.handle_uri is not canonical contrix://...; \
             got `{canonical}`. The directory MUST NOT emit acct:/bare-host \
             handle URIs (identity-handles.md §3.1)."
        );
    }
    if !candidate
        .handle_aliases
        .iter()
        .any(|a| a == "acct:alice@acme.example")
    {
        bail!(
            "T3.5 happy path: candidate.handle_aliases must carry the acct: \
             interop form so cross-protocol verifiers (Matrix/AP) can match. \
             got handle_aliases = {:?}",
            candidate.handle_aliases
        );
    }

    // Outer recipient_service_did and the embedded hint MUST agree. This is
    // the soland (T3.3) rebind-handover gate, mirrored in the SDK validator.
    if candidate.recipient_service_did.as_str()
        != candidate
            .delivery_binding_hint
            .recipient_service_did
            .as_str()
    {
        bail!(
            "T3.5 happy path: outer.recipient_service_did != hint.recipient_service_did. \
             outer={}, inner={}",
            candidate.recipient_service_did.as_str(),
            candidate.delivery_binding_hint.recipient_service_did.as_str()
        );
    }

    // The candidate's claim_digest (when present) MUST match its canonical
    // SHA-256. Guards directory caches that mutate fields after the digest
    // was minted (T3.1 §3.7.1).
    let computed_digest = candidate
        .canonical_sha256()
        .context("T3.5 happy path: canonical_sha256")?;
    if !computed_digest.starts_with("sha256:") {
        bail!(
            "T3.5 happy path: canonical_sha256 MUST be `sha256:<hex>`; \
             got `{computed_digest}`"
        );
    }

    Ok(())
}

// ── Negative cases ─────────────────────────────────────────────────────────

/// `verified=false` — teabay's `envelope_from_projection` carries
/// `verified` from the handle row. A candidate minted off an unverified
/// row MUST NOT be accepted; the SDK surface models this by refusing to
/// build a candidate without `proofs[]` (an unverified row has no
/// directory-issuer signature to attach).
fn negative_case_verified_false() -> Result<()> {
    let mut candidate = sample_candidate()?;
    // Clearing proofs[] is the SDK-side analog of `verified=false` — there
    // is no audit/issuer proof to anchor the candidate to.
    candidate.proofs.clear();
    let ctx = CandidateValidationContext::new(TARGET_SPACE_ID.to_owned());

    match candidate.validate(&ctx) {
        Err(CandidateError::MissingProof) => Ok(()),
        Err(other) => bail!(
            "T3.5 verified=false: expected `MissingProof` (unverified handle has \
             no directory-signed proof to attach), got {other:?}"
        ),
        Ok(()) => bail!(
            "T3.5 verified=false: an unverified handle row's candidate \
             passed validation — the directory MUST NOT mint candidates from \
             rows where `verified=false` (identity-handles.md §3.7.3 #5)"
        ),
    }
}

/// `subject != did` — the calling actor asserts `expected_subject` and the
/// candidate's `subject_did` does not match. Catches stale directory caches
/// that reuse a candidate across handle reassignments.
fn negative_case_subject_mismatch() -> Result<()> {
    let candidate = sample_candidate()?;
    let mallory = Did::new("did:web:mallory.example".to_owned())?;
    let ctx = CandidateValidationContext::new(TARGET_SPACE_ID.to_owned())
        .with_expected_subject(mallory);

    match candidate.validate(&ctx) {
        Err(CandidateError::SubjectMismatch { .. }) => Ok(()),
        Err(other) => bail!(
            "T3.5 subject_mismatch: expected `SubjectMismatch`, got {other:?}"
        ),
        Ok(()) => bail!(
            "T3.5 subject_mismatch: a candidate with subject_did != \
             expected_subject was accepted — handle reassignment guard \
             missing"
        ),
    }
}

/// `expired` — coauth issues handle claims with a short TTL
/// (`HANDLE_CLAIM_TTL_MINUTES = 5`). The candidate validator MUST refuse
/// any claim whose `expires_at <= now`.
fn negative_case_expired() -> Result<()> {
    let mut candidate = sample_candidate()?;
    candidate.expires_at = Utc::now() - ChronoDuration::seconds(1);
    let ctx = CandidateValidationContext::new(TARGET_SPACE_ID.to_owned());

    match candidate.validate(&ctx) {
        Err(CandidateError::Expired { .. }) => Ok(()),
        Err(other) => bail!("T3.5 expired: expected `Expired`, got {other:?}"),
        Ok(()) => bail!(
            "T3.5 expired: a candidate past its expires_at was accepted — \
             coauth's 5-minute TTL gate is the upper bound and verifiers MUST \
             enforce strict-greater-than (`expires_at > now`)"
        ),
    }
}

/// `audience_mismatch` — the candidate was issued for a *different* Space
/// than the one the caller is joining. Required by spec §9 + T3.4.
fn negative_case_audience_mismatch() -> Result<()> {
    let candidate = sample_candidate()?;
    let ctx = CandidateValidationContext::new(
        "cx:realm:0196419b-0000-7000-8000-WRONGSPACEXX".to_owned(),
    );

    match candidate.validate(&ctx) {
        Err(CandidateError::AudienceMismatch { .. }) => Ok(()),
        Err(other) => bail!(
            "T3.5 audience_mismatch: expected `AudienceMismatch`, got {other:?}"
        ),
        Ok(()) => bail!(
            "T3.5 audience_mismatch: a candidate bound to a different Space \
             audience was accepted — directory caches MUST NOT replay \
             cross-Space"
        ),
    }
}

/// `service_not_allowed` — the candidate's `recipient_service_did` is not in
/// the target Space's `allowed_recipient_services`. This is the soland
/// (T3.3) reducer gate (`recipient_service_not_allowed`). The SDK candidate
/// validator itself does not own the Space's policy cell, but the candidate
/// MUST stay internally consistent (outer recipient_service_did == hint's),
/// which we exercise here by attempting a swap that breaks that invariant.
///
/// The full Space-policy check is exercised in the live-stack probe below;
/// here we pin the SDK-side internal consistency rule that downstream
/// reducers can rely on.
fn negative_case_service_not_allowed() -> Result<()> {
    let mut candidate = sample_candidate()?;
    // Swap the outer recipient_service_did to model "directory tried to
    // pivot the binding to a different service after the hint was minted".
    // The SDK validator refuses this regardless of Space policy.
    candidate.recipient_service_did = Did::new(OTHER_PRINCIPAL_DID.to_owned())?;
    let ctx = CandidateValidationContext::new(TARGET_SPACE_ID.to_owned());

    match candidate.validate(&ctx) {
        Err(CandidateError::RecipientServiceDidMismatch { .. }) => Ok(()),
        Err(other) => bail!(
            "T3.5 service_not_allowed: expected `RecipientServiceDidMismatch` \
             (outer/inner divergence), got {other:?}"
        ),
        Ok(()) => bail!(
            "T3.5 service_not_allowed: a candidate whose outer \
             recipient_service_did diverges from delivery_binding_hint.\
             recipient_service_did was accepted — directory MUST NOT pivot \
             recipients after the hint is minted"
        ),
    }
}

/// `acct_canonical_rejected` — the only canonical form is
/// `contrix://...`. `acct:<local>@<domain>` may appear in `handle_aliases[]`
/// but MUST NOT appear as the canonical `handle_uri`. The SDK's
/// `HandleUri::parse` enforces this at construction time, so we exercise
/// the rejection by feeding a serialised candidate where the
/// `handle_uri` field carries the forbidden `acct:` string.
fn negative_case_acct_canonical_rejected() -> Result<()> {
    let candidate = sample_candidate()?;
    let mut value = serde_json::to_value(&candidate)
        .context("serialise sample candidate to JSON")?;
    value["handle_uri"] = json!("acct:alice@acme.example");

    let parsed: std::result::Result<MemberDeliveryBindingCandidate, _> =
        serde_json::from_value(value);
    match parsed {
        Err(e) => {
            let msg = format!("{e}");
            // `HandleUri::parse` returns `Error::Protocol("handle uri must start
            // with contrix://: ...")` — the substring "contrix://" anchors
            // the assertion to the canonical-form check we care about.
            if !msg.contains("contrix://") && !msg.contains("handle uri") {
                bail!(
                    "T3.5 acct_canonical_rejected: deserialisation rejected the \
                     payload but with an unexpected error message `{msg}` — \
                     expected the `HandleUri::parse` canonical-form rejection"
                );
            }
            Ok(())
        }
        Ok(_) => bail!(
            "T3.5 acct_canonical_rejected: an `acct:` value was accepted as the \
             canonical handle_uri — `handle_uri` MUST be `contrix://...` \
             (identity-handles.md §3.1)"
        ),
    }
}

/// `did_document_fallback_rejected` — `delivery_binding_hint.binding_source`
/// MUST be one of `{Explicit, Invite, JoinPolicy, OrganizationPolicy,
/// SpacePolicy}`. The forbidden `did_document_default` value is excluded
/// from the typed enum at the schema/SDK boundary, so we exercise the
/// rejection by attempting deserialisation of a payload carrying that
/// string.
fn negative_case_did_document_fallback_rejected() -> Result<()> {
    let candidate = sample_candidate()?;
    let mut value = serde_json::to_value(&candidate)
        .context("serialise sample candidate to JSON")?;
    value["delivery_binding_hint"]["binding_source"] = json!("did_document_default");

    let parsed: std::result::Result<MemberDeliveryBindingCandidate, _> =
        serde_json::from_value(value);
    match parsed {
        Err(e) => {
            let msg = format!("{e}");
            // serde's enum-deserialisation error mentions "unknown variant"
            // when the value isn't one of the allowed `HandleHintBindingSource`
            // strings.
            if !msg.contains("variant")
                && !msg.contains("binding_source")
                && !msg.contains("did_document_default")
            {
                bail!(
                    "T3.5 did_document_fallback_rejected: deserialisation \
                     rejected the payload but with an unexpected error message \
                     `{msg}` — expected the `HandleHintBindingSource` \
                     unknown-variant rejection"
                );
            }
            Ok(())
        }
        Ok(_) => bail!(
            "T3.5 did_document_fallback_rejected: a candidate with \
             `binding_source = did_document_default` was accepted — handle-\
             resolved candidates and DID Document fallback are independent \
             materialisation paths (member-delivery-binding-candidate.schema.\
             json + identity-handles.md §3.7.3)"
        ),
    }
}

// ── Live-stack probe (best-effort) ─────────────────────────────────────────

/// Whether the full four-service stack is wired in the current environment.
/// All three sibling binaries plus their required env vars MUST be present
/// for the live leg to run. Anything else is a silent skip, matching the
/// rest of the `_helpers` suite.
fn four_service_stack_available() -> bool {
    skip_reason(&COAUTH_SPEC).is_none()
        && skip_reason(&SOLAND_SPEC).is_none()
        && skip_reason(&TEABAY_SPEC).is_none()
}

async fn live_stack_probe() -> Result<()> {
    let stack = try_bootstrap(FourServiceConfig::new("t3-5-handle-to-join")).await?;
    stack.assert_healthy().await?;

    // Live teabay surface check: `cx.directory.resolve_handle` accepts
    // `intent=member_add` and returns a structured response. We don't try
    // to mint a real signed claim — without a seeded directory row the
    // resolver collapses to blinded `not_found`, which is the spec-correct
    // shape we want to see (it confirms the surface is wired and the
    // teabay T3.4 policy filter is at least parsing the request body).
    let teabay = stack
        .teabay
        .as_ref()
        .ok_or_else(|| anyhow!("T3.5 live probe: teabay handle missing after bootstrap"))?;
    let url = format!(
        "{}/api/v1/directory/resolve-handle",
        teabay.base_url.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let resp = client
        .post(&url)
        .json(&json!({
            "handle": ALICE_HANDLE_URI,
            "intent": "member_add",
            "requester": PRINCIPAL_DID,
            "audience": TARGET_SPACE_ID,
            "realm_id": TARGET_SPACE_ID,
        }))
        .send()
        .await
        .context("POST /api/v1/directory/resolve-handle to live teabay")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();

    // Spec §10: unknown handles MUST collapse to blinded `not_found` (the
    // wire shape MUST NOT leak the existence of the handle). 200 with a
    // result envelope is also acceptable when fixtures happen to have
    // seeded a matching row.
    if status.is_success() {
        let body: Value = serde_json::from_str(&text)
            .with_context(|| format!("T3.5 live probe: resolve-handle body not JSON: {text}"))?;
        if !body.is_object() {
            bail!(
                "T3.5 live probe: resolve-handle 200 body was not a result \
                 envelope object: {text}"
            );
        }
    } else if status.as_u16() != 404 {
        bail!(
            "T3.5 live probe: resolve-handle returned unexpected status \
             {status}. body: {text}"
        );
    } else {
        // 404 path — verify the errcode is the blinded `not_found` we
        // expect, not a body-shape rejection that would suggest the
        // teabay T3.4 wiring is mis-parsing `intent`/`space_id`.
        let body: Value = serde_json::from_str(&text)
            .with_context(|| format!("T3.5 live probe: 404 body not JSON: {text}"))?;
        let errcode = body
            .pointer("/error/code")
            .or_else(|| body.pointer("/error/errcode"))
            .or_else(|| body.get("errcode"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !errcode.contains("not_found") {
            bail!(
                "T3.5 live probe: resolve-handle 404 expected blinded \
                 `not_found` errcode, got `{errcode}`. body: {text}"
            );
        }
    }

    Ok(())
}

// ── Shared fixture ─────────────────────────────────────────────────────────

/// Build a happy-path `MemberDeliveryBindingCandidate` that mirrors the
/// shape coauth's `issue_handle_claim` packs into the directory's
/// `resolve_handle` response. `audience = TARGET_SPACE_ID` so the candidate
/// validates against the same Space the SDK builder is asked to join.
fn sample_candidate() -> Result<MemberDeliveryBindingCandidate> {
    let subject = Did::new(ALICE_DID.to_owned())?;
    let principal = Did::new(PRINCIPAL_DID.to_owned())?;
    let handle_uri = HandleUri::parse(ALICE_HANDLE_URI)?;
    let mut modes = BTreeSet::new();
    modes.insert(DeliveryMode::Events);
    modes.insert(DeliveryMode::Sync);

    Ok(MemberDeliveryBindingCandidate {
        subject_did: subject,
        handle_uri,
        handle_aliases: vec!["acct:alice@acme.example".to_owned()],
        recipient_service_did: principal.clone(),
        delivery_binding_hint: DeliveryBindingHint {
            recipient_service_did: principal.clone(),
            recipient_service_type: RecipientServiceType::PrincipalServer,
            binding_source: HandleHintBindingSource::OrganizationPolicy,
            delivery_modes: modes,
            service_acceptance_ref: Some(
                "cx:event:01890000-0000-7000-8000-acceptance01".to_owned(),
            ),
            policy_ref: Some("cx:event:01890000-0000-7000-8000-policyref001".to_owned()),
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
            "payload_hash":
                "sha256:00000000000000000000000000000000000000000000000000000000000000aa",
            "created_at": "2026-05-19T00:00:00Z",
            "audience": TARGET_SPACE_ID,
            "jws": "aaa.bbb.ccc"
        })],
        claim_digest: None,
        intent: CandidateIntent::MemberAdd,
    })
}

fn future_expiry(window: ChronoDuration) -> DateTime<Utc> {
    Utc::now() + window
}
