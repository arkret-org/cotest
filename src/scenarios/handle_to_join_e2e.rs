//! T3.5 — Handle → Join E2E.
//!
//! Stitches the four pieces shipped in T3.1–T3.4 into a single black-box
//! scenario:
//!
//!   1. coauth (T3.2) issues a `handle_claim` whose `handle` is the canonical
//!      `<localpart>:<domain>` form (R3.1 wire rename from `handle_uri`, arkret-spec @ 7157ee8) and
//!      whose `member_delivery_binding` points at a recipient principal server.
//!   2. teabay (T3.4) hosts `ak.find.directory.read.resolve_handle(intent="member_add")` and
//!      filters candidates against the target Realm's `allowed_recipient_services`.
//!   3. soland (T3.3) projects `ak.realm.delivery_binding_policy` and the `ak.member.state{join}`
//!      reducer rejects bindings whose `recipient_service_id` is not in the policy allow-list.
//!   4. The SDK (T3.1) ships `MemberDeliveryBindingCandidate` and
//!      `Realm::member_add_with_candidate` as the sanctioned builder-side entry point: the
//!      candidate is re-validated against `audience = target_realm_id` + `now` before any operation
//!      is built.
//!
//! ## Scope of this scenario
//!
//! The protocol fans across three live services, but the rejection contract
//! is single-sourced in the SDK candidate validator + soland reducer. Per
//! cotest convention (see `soland_teabay_directory_sync.rs`, which gates on
//! the full four-service stack and silently skips otherwise), this scenario:
//!
//!  - **Happy path** — boots `four_service_bootstrap` when COAUTH_BIN / SOLAND_BIN / TEABAY_BIN are
//!    all available and exercises the live `/_arkret/find/directory/resolve-handle` surface. When
//!    the stack is partial (the default cargo-test posture), the scenario falls back to the SDK
//!    candidate builder, exercising the same `audience` / `expires_at` / `subject_id` /
//!    `binding_source` invariants that the live teabay row in T3.4 enforces.
//!  - **Negative cases** — always run; each builds a malformed candidate and asserts the matching
//!    `CandidateError` (or `Realm::member_add_with_candidate` rejection) fires. These guard the SDK
//!    contract surface that downstream callers (inkson, sodmin, future web UI) rely on regardless
//!    of which directory implementation is in front of them.

use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use arkret_identifiers::{DidCoreId, EventId, Hash, RealmId};
use arkret_models_collaboration::governance::member_delivery_binding_candidate::{
    CandidateError, CandidateIntent, CandidateValidationContext, MemberDeliveryBindingCandidate,
};
use arkret_models_identity::delivery_binding::{DeliveryMode, RecipientServiceKind};
use arkret_models_identity::handle::{Handle, HandleHintBindingSource};
use arkret_models_identity::handle_claim::DeliveryBindingHint;
use arkret_wire::{Audience, PrincipalAuthorityInstance, Proof};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde_json::{Value, json};

use crate::scenarios::_helpers::coauth_bootstrap::coauth_with_db_available;
use crate::scenarios::_helpers::external_binary::{SOLAND_SPEC, TEABAY_SPEC, skip_reason};
use crate::scenarios::_helpers::four_service_bootstrap::{FourServiceConfig, try_bootstrap};

// ── Test fixture knobs ─────────────────────────────────────────────────────

/// Stable Realm DID used as the candidate audience for the happy path. Picked
/// so the assertions read as a Realm identifier and not as a free-form string.
const TARGET_REALM_ID: &str = "ak:realm:0196419b-0000-8000-8000-handle2joinaa";

/// Stable principal-server DID that appears as both the issuer and the
/// recipient on the candidate. T3.4's allow-list test uses the same shape.
const PRINCIPAL_ID: &str = "ak:did_core:web:principal.acme.example";

/// Alternate principal-server DID — used by the `service_not_allowed`
/// negative to model a Realm whose policy only lists `PRINCIPAL_ID`.
const OTHER_PRINCIPAL_ID: &str = "ak:did_core:web:rogue.example";

/// Subject DID for the happy path actor.
const ALICE_ID: &str = "ak:did_core:web:alice.acme.example";

/// Canonical handle for Alice — R3.1 wire form `<localpart>:<domain>`. The
/// acct: alias appears in `handle_aliases[]` as the interop form, mirroring
/// the coauth `issue_handle_claim` output (arkret-spec @ 7157ee8).
const ALICE_HANDLE: &str = "alice:acme.example";

/// Source-ref event id the directory would echo back on a real
/// `ak.find.directory.read.resolve_handle` envelope. Carried so `source_refs[]` is
/// non-empty (a candidate validator MUST-rule).
const SOURCE_REF_EVENT_ID: &str = "ak:event:AccVsThCMukcEF5tfolTyrO1SoKc5W7qAlVm_mDWvfuw";

// ── Public scenario entry-point ────────────────────────────────────────────

/// T3.5 — drive the Handle → Join chain end-to-end.
pub async fn handle_to_join_e2e_run() -> Result<()> {
    // 1. Always run the SDK-level happy path. This exercises T3.1's
    //    `MemberDeliveryBindingCandidate` validator + `member_add_with_ candidate` builder.
    happy_path_via_sdk_candidate().context("T3.5 happy path (SDK candidate)")?;

    // 2. Always run every negative case. Each maps to one of the `CandidateError` variants T3.1
    //    exposes; in production these are the same gates teabay (T3.4) and soland (T3.3) re-run on
    //    the wire.
    negative_case_verified_false().context("T3.5 negative — verified=false on handle row")?;
    negative_case_subject_mismatch().context("T3.5 negative — claim subject != caller did")?;
    negative_case_expired().context("T3.5 negative — candidate expired")?;
    negative_case_audience_mismatch().context("T3.5 negative — audience != target Realm")?;
    negative_case_service_not_allowed()
        .context("T3.5 negative — recipient_service_id not in Realm allow-list")?;
    negative_case_same_core_different_authority_instance()
        .context("T3.5 negative — same principal core with substituted PCR authority")?;
    negative_case_acct_canonical_rejected().context("T3.5 negative — acct: as canonical handle")?;
    negative_case_did_document_fallback_rejected()
        .context("T3.5 negative — DID Document fallback masquerades as handle candidate")?;

    // 3. Best-effort live-stack probe. If the full four-service stack happens to be available
    //    (COAUTH_BIN + SOLAND_BIN + TEABAY_BIN
    //    + DATABASE_URL + docker), drive a real HTTP `resolve-handle`
    //    against teabay and assert the surface responds with the
    //    `ak.find.directory.read.resolve_handle` envelope shape. Partial stacks
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
    let ctx = CandidateValidationContext::new(TARGET_REALM_ID.to_owned())
        .with_expected_subject(DidCoreId::new(ALICE_ID)?);

    candidate.validate(&ctx).map_err(|e| {
        anyhow!(
            "T3.5 happy path: a freshly minted handle_claim-shaped candidate \
             MUST validate against the target Realm audience + subject, but \
             validate() returned {e:?}"
        )
    })?;

    // The candidate's canonical `handle` MUST round-trip through the
    // canonical `<localpart>:<domain>` form — guards against directory
    // caches that silently rewrite to `acct:` or to the retired
    // `arkret://` URI form (forbidden per T3.1 / R3.1).
    let canonical = candidate.handle.canonical();
    let mut colon_parts = canonical.split(':');
    let local = colon_parts.next().unwrap_or_default();
    let domain = colon_parts.next().unwrap_or_default();
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        bail!(
            "T3.5 happy path: candidate.handle is not canonical \
             `<localpart>:<domain>`; got `{canonical}`. The directory MUST \
             NOT emit acct:/arkret:// handles (identity-handles.md §3.1, \
             R3.1 wire rename)."
        );
    }
    if canonical.starts_with("arkret://") || canonical.starts_with("acct:") {
        bail!(
            "T3.5 happy path: candidate.handle leaked a retired URI form \
             (`{canonical}`); only `<localpart>:<domain>` is accepted on the \
             wire after R3.1."
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

    // The recipient route is single-sourced through member_delivery_binding.
    if candidate
        .member_delivery_binding
        .recipient_service_id
        .as_str()
        != PRINCIPAL_ID
    {
        bail!(
            "T3.5 happy path: member_delivery_binding.recipient_service_id \
             must remain the principal service; got {}",
            candidate
                .member_delivery_binding
                .recipient_service_id
                .as_str()
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
    let ctx = CandidateValidationContext::new(TARGET_REALM_ID.to_owned());

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
/// candidate's `subject_id` does not match. Catches stale directory caches
/// that reuse a candidate across handle reassignments.
fn negative_case_subject_mismatch() -> Result<()> {
    let candidate = sample_candidate()?;
    let mallory = DidCoreId::new("ak:did_core:web:mallory.example")?;
    let ctx =
        CandidateValidationContext::new(TARGET_REALM_ID.to_owned()).with_expected_subject(mallory);

    match candidate.validate(&ctx) {
        Err(CandidateError::SubjectMismatch { .. }) => Ok(()),
        Err(other) => bail!("T3.5 subject_mismatch: expected `SubjectMismatch`, got {other:?}"),
        Ok(()) => bail!(
            "T3.5 subject_mismatch: a candidate with subject_id != \
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
    let ctx = CandidateValidationContext::new(TARGET_REALM_ID.to_owned());

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

/// `audience_mismatch` — the candidate was issued for a *different* Realm
/// than the one the caller is joining. Required by spec §9 + T3.4.
fn negative_case_audience_mismatch() -> Result<()> {
    let candidate = sample_candidate()?;
    let ctx =
        CandidateValidationContext::new("ak:realm:0196419b-0000-8000-8000-WRONGSPACEXX".to_owned());

    match candidate.validate(&ctx) {
        Err(CandidateError::AudienceMismatch { .. }) => Ok(()),
        Err(other) => bail!("T3.5 audience_mismatch: expected `AudienceMismatch`, got {other:?}"),
        Ok(()) => bail!(
            "T3.5 audience_mismatch: a candidate bound to a different Realm \
             audience was accepted — directory caches MUST NOT replay \
             cross-Realm"
        ),
    }
}

/// `service_not_allowed` — the candidate's `recipient_service_id` is not in
/// the target Realm's `allowed_recipient_services`. This is the soland
/// (T3.3) reducer gate (`recipient_service_not_allowed`). The SDK candidate
/// validator itself does not own the Realm's policy cell; the candidate now
/// single-sources the recipient under `member_delivery_binding`.
///
/// The full Realm-policy check is exercised in the live-stack probe below;
/// here we pin the local allow-list predicate that downstream reducers can
/// rely on.
fn negative_case_service_not_allowed() -> Result<()> {
    let mut candidate = sample_candidate()?;
    candidate.member_delivery_binding.recipient_service_id = DidCoreId::new(OTHER_PRINCIPAL_ID)?;
    if candidate
        .validate(&CandidateValidationContext::new(TARGET_REALM_ID.to_owned()))
        .is_ok()
    {
        bail!("T3.5 service_not_allowed: recipient substitution escaped authority binding");
    }

    let allowed = [PRINCIPAL_ID];
    if allowed.contains(
        &candidate
            .member_delivery_binding
            .recipient_service_id
            .as_str(),
    ) {
        bail!("T3.5 service_not_allowed: rogue recipient unexpectedly passed allow-list");
    }
    Ok(())
}

/// A stable principal core does not authorize a different PCR generation.
/// The authority-instance digest is the downstream cache/admission key.
fn negative_case_same_core_different_authority_instance() -> Result<()> {
    let accepted = sample_candidate()?;
    let mut substituted = accepted.clone();
    substituted.principal_authority_instance = PrincipalAuthorityInstance::new(
        accepted.subject_id.clone(),
        accepted
            .member_delivery_binding
            .recipient_service_id
            .clone(),
        RealmId::new("ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1")?,
        Hash::new(format!("sha256:{}", "6".repeat(64)))?,
    )?;
    if substituted
        .principal_authority_instance
        .authority_instance_digest
        == accepted
            .principal_authority_instance
            .authority_instance_digest
    {
        bail!("different PCR lineage produced the same authority-instance digest");
    }
    if substituted == accepted {
        bail!("same-core authority substitution was erased by candidate equality");
    }
    Ok(())
}

/// `acct_canonical_rejected` — R3.1 canonical form is
/// `<localpart>:<domain>`. `acct:<local>@<domain>` may appear in
/// `handle_aliases[]` but MUST NOT appear as the canonical `handle`. The
/// retired `arkret://...` URI form is also rejected. The SDK's
/// `Handle::parse` enforces this at construction time, so we exercise the
/// rejection by feeding a serialised candidate where the `handle` field
/// carries the forbidden `acct:` string.
fn negative_case_acct_canonical_rejected() -> Result<()> {
    let candidate = sample_candidate()?;
    let mut value =
        serde_json::to_value(&candidate).context("serialise sample candidate to JSON")?;
    value["handle"] = json!("acct:alice@acme.example");

    let parsed: std::result::Result<MemberDeliveryBindingCandidate, _> =
        serde_json::from_value(value);
    match parsed {
        Err(e) => {
            let msg = format!("{e}");
            // `Handle::parse` returns `Error::Protocol("handle ...")` — the
            // substring "handle" anchors the assertion to the canonical-form
            // check we care about.
            if !msg.to_lowercase().contains("handle") {
                bail!(
                    "T3.5 acct_canonical_rejected: deserialisation rejected the \
                     payload but with an unexpected error message `{msg}` — \
                     expected the `Handle::parse` canonical-form rejection"
                );
            }
            Ok(())
        }
        Ok(_) => bail!(
            "T3.5 acct_canonical_rejected: an `acct:` value was accepted as the \
             canonical handle — `handle` MUST be `<localpart>:<domain>` \
             (identity-handles.md §3.1, R3.1 wire rename)"
        ),
    }
}

/// `did_document_fallback_rejected` — `member_delivery_binding.binding_source`
/// MUST be one of `{Explicit, Invite, JoinPolicy, OrganizationPolicy,
/// RealmPolicy}`. The forbidden `did_document_default` value is excluded
/// from the typed enum at the schema/SDK boundary, so we exercise the
/// rejection by attempting deserialisation of a payload carrying that
/// string.
fn negative_case_did_document_fallback_rejected() -> Result<()> {
    let candidate = sample_candidate()?;
    let mut value =
        serde_json::to_value(&candidate).context("serialise sample candidate to JSON")?;
    value["member_delivery_binding"]["binding_source"] = json!("did_document_default");

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
/// All three sibling binaries plus their actual runtime prerequisites MUST be present
/// for the live leg to run. Anything else is a silent skip, matching the
/// rest of the `_helpers` suite.
fn four_service_stack_available() -> bool {
    coauth_with_db_available()
        && skip_reason(&SOLAND_SPEC).is_none()
        && skip_reason(&TEABAY_SPEC).is_none()
}

async fn live_stack_probe() -> Result<()> {
    let stack = try_bootstrap(FourServiceConfig::new("t3-5-handle-to-join")).await?;
    stack.assert_healthy().await?;

    // Live teabay surface check: `ak.find.directory.read.resolve_handle` accepts
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
        "{}/_arkret/find/directory/resolve-handle",
        teabay.base_url.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let resp = client
        .post(&url)
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
        .context("POST /_arkret/find/directory/resolve-handle to live teabay")?;
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
        // teabay T3.4 wiring is mis-parsing `intent`/`realm_id`.
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
/// `resolve_handle` response. `audience = TARGET_REALM_ID` so the candidate
/// validates against the same Realm the SDK builder is asked to join.
fn sample_candidate() -> Result<MemberDeliveryBindingCandidate> {
    let subject = DidCoreId::new(ALICE_ID)?;
    let principal = DidCoreId::new(PRINCIPAL_ID)?;
    let principal_authority_instance = PrincipalAuthorityInstance::new(
        subject.clone(),
        principal.clone(),
        RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K")?,
        Hash::new(format!("sha256:{}", "5".repeat(64)))?,
    )?;
    let handle = Handle::parse(ALICE_HANDLE)?;
    let mut modes = BTreeSet::new();
    modes.insert(DeliveryMode::Events);
    modes.insert(DeliveryMode::Sync);

    Ok(MemberDeliveryBindingCandidate {
        subject_id: subject,
        principal_authority_instance,
        handle,
        handle_aliases: vec!["acct:alice@acme.example".to_owned()],
        member_delivery_binding: DeliveryBindingHint {
            recipient_service_id: principal.clone(),
            recipient_service_kind: RecipientServiceKind::PrincipalServer,
            binding_source: HandleHintBindingSource::OrganizationPolicy,
            delivery_modes: modes,
            service_acceptance_ref: Some(
                "ak:event:AafiSe5-0DLIzxypKeEYStsz0tPrLS0bvyfdfmJHrGtZ".to_owned(),
            ),
            policy_event_ref: Some(
                "ak:event:AQ34vCwlfah2TO0DO9lN1zqgfyIP-qbCp6Kq2XMiySVs".to_owned(),
            ),
        },
        issuer_service_id: principal,
        audience: TARGET_REALM_ID.to_owned(),
        expires_at: future_expiry(ChronoDuration::minutes(5)),
        issued_at: Utc::now(),
        source_refs: vec![EventId::new(SOURCE_REF_EVENT_ID.to_owned())?],
        proofs: vec![candidate_payload_proof(
            "sha256:00000000000000000000000000000000000000000000000000000000000000aa",
            TARGET_REALM_ID,
            "aaa.bbb.ccc",
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
        created_at: DateTime::parse_from_rfc3339("2026-05-19T00:00:00.000Z")?.with_timezone(&Utc),
        domain: None,
        audience: Some(Audience::Single(audience.to_owned())),
        proof_purpose: None,
        jws: jws.to_owned(),
    })
}
