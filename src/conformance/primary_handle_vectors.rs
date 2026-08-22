//! §3.2.1 primary handle selection conformance vectors (VECT-COT-1).
//!
//! Spec source: `identity/identity-handles.md §3.2.1` +
//! `handle-claim.schema.json`.
//!
//! These vectors drive the SDK's deterministic selection algorithm
//! ([`arkret::identity::select_primary_handle`]) and the canonical claim
//! digest ([`arkret::identity::claim_digest`]) directly, so every
//! implementation (inkson / sodmin / soland / teabay) agrees byte-for-byte.
//!
//! The §3.2.1 algorithm is a pure function of a six-tuple:
//! `(subject_id, context, claim_set_snapshot, policy_snapshot,
//!   holder_primary_handle_at_as_of, resolution_as_of)`. The
//! holder-preference layer is injected via `holder_primary_handle_at_as_of`
//! (materialised from the subject DID Document `metadata.primary_handle`).

use anyhow::{Result, anyhow, bail};
use arkret::identity::{
    HandleIssuerAuthorityClass, HandleIssuerPolicyEntry, PrimaryHandleSelectInput, claim_digest,
    select_primary_handle,
};
use arkret_identifiers::{DidCoreId, Hash};
use arkret_models_identity::{Handle, HandleBindingState, HandleClaim};
use arkret_wire::PayloadProof;
use chrono::{DateTime, TimeZone, Utc};

pub const VECTOR_ID_PH_EMPTY_FALLBACK: &str =
    "ak.cotest_vector.primary_handle_selection.empty_candidate_fallback.v1";
pub const VECTOR_ID_PH_SINGLE_PASSTHROUGH: &str =
    "ak.cotest_vector.primary_handle_selection.single_candidate_passthrough.v1";
pub const VECTOR_ID_PH_AUDIENCE_MATCH_WINS: &str =
    "ak.cotest_vector.primary_handle_selection.audience_match_wins.v1";
pub const VECTOR_ID_PH_HOLDER_FLAG_WINS: &str =
    "ak.cotest_vector.primary_handle_selection.holder_flag_wins_over_most_recent.v1";
pub const VECTOR_ID_PH_MOST_RECENT_WINS: &str =
    "ak.cotest_vector.primary_handle_selection.most_recent_wins_when_neither.v1";
pub const VECTOR_ID_PH_TIE_BREAK_ISSUER: &str =
    "ak.cotest_vector.primary_handle_selection.tie_break_by_accepted_issuers_position.v1";
pub const VECTOR_ID_PH_TIE_BREAK_CREATED_AT: &str =
    "ak.cotest_vector.primary_handle_selection.tie_break_by_created_at.v1";
pub const VECTOR_ID_PH_TIE_BREAK_CLAIM_DIGEST: &str =
    "ak.cotest_vector.primary_handle_selection.tie_break_by_claim_digest.v1";
pub const VECTOR_ID_PH_HOLDER_PRIMARY_NULL: &str =
    "ak.cotest_vector.primary_handle_selection.holder_primary_null_skips_layer.v1";
pub const VECTOR_ID_PH_AS_OF_REPLAY: &str =
    "ak.cotest_vector.primary_handle_selection.as_of_replay_vs_realtime.v1";
pub const VECTOR_ID_PH_CLAIM_DIGEST_STABLE: &str =
    "ak.cotest_vector.primary_handle_selection.claim_digest_stable_under_hint.v1";
pub const VECTOR_ID_PH_POLICY_SNAPSHOT_REPLAY: &str =
    "ak.cotest_vector.primary_handle_selection.policy_snapshot_as_of_replay.v1";

pub const ALL_PRIMARY_HANDLE_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_PH_EMPTY_FALLBACK,
    VECTOR_ID_PH_SINGLE_PASSTHROUGH,
    VECTOR_ID_PH_AUDIENCE_MATCH_WINS,
    VECTOR_ID_PH_HOLDER_FLAG_WINS,
    VECTOR_ID_PH_MOST_RECENT_WINS,
    VECTOR_ID_PH_TIE_BREAK_ISSUER,
    VECTOR_ID_PH_TIE_BREAK_CREATED_AT,
    VECTOR_ID_PH_TIE_BREAK_CLAIM_DIGEST,
    VECTOR_ID_PH_HOLDER_PRIMARY_NULL,
    VECTOR_ID_PH_AS_OF_REPLAY,
    VECTOR_ID_PH_CLAIM_DIGEST_STABLE,
    VECTOR_ID_PH_POLICY_SNAPSHOT_REPLAY,
];

// ── Fixture helpers ─────────────────────────────────────────────────────────

const ACME_ISSUER: &str = "ak:did_core:web:coauth.acme.example";
const OTHER_ISSUER: &str = "ak:did_core:web:coauth.other.example";

fn subject() -> Result<DidCoreId> {
    DidCoreId::new("ak:did_core:web:alice.principal.example").map_err(|e| anyhow!("subject: {e}"))
}

fn at(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .expect("valid pinned timestamp")
}

fn now_anchor() -> DateTime<Utc> {
    at(2026, 5, 27)
}

/// A verified handle claim. `created`/`expires` straddle the resolution
/// anchor so Step 0 keeps it unless overridden.
fn claim(
    handle: &str,
    issuer: &str,
    created: DateTime<Utc>,
    expires: DateTime<Utc>,
    audience: Option<&str>,
) -> Result<HandleClaim> {
    Ok(HandleClaim {
        schema: HandleClaim::SCHEMA.to_owned(),
        handle: Some(Handle::parse(handle).map_err(|e| anyhow!("handle parse {handle}: {e}"))?),
        handle_aliases: Vec::new(),
        subject: Some(subject()?),
        issuer: Some(DidCoreId::new(issuer)?),
        issuer_service_id: None,
        binding_state: Some(HandleBindingState::Verified),
        claim_kind: None,
        visibility: None,
        audience: audience.map(str::to_owned),
        challenge: None,
        claim_scope: Default::default(),
        member_delivery_binding: None,
        claims: Vec::new(),
        created_at: created,
        expires_at: Some(expires),
        verified_at: None,
        source_refs: Vec::new(),
        proofs: Vec::new(),
    })
}

fn accepted(issuers: &[&str]) -> Vec<HandleIssuerPolicyEntry> {
    issuers
        .iter()
        .map(|issuer| HandleIssuerPolicyEntry {
            issuer: DidCoreId::new(*issuer).expect("fixture issuer is a valid core id"),
            authorized_handle_domains: vec![if issuer.contains("other") {
                "other.example".to_owned()
            } else {
                "acme.example".to_owned()
            }],
            issuer_class: HandleIssuerAuthorityClass::DomainAuthority,
        })
        .collect()
}

fn chosen_handle(claim: &HandleClaim) -> Result<String> {
    claim
        .handle
        .as_ref()
        .map(|h| h.canonical().to_owned())
        .ok_or_else(|| anyhow!("selected claim has no handle"))
}

// ── VECT-COT-1.1 — empty candidate fallback ─────────────────────────────────

pub fn run_empty_candidate_fallback_vector() -> Result<()> {
    let s = subject()?;
    let input = PrimaryHandleSelectInput {
        subject_id: s.as_str(),
        context: None,
        claim_set_snapshot: &[],
        handle_issuer_policy: &accepted(&[ACME_ISSUER]),
        holder_primary_handle_at_as_of: None,
        resolution_as_of: now_anchor(),
    };
    if select_primary_handle(&input).is_some() {
        bail!("empty candidate set MUST return None (caller follows §3.8.2 unresolved path)");
    }
    Ok(())
}

// ── VECT-COT-1.2 — single candidate passthrough ─────────────────────────────

pub fn run_single_candidate_passthrough_vector() -> Result<()> {
    let s = subject()?;
    let snapshot = vec![claim(
        "alice:acme.example",
        ACME_ISSUER,
        at(2026, 5, 1),
        at(2026, 6, 1),
        None,
    )?];
    let input = PrimaryHandleSelectInput {
        subject_id: s.as_str(),
        context: None,
        claim_set_snapshot: &snapshot,
        handle_issuer_policy: &accepted(&[ACME_ISSUER]),
        holder_primary_handle_at_as_of: None,
        resolution_as_of: now_anchor(),
    };
    let chosen = select_primary_handle(&input)
        .ok_or_else(|| anyhow!("single verified candidate MUST be selected"))?;
    if chosen_handle(&chosen)? != "alice:acme.example" {
        bail!("single candidate passthrough drifted");
    }
    Ok(())
}

// ── VECT-COT-1.3 — audience match wins over holder/most-recent ──────────────

pub fn run_audience_match_wins_vector() -> Result<()> {
    let s = subject()?;
    let realm_ctx = "ak:realm:AWEs1cV4Rn1CVWdYoOUZ1yiMPe9Ze6ZYmP0ChDr89cPl";
    // Newer, holder-flagged, but no audience.
    let newer = claim(
        "alice:other.example",
        OTHER_ISSUER,
        at(2026, 5, 20),
        at(2026, 6, 20),
        None,
    )?;
    // Older but audience-scoped to the realm context.
    let audience_scoped = claim(
        "alice:acme.example",
        ACME_ISSUER,
        at(2026, 5, 1),
        at(2026, 6, 20),
        Some(realm_ctx),
    )?;
    let snapshot = vec![newer, audience_scoped];
    let input = PrimaryHandleSelectInput {
        subject_id: s.as_str(),
        context: Some(realm_ctx),
        claim_set_snapshot: &snapshot,
        handle_issuer_policy: &accepted(&[ACME_ISSUER, OTHER_ISSUER]),
        // holder flags the newer handle, yet audience-match MUST still win.
        holder_primary_handle_at_as_of: Some("alice:other.example"),
        resolution_as_of: now_anchor(),
    };
    let chosen = select_primary_handle(&input)
        .ok_or_else(|| anyhow!("audience-scoped candidate MUST be selected"))?;
    if chosen_handle(&chosen)? != "alice:acme.example" {
        bail!("audience-match MUST win over holder-flagged + most-recent");
    }
    Ok(())
}

// ── VECT-COT-1.4 — holder flag wins over most-recent ────────────────────────

pub fn run_holder_flag_wins_over_most_recent_vector() -> Result<()> {
    let s = subject()?;
    // Most-recent.
    let newer = claim(
        "alice:other.example",
        OTHER_ISSUER,
        at(2026, 5, 25),
        at(2026, 6, 25),
        None,
    )?;
    // Older but holder-flagged.
    let holder_flagged = claim(
        "alice:acme.example",
        ACME_ISSUER,
        at(2026, 5, 1),
        at(2026, 6, 25),
        None,
    )?;
    let snapshot = vec![newer, holder_flagged];
    let input = PrimaryHandleSelectInput {
        subject_id: s.as_str(),
        context: None,
        claim_set_snapshot: &snapshot,
        handle_issuer_policy: &accepted(&[ACME_ISSUER, OTHER_ISSUER]),
        holder_primary_handle_at_as_of: Some("alice:acme.example"),
        resolution_as_of: now_anchor(),
    };
    let chosen = select_primary_handle(&input)
        .ok_or_else(|| anyhow!("holder-flagged candidate MUST be selected"))?;
    if chosen_handle(&chosen)? != "alice:acme.example" {
        bail!("holder-flagged MUST win over most-recent when no audience match");
    }
    Ok(())
}

// ── VECT-COT-1.5 — most-recent wins when neither audience nor holder ────────

pub fn run_most_recent_wins_when_neither_vector() -> Result<()> {
    let s = subject()?;
    // Same issuer (equal accepted_issuers position) so the most-recent
    // layer's created_at discriminator is what decides the winner — neither
    // an audience match nor a holder flag applies.
    let older = claim(
        "alice:acme.example",
        ACME_ISSUER,
        at(2026, 5, 1),
        at(2026, 6, 25),
        None,
    )?;
    let newer = claim(
        "bob:acme.example",
        ACME_ISSUER,
        at(2026, 5, 20),
        at(2026, 6, 25),
        None,
    )?;
    let snapshot = vec![older, newer];
    let input = PrimaryHandleSelectInput {
        subject_id: s.as_str(),
        context: None,
        claim_set_snapshot: &snapshot,
        handle_issuer_policy: &accepted(&[ACME_ISSUER]),
        holder_primary_handle_at_as_of: None,
        resolution_as_of: now_anchor(),
    };
    let chosen = select_primary_handle(&input)
        .ok_or_else(|| anyhow!("most-recent candidate MUST be selected"))?;
    if chosen_handle(&chosen)? != "bob:acme.example" {
        bail!("most-recent (later created_at) MUST win when no audience/holder layer applies");
    }
    Ok(())
}

// ── VECT-COT-1.6 — tie-break by accepted_issuers position ───────────────────

pub fn run_tie_break_by_accepted_issuers_position_vector() -> Result<()> {
    let s = subject()?;
    let created = at(2026, 5, 10);
    let expires = at(2026, 6, 25);
    // Two claims, identical created_at, different issuers.
    let from_other = claim("alice:other.example", OTHER_ISSUER, created, expires, None)?;
    let from_acme = claim("alice:acme.example", ACME_ISSUER, created, expires, None)?;
    let snapshot = vec![from_other, from_acme];
    // ACME listed first → more trusted → wins the tie.
    let input = PrimaryHandleSelectInput {
        subject_id: s.as_str(),
        context: None,
        claim_set_snapshot: &snapshot,
        handle_issuer_policy: &accepted(&[ACME_ISSUER, OTHER_ISSUER]),
        holder_primary_handle_at_as_of: None,
        resolution_as_of: now_anchor(),
    };
    let chosen =
        select_primary_handle(&input).ok_or_else(|| anyhow!("a candidate MUST be selected"))?;
    if chosen_handle(&chosen)? != "alice:acme.example" {
        bail!("tie-break MUST prefer the earlier accepted_issuers position");
    }
    // Reverse the policy order → OTHER now wins, proving the position
    // drives the tie-break deterministically.
    let reversed = PrimaryHandleSelectInput {
        handle_issuer_policy: &accepted(&[OTHER_ISSUER, ACME_ISSUER]),
        ..input
    };
    let chosen_rev = select_primary_handle(&reversed)
        .ok_or_else(|| anyhow!("a candidate MUST be selected (reversed)"))?;
    if chosen_handle(&chosen_rev)? != "alice:other.example" {
        bail!("tie-break MUST follow accepted_issuers order when it is reversed");
    }
    Ok(())
}

// ── VECT-COT-1.7 — tie-break by created_at (later wins) ─────────────────────

pub fn run_tie_break_by_created_at_vector() -> Result<()> {
    let s = subject()?;
    let expires = at(2026, 6, 25);
    // Same issuer (same accepted_issuers position) → created_at decides.
    let earlier = claim(
        "alice:acme.example",
        ACME_ISSUER,
        at(2026, 5, 1),
        expires,
        None,
    )?;
    let later = claim(
        "bob:acme.example",
        ACME_ISSUER,
        at(2026, 5, 20),
        expires,
        None,
    )?;
    let snapshot = vec![earlier, later];
    let input = PrimaryHandleSelectInput {
        subject_id: s.as_str(),
        context: None,
        claim_set_snapshot: &snapshot,
        handle_issuer_policy: &accepted(&[ACME_ISSUER]),
        holder_primary_handle_at_as_of: None,
        resolution_as_of: now_anchor(),
    };
    let chosen =
        select_primary_handle(&input).ok_or_else(|| anyhow!("a candidate MUST be selected"))?;
    if chosen_handle(&chosen)? != "bob:acme.example" {
        bail!("tie-break MUST prefer the later created_at when issuer position is equal");
    }
    Ok(())
}

// ── VECT-COT-1.8 — tie-break by claim_digest (smaller wins) ─────────────────

pub fn run_tie_break_by_claim_digest_vector() -> Result<()> {
    let s = subject()?;
    let created = at(2026, 5, 10);
    let expires = at(2026, 6, 25);
    // Identical issuer + created_at → claim_digest (lexicographically
    // smaller) is the final deterministic discriminator.
    let c1 = claim("alice:acme.example", ACME_ISSUER, created, expires, None)?;
    let c2 = claim("zoe:acme.example", ACME_ISSUER, created, expires, None)?;
    let d1 = claim_digest(&c1).map_err(|e| anyhow!("claim_digest c1: {e}"))?;
    let d2 = claim_digest(&c2).map_err(|e| anyhow!("claim_digest c2: {e}"))?;
    if d1 == d2 {
        bail!("vector setup error: distinct claims produced identical claim_digest");
    }
    let (smaller_handle, _) = if d1 < d2 {
        (chosen_handle(&c1)?, d1.clone())
    } else {
        (chosen_handle(&c2)?, d2.clone())
    };
    let snapshot = vec![c1, c2];
    let input = PrimaryHandleSelectInput {
        subject_id: s.as_str(),
        context: None,
        claim_set_snapshot: &snapshot,
        handle_issuer_policy: &accepted(&[ACME_ISSUER]),
        holder_primary_handle_at_as_of: None,
        resolution_as_of: now_anchor(),
    };
    let chosen =
        select_primary_handle(&input).ok_or_else(|| anyhow!("a candidate MUST be selected"))?;
    if chosen_handle(&chosen)? != smaller_handle {
        bail!(
            "tie-break MUST prefer the lexicographically smaller claim_digest; \
             expected {smaller_handle}, got {}",
            chosen_handle(&chosen)?
        );
    }
    Ok(())
}

// ── VECT-COT-1.9 — holder_primary null skips the holder layer ───────────────

pub fn run_holder_primary_null_skips_layer_vector() -> Result<()> {
    let s = subject()?;
    let expires = at(2026, 6, 25);
    let older = claim(
        "alice:acme.example",
        ACME_ISSUER,
        at(2026, 5, 1),
        expires,
        None,
    )?;
    let newer = claim(
        "bob:acme.example",
        ACME_ISSUER,
        at(2026, 5, 20),
        expires,
        None,
    )?;
    let snapshot = vec![older, newer];
    // With holder_primary=null the holder layer is empty, so selection
    // falls through to most-recent.
    let input = PrimaryHandleSelectInput {
        subject_id: s.as_str(),
        context: None,
        claim_set_snapshot: &snapshot,
        handle_issuer_policy: &accepted(&[ACME_ISSUER]),
        holder_primary_handle_at_as_of: None,
        resolution_as_of: now_anchor(),
    };
    let chosen =
        select_primary_handle(&input).ok_or_else(|| anyhow!("a candidate MUST be selected"))?;
    if chosen_handle(&chosen)? != "bob:acme.example" {
        bail!("holder_primary=null MUST skip the holder layer and use most-recent");
    }
    // Non-null holder flag pointing at the older handle flips the result,
    // proving the layer is otherwise active.
    let with_holder = PrimaryHandleSelectInput {
        holder_primary_handle_at_as_of: Some("alice:acme.example"),
        ..input
    };
    let chosen2 = select_primary_handle(&with_holder)
        .ok_or_else(|| anyhow!("a candidate MUST be selected (holder set)"))?;
    if chosen_handle(&chosen2)? != "alice:acme.example" {
        bail!("non-null holder_primary MUST activate the holder-flagged layer");
    }
    Ok(())
}

// ── VECT-COT-1.10 — as_of replay vs realtime ────────────────────────────────

pub fn run_as_of_replay_vs_realtime_vector() -> Result<()> {
    let s = subject()?;
    // A claim that only becomes valid (issued) on 2026-05-15.
    let later_claim = claim(
        "alice:acme.example",
        ACME_ISSUER,
        at(2026, 5, 15),
        at(2026, 7, 1),
        None,
    )?;
    let snapshot = vec![later_claim];

    // Historical replay at as_of=2026-05-10: claim not yet issued → Step 0
    // drops it → no selection.
    let replay = PrimaryHandleSelectInput {
        subject_id: s.as_str(),
        context: None,
        claim_set_snapshot: &snapshot,
        handle_issuer_policy: &accepted(&[ACME_ISSUER]),
        holder_primary_handle_at_as_of: None,
        resolution_as_of: at(2026, 5, 10),
    };
    if select_primary_handle(&replay).is_some() {
        bail!("as_of replay before issuance MUST drop the claim (created_at > as_of)");
    }

    // Realtime at as_of=2026-05-27: claim is live → selected.
    let realtime = PrimaryHandleSelectInput {
        resolution_as_of: now_anchor(),
        ..replay
    };
    let chosen = select_primary_handle(&realtime)
        .ok_or_else(|| anyhow!("realtime resolution MUST select the issued claim"))?;
    if chosen_handle(&chosen)? != "alice:acme.example" {
        bail!("realtime selection drifted");
    }
    Ok(())
}

// ── VECT-COT-1.11 — claim_digest stable under hint mutation ─────────────────

pub fn run_claim_digest_stable_under_hint_vector() -> Result<()> {
    let created = at(2026, 5, 10);
    let expires = at(2026, 6, 25);
    let mut canonical = claim("alice:acme.example", ACME_ISSUER, created, expires, None)?;
    canonical.handle_aliases = vec!["acct:alice@acme.example".to_owned()];
    canonical.source_refs =
        vec!["ak:event:AXDgux9OM2cf4fa-H7RpMXKtH9u31ncdIX_06P0_BG9X".to_owned()];

    let base = claim_digest(&canonical).map_err(|e| anyhow!("claim_digest base: {e}"))?;

    // Mutate ONLY the non-semantic hint fields (verified_at / challenge /
    // proofs). The digest MUST stay byte-identical.
    let mut hinted = canonical.clone();
    hinted.verified_at = Some(at(2026, 5, 26));
    hinted.challenge = Some("nonce-xyz".to_owned());
    hinted.proofs = vec![PayloadProof {
        kind: "detached_jws".to_owned(),
        verification_method: crate::fixture_did_url("did:web:coauth.acme.example#key-1"),
        payload_digest: Hash::new(
            "sha256:0000000000000000000000000000000000000000000000000000000000000001",
        )?,
        created_at: at(2026, 5, 26),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "hint.only.shape".to_owned(),
    }];
    let after = claim_digest(&hinted).map_err(|e| anyhow!("claim_digest hinted: {e}"))?;
    if base != after {
        bail!(
            "claim_digest MUST be invariant under verified_at / challenge / proofs hint \
             mutation; got {base} vs {after}"
        );
    }

    // Re-ordering an unordered-collection array (handle_aliases) MUST also
    // leave the digest unchanged (the SDK sorts before canonicalisation).
    let mut reordered = canonical.clone();
    reordered.handle_aliases = vec!["acct:alice@acme.example".to_owned()];
    let reordered_digest = claim_digest(&reordered).map_err(|e| anyhow!("reordered: {e}"))?;
    if reordered_digest != base {
        bail!("claim_digest drifted across equivalent handle_aliases ordering");
    }

    // A semantic change (the handle itself) MUST move the digest.
    let mut semantic = canonical.clone();
    semantic.handle = Some(Handle::parse("bob:acme.example").map_err(|e| anyhow!("handle: {e}"))?);
    let semantic_digest = claim_digest(&semantic).map_err(|e| anyhow!("semantic: {e}"))?;
    if semantic_digest == base {
        bail!("claim_digest MUST change when a semantic field (handle) changes");
    }
    if !base.starts_with("sha256:") {
        bail!("claim_digest MUST be sha256:<hex>");
    }
    Ok(())
}

// ── VECT-COT-1.12 — policy snapshot as_of replay ────────────────────────────

pub fn run_policy_snapshot_as_of_replay_vector() -> Result<()> {
    let s = subject()?;
    let created = at(2026, 5, 10);
    let expires = at(2026, 6, 25);
    let from_acme = claim("alice:acme.example", ACME_ISSUER, created, expires, None)?;
    let from_other = claim("alice:other.example", OTHER_ISSUER, created, expires, None)?;
    let snapshot = vec![from_acme, from_other];

    // Historical Realm policy (version 1) trusted only OTHER, then later
    // reversed trust. The policy_snapshot (accepted_issuers) drives the
    // historical replay output deterministically.
    let policy_v1 = accepted(&[OTHER_ISSUER]);
    let replay_v1 = PrimaryHandleSelectInput {
        subject_id: s.as_str(),
        context: None,
        claim_set_snapshot: &snapshot,
        handle_issuer_policy: &policy_v1,
        holder_primary_handle_at_as_of: None,
        resolution_as_of: now_anchor(),
    };
    let chosen_v1 = select_primary_handle(&replay_v1)
        .ok_or_else(|| anyhow!("policy v1 MUST select the OTHER-issued claim"))?;
    if chosen_handle(&chosen_v1)? != "alice:other.example" {
        bail!("policy v1 replay MUST only admit the OTHER-trusted claim");
    }

    // Current policy (version 2) trusts both, ACME first → ACME wins.
    let policy_v2 = accepted(&[ACME_ISSUER, OTHER_ISSUER]);
    let realtime_v2 = PrimaryHandleSelectInput {
        handle_issuer_policy: &policy_v2,
        ..replay_v1
    };
    let chosen_v2 = select_primary_handle(&realtime_v2)
        .ok_or_else(|| anyhow!("policy v2 MUST select a claim"))?;
    if chosen_handle(&chosen_v2)? != "alice:acme.example" {
        bail!("policy v2 (ACME trusted first) MUST flip the historical replay output");
    }
    Ok(())
}

// ── Suite entry-point ──────────────────────────────────────────────────────

pub fn run_primary_handle_vector_suite() -> Result<()> {
    if ALL_PRIMARY_HANDLE_VECTOR_IDS.len() != 12 {
        bail!(
            "expected 12 primary-handle vector ids, got {}",
            ALL_PRIMARY_HANDLE_VECTOR_IDS.len()
        );
    }
    run_empty_candidate_fallback_vector()?;
    run_single_candidate_passthrough_vector()?;
    run_audience_match_wins_vector()?;
    run_holder_flag_wins_over_most_recent_vector()?;
    run_most_recent_wins_when_neither_vector()?;
    run_tie_break_by_accepted_issuers_position_vector()?;
    run_tie_break_by_created_at_vector()?;
    run_tie_break_by_claim_digest_vector()?;
    run_holder_primary_null_skips_layer_vector()?;
    run_as_of_replay_vs_realtime_vector()?;
    run_claim_digest_stable_under_hint_vector()?;
    run_policy_snapshot_as_of_replay_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primary_handle_vector_suite_runs_clean() {
        run_primary_handle_vector_suite().unwrap();
    }
}
