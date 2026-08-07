//! §3.8 mention rendering conformance vectors (VECT-COT-2).
//!
//! Spec source: `models/strand-and-message.md §9.4` +
//! `identity/identity-handles.md §3.8.1 / §3.8.2`.
//!
//! R3.2 mention node shape:
//!   `{kind="mention", subject_id (MUST), handle_at_time?, display_name_at_time?,
//!     mention_text_original?, resolved_at?}`.
//! `subject_id` is the ONLY authoritative field for actor attribution; the
//! handle / display strings are audit metadata.
//!
//! Rendering (§3.8.2) is driven through the SDK
//! [`arkret::identity::render_mention`] helper, which runs §3.2.1 over the
//! Realm-scoped claim projection then walks the degraded fallback ladder
//! `Verified → Cached → NameOnly → Unresolved`.

use anyhow::{Result, anyhow, bail};
use arkret::identity::{MentionRender, PrimaryHandleSelectInput, render_mention};
use arkret_identifiers::Did;
use arkret_models_collaboration::events_payloads::mention::Mention;
use arkret_models_identity::{Handle, HandleBindingState, HandleClaim};
use chrono::{DateTime, TimeZone, Utc};
use serde_json::json;

pub const VECTOR_ID_MENTION_NEW_ACCEPTED: &str =
    "ak.cotest_vector.mention_rendering.new_shape_accepted.v1";
pub const VECTOR_ID_MENTION_STEP1_UNIQUE: &str =
    "ak.cotest_vector.mention_rendering.render_step1_unique_success.v1";
pub const VECTOR_ID_MENTION_STEP1_MULTI_TO_STEP2: &str =
    "ak.cotest_vector.mention_rendering.render_step1_multi_to_step2_live.v1";
pub const VECTOR_ID_MENTION_FALLBACK_CACHED: &str =
    "ak.cotest_vector.mention_rendering.render_fallback_cached.v1";
pub const VECTOR_ID_MENTION_FALLBACK_NAME_ONLY: &str =
    "ak.cotest_vector.mention_rendering.render_fallback_name_only.v1";
pub const VECTOR_ID_MENTION_FALLBACK_UNRESOLVED: &str =
    "ak.cotest_vector.mention_rendering.render_fallback_unresolved.v1";
pub const VECTOR_ID_MENTION_ACTOR_ATTRIBUTION_INDEPENDENT: &str =
    "ak.cotest_vector.mention_rendering.actor_attribution_independent_of_handle_at_time.v1";

pub const ALL_MENTION_RENDERING_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_MENTION_NEW_ACCEPTED,
    VECTOR_ID_MENTION_STEP1_UNIQUE,
    VECTOR_ID_MENTION_STEP1_MULTI_TO_STEP2,
    VECTOR_ID_MENTION_FALLBACK_CACHED,
    VECTOR_ID_MENTION_FALLBACK_NAME_ONLY,
    VECTOR_ID_MENTION_FALLBACK_UNRESOLVED,
    VECTOR_ID_MENTION_ACTOR_ATTRIBUTION_INDEPENDENT,
];

// ── Fixture helpers ─────────────────────────────────────────────────────────

const ISSUER: &str = "did:web:coauth.acme.example";

fn subject() -> Result<Did> {
    Did::new("did:web:alice.principal.example".to_owned()).map_err(|e| anyhow!("subject: {e}"))
}

fn at(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .expect("valid pinned timestamp")
}

fn now_anchor() -> DateTime<Utc> {
    at(2026, 5, 27)
}

fn verified_claim(handle: &str, subject: &Did, audience: Option<&str>) -> Result<HandleClaim> {
    Ok(HandleClaim {
        handle: Some(Handle::parse(handle).map_err(|e| anyhow!("handle parse: {e}"))?),
        subject: Some(subject.clone()),
        issuer: Some(ISSUER.to_owned()),
        binding_state: Some(HandleBindingState::Verified),
        audience: audience.map(str::to_owned),
        created_at: Some(at(2026, 5, 1)),
        expires_at: Some(at(2026, 7, 1)),
        ..Default::default()
    })
}

fn empty_selection<'a>(
    subject: &'a Did,
    snapshot: &'a [HandleClaim],
) -> PrimaryHandleSelectInput<'a> {
    PrimaryHandleSelectInput {
        subject_id: subject.as_str(),
        context: None,
        claim_set_snapshot: snapshot,
        accepted_issuers: &[],
        holder_primary_handle_at_as_of: None,
        resolution_as_of: now_anchor(),
    }
}

// ── VECT-COT-2.2 — new shape accepted ───────────────────────────────────────

pub fn run_new_shape_accepted_vector() -> Result<()> {
    let value = json!({
        "kind": "mention",
        "subject_id": "did:web:alice.principal.example",
        "handle_at_time": "alice:acme.example",
        "display_name_at_time": "Alice Zhang",
        "mention_text_original": "@alice:acme.example",
        "resolved_at": "2026-05-19T10:00:00.000Z"
    });
    let mention: Mention =
        serde_json::from_value(value).map_err(|e| anyhow!("new mention shape MUST parse: {e}"))?;
    if mention.subject_id.as_str() != "did:web:alice.principal.example" {
        bail!("subject_id drifted under parse");
    }
    if mention.handle_at_time.as_ref().map(Handle::canonical) != Some("alice:acme.example") {
        bail!("handle_at_time audit metadata drifted");
    }
    // Minimal shape (kind + subject_id) MUST also accept; audit metadata omitted.
    let minimal: Mention = serde_json::from_value(json!({
        "kind": "mention",
        "subject_id": "did:web:bob.principal.example"
    }))
    .map_err(|e| anyhow!("minimal mention MUST parse: {e}"))?;
    let wire = serde_json::to_value(&minimal).map_err(|e| anyhow!("serialise: {e}"))?;
    if wire.get("handle_at_time").is_some() {
        bail!("unset handle_at_time MUST be omitted on the wire");
    }
    Ok(())
}

// ── VECT-COT-2.3 — render step 1 unique success (verified) ──────────────────

pub fn run_render_step1_unique_success_vector() -> Result<()> {
    let s = subject()?;
    let snapshot = vec![verified_claim("alice:acme.example", &s, None)?];
    let accepted = vec![issuer_string()];
    let selection = PrimaryHandleSelectInput {
        accepted_issuers: &accepted,
        ..empty_selection(&s, &snapshot)
    };
    let render = render_mention(&s, &selection, None, Some("Alice Zhang"));
    match render {
        MentionRender::Verified { handle } if handle.canonical() == "alice:acme.example" => Ok(()),
        other => bail!("step 1 unique projection MUST render Verified; got {other:?}"),
    }
}

// ── VECT-COT-2.4 — render step 1 multi → step 2 live ────────────────────────

pub fn run_render_step1_multi_to_step2_live_vector() -> Result<()> {
    let s = subject()?;
    let realm_ctx = "ak:realm:AWEs1cV4Rn1CVWdYoOUZ1yiMPe9Ze6ZYmP0ChDr89cPl";
    // Two candidates: the Realm-scoped projection is "not unique" until the
    // live audience context discriminates. With context set, §3.2.1 picks
    // the audience-matched claim deterministically (the §3.8.2 step-2 live
    // resolve outcome).
    let snapshot = vec![
        verified_claim("alice:other.example", &s, None)?,
        verified_claim("alice:acme.example", &s, Some(realm_ctx))?,
    ];
    let accepted = vec![issuer_string()];
    let selection = PrimaryHandleSelectInput {
        subject_id: s.as_str(),
        context: Some(realm_ctx),
        claim_set_snapshot: &snapshot,
        accepted_issuers: &accepted,
        holder_primary_handle_at_as_of: None,
        resolution_as_of: now_anchor(),
    };
    let render = render_mention(&s, &selection, None, Some("Alice Zhang"));
    match render {
        MentionRender::Verified { handle } if handle.canonical() == "alice:acme.example" => Ok(()),
        other => bail!(
            "multi-candidate live resolve MUST render the audience-matched Verified handle; got {other:?}"
        ),
    }
}

// ── VECT-COT-2.5 — fallback to cached (degraded) ────────────────────────────

pub fn run_render_fallback_cached_vector() -> Result<()> {
    let s = subject()?;
    // No verifiable projection (empty accepted_issuers drops the claim),
    // but a stale local cache verified handle exists.
    let snapshot = vec![verified_claim("alice:acme.example", &s, None)?];
    let selection = empty_selection(&s, &snapshot); // accepted_issuers empty → Step 0 drops it
    let cached = Handle::parse("alice:acme.example").map_err(|e| anyhow!("handle: {e}"))?;
    let render = render_mention(&s, &selection, Some(&cached), Some("Alice Zhang"));
    match render {
        MentionRender::Cached { handle } if handle.canonical() == "alice:acme.example" => Ok(()),
        other => bail!("resolution failure with a local cache MUST render Cached; got {other:?}"),
    }
}

// ── VECT-COT-2.6 — fallback to name-only (degraded) ─────────────────────────

pub fn run_render_fallback_name_only_vector() -> Result<()> {
    let s = subject()?;
    let snapshot: Vec<HandleClaim> = vec![];
    let selection = empty_selection(&s, &snapshot);
    let render = render_mention(&s, &selection, None, Some("Alice Zhang"));
    match render {
        MentionRender::NameOnly { name } if name == "Alice Zhang" => Ok(()),
        other => bail!("no claim + no cache MUST fall back to NameOnly; got {other:?}"),
    }
}

// ── VECT-COT-2.7 — fallback to unresolved (truncated DID) ───────────────────

pub fn run_render_fallback_unresolved_vector() -> Result<()> {
    let s = subject()?;
    let snapshot: Vec<HandleClaim> = vec![];
    let selection = empty_selection(&s, &snapshot);
    let render = render_mention(&s, &selection, None, None);
    match render {
        MentionRender::Unresolved { truncated_did } => {
            if truncated_did.is_empty() {
                bail!("unresolved render MUST surface a truncated DID");
            }
            Ok(())
        }
        other => bail!("nothing resolvable MUST render Unresolved; got {other:?}"),
    }
}

// ── VECT-COT-2.8 — actor attribution independent of handle_at_time ──────────

pub fn run_actor_attribution_independent_of_handle_at_time_vector() -> Result<()> {
    let s = subject()?;
    // A mention whose audit `handle_at_time` is deliberately nonsense /
    // stale. Actor attribution MUST come from `subject_id` only.
    let mention = Mention::new(s.clone())
        .with_handle_at_time(Handle::parse("mallory:evil.example").map_err(|e| anyhow!("h: {e}"))?)
        .with_display_name_at_time("Totally Not Alice")
        .with_mention_text_original("@mallory:evil.example");

    if mention.subject_id != s {
        bail!("attribution field (subject_id) MUST be the authoritative subject");
    }

    // Render: the authoritative selection over Alice's real claim MUST win
    // regardless of the misleading handle_at_time.
    let snapshot = vec![verified_claim("alice:acme.example", &s, None)?];
    let accepted = vec![issuer_string()];
    let selection = PrimaryHandleSelectInput {
        accepted_issuers: &accepted,
        ..empty_selection(&s, &snapshot)
    };
    let render = render_mention(&mention.subject_id, &selection, None, None);
    match render {
        MentionRender::Verified { handle } if handle.canonical() == "alice:acme.example" => {}
        other => bail!(
            "render MUST resolve from subject_id, NOT the bogus handle_at_time; got {other:?}"
        ),
    }

    // The audit metadata round-trips but is independent of attribution.
    let wire = serde_json::to_value(&mention).map_err(|e| anyhow!("serialise: {e}"))?;
    if wire.get("handle_at_time").and_then(|v| v.as_str()) != Some("mallory:evil.example") {
        bail!("handle_at_time MUST round-trip as opaque audit metadata");
    }
    if wire.get("subject_id").and_then(|v| v.as_str()) != Some(s.as_str()) {
        bail!("subject_id MUST round-trip as the authoritative reference");
    }
    Ok(())
}

fn issuer_string() -> String {
    ISSUER.to_owned()
}

// ── Suite entry-point ──────────────────────────────────────────────────────

pub fn run_mention_rendering_vector_suite() -> Result<()> {
    if ALL_MENTION_RENDERING_VECTOR_IDS.len() != 7 {
        bail!(
            "expected 7 mention-rendering vector ids, got {}",
            ALL_MENTION_RENDERING_VECTOR_IDS.len()
        );
    }
    run_new_shape_accepted_vector()?;
    run_render_step1_unique_success_vector()?;
    run_render_step1_multi_to_step2_live_vector()?;
    run_render_fallback_cached_vector()?;
    run_render_fallback_name_only_vector()?;
    run_render_fallback_unresolved_vector()?;
    run_actor_attribution_independent_of_handle_at_time_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mention_rendering_vector_suite_runs_clean() {
        run_mention_rendering_vector_suite().unwrap();
    }
}
