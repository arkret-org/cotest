//! `ak.find.directory.read.list_handles_for_subject.v1` conformance vectors (VECT-COT-3).
//!
//! Spec source: `discovery/discovery-directory.md §9.0` +
//! `artifacts/schemas/list-handles-for-subject-response.schema.json`
//! (`ak.schema.list_handles_for_subject_response.v1`).
//!
//! The operation is the inverse of `resolve_handle` (handle → subject):
//! given a holder/principal DID it returns the current context-visible
//! signed `ak.schema.handle_claim.v1` set. The response schema enforces
//! `claims[].subject == subject` (byte-equal); mismatches MUST drop or fail
//! closed (exercised through
//! [`DirectorySubjectHandleList::validate`]).

use anyhow::{Result, anyhow, bail};
use arkret::identity::{
    HandleIssuerAuthorityClass, HandleIssuerPolicyEntry, PrimaryHandleSelectInput,
    select_primary_handle,
};
use arkret_identifiers::DidCoreId;
use arkret_models_discovery::{
    DirectoryListHandlesForSubjectRequestBody, DirectorySubjectHandleList,
};
use arkret_models_identity::{Handle, HandleClaim};
use arkret_wire::AccountId;
use chrono::{DateTime, TimeZone, Utc};

pub const VECTOR_ID_LH_HAPPY_SINGLE: &str =
    "ak.cotest_vector.directory.list_handles_for_subject.happy_path_single_claim.v1";
pub const VECTOR_ID_LH_SUBJECT_MISMATCH: &str =
    "ak.cotest_vector.directory.list_handles_for_subject.subject_mismatch_rejected.v1";
pub const VECTOR_ID_LH_AUDIENCE_FILTER: &str =
    "ak.cotest_vector.directory.list_handles_for_subject.audience_filter_applied.v1";
pub const VECTOR_ID_LH_ISSUER_TRUST_FILTER: &str =
    "ak.cotest_vector.directory.list_handles_for_subject.issuer_trust_filter.v1";
pub const VECTOR_ID_LH_CURSOR_PAGINATION: &str =
    "ak.cotest_vector.directory.list_handles_for_subject.cursor_pagination.v1";
pub const VECTOR_ID_LH_PRIMARY_ALIGNED: &str = "ak.cotest_vector.directory.list_handles_for_subject.primary_handle_field_aligned_with_3_2_1.v1";
pub const VECTOR_ID_LH_AS_OF_HISTORICAL: &str =
    "ak.cotest_vector.directory.list_handles_for_subject.as_of_historical_replay.v1";

pub const ALL_LIST_HANDLES_FOR_SUBJECT_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_LH_HAPPY_SINGLE,
    VECTOR_ID_LH_SUBJECT_MISMATCH,
    VECTOR_ID_LH_AUDIENCE_FILTER,
    VECTOR_ID_LH_ISSUER_TRUST_FILTER,
    VECTOR_ID_LH_CURSOR_PAGINATION,
    VECTOR_ID_LH_PRIMARY_ALIGNED,
    VECTOR_ID_LH_AS_OF_HISTORICAL,
];

// ── Fixture helpers ─────────────────────────────────────────────────────────

const ACME_ISSUER: &str = "ak:did_core:web:coauth.acme.example";
const OTHER_ISSUER: &str = "ak:did_core:web:coauth.other.example";

fn subject() -> Result<AccountId> {
    Ok(AccountId::new(
        DidCoreId::new("ak:did_core:web:alice.principal.example")?,
        DidCoreId::new("ak:did_core:web:station.acme.example")?,
    ))
}

fn at(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .expect("valid pinned timestamp")
}

fn now_anchor() -> DateTime<Utc> {
    at(2026, 5, 27)
}

fn claim_for(
    handle: &str,
    subj: &AccountId,
    issuer: &str,
    audience: Option<&str>,
) -> Result<HandleClaim> {
    Ok(crate::fixture_verified_handle_claim_at(
        handle,
        subj.clone(),
        DidCoreId::new(issuer)?,
        audience.map(str::to_owned),
        at(2026, 5, 1),
        Some(at(2026, 7, 1)),
        now_anchor(),
    )?)
}

// ── VECT-COT-3.1 — happy path single claim ──────────────────────────────────

pub fn run_happy_path_single_claim_vector() -> Result<()> {
    let s = subject()?;
    // Request shape round-trips and carries the holder DID as the lookup key.
    let req = DirectoryListHandlesForSubjectRequestBody {
        account_id: s.clone(),
        realm_id: None,
        intent: Some(arkret_models_discovery::DirectoryIntent::Mention),
        requester_id: None,
        proof_challenge: None,
        proofs: vec![],
        as_of: None,
        cursor: None,
        limit: None,
    };
    let req_wire = serde_json::to_value(&req).map_err(|e| anyhow!("serialise req: {e}"))?;
    if req_wire.get("account_id") != Some(&serde_json::to_value(&s)?) {
        bail!("request MUST carry `account_id` as the reverse-lookup key");
    }

    let res = DirectorySubjectHandleList {
        account_id: s.clone(),
        claims: vec![claim_for("alice:acme.example", &s, ACME_ISSUER, None)?],
        primary_handle: Some(Handle::parse("alice:acme.example").map_err(|e| anyhow!("h: {e}"))?),
        as_of: now_anchor(),
        next_cursor: None,
        has_more: false,
    };
    res.validate()
        .map_err(|e| anyhow!("happy path MUST validate: {e}"))?;
    if res.claims.len() != 1 {
        bail!("happy path MUST return exactly one active claim");
    }
    // Round-trip the response shape.
    let wire = serde_json::to_value(&res).map_err(|e| anyhow!("serialise res: {e}"))?;
    let decoded: DirectorySubjectHandleList =
        serde_json::from_value(wire).map_err(|e| anyhow!("deserialise res: {e}"))?;
    if decoded.account_id != s {
        bail!("response subject drifted under round-trip");
    }
    Ok(())
}

// ── VECT-COT-3.2 — subject mismatch rejected (fail closed) ──────────────────

pub fn run_subject_mismatch_rejected_vector() -> Result<()> {
    let s = subject()?;
    let other = AccountId::new(
        DidCoreId::new("ak:did_core:web:mallory.principal.example")?,
        DidCoreId::new("ak:did_core:web:station.acme.example")?,
    );
    // A claim whose subject != response.subject MUST fail closed.
    let res = DirectorySubjectHandleList {
        account_id: s.clone(),
        claims: vec![claim_for(
            "mallory:acme.example",
            &other,
            ACME_ISSUER,
            None,
        )?],
        primary_handle: None,
        as_of: now_anchor(),
        next_cursor: None,
        has_more: false,
    };
    if res.validate().is_ok() {
        bail!("claims[].subject != response.subject MUST fail closed via validate()");
    }
    // The fail-closed remedy is to drop the mismatched claim entirely; an
    // empty (filtered) response then validates.
    let filtered = DirectorySubjectHandleList {
        claims: vec![],
        ..res
    };
    filtered
        .validate()
        .map_err(|e| anyhow!("dropped-claim response MUST validate: {e}"))?;
    Ok(())
}

// ── VECT-COT-3.3 — audience filter applied ──────────────────────────────────

pub fn run_audience_filter_applied_vector() -> Result<()> {
    let s = subject()?;
    let realm_ctx = "ak:realm:AWEs1cV4Rn1CVWdYoOUZ1yiMPe9Ze6ZYmP0ChDr89cPl";
    let other_ctx = "ak:realm:AXtiTCGdzsbb1XG-rkp3XUaCpG_O0IrZEsNWa6dm1J70";

    // Directory has two claims; one is scoped to a different audience.
    let in_scope = claim_for("alice:acme.example", &s, ACME_ISSUER, Some(realm_ctx))?;
    let out_of_scope = claim_for("alice:other.example", &s, ACME_ISSUER, Some(other_ctx))?;

    // The directory MUST filter out the audience-mismatched claim before
    // returning. We model that filter and assert the visible set.
    let visible: Vec<HandleClaim> = [in_scope.clone(), out_of_scope]
        .into_iter()
        .filter(|c| match c.claim.audience.as_deref() {
            Some(a) => a == realm_ctx,
            None => true,
        })
        .collect();
    if visible.len() != 1 {
        bail!("audience filter MUST drop the context-mismatched claim");
    }
    let res = DirectorySubjectHandleList {
        account_id: s.clone(),
        claims: visible,
        primary_handle: Some(in_scope.claim.handle.clone()),
        as_of: now_anchor(),
        next_cursor: None,
        has_more: false,
    };
    res.validate()
        .map_err(|e| anyhow!("audience-filtered response MUST validate: {e}"))?;
    if res.claims[0].claim.audience.as_deref() != Some(realm_ctx) {
        bail!("only the in-scope claim MAY remain");
    }
    Ok(())
}

// ── VECT-COT-3.4 — issuer-trust filter ──────────────────────────────────────

pub fn run_issuer_trust_filter_vector() -> Result<()> {
    let s = subject()?;
    let trusted = claim_for("alice:acme.example", &s, ACME_ISSUER, None)?;
    let untrusted = claim_for("alice:other.example", &s, OTHER_ISSUER, None)?;
    let accepted_issuer_ids = [DidCoreId::new(ACME_ISSUER)?];

    // Directory MUST drop claims whose issuer is not in policy
    // accepted_issuer_ids.
    let visible: Vec<HandleClaim> = [trusted.clone(), untrusted]
        .into_iter()
        .filter(|c| {
            accepted_issuer_ids
                .iter()
                .any(|accepted| accepted == &c.claim.issuer_id)
        })
        .collect();
    if visible.len() != 1 || visible[0].claim.issuer_id.as_str() != ACME_ISSUER {
        bail!("issuer-trust filter MUST keep only accepted_issuer_ids claims");
    }
    let res = DirectorySubjectHandleList {
        account_id: s.clone(),
        claims: visible,
        primary_handle: Some(trusted.claim.handle.clone()),
        as_of: now_anchor(),
        next_cursor: None,
        has_more: false,
    };
    res.validate()
        .map_err(|e| anyhow!("issuer-filtered response MUST validate: {e}"))?;
    Ok(())
}

// ── VECT-COT-3.5 — cursor pagination ────────────────────────────────────────

pub fn run_cursor_pagination_vector() -> Result<()> {
    let s = subject()?;
    // First page: limit=1, has_more=true, opaque next_cursor present.
    let page1 = DirectorySubjectHandleList {
        account_id: s.clone(),
        claims: vec![claim_for("alice:acme.example", &s, ACME_ISSUER, None)?],
        primary_handle: None,
        as_of: now_anchor(),
        next_cursor: Some("ak:cursor:eyJ2IjoiMSIsIngiOjF9".to_owned()),
        has_more: true,
    };
    page1
        .validate()
        .map_err(|e| anyhow!("page1 MUST validate: {e}"))?;
    let cursor = page1
        .next_cursor
        .as_deref()
        .ok_or_else(|| anyhow!("has_more=true MUST carry next_cursor"))?;
    if !cursor.starts_with("ak:cursor:") {
        bail!("next_cursor MUST be an opaque `ak:cursor:` token; got `{cursor}`");
    }

    // A follow-up request echoes the cursor.
    let req2 = DirectoryListHandlesForSubjectRequestBody {
        account_id: s.clone(),
        realm_id: None,
        intent: None,
        requester_id: None,
        proof_challenge: None,
        proofs: vec![],
        as_of: None,
        cursor: page1.next_cursor.clone(),
        limit: Some(1),
    };
    let req_wire = serde_json::to_value(&req2).map_err(|e| anyhow!("serialise req2: {e}"))?;
    if req_wire.get("cursor").is_none() {
        bail!("pagination follow-up request MUST carry the cursor");
    }

    // Last page: no cursor, has_more=false.
    let page2 = DirectorySubjectHandleList {
        account_id: s.clone(),
        claims: vec![claim_for("alice:other.example", &s, ACME_ISSUER, None)?],
        primary_handle: None,
        as_of: now_anchor(),
        next_cursor: None,
        has_more: false,
    };
    page2
        .validate()
        .map_err(|e| anyhow!("page2 MUST validate: {e}"))?;
    if page2.has_more {
        bail!("terminal page MUST set has_more=false");
    }
    if page2.next_cursor.is_some() {
        bail!("terminal page MUST NOT carry next_cursor");
    }
    Ok(())
}

// ── VECT-COT-3.6 — primary_handle aligned with §3.2.1 ───────────────────────

pub fn run_primary_handle_field_aligned_with_3_2_1_vector() -> Result<()> {
    let s = subject()?;
    let realm_ctx = "ak:realm:AWEs1cV4Rn1CVWdYoOUZ1yiMPe9Ze6ZYmP0ChDr89cPl";
    let snapshot = vec![
        claim_for("alice:other.example", &s, OTHER_ISSUER, None)?,
        claim_for("alice:acme.example", &s, ACME_ISSUER, Some(realm_ctx))?,
    ];
    let accepted = vec![
        HandleIssuerPolicyEntry {
            issuer_id: DidCoreId::new(ACME_ISSUER)?,
            authorized_handle_domains: vec!["acme.example".to_owned()],
            issuer_class: HandleIssuerAuthorityClass::DomainAuthority,
        },
        HandleIssuerPolicyEntry {
            issuer_id: DidCoreId::new(OTHER_ISSUER)?,
            authorized_handle_domains: vec!["other.example".to_owned()],
            issuer_class: HandleIssuerAuthorityClass::DomainAuthority,
        },
    ];

    // The directory's `primary_handle` field MUST equal the §3.2.1
    // selection output for the same context + policy.
    let selection = PrimaryHandleSelectInput {
        account_id: &s,
        context: Some(realm_ctx),
        claim_set_snapshot: &snapshot,
        handle_issuer_policies: &accepted,
        holder_primary_handle_at_as_of: None,
        resolution_as_of: now_anchor(),
    };
    let selected = select_primary_handle(&selection)
        .ok_or_else(|| anyhow!("§3.2.1 MUST select a primary handle"))?;
    let selected_handle = selected.claim.handle.clone();

    let res = DirectorySubjectHandleList {
        account_id: s.clone(),
        claims: snapshot.clone(),
        primary_handle: Some(selected_handle.clone()),
        as_of: now_anchor(),
        next_cursor: None,
        has_more: false,
    };
    res.validate()
        .map_err(|e| anyhow!("aligned response MUST validate: {e}"))?;
    match &res.primary_handle {
        Some(h) if h.canonical() == selected_handle.canonical() => {}
        other => bail!(
            "response.primary_handle MUST equal select_primary_handle() output; \
             expected {}, got {other:?}",
            selected_handle.canonical()
        ),
    }
    if selected_handle.canonical() != "alice:acme.example" {
        bail!("vector setup: audience-matched claim expected to win §3.2.1");
    }
    Ok(())
}

// ── VECT-COT-3.7 — as_of historical replay ──────────────────────────────────

pub fn run_as_of_historical_replay_vector() -> Result<()> {
    let s = subject()?;
    // Request carries an as_of timestamp; the directory replays the visible
    // set effective at that instant.
    let historical_as_of = at(2026, 5, 10);
    let req = DirectoryListHandlesForSubjectRequestBody {
        account_id: s.clone(),
        realm_id: None,
        intent: None,
        requester_id: None,
        proof_challenge: None,
        proofs: vec![],
        as_of: Some(historical_as_of),
        cursor: None,
        limit: None,
    };
    let req_wire = serde_json::to_value(&req).map_err(|e| anyhow!("serialise req: {e}"))?;
    if req_wire.get("as_of").is_none() {
        bail!("historical replay request MUST carry as_of");
    }

    // The historical response MUST echo the as_of it replayed at (NOT the
    // current wall clock), so downstream caches key off the right instant.
    let res = DirectorySubjectHandleList {
        account_id: s.clone(),
        claims: vec![claim_for("alice:acme.example", &s, ACME_ISSUER, None)?],
        primary_handle: None,
        as_of: historical_as_of,
        next_cursor: None,
        has_more: false,
    };
    res.validate()
        .map_err(|e| anyhow!("historical response MUST validate: {e}"))?;
    if res.as_of != historical_as_of {
        bail!("historical response.as_of MUST reflect the replayed instant");
    }
    if res.as_of >= now_anchor() {
        bail!("historical as_of MUST be earlier than the realtime anchor");
    }
    Ok(())
}

// ── Suite entry-point ──────────────────────────────────────────────────────

pub fn run_list_handles_for_subject_vector_suite() -> Result<()> {
    if ALL_LIST_HANDLES_FOR_SUBJECT_VECTOR_IDS.len() != 7 {
        bail!(
            "expected 7 list-handles-for-subject vector ids, got {}",
            ALL_LIST_HANDLES_FOR_SUBJECT_VECTOR_IDS.len()
        );
    }
    run_happy_path_single_claim_vector()?;
    run_subject_mismatch_rejected_vector()?;
    run_audience_filter_applied_vector()?;
    run_issuer_trust_filter_vector()?;
    run_cursor_pagination_vector()?;
    run_primary_handle_field_aligned_with_3_2_1_vector()?;
    run_as_of_historical_replay_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_handles_for_subject_vector_suite_runs_clean() {
        run_list_handles_for_subject_vector_suite().unwrap();
    }
}
