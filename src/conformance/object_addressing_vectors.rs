//! CKP-0011 shareable object-addressing + `ck.find.directory.query.resolve_target`
//! conformance vectors (OA-COT-1..4).
//!
//! Spec source: `discovery/discovery-directory.md §9.1` (resolve_target +
//! common directory response fields) + the CKP-0011 object-addressing grammar.
//!
//! The vectors below are deterministic, pure unit checks against the SDK's
//! object-addressing surface (`cokret_core::models::*`, re-exported from
//! `crate::model::object_address`). No live server is required for
//! OA-COT-1..4; the live share→resolve→open leg is the `#[ignore]` companion
//! `test_oa_cot_5_share_resolve_open_live` in
//! `tests/r3_conformance_vectors.rs`.
//!
//! Grammar invariants pinned here:
//!   * `web+cokret:` ⇄ HTTPS-fragment forms parse to the SAME ParsedAddress.
//!   * realm-only / strand / message hierarchy forms.
//!   * unknown keyword and wrong hierarchy order fail closed (`parse_address` returns Err); retired
//!     `via` hints are ignored.
//!   * `<realm>` disambiguation: UUIDv7 → RealmRef::RealmId, dotted/domain → RealmRef::Alias.
//!   * `target_digest` covers ONLY the identity tuple + link_type — adding / removing action/tok/lt
//!     does NOT change it; switching strand/message DOES; absent hierarchy fields are OMITTED (not
//!     `null`) in the canonical shape.
//!   * scope-confusion: an A-object token fails `verify_token_target` against a B-object address;
//!     the token's link_type wins over a disagreeing URL `lt` hint (modeled via the
//!     `effective_link_type` argument).
//!   * `DirectoryTargetResolutionOutcome` deserializes the §9.1 common fields (`as_of`,
//!     `source_refs`, `join_candidates`) + `target_kind`; a realm target carries `realm_preview`.

use anyhow::{Result, anyhow, bail};
use chrono::{TimeZone, Utc};
use cokret_core::models::{
    AddressAction, DirectoryTargetResolutionOutcome, LinkType, RealmRef, TargetDescriptor,
    TargetKind, build_address, build_https_landing, parse_address, target_digest,
    verify_token_target,
};
use serde_json::json;

// ── Vector ids ───────────────────────────────────────────────────────────────

pub const VECTOR_ID_OA_GRAMMAR_SCHEME_EQUIVALENCE: &str =
    "ck.cotest_vector.object_addressing.grammar.scheme_fragment_equivalence.v1";
pub const VECTOR_ID_OA_GRAMMAR_HIERARCHY_FORMS: &str =
    "ck.cotest_vector.object_addressing.grammar.realm_strand_message_forms.v1";
pub const VECTOR_ID_OA_GRAMMAR_FAIL_CLOSED: &str =
    "ck.cotest_vector.object_addressing.grammar.fail_closed.v1";
pub const VECTOR_ID_OA_GRAMMAR_REALM_DISAMBIGUATION: &str =
    "ck.cotest_vector.object_addressing.grammar.realm_id_vs_alias.v1";
pub const VECTOR_ID_OA_DIGEST_IGNORES_HINTS: &str =
    "ck.cotest_vector.object_addressing.target_digest.ignores_hints.v1";
pub const VECTOR_ID_OA_DIGEST_TRACKS_OBJECT: &str =
    "ck.cotest_vector.object_addressing.target_digest.tracks_object_identity.v1";
pub const VECTOR_ID_OA_DIGEST_OMITS_ABSENT: &str =
    "ck.cotest_vector.object_addressing.target_digest.omits_absent_levels.v1";
pub const VECTOR_ID_OA_SCOPE_CONFUSION_REPLAY: &str =
    "ck.cotest_vector.object_addressing.scope_confusion.cross_object_replay_rejected.v1";
pub const VECTOR_ID_OA_SCOPE_TOKEN_LINK_TYPE_WINS: &str =
    "ck.cotest_vector.object_addressing.scope_confusion.token_link_type_wins.v1";
pub const VECTOR_ID_OA_RESOLVE_TARGET_COMMON_FIELDS: &str =
    "ck.cotest_vector.object_addressing.resolve_target.common_fields_shape.v1";
pub const VECTOR_ID_OA_RESOLVE_TARGET_REALM_PREVIEW: &str =
    "ck.cotest_vector.object_addressing.resolve_target.realm_target_carries_preview.v1";

pub const ALL_OBJECT_ADDRESSING_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_OA_GRAMMAR_SCHEME_EQUIVALENCE,
    VECTOR_ID_OA_GRAMMAR_HIERARCHY_FORMS,
    VECTOR_ID_OA_GRAMMAR_FAIL_CLOSED,
    VECTOR_ID_OA_GRAMMAR_REALM_DISAMBIGUATION,
    VECTOR_ID_OA_DIGEST_IGNORES_HINTS,
    VECTOR_ID_OA_DIGEST_TRACKS_OBJECT,
    VECTOR_ID_OA_DIGEST_OMITS_ABSENT,
    VECTOR_ID_OA_SCOPE_CONFUSION_REPLAY,
    VECTOR_ID_OA_SCOPE_TOKEN_LINK_TYPE_WINS,
    VECTOR_ID_OA_RESOLVE_TARGET_COMMON_FIELDS,
    VECTOR_ID_OA_RESOLVE_TARGET_REALM_PREVIEW,
];

// ── Pinned fixture identifiers (bare lowercase uuidv7) ───────────────────────

const R: &str = "01904100-0000-7000-8000-0000000000aa";
const F: &str = "01904100-0000-7000-8000-0000000000bb";
const F2: &str = "01904100-0000-7000-8000-0000000000cc";
const M: &str = "01904100-0000-7000-8000-0000000000dd";
const VIA: &str = "did:web:relay.example";
const LANDING: &str = "https://share.cokret.example";

// ════════════════════════════════════════════════════════════════════════════
// OA-COT-1 — Grammar
// ════════════════════════════════════════════════════════════════════════════

/// OA-COT-1.1 — `web+cokret:` ⇄ HTTPS-fragment equivalence. Both envelopes
/// share ONE grammar after the shell is stripped, so they MUST parse to the
/// byte-equal same [`ParsedAddress`], and a freshly built landing URL MUST
/// round-trip back through the parser.
pub fn run_scheme_fragment_equivalence_vector() -> Result<()> {
    // Same logical address expressed in both envelopes.
    let scheme_form = format!("web+cokret:realm/{R}/strand/{F}?via={VIA}&action=join");
    let from_scheme = parse_address(&scheme_form).map_err(|e| anyhow!("parse scheme form: {e}"))?;

    let landing_form = format!("{LANDING}/#realm/{R}/strand/{F}?via={VIA}&action=join");
    let from_landing =
        parse_address(&landing_form).map_err(|e| anyhow!("parse landing form: {e}"))?;

    if from_scheme != from_landing {
        bail!(
            "web+cokret: and HTTPS-fragment forms MUST parse to the same \
             ParsedAddress; scheme={from_scheme:?} landing={from_landing:?}"
        );
    }

    // build_https_landing(scheme-parsed) reparses to the same address.
    let built_landing = build_https_landing(LANDING, &from_scheme);
    if !built_landing.starts_with(&format!("{LANDING}/#realm/")) {
        bail!("build_https_landing MUST emit `<landing>/#realm/...`; got {built_landing}");
    }
    let reparsed_landing =
        parse_address(&built_landing).map_err(|e| anyhow!("reparse built landing: {e}"))?;
    if reparsed_landing != from_scheme {
        bail!("built HTTPS landing MUST reparse to the original ParsedAddress");
    }

    // build_address round-trips the canonical web+cokret: form too.
    let rebuilt = build_address(&from_scheme);
    let reparsed_scheme = parse_address(&rebuilt).map_err(|e| anyhow!("reparse rebuilt: {e}"))?;
    if reparsed_scheme != from_scheme {
        bail!("build_address → parse_address MUST be identity; got {rebuilt}");
    }
    Ok(())
}

/// OA-COT-1.2 — realm-only / strand / message hierarchy forms parse to the right
/// class (`is_realm` / `is_strand` / `is_message`) with the expected segments.
pub fn run_realm_strand_message_forms_vector() -> Result<()> {
    // Realm-only: no strand/message.
    let realm =
        parse_address(&format!("web+cokret:realm/{R}")).map_err(|e| anyhow!("realm: {e}"))?;
    if !realm.is_realm() || realm.is_strand() || realm.is_message() {
        bail!("realm-only form MUST classify as realm");
    }
    if realm.strand.is_some() || realm.message.is_some() {
        bail!("realm-only form MUST NOT carry strand/message segments");
    }
    if realm.realm != RealmRef::RealmId(R.to_owned()) {
        bail!("realm-only realm segment MUST be a RealmId");
    }

    // Strand: realm/<r>/strand/<f>. Retired `via` is ignored if present.
    let strand = parse_address(&format!("web+cokret:realm/{R}/strand/{F}?via={VIA}"))
        .map_err(|e| anyhow!("strand: {e}"))?;
    if !strand.is_strand() || strand.is_realm() || strand.is_message() {
        bail!("strand form MUST classify as strand");
    }
    if strand.strand.as_deref() != Some(F) || strand.message.is_some() {
        bail!("strand form segments drifted");
    }

    // Message: realm/<r>/strand/<f>/m/<msg>. Retired `via` is ignored if present.
    let msg = parse_address(&format!(
        "web+cokret:realm/{R}/strand/{F}/m/{M}?via={VIA}&action=reply"
    ))
    .map_err(|e| anyhow!("message: {e}"))?;
    if !msg.is_message() || msg.is_realm() || msg.is_strand() {
        bail!("message form MUST classify as message");
    }
    if msg.strand.as_deref() != Some(F) || msg.message.as_deref() != Some(M) {
        bail!("message form segments drifted");
    }
    if msg.action != AddressAction::Reply {
        bail!("message form MUST carry the action=reply hint");
    }
    Ok(())
}

/// OA-COT-1.3 — fail-closed grammar: an unknown path keyword, a wrong
/// hierarchy order MUST make `parse_address` return `Err`.
pub fn run_grammar_fail_closed_vector() -> Result<()> {
    // Unknown keyword (not in the v1 legal set realm/strand/m) — forward-compat
    // fail-closed, never a fork.
    for unknown in [
        format!("web+cokret:space/{R}"),
        format!("web+cokret:realm/{R}/thread/{F}?via={VIA}"),
        format!("web+cokret:realm/{R}/strand/{F}/reply/{M}?via={VIA}"),
    ] {
        if parse_address(&unknown).is_ok() {
            bail!("unknown keyword MUST fail closed: {unknown}");
        }
    }

    // Wrong hierarchy order.
    for misordered in [
        format!("web+cokret:strand/{F}/realm/{R}?via={VIA}"),
        // `m/` without an intermediate `strand/` level.
        format!("web+cokret:realm/{R}/m/{M}?via={VIA}"),
    ] {
        if parse_address(&misordered).is_ok() {
            bail!("wrong hierarchy order MUST fail closed: {misordered}");
        }
    }

    // Control: strand/message addresses without `via` now parse; join routing
    // comes from Directory `join_candidates[]`.
    parse_address(&format!("web+cokret:realm/{R}/strand/{F}"))
        .map_err(|e| anyhow!("control: strand without via MUST parse: {e}"))?;
    parse_address(&format!("web+cokret:realm/{R}/strand/{F}/m/{M}"))
        .map_err(|e| anyhow!("control: message without via MUST parse: {e}"))?;
    Ok(())
}

/// OA-COT-1.4 — `<realm>` segment disambiguation. A UUIDv7 textual realm
/// segment classifies as [`RealmRef::RealmId`]; a dotted/domain-style segment
/// classifies as [`RealmRef::Alias`].
pub fn run_realm_id_vs_alias_vector() -> Result<()> {
    let uuid_form =
        parse_address(&format!("web+cokret:realm/{R}")).map_err(|e| anyhow!("uuid realm: {e}"))?;
    match &uuid_form.realm {
        RealmRef::RealmId(id) if id == R => {}
        other => bail!("a UUIDv7 realm segment MUST be RealmRef::RealmId; got {other:?}"),
    }

    for alias in ["team.example.com", "acme.example"] {
        let parsed = parse_address(&format!("web+cokret:realm/{alias}"))
            .map_err(|e| anyhow!("alias realm: {e}"))?;
        match &parsed.realm {
            RealmRef::Alias(a) if a == alias => {}
            other => bail!("a dotted/domain realm segment MUST be RealmRef::Alias; got {other:?}"),
        }
    }

    // Direct classifier check (the parser's underlying rule).
    if RealmRef::parse(R) != RealmRef::RealmId(R.to_owned()) {
        bail!("RealmRef::parse MUST map a UUIDv7 to RealmId");
    }
    if RealmRef::parse("team.example.com") != RealmRef::Alias("team.example.com".to_owned()) {
        bail!("RealmRef::parse MUST map a domain string to Alias");
    }
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════
// OA-COT-2 — target_digest stability
// ════════════════════════════════════════════════════════════════════════════

fn digest_for(addr: &str) -> Result<String> {
    let parsed = parse_address(addr).map_err(|e| anyhow!("parse {addr}: {e}"))?;
    target_digest(&TargetDescriptor::from_parsed(&parsed))
        .map_err(|e| anyhow!("digest {addr}: {e}"))
}

/// OA-COT-2.1 — adding / removing `via`, `action`, `tok`, `lt` on the SAME
/// identity tuple does NOT change `target_digest` (the digest is computed over
/// the identity tuple + link_type only).
pub fn run_target_digest_ignores_hints_vector() -> Result<()> {
    // Baseline strand target (reference link).
    let base = digest_for(&format!("web+cokret:realm/{R}/strand/{F}?via={VIA}"))?;
    if !base.starts_with("sha256:") {
        bail!("target_digest MUST be a `sha256:<hex>` digest; got {base}");
    }

    // Extra via hints + an action hint — identity unchanged → same digest.
    let more_hints = digest_for(&format!(
        "web+cokret:realm/{R}/strand/{F}?via=did:web:a&via=did:web:b&action=join"
    ))?;
    if base != more_hints {
        bail!("adding via/action hints MUST NOT change target_digest");
    }

    // An invite link adds lt=invite + tok=...; link_type is part of the
    // descriptor, so to isolate the via/action/tok effect we keep the SAME
    // link_type for both sides by parsing two reference forms that differ only
    // in their (ignored) hints. The invite/reference distinction is asserted
    // separately below.
    let no_hints = digest_for(&format!(
        "web+cokret:realm/{R}/strand/{F}?via={VIA}&action=view"
    ))?;
    if base != no_hints {
        bail!("the default action=view hint MUST NOT change target_digest");
    }

    // Reference vs invite: the descriptor's link_type DOES participate in the
    // digest, but a token's `tok` value never does. Build two invite addresses
    // with different tokens but the same identity — same digest.
    let invite_tok_x = digest_for(&format!(
        "web+cokret:realm/{R}/strand/{F}?via={VIA}&lt=invite&tok=token-x"
    ))?;
    let invite_tok_y = digest_for(&format!(
        "web+cokret:realm/{R}/strand/{F}?via={VIA}&lt=invite&tok=token-y"
    ))?;
    if invite_tok_x != invite_tok_y {
        bail!("the opaque `tok` value MUST NOT change target_digest");
    }
    // Sanity: invite differs from reference (link_type IS part of the tuple).
    if invite_tok_x == base {
        bail!("link_type IS part of the digest tuple — invite vs reference MUST differ");
    }
    Ok(())
}

/// OA-COT-2.2 — switching `strand_id` or `message_id` DOES change the digest
/// (scope identity is bound into the digest).
pub fn run_target_digest_tracks_object_vector() -> Result<()> {
    let strand_a = digest_for(&format!("web+cokret:realm/{R}/strand/{F}?via={VIA}"))?;
    let strand_b = digest_for(&format!("web+cokret:realm/{R}/strand/{F2}?via={VIA}"))?;
    if strand_a == strand_b {
        bail!("switching strand_id MUST change target_digest");
    }

    let message = digest_for(&format!("web+cokret:realm/{R}/strand/{F}/m/{M}?via={VIA}"))?;
    if strand_a == message {
        bail!("promoting strand → message MUST change target_digest");
    }

    // Realm-only differs from any strand under it.
    let realm = digest_for(&format!("web+cokret:realm/{R}"))?;
    if realm == strand_a {
        bail!("a realm target MUST differ from a strand target under it");
    }
    Ok(())
}

/// OA-COT-2.3 — a descriptor with an absent hierarchy field is the canonical
/// form: the digest is computed over the OMITTED-key shape, NOT a `null` shape.
/// We assert (a) the serialized descriptor omits the absent keys entirely and
/// (b) the digest equals the digest of a hand-built omitted-key descriptor —
/// and differs from a descriptor whose absent fields were serialized as
/// `null`.
pub fn run_target_digest_omits_absent_vector() -> Result<()> {
    // Realm-only target → strand_id / message_id absent.
    let realm =
        parse_address(&format!("web+cokret:realm/{R}")).map_err(|e| anyhow!("realm: {e}"))?;
    let desc = TargetDescriptor::from_parsed(&realm);
    if desc.strand_id.is_some() || desc.message_id.is_some() {
        bail!("realm-only descriptor MUST have absent strand_id / message_id");
    }
    if desc.realm_id != format!("ck:realm:{R}") {
        bail!(
            "descriptor realm_id MUST be the typed canonical id; got {}",
            desc.realm_id
        );
    }

    // The canonical serialized shape OMITS the absent keys (never `null`).
    let serialized = serde_json::to_value(&desc).map_err(|e| anyhow!("serialise desc: {e}"))?;
    let obj = serialized
        .as_object()
        .ok_or_else(|| anyhow!("descriptor MUST serialize to an object"))?;
    if obj.contains_key("strand_id") || obj.contains_key("message_id") {
        bail!(
            "absent hierarchy levels MUST be omitted, NOT serialized (even as null); \
             got keys {:?}",
            obj.keys().collect::<Vec<_>>()
        );
    }
    let raw = serde_json::to_string(&desc).map_err(|e| anyhow!("string desc: {e}"))?;
    if raw.contains("null") {
        bail!("canonical descriptor MUST NOT contain `null`; got {raw}");
    }

    // The digest is computed over the omitted-key shape. A hypothetical
    // `null`-bearing shape produces a DIFFERENT canonical-JSON byte string and
    // therefore a different sha256 — proving the SDK canonicalizes over the
    // omitted form, not the null form.
    let digest = target_digest(&desc).map_err(|e| anyhow!("digest: {e}"))?;

    let omitted_bytes = b"{\"link_type\":\"reference\",\"realm_id\":\"ck:realm:01904100-0000-7000-8000-0000000000aa\"}";
    let null_bytes = b"{\"strand_id\":null,\"link_type\":\"reference\",\"message_id\":null,\"realm_id\":\"ck:realm:01904100-0000-7000-8000-0000000000aa\"}";
    let omitted_expected = super::sha256_prefixed(omitted_bytes);
    let null_expected = super::sha256_prefixed(null_bytes);

    if digest != omitted_expected {
        bail!(
            "target_digest MUST be computed over the OMITTED-key canonical shape; \
             expected {omitted_expected}, got {digest}"
        );
    }
    if digest == null_expected {
        bail!("target_digest MUST NOT match the `null`-shape canonicalization");
    }
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════
// OA-COT-3 — scope-confusion
// ════════════════════════════════════════════════════════════════════════════

/// Build the signed-token descriptor for an invite address (link_type pinned to
/// Invite, as a real minted token would carry).
fn token_descriptor_for(addr: &str) -> Result<TargetDescriptor> {
    let parsed = parse_address(addr).map_err(|e| anyhow!("parse {addr}: {e}"))?;
    let mut desc = TargetDescriptor::from_parsed(&parsed);
    desc.link_type = LinkType::Invite;
    Ok(desc)
}

/// OA-COT-3.1 — a token bound to object A MUST NOT validate against an address
/// parsed for a different object B (cross-object replay rejected). The matching
/// case validates as a positive control.
pub fn run_scope_confusion_replay_vector() -> Result<()> {
    // Token minted for strand A.
    let addr_a = parse_address(&format!(
        "web+cokret:realm/{R}/strand/{F}?via={VIA}&lt=invite&tok=t"
    ))
    .map_err(|e| anyhow!("addr_a: {e}"))?;
    let token_desc = token_descriptor_for(&format!(
        "web+cokret:realm/{R}/strand/{F}?via={VIA}&lt=invite&tok=t"
    ))?;

    // Positive control: A-token validates against the A-address.
    if !verify_token_target(&token_desc, &addr_a, LinkType::Invite) {
        bail!("an A-object token MUST validate against its own A-address");
    }

    // Replay onto a different strand B → MUST fail closed.
    let addr_b = parse_address(&format!(
        "web+cokret:realm/{R}/strand/{F2}?via={VIA}&lt=invite&tok=t"
    ))
    .map_err(|e| anyhow!("addr_b: {e}"))?;
    if verify_token_target(&token_desc, &addr_b, LinkType::Invite) {
        bail!("an A-object token MUST NOT validate against a B-object address (scope confusion)");
    }

    // Replay onto a message under the same strand → still a different object.
    let addr_msg = parse_address(&format!(
        "web+cokret:realm/{R}/strand/{F}/m/{M}?via={VIA}&lt=invite&tok=t"
    ))
    .map_err(|e| anyhow!("addr_msg: {e}"))?;
    if verify_token_target(&token_desc, &addr_msg, LinkType::Invite) {
        bail!("a strand-scoped token MUST NOT validate against a message under it");
    }
    Ok(())
}

/// OA-COT-3.2 — when the URL `lt` hint disagrees with the token's link_type,
/// the TOKEN's link_type wins. Modeled via the `effective_link_type` argument:
/// the comparison is performed under the (trusted) effective link_type, not
/// whatever the untrusted address query claimed.
pub fn run_scope_token_link_type_wins_vector() -> Result<()> {
    // The token was minted as an INVITE for strand A.
    let token_desc = token_descriptor_for(&format!(
        "web+cokret:realm/{R}/strand/{F}?via={VIA}&lt=invite&tok=t"
    ))?;

    // The presented URL, however, was DOWNGRADED to a reference link (the
    // attacker stripped `lt=invite`). Its parsed link_type is Reference.
    let downgraded = parse_address(&format!("web+cokret:realm/{R}/strand/{F}?via={VIA}"))
        .map_err(|e| anyhow!("downgraded: {e}"))?;
    if downgraded.link_type != LinkType::Reference {
        bail!("vector setup: the downgraded URL MUST parse as a reference link");
    }

    // Comparing under the URL's (untrusted) reference link_type MUST fail —
    // the digests differ because link_type participates in the tuple.
    if verify_token_target(&token_desc, &downgraded, LinkType::Reference) {
        bail!("a reference-typed comparison MUST NOT match an invite token descriptor");
    }

    // Comparing under the TOKEN's effective Invite link_type MUST succeed —
    // the token's link_type wins over the URL hint.
    if !verify_token_target(&token_desc, &downgraded, LinkType::Invite) {
        bail!(
            "the token's link_type MUST win over a disagreeing URL `lt` hint \
             (compare under effective_link_type = Invite)"
        );
    }

    // Symmetric case: a reference token presented under an invite URL still
    // compares under the trusted (reference) link_type → no privilege escalation.
    let ref_token = {
        let parsed = parse_address(&format!("web+cokret:realm/{R}/strand/{F}?via={VIA}"))
            .map_err(|e| anyhow!("ref token addr: {e}"))?;
        TargetDescriptor::from_parsed(&parsed)
    };
    if ref_token.link_type != LinkType::Reference {
        bail!("vector setup: reference token descriptor MUST carry Reference link_type");
    }
    let upgraded_url = parse_address(&format!(
        "web+cokret:realm/{R}/strand/{F}?via={VIA}&lt=invite&tok=t"
    ))
    .map_err(|e| anyhow!("upgraded url: {e}"))?;
    // Under the trusted Reference link_type the reference token matches; it
    // MUST NOT match under a forged Invite effective type.
    if !verify_token_target(&ref_token, &upgraded_url, LinkType::Reference) {
        bail!("a reference token MUST match under its own (reference) effective link_type");
    }
    if verify_token_target(&ref_token, &upgraded_url, LinkType::Invite) {
        bail!("a reference token MUST NOT be upgraded to invite via the URL `lt` hint");
    }
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════
// OA-COT-4 — resolve_target response shape
// ════════════════════════════════════════════════════════════════════════════

/// OA-COT-4.1 — `DirectoryTargetResolutionOutcome` deserializes the §9.1 common
/// directory fields (`as_of`, `source_refs`, `join_candidates`) and `target_kind`.
pub fn run_resolve_target_common_fields_vector() -> Result<()> {
    let wire = json!({
        "target_kind": "strand",
        "object_preview": { "strand_id": format!("ck:strand:{F}"), "title": "Launch planning" },
        "join_rule": "knock",
        "as_of": "2026-05-27T00:00:00Z",
        "source_refs": [
            "ck:event:01904100-0000-7000-8000-0000000000e1",
            "ck:event:01904100-0000-7000-8000-0000000000e2"
        ],
        "join_candidates": [
            {
                "realm_id": format!("ck:realm:{R}"),
                "service_did": "did:web:relay.example",
                "service_type": "principal_server",
                "role": "primary",
                "operations": ["ck.self.events.command.submit"],
                "join_methods": ["invite_accept", "member_join", "knock"],
                "priority": 0,
                "source": "directory_ingest",
                "source_refs": ["ck:event:01904100-0000-7000-8000-0000000000e1"],
                "as_of": "2026-05-27T00:00:00Z",
                "expires_at": "2026-05-27T00:15:00Z"
            },
            {
                "realm_id": format!("ck:realm:{R}"),
                "service_did": "did:web:teabay.example",
                "service_type": "principal_server",
                "role": "mirror",
                "operations": ["ck.self.events.command.submit"],
                "join_methods": ["invite_accept", "member_join", "knock"],
                "priority": 1,
                "source": "directory_ingest",
                "source_refs": ["ck:event:01904100-0000-7000-8000-0000000000e2"],
                "as_of": "2026-05-27T00:00:00Z",
                "expires_at": "2026-05-27T00:15:00Z"
            }
        ],
        "policy_revision": "rev-7",
        "stale": false
    });
    let body: DirectoryTargetResolutionOutcome =
        serde_json::from_value(wire).map_err(|e| anyhow!("deserialise resolve_target res: {e}"))?;

    if body.target_kind != TargetKind::Strand {
        bail!("target_kind MUST deserialize to TargetKind::Strand");
    }
    // §9.1 common fields.
    let expected_as_of = Utc
        .with_ymd_and_hms(2026, 5, 27, 0, 0, 0)
        .single()
        .ok_or_else(|| anyhow!("pinned as_of"))?;
    if body.as_of != expected_as_of {
        bail!("as_of common field MUST round-trip the §9.1 timestamp");
    }
    if body.source_refs.len() != 2 {
        bail!("source_refs §9.1 field MUST carry both source events");
    }
    let candidate_services: Vec<&str> = body
        .join_candidates
        .iter()
        .map(|candidate| candidate.service_did.as_str())
        .collect();
    if candidate_services != vec!["did:web:relay.example", "did:web:teabay.example"] {
        bail!("join_candidates common field MUST round-trip in order");
    }
    // A strand target carries object_preview (opaque), not realm_preview.
    if body.realm_preview.is_some() {
        bail!("a strand target MUST NOT carry realm_preview");
    }
    if body.object_preview.is_none() {
        bail!("a strand target MUST carry the opaque object_preview");
    }

    // Re-serialize and confirm the common fields survive the round trip.
    let reser = serde_json::to_value(&body).map_err(|e| anyhow!("reserialise: {e}"))?;
    if reser.get("target_kind").and_then(|v| v.as_str()) != Some("strand") {
        bail!("target_kind MUST survive round-trip serialization");
    }
    if reser.get("as_of").is_none() || reser.get("source_refs").is_none() {
        bail!("§9.1 common fields MUST survive round-trip serialization");
    }
    Ok(())
}

/// OA-COT-4.2 — a realm-target `resolve_target` response carries
/// `realm_preview` (and classifies as `TargetKind::Realm`).
pub fn run_resolve_target_realm_preview_vector() -> Result<()> {
    let wire = json!({
        "target_kind": "realm",
        "realm_preview": {
            "realm_id": format!("ck:realm:{R}"),
            "title": "Acme HQ",
            "as_of": "2026-05-27T00:00:00Z",
            "policy_revision": "rev-1",
            "preview": { "member_count": 42 }
        },
        "join_rule": "invite",
        "as_of": "2026-05-27T00:00:00Z",
        "source_refs": ["ck:event:01904100-0000-7000-8000-0000000000e1"],
        "join_candidates": []
    });
    let body: DirectoryTargetResolutionOutcome =
        serde_json::from_value(wire).map_err(|e| anyhow!("deserialise realm res: {e}"))?;

    if body.target_kind != TargetKind::Realm {
        bail!("target_kind MUST deserialize to TargetKind::Realm");
    }
    let preview = body
        .realm_preview
        .as_ref()
        .ok_or_else(|| anyhow!("a realm target MUST carry realm_preview"))?;
    if preview.realm_id.as_str() != format!("ck:realm:{R}") {
        bail!("realm_preview.realm_id MUST round-trip the typed realm id");
    }
    if preview.title.as_deref() != Some("Acme HQ") {
        bail!("realm_preview.title MUST round-trip");
    }
    // A realm target MUST NOT carry an object_preview (that is strand/message).
    if body.object_preview.is_some() {
        bail!("a realm target MUST NOT carry object_preview");
    }
    Ok(())
}

// ── Suite entry-point ──────────────────────────────────────────────────────

pub fn run_object_addressing_vector_suite() -> Result<()> {
    if ALL_OBJECT_ADDRESSING_VECTOR_IDS.len() != 11 {
        bail!(
            "expected 11 object-addressing vector ids, got {}",
            ALL_OBJECT_ADDRESSING_VECTOR_IDS.len()
        );
    }
    // OA-COT-1 — grammar (4 cases).
    run_scheme_fragment_equivalence_vector()?;
    run_realm_strand_message_forms_vector()?;
    run_grammar_fail_closed_vector()?;
    run_realm_id_vs_alias_vector()?;
    // OA-COT-2 — target_digest stability (3 cases).
    run_target_digest_ignores_hints_vector()?;
    run_target_digest_tracks_object_vector()?;
    run_target_digest_omits_absent_vector()?;
    // OA-COT-3 — scope-confusion (2 cases).
    run_scope_confusion_replay_vector()?;
    run_scope_token_link_type_wins_vector()?;
    // OA-COT-4 — resolve_target response shape (2 cases).
    run_resolve_target_common_fields_vector()?;
    run_resolve_target_realm_preview_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_addressing_vector_suite_runs_clean() {
        run_object_addressing_vector_suite().unwrap();
    }
}
