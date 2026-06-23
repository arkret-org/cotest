//! History-visibility projection and redaction-driven history-visibility
//! wire-model conformance vectors, including cross-server redaction.

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{emit_vector, expected_outcome, expected_reason, load_local_fixture};
use crate::conformance::{required_str, validate_profile};

/// B4 Round 26 — per-viewer history-visibility projection check.
///
/// Spec: `data-structures/history-visibility.md` +
/// `authz/event-auth-state-resolution.md`. The history_visibility cell
/// (cas-register `ck:cell:ck.component.realm.history_visibility.v1:<realm_id>`)
/// holds one of {joined, invited, world_readable, shared}. The reducer
/// projects the timeline differently per viewer based on
/// (membership_state, history_visibility, event_origin_ts vs viewer_join_ts /
/// invite_ts / shared_since_ts).
///
/// For each positive vector this validator reifies the spec's projection
/// function and asserts the visible/hidden split matches `expected.*`.
/// Negative vectors check the rejection reason_code.
pub fn run_history_visibility_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("history_visibility_fixture.json")?;
    validate_profile(&fixture, "ck.profile.history_visibility_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("history_visibility fixture missing vectors[]"))?;
    if vectors.len() < 4 {
        bail!(
            "history_visibility fixture has {} vectors, expected >= 4",
            vectors.len()
        );
    }

    let mut covered_visibilities = std::collections::BTreeSet::<String>::new();
    let mut saw_admin_override = false;
    let mut saw_redacted_view = false;
    let mut saw_ban_transition = false;

    for v in vectors {
        let name = required_str(v, "name")?;
        let visibility = required_str(v, "history_visibility")?;
        if !["joined", "invited", "world_readable", "shared"].contains(&visibility) {
            bail!("vector {name} unknown history_visibility {visibility}");
        }
        covered_visibilities.insert(visibility.to_owned());

        let outcome = expected_outcome(v, name)?;
        if outcome != "accept" {
            bail!("positive vector {name} must have outcome=accept");
        }

        // Admin override path: validate capability gate.
        if let Some(admin) = v.get("admin_override") {
            if let Some(cap) = admin.get("capability").and_then(Value::as_str) {
                if cap != "ck.recovery.read.history.v1" {
                    bail!(
                        "vector {name} admin_override.capability must be ck.recovery.read.history.v1"
                    );
                }
                let view_mode = v
                    .pointer("/expected/view_mode")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        anyhow!("vector {name} admin override must declare view_mode")
                    })?;
                if view_mode != "audit_view" {
                    bail!("vector {name} admin override view_mode must be audit_view");
                }
                let audit_log = v
                    .pointer("/expected/audit_log_emitted")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| {
                        anyhow!("vector {name} admin override missing audit_log_emitted")
                    })?;
                if !audit_log {
                    bail!("vector {name} admin override must require audit_log_emitted=true");
                }
                saw_admin_override = true;
            }
            emit_vector(
                "history_visibility.admin_override",
                v,
                json!({"name": name, "visibility": visibility}),
            );
            continue;
        }

        // Redacted-event vector uses a different shape (multi-viewer).
        if v.get("redacted_event").is_some() {
            let viewers = v
                .get("viewers")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("vector {name} redacted needs viewers[]"))?;
            for viewer in viewers {
                let view = required_str(viewer, "expected_view")?;
                if !["audit_view_with_original", "tombstone_only"].contains(&view) {
                    bail!("vector {name} viewer.expected_view {view} unknown");
                }
            }
            saw_redacted_view = true;
            emit_vector(
                "history_visibility.redacted",
                v,
                json!({"name": name, "visibility": visibility}),
            );
            continue;
        }

        // Ban-transition vector: viewer membership_state=ban must hide
        // everything regardless of history_visibility (except world_readable).
        let viewer = v
            .get("viewer")
            .ok_or_else(|| anyhow!("vector {name} missing viewer"))?;
        let membership = viewer.get("membership_state").and_then(Value::as_str);
        if membership == Some("ban") {
            saw_ban_transition = true;
        }

        let events = v
            .get("events")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("vector {name} missing events[]"))?;
        let visible_expected: std::collections::BTreeSet<String> = v
            .pointer("/expected/visible_event_ids")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();
        let hidden_expected: std::collections::BTreeSet<String> = v
            .pointer("/expected/hidden_event_ids")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        // Project per-spec.
        let viewer_join_ts = viewer.get("join_ts").and_then(Value::as_u64);
        let viewer_invite_ts = viewer.get("invite_ts").and_then(Value::as_u64);
        let shared_since_ts = v.get("shared_since_ts").and_then(Value::as_u64);
        for ev in events {
            let ev_id = required_str(ev, "event_id")?;
            let origin_ts = ev
                .get("origin_ts")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow!("event missing origin_ts"))?;
            let projected_visible = project_history_visibility(
                visibility,
                membership,
                viewer_join_ts,
                viewer_invite_ts,
                shared_since_ts,
                origin_ts,
            );
            let listed_visible = visible_expected.contains(ev_id);
            let listed_hidden = hidden_expected.contains(ev_id);
            if projected_visible && !listed_visible {
                bail!(
                    "vector {name} event {ev_id} should be VISIBLE per projection but fixture lists it hidden/absent"
                );
            }
            if !projected_visible && !listed_hidden {
                bail!(
                    "vector {name} event {ev_id} should be HIDDEN per projection but fixture lists it visible/absent"
                );
            }
        }
        emit_vector(
            "history_visibility.projection",
            v,
            json!({
                "name": name,
                "visibility": visibility,
                "membership": membership,
                "visible_count": visible_expected.len(),
                "hidden_count": hidden_expected.len(),
            }),
        );
    }

    let required_visibilities = ["joined", "invited", "world_readable", "shared"];
    for required in required_visibilities {
        if !covered_visibilities.contains(required) {
            bail!("history_visibility fixture missing coverage for {required}");
        }
    }
    if !saw_admin_override {
        bail!("history_visibility fixture must cover admin_override path");
    }
    if !saw_redacted_view {
        bail!("history_visibility fixture must cover redacted-event per-viewer audit_view");
    }
    if !saw_ban_transition {
        bail!("history_visibility fixture must cover ban-transition viewer");
    }

    // Negatives: structural reason_code check.
    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("history_visibility fixture missing negative_vectors[]"))?;
    for v in negatives {
        let name = required_str(v, "name")?;
        let outcome = expected_outcome(v, name)?;
        if outcome != "reject" {
            bail!("negative {name} outcome must be reject");
        }
        let reason = expected_reason(v)
            .ok_or_else(|| anyhow!("negative {name} missing expected.reason_code"))?;
        if !["history_visibility_denied", "capability_not_held"].contains(&reason) {
            bail!("negative {name} unknown reason_code {reason}");
        }
    }

    Ok(())
}
/// Round-26 standalone — history-visibility projection function: assert
/// the spec's per-membership × per-visibility decision matrix matches the
/// implementation's projection on a hand-rolled cross-product.
pub fn run_history_visibility_projection_matrix_check() -> Result<()> {
    // (visibility, membership, viewer_join_ts, viewer_invite_ts,
    //  shared_since_ts, event_origin_ts, expected_visible).
    type Row = (
        &'static str,
        Option<&'static str>,
        Option<u64>,
        Option<u64>,
        Option<u64>,
        u64,
        bool,
    );
    let rows: &[Row] = &[
        // world_readable: always visible.
        ("world_readable", None, None, None, None, 1, true),
        ("world_readable", Some("ban"), None, None, None, 1, true),
        // joined: requires join state + post-join origin_ts.
        ("joined", Some("join"), Some(100), None, None, 50, false),
        ("joined", Some("join"), Some(100), None, None, 150, true),
        ("joined", None, None, None, None, 50, false),
        ("joined", Some("ban"), Some(100), None, None, 150, false),
        // invited: invite_ts cutoff (joined or invite both ok).
        ("invited", Some("invite"), None, Some(200), None, 150, false),
        ("invited", Some("invite"), None, Some(200), None, 250, true),
        ("invited", Some("join"), Some(100), Some(80), None, 90, true),
        // shared: members use join_ts; non-members use shared_since_ts.
        (
            "shared",
            Some("join"),
            Some(100),
            None,
            Some(200),
            150,
            true,
        ),
        ("shared", None, None, None, Some(200), 150, false),
        ("shared", None, None, None, Some(200), 250, true),
    ];
    for (visibility, membership, jt, it, st, ots, expected) in rows {
        let actual = project_history_visibility(visibility, *membership, *jt, *it, *st, *ots);
        if actual != *expected {
            bail!(
                "projection mismatch: visibility={visibility} membership={membership:?} jt={jt:?} it={it:?} st={st:?} ots={ots} → expected {expected}, got {actual}"
            );
        }
    }
    Ok(())
}
/// B2 Round 24 — redaction reducer × history_visibility composition vectors.
pub fn run_redaction_history_visibility_fixture_suite() -> Result<()> {
    use std::collections::BTreeSet;

    let fixture = load_local_fixture("redaction_history_visibility_fixture.json")?;
    validate_profile(
        &fixture,
        "ck.profile.redaction_history_visibility_vectors.v1",
    )?;

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("redaction_history_visibility fixture missing vectors[]"))?;
    if vectors.len() < 4 {
        bail!(
            "redaction_history_visibility fixture has {} vectors, expected >= 4",
            vectors.len()
        );
    }

    let valid_visibility: BTreeSet<&str> = ["world_readable", "shared", "joined", "invited"]
        .into_iter()
        .collect();

    let mut saw_author = false;
    let mut saw_member_hidden = false;
    let mut saw_world_readable_remove = false;
    let mut saw_unredact = false;

    for v in vectors {
        let name = required_str(v, "name")?;
        let visibility = required_str(v, "history_visibility")?;
        if !valid_visibility.contains(visibility) {
            bail!("vector {name} history_visibility {visibility} invalid");
        }
        let viewer_role = required_str(v, "viewer_role")?;
        let original = v
            .get("original_event")
            .ok_or_else(|| anyhow!("vector {name} missing original_event"))?;
        let _ = required_str(original, "event_id")?;
        if required_str(original, "kind")? != "ck.message.create" {
            bail!("vector {name} original_event kind must be ck.message.create");
        }

        let redaction = v
            .get("redaction_event")
            .ok_or_else(|| anyhow!("vector {name} missing redaction_event"))?;
        if required_str(redaction, "kind")? != "ck.message.redact" {
            bail!("vector {name} redaction_event kind must be ck.message.redact");
        }
        let redacts = required_str(redaction, "redacts")?;
        let original_id = required_str(original, "event_id")?;
        if redacts != original_id {
            bail!("vector {name} redaction.redacts {redacts} != original.event_id {original_id}");
        }

        let expected = v
            .get("expected")
            .ok_or_else(|| anyhow!("vector {name} missing expected"))?;
        let tombstone_visible = expected
            .get("tombstone_visible")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} missing expected.tombstone_visible"))?;
        let original_visible = expected
            .get("original_content_visible")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} missing expected.original_content_visible"))?;

        match (viewer_role, visibility) {
            ("author", _) => {
                if !tombstone_visible || !original_visible {
                    bail!("vector {name} author MUST see both tombstone and original content");
                }
                saw_author = true;
            }
            ("world_reader", "world_readable") => {
                let fully = expected
                    .get("fully_removed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if tombstone_visible || original_visible || !fully {
                    bail!(
                        "vector {name} world_readable redaction must be fully_removed for world reader"
                    );
                }
                saw_world_readable_remove = true;
            }
            ("member", _) => {
                if v.get("unredaction_move").is_some() {
                    if !original_visible || tombstone_visible {
                        bail!(
                            "vector {name} reverse-redaction must re-expose original and hide tombstone"
                        );
                    }
                    let mv = v.get("unredaction_move").unwrap();
                    if required_str(mv, "kind")? != "ck.message.unredact" {
                        bail!("vector {name} unredaction_move kind must be ck.message.unredact");
                    }
                    let removes = mv
                        .get("removes")
                        .and_then(Value::as_array)
                        .ok_or_else(|| anyhow!("vector {name} unredact missing removes[]"))?;
                    let red_id = required_str(redaction, "event_id")?;
                    let listed: Vec<&str> = removes.iter().filter_map(Value::as_str).collect();
                    if !listed.contains(&red_id) {
                        bail!("vector {name} unredact removes[] must reference redaction event_id");
                    }
                    saw_unredact = true;
                } else {
                    if !tombstone_visible || original_visible {
                        bail!("vector {name} member must see tombstone but NOT original content");
                    }
                    saw_member_hidden = true;
                }
            }
            (role, vis) => bail!("vector {name} unexpected (viewer_role={role}, visibility={vis})"),
        }
        emit_vector(
            "redaction_history_visibility.vector",
            v,
            json!({
                "name": name,
                "history_visibility": visibility,
                "viewer_role": viewer_role,
                "tombstone_visible": tombstone_visible,
                "original_content_visible": original_visible,
            }),
        );
    }

    if !(saw_author && saw_member_hidden && saw_world_readable_remove && saw_unredact) {
        bail!(
            "redaction_history_visibility fixture must cover author + member_hidden + world_readable_remove + reverse_redaction"
        );
    }

    Ok(())
}
/// E6 Round 27 — redacted Move cross-server projection (round-25 MAL-14).
pub fn run_redacted_cross_server_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("redacted_cross_server_fixture.json")?;
    validate_profile(&fixture, "ck.profile.redacted_cross_server_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("redacted_cross_server missing vectors[]"))?;
    if vectors.len() < 2 {
        bail!(
            "redacted_cross_server requires >= 2 vectors, got {}",
            vectors.len()
        );
    }
    let mut saw_member_tombstone = false;
    let mut saw_author_audit = false;
    let mut saw_un_redaction = false;
    for v in vectors {
        let name = required_str(v, "name")?;
        if expected_outcome(v, name)? != "accept" {
            bail!("vector {name} outcome must be accept");
        }
        let viewer_is_author = v
            .get("viewer_is_author")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} missing viewer_is_author"))?;
        let projection = v
            .pointer("/expected/projection_on_peer_b")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing projection_on_peer_b"))?;
        let body_visible = v
            .pointer("/expected/body_visible")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        match name {
            "redaction_propagates_to_peer_b_member_sees_tombstone" => {
                if viewer_is_author {
                    bail!("vector {name} viewer_is_author must be false for member-tombstone case");
                }
                if projection != "tombstone_only" || body_visible {
                    bail!("vector {name} member view must be tombstone_only with body hidden");
                }
                saw_member_tombstone = true;
            }
            "redaction_propagates_author_audit_view_full_body" => {
                if !viewer_is_author {
                    bail!("vector {name} viewer_is_author must be true for author audit");
                }
                if projection != "audit_view" || !body_visible {
                    bail!("vector {name} author view must be audit_view with body visible");
                }
                saw_author_audit = true;
            }
            "un_redaction_move_propagates_cross_server_restores_body" => {
                if !v
                    .get("redaction_then_un_redaction")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    bail!("vector {name} redaction_then_un_redaction must be true");
                }
                if !body_visible || projection != "body_visible" {
                    bail!("vector {name} un-redaction must restore body_visible");
                }
                saw_un_redaction = true;
            }
            other => bail!("redacted_cross_server unexpected vector {other}"),
        }
        emit_vector(
            "redacted_cross_server.vector",
            v,
            json!({
                "name": name,
                "viewer_is_author": viewer_is_author,
                "projection": projection,
                "body_visible": body_visible,
            }),
        );
    }
    if !(saw_member_tombstone && saw_author_audit && saw_un_redaction) {
        bail!("redacted_cross_server must cover member_tombstone + author_audit + un_redaction");
    }
    Ok(())
}
/// Project per-spec history-visibility decision for a single event.
fn project_history_visibility(
    visibility: &str,
    viewer_membership: Option<&str>,
    viewer_join_ts: Option<u64>,
    viewer_invite_ts: Option<u64>,
    shared_since_ts: Option<u64>,
    event_origin_ts: u64,
) -> bool {
    // Banned/leave viewers see nothing except world_readable.
    if let Some(state) = viewer_membership
        && matches!(state, "ban" | "leave")
        && visibility != "world_readable"
    {
        return false;
    }
    match visibility {
        "world_readable" => true,
        "joined" => match (viewer_membership, viewer_join_ts) {
            (Some("join"), Some(join_ts)) => event_origin_ts >= join_ts,
            _ => false,
        },
        "invited" => match (viewer_membership, viewer_invite_ts) {
            (Some("invite") | Some("join"), Some(invite_ts)) => event_origin_ts >= invite_ts,
            _ => false,
        },
        "shared" => {
            // Members: post-join visible; non-members: post-shared_since visible.
            match viewer_membership {
                Some("join") => match viewer_join_ts {
                    Some(jt) => event_origin_ts >= jt,
                    None => false,
                },
                _ => shared_since_ts
                    .map(|since| event_origin_ts >= since)
                    .unwrap_or(false),
            }
        }
        _ => false,
    }
}
