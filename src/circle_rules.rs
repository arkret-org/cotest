//! Circle-rollout (CXP-0007) structural drift rules.
//!
//! contrix-spec commit `2b0d70d` (range `9cb47c1..2b0d70d`) introduces the
//! **Circle primitive** as the new intra-Realm security boundary. The spec
//! hard-removes [`Flow.discussion_realm_ref`] and a handful of `_ref` /
//! `_id` naming legacies in favour of:
//!
//! * `scope_circle_id` (and `default_scope_circle_id`) on Flow / Space / Morph / GrantConstraint,
//!   typed `cx:circle:<uuidv7>`.
//! * `EffectiveScope { kind: realm | circle, realm_id, circle_id? }` on every v1 event envelope
//!   (`$defs.effective_scope`).
//! * A new `confidential_discussion_of` Relation between two `cx:flow:` identifiers
//!   (broad-composition + narrow-discussion duo).
//! * 7 new event kinds (`cx.circle.create`, `cx.circle.update`, `cx.circle.archive`,
//!   `cx.circle.restore`, `cx.circle.tombstone`, `cx.circle.member.state`,
//!   `cx.circle.anchor_commit`).
//! * 6 new capability actions (`cx.circle.create`, `cx.circle.manage`, `cx.circle.member.add`,
//!   `cx.circle.member.manage`, `cx.circle.member.add.others`, `cx.circle.audit`).
//! * 6 new reason / error codes (5 CXP-0007 sub-reasons plus `delivery_binding_handed_over`
//!   registered in CXP-0006).
//!
//! This module hosts the **literal-scanner** counterparts that protect the
//! downstream tree from silently regressing on those wire-shape decisions.
//! The rules deliberately stay heuristic; false positives must remain rare
//! and the marker comment `CIRCLE-ALLOW` on the offending or immediately
//! preceding line suppresses a finding.
//!
//! Rules emitted here:
//!
//! 1. **`DiscussionRealmRef`** — any occurrence of the deleted `discussion_realm_ref` field as a
//!    Rust / TS / JSON identifier or string literal. Spec status: hard-removed (CXP-0007).
//!    Replacement: `scope_circle_id`.
//! 2. **`UnknownCircleEventKind`** — any string literal beginning with `cx.circle.` whose tail is
//!    **not** on the canonical allowlist (7 event kinds + 6 capability actions registered by
//!    CXP-0007).
//! 3. **`UnknownCircleErrorCode`** — any string literal whose value is one of the CXP-0007 reason
//!    code names (we still want the canonical spelling to be the only spelling). Unknown variants
//!    surface here.
//!
//! Wired into the harness through [`crate::literal_scanner::scan_tree_circle`].

use std::path::{Path, PathBuf};

use serde::Serialize;

/// Marker comment that suppresses circle-rule findings on its own line or
/// the immediately preceding non-blank line.
pub const CIRCLE_ALLOW_MARKER: &str = "CIRCLE-ALLOW";

/// Canonical `cx.circle.*` event-kind allowlist. Mirrors
/// `contrix-core::events::kinds` (`CIRCLE_*` constants) and
/// `contrix-spec/spec/v1/artifacts/registry/event-kind-registry.json`.
pub const CIRCLE_EVENT_KINDS: &[&str] = &[
    "cx.circle.create",
    "cx.circle.update",
    "cx.circle.archive",
    "cx.circle.restore",
    "cx.circle.tombstone",
    "cx.circle.member.state",
    "cx.circle.anchor_commit",
];

/// Canonical `cx.circle.*` capability-action allowlist. Mirrors
/// `contrix-core::model::constants` (`CAP_ACTION_CIRCLE_*`) and
/// `contrix-spec/spec/v1/artifacts/registry/capability-action-registry.json`.
pub const CIRCLE_CAPABILITY_ACTIONS: &[&str] = &[
    "cx.circle.create",
    "cx.circle.manage",
    "cx.circle.member.add",
    "cx.circle.member.manage",
    "cx.circle.member.add.others",
    "cx.circle.audit",
];

/// CXP-0007 reason codes (sub-codes of `failed_precondition` /
/// `schema_violation`). Mirrors `contrix-core::error::KNOWN_REASON_CODES_CXP_0007`
/// plus the 6th top-level `delivery_binding_handed_over` code.
pub const CIRCLE_REASON_CODES: &[&str] = &[
    "circle_realm_mismatch",
    "circle_not_active",
    "circle_member_must_be_realm_member",
    "scope_rebind_forbidden",
    "metadata_encryption_floor_violation",
    "delivery_binding_handed_over",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CircleRule {
    /// `discussion_realm_ref` is hard-removed (CXP-0007).
    DiscussionRealmRef,
    /// A `cx.circle.*` literal not on the canonical allowlist.
    UnknownCircleEventKind,
    /// Reserved for future expansion — string-literal reason codes that
    /// look like CXP-0007 codes but are mis-spelled. Currently surfaced
    /// only via the constant list [`CIRCLE_REASON_CODES`].
    UnknownCircleErrorCode,
    /// A `Relation::ConfidentialDiscussionOf` literal whose visible
    /// `from` / `to` operands do not both look like `cx:flow:` ids.
    ConfidentialDiscussionEndpointsNotFlow,
    /// A literal `EffectiveScope::Circle { ... }` or
    /// `"kind": "circle"` envelope scope that does not also mention
    /// `circle_id`.
    EffectiveScopeCircleMissingId,
}

impl CircleRule {
    pub fn as_str(self) -> &'static str {
        match self {
            CircleRule::DiscussionRealmRef => "discussion_realm_ref",
            CircleRule::UnknownCircleEventKind => "unknown_circle_event_kind",
            CircleRule::UnknownCircleErrorCode => "unknown_circle_error_code",
            CircleRule::ConfidentialDiscussionEndpointsNotFlow => {
                "confidential_discussion_endpoints_not_flow"
            }
            CircleRule::EffectiveScopeCircleMissingId => "effective_scope_circle_missing_id",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CircleFinding {
    pub path: PathBuf,
    pub line: usize,
    pub column: usize,
    pub rule: CircleRule,
    pub matched_literal: String,
    pub message: String,
}

/// Walk `path` line-by-line and emit findings for every circle rule.
pub fn scan_circle(path: &Path, contents: &str, out: &mut Vec<CircleFinding>) {
    if is_allowed_path(path) {
        return;
    }
    let lines: Vec<&str> = contents.lines().collect();
    let mut new_findings: Vec<CircleFinding> = Vec::new();
    for (line_idx, line) in lines.iter().enumerate() {
        scan_discussion_realm_ref(path, line_idx, line, &mut new_findings);
        scan_circle_dotted_string(path, line_idx, line, &mut new_findings);
        scan_effective_scope_circle(path, line_idx, line, &mut new_findings);
        scan_confidential_discussion_relation(path, line_idx, line, &mut new_findings);
    }
    const LOOKBACK: usize = 3;
    for f in new_findings {
        let cur = lines.get(f.line - 1).copied().unwrap_or("");
        let mut allowed = cur.contains(CIRCLE_ALLOW_MARKER);
        if !allowed && f.line >= 2 {
            let mut found = 0usize;
            let mut k = f.line - 2;
            loop {
                let l = lines.get(k).copied().unwrap_or("");
                if !l.trim().is_empty() {
                    if l.contains(CIRCLE_ALLOW_MARKER) {
                        allowed = true;
                        break;
                    }
                    found += 1;
                    if found >= LOOKBACK {
                        break;
                    }
                }
                if k == 0 {
                    break;
                }
                k -= 1;
            }
        }
        if !allowed {
            out.push(f);
        }
    }
}

fn is_allowed_path(path: &Path) -> bool {
    let s = path.to_string_lossy().to_ascii_lowercase();
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let lower = name.to_ascii_lowercase();
        if lower.starts_with("changelog") {
            return true;
        }
        // Allow this very file to talk about the forbidden names without
        // flagging itself.
        if lower == "circle_rules.rs" {
            return true;
        }
        // Other drift scanners discuss the forbidden field name in their
        // own rule messages.
        if lower == "round23_rules.rs" || lower == "literal_scanner.rs" {
            return true;
        }
    }
    [
        "/changelog/",
        "\\changelog\\",
        "/legacy_negative/",
        "\\legacy_negative\\",
        "/legacy_migration/",
        "\\legacy_migration\\",
        "/migrations/",
        "\\migrations\\",
        "/interop_matrix/",
        "\\interop_matrix\\",
        "/compat/",
        "\\compat\\",
    ]
    .iter()
    .any(|needle| s.contains(needle))
}

// ── Rule 1: discussion_realm_ref hard-removal ───────────────────────────────

fn scan_discussion_realm_ref(
    path: &Path,
    line_idx: usize,
    line: &str,
    out: &mut Vec<CircleFinding>,
) {
    let token = "discussion_realm_ref";
    if let Some(col) = find_literal_token(line, token) {
        out.push(CircleFinding {
            path: path.to_path_buf(),
            line: line_idx + 1,
            column: col + 1,
            rule: CircleRule::DiscussionRealmRef,
            matched_literal: token.to_string(),
            message: format!(
                "`{token}` is hard-removed by CXP-0007 (contrix-spec 2b0d70d). \
                 Replacement: `scope_circle_id` (typed `cx:circle:<uuidv7>`). \
                 The legacy field MUST NOT appear in any wire payload, \
                 fixture, or schema literal."
            ),
        });
    }
}

// ── Rule 2: `cx.circle.*` event-kind / capability-action allowlist ──────────

fn scan_circle_dotted_string(
    path: &Path,
    line_idx: usize,
    line: &str,
    out: &mut Vec<CircleFinding>,
) {
    // Find every occurrence of `cx.circle.` and extract the following
    // dotted-identifier tail until a non-identifier-non-dot char or quote.
    let needle = "cx.circle.";
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] != needle.as_bytes() {
            i += 1;
            continue;
        }
        // Boundary check: prev byte must not be an ident byte (so
        // `foo_cx.circle.create` doesn't match).
        let prev_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
        if !prev_ok {
            i += needle.len();
            continue;
        }
        let tail_start = i + needle.len();
        let mut j = tail_start;
        while j < bytes.len() {
            let b = bytes[j];
            if is_ident_byte(b) || b == b'.' {
                j += 1;
            } else {
                break;
            }
        }
        let tail = std::str::from_utf8(&bytes[tail_start..j]).unwrap_or("");
        if tail.is_empty() {
            i = j.max(i + 1);
            continue;
        }
        // Skip when the tail ends with a trailing `.` (likely a sentence
        // fragment in prose like "the `cx.circle.` family"). Trim trailing
        // dots before checking.
        let tail_trimmed = tail.trim_end_matches('.');
        if tail_trimmed.is_empty() {
            i = j.max(i + 1);
            continue;
        }
        let full = format!("cx.circle.{tail_trimmed}");
        let on_event_allowlist = CIRCLE_EVENT_KINDS.contains(&full.as_str());
        let on_capability_allowlist = CIRCLE_CAPABILITY_ACTIONS.contains(&full.as_str());
        if !(on_event_allowlist || on_capability_allowlist) {
            out.push(CircleFinding {
                path: path.to_path_buf(),
                line: line_idx + 1,
                column: i + 1,
                rule: CircleRule::UnknownCircleEventKind,
                matched_literal: full,
                message: format!(
                    "Unknown `cx.circle.*` identifier — not in the CXP-0007 \
                     allowlist of {event_n} event kinds or {cap_n} capability \
                     actions. Suppress with a `{CIRCLE_ALLOW_MARKER}` marker \
                     comment when the literal is a known scanner test or \
                     migration note.",
                    event_n = CIRCLE_EVENT_KINDS.len(),
                    cap_n = CIRCLE_CAPABILITY_ACTIONS.len(),
                ),
            });
        }
        i = j.max(i + 1);
    }
}

// ── Rule 3: EffectiveScope::Circle envelopes MUST carry circle_id ───────────

fn scan_effective_scope_circle(
    path: &Path,
    line_idx: usize,
    line: &str,
    out: &mut Vec<CircleFinding>,
) {
    // Heuristic: a line that mentions the Circle scope variant — either as
    // the Rust enum literal `EffectiveScope::Circle` or as the JSON
    // discriminator `"kind": "circle"` — should also visibly reference a
    // `circle_id` on the same line.
    let mentions_rust = line.contains("EffectiveScope::Circle");
    let mentions_json =
        line.contains("\"kind\": \"circle\"") || line.contains("\"kind\":\"circle\"");
    if !(mentions_rust || mentions_json) {
        return;
    }
    if line.contains("circle_id") {
        return;
    }
    let col = if mentions_rust {
        line.find("EffectiveScope::Circle").unwrap_or(0)
    } else {
        line.find("\"kind\"").unwrap_or(0)
    };
    out.push(CircleFinding {
        path: path.to_path_buf(),
        line: line_idx + 1,
        column: col + 1,
        rule: CircleRule::EffectiveScopeCircleMissingId,
        matched_literal: if mentions_rust {
            "EffectiveScope::Circle".to_string()
        } else {
            "\"kind\":\"circle\"".to_string()
        },
        message: format!(
            "`EffectiveScope::Circle` requires both `realm_id` and \
             `circle_id` (schemas/event-envelope.schema.json `$defs.effective_scope`); \
             this line names the Circle variant but does not visibly bind \
             `circle_id`. Suppress with `{CIRCLE_ALLOW_MARKER}` if the \
             binding lives on an adjacent line."
        ),
    });
}

// ── Rule 4: confidential_discussion_of endpoints MUST be cx:flow: ids ───────

fn scan_confidential_discussion_relation(
    path: &Path,
    line_idx: usize,
    line: &str,
    out: &mut Vec<CircleFinding>,
) {
    // Heuristic: a line that mentions `ConfidentialDiscussionOf` (Rust)
    // OR `"confidential_discussion_of"` (JSON) should — when it also
    // contains a Contrix typed-id literal — only reference `cx:flow:` ids
    // for that Relation's from/to. Any non-flow `cx:<kind>:` literal on
    // the same line is a violation.
    let mentions = line.contains("ConfidentialDiscussionOf")
        || line.contains("\"confidential_discussion_of\"");
    if !mentions {
        return;
    }
    // Bail when no typed-id literal is visible (e.g. doc-comment line).
    let needle = "cx:";
    let mut i = 0usize;
    let bytes = line.as_bytes();
    let mut bad: Option<String> = None;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] != needle.as_bytes() {
            i += 1;
            continue;
        }
        // Read the kind segment between the first and second `:`.
        let kind_start = i + needle.len();
        let mut j = kind_start;
        while j < bytes.len() && bytes[j] != b':' && bytes[j] != b'"' && bytes[j] != b' ' {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b':' {
            let kind = std::str::from_utf8(&bytes[kind_start..j]).unwrap_or("");
            if !kind.is_empty() && kind != "flow" {
                bad = Some(kind.to_string());
                break;
            }
        }
        i = (j + 1).max(i + 1);
    }
    if let Some(kind) = bad {
        let col = line.find("cx:").unwrap_or(0);
        out.push(CircleFinding {
            path: path.to_path_buf(),
            line: line_idx + 1,
            column: col + 1,
            rule: CircleRule::ConfidentialDiscussionEndpointsNotFlow,
            matched_literal: format!("cx:{kind}:"),
            message: format!(
                "`ConfidentialDiscussionOf` Relation endpoints (from / to) \
                 MUST both be `cx:flow:` ids; saw `cx:{kind}:` on the same \
                 line. See `contrix_core::model::primitives::Relation::\
                 ConfidentialDiscussionOf`."
            ),
        });
    }
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn find_literal_token(line: &str, token: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let tlen = token.len();
    if tlen == 0 || bytes.len() < tlen {
        return None;
    }
    let mut i = 0;
    while i + tlen <= bytes.len() {
        if &bytes[i..i + tlen] == token.as_bytes() {
            let prev_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
            let next = bytes.get(i + tlen).copied();
            let next_ok = match next {
                None => true,
                Some(b) => !is_ident_byte(b),
            };
            if prev_ok && next_ok {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(text: &str) -> Vec<CircleFinding> {
        let mut out = vec![];
        // Use a `.rs` path that is NOT one of the allowed scanner sources.
        scan_circle(Path::new("src/foo.rs"), text, &mut out);
        out
    }

    #[test]
    fn flags_discussion_realm_ref_in_json_literal() {
        let f = scan(r#"let payload = json!({"discussion_realm_ref": "x"});"#);
        assert!(
            f.iter().any(|r| r.rule == CircleRule::DiscussionRealmRef),
            "expected DiscussionRealmRef finding, got {f:?}",
        );
    }

    #[test]
    fn allows_known_circle_event_kind() {
        let f = scan(r#"const KIND: &str = "cx.circle.member.state";"#);
        assert!(
            f.iter()
                .all(|r| r.rule != CircleRule::UnknownCircleEventKind),
            "did not expect UnknownCircleEventKind, got {f:?}",
        );
    }

    #[test]
    fn flags_unknown_circle_event_kind() {
        let f = scan(r#"const KIND: &str = "cx.circle.bogus.action";"#);
        assert!(
            f.iter()
                .any(|r| r.rule == CircleRule::UnknownCircleEventKind),
            "expected UnknownCircleEventKind, got {f:?}",
        );
    }

    #[test]
    fn allows_known_capability_action() {
        let f = scan(r#"let cap = "cx.circle.member.add.others";"#);
        assert!(
            f.iter()
                .all(|r| r.rule != CircleRule::UnknownCircleEventKind),
            "did not expect UnknownCircleEventKind, got {f:?}",
        );
    }

    #[test]
    fn marker_comment_suppresses_finding() {
        // CIRCLE-ALLOW: scanner self-test asserts marker suppression.
        let text =
            "// CIRCLE-ALLOW: documenting the forbidden field\nlet x = \"discussion_realm_ref\";";
        let f = scan(text);
        assert!(
            f.iter().all(|r| r.rule != CircleRule::DiscussionRealmRef),
            "expected marker to suppress finding, got {f:?}",
        );
    }

    #[test]
    fn reason_code_list_is_six() {
        // CIRCLE-ALLOW: documenting the canonical CXP-0007 count.
        assert_eq!(
            CIRCLE_REASON_CODES.len(),
            6,
            "CXP-0007 advertises exactly six reason codes (5 sub + 1 top-level)",
        );
    }

    #[test]
    fn event_kinds_match_sdk_count() {
        // CIRCLE-ALLOW: documenting the canonical CXP-0007 count.
        assert_eq!(
            CIRCLE_EVENT_KINDS.len(),
            7,
            "CXP-0007 introduces exactly 7 cx.circle.* event kinds",
        );
    }

    #[test]
    fn capability_actions_match_sdk_count() {
        // CIRCLE-ALLOW: documenting the canonical CXP-0007 count.
        assert_eq!(
            CIRCLE_CAPABILITY_ACTIONS.len(),
            6,
            "CXP-0007 introduces exactly 6 cx.circle.* capability actions",
        );
    }

    #[test]
    fn flags_effective_scope_circle_without_id() {
        let f = scan(r#"let scope = EffectiveScope::Circle { realm_id };"#);
        assert!(
            f.iter()
                .any(|r| r.rule == CircleRule::EffectiveScopeCircleMissingId),
            "expected EffectiveScopeCircleMissingId, got {f:?}",
        );
    }

    #[test]
    fn allows_effective_scope_circle_with_id() {
        let f = scan(r#"EffectiveScope::Circle { realm_id, circle_id }"#);
        assert!(
            f.iter()
                .all(|r| r.rule != CircleRule::EffectiveScopeCircleMissingId),
            "did not expect EffectiveScopeCircleMissingId, got {f:?}",
        );
    }

    #[test]
    fn flags_confidential_discussion_with_realm_id() {
        let f = scan(
            r#"add_relation(Relation::ConfidentialDiscussionOf, "cx:realm:abc", "cx:flow:def");"#,
        );
        assert!(
            f.iter()
                .any(|r| r.rule == CircleRule::ConfidentialDiscussionEndpointsNotFlow),
            "expected ConfidentialDiscussionEndpointsNotFlow, got {f:?}",
        );
    }

    #[test]
    fn allows_confidential_discussion_with_two_flows() {
        let f =
            scan(r#"add_relation(Relation::ConfidentialDiscussionOf, "cx:flow:a", "cx:flow:b");"#);
        assert!(
            f.iter()
                .all(|r| r.rule != CircleRule::ConfidentialDiscussionEndpointsNotFlow),
            "did not expect ConfidentialDiscussionEndpointsNotFlow, got {f:?}",
        );
    }
}
