//! Repo-level structural drift rules introduced by contrix-spec round 2+3
//! (commit `8b7978d spec: round 2+3 cleanup`).
//!
//! The existing [`crate::literal_scanner`] handles identifier-level drift
//! (removed event kinds, forbidden wire fields, renames). Round 2+3 added
//! a handful of **structural** drift rules that don't fit the
//! "identifier appeared in source" shape — they require looking at *where*
//! a literal appears, *which kind* it is, or *what range* a numeric value
//! falls into. Those are handled here:
//!
//! * **Receipt object/event split (T23)**: `cx.event_batch_receipt` is an
//!   object-only kind. If it appears as `Event.kind` (i.e. in the
//!   `cx.events.submit` payload), report a violation.
//!
//! * **Durable/ephemeral envelope split (T02)**: 12 `wire_scope=ephemeral_event`
//!   kinds (`cx.call.signal`, `cx.presence`, `cx.typing`, `cx.receipt.read`,
//!   `cx.key.verification.*`) MUST NOT be durable events. If any appears in
//!   a `cx.events.submit` payload literal, report a violation.
//!
//! * **`relaxed_window_max_ms` hard ceiling (T09)**: the absolute hard
//!   ceiling is 300_000 ms. Any literal `relaxed_window_max_ms` assignment
//!   above 300_000 in `policy_components` is a violation.
//!
//! * **Cursor handle entropy floor (T03)**: `h.minLength` is now 22. Any
//!   cursor handle literal `h: "..."` shorter than 22 chars matching the
//!   base64url-ish pattern is a violation.
//!
//! These rules don't drive `cx.events.submit` semantics directly — they're
//! lint-style protections against drift in downstream code that copies the
//! spec by example. The detection is heuristic but conservative (false
//! negatives are acceptable; false positives must remain rare).

use std::path::{Path, PathBuf};

use serde::Serialize;

/// Twelve event kinds that — as of round 3 (T02) — are *ephemeral only*.
/// They MUST NOT be submitted via `cx.events.submit` as durable events.
pub const EPHEMERAL_ONLY_KINDS: &[&str] = &[
    "cx.call.signal",
    "cx.presence",
    "cx.typing",
    "cx.receipt.read",
    "cx.key.verification.start",
    "cx.key.verification.ready",
    "cx.key.verification.accept",
    "cx.key.verification.key",
    "cx.key.verification.mac",
    "cx.key.verification.done",
    "cx.key.verification.cancel",
    "cx.key.verification.request",
];

/// Object-only kinds that MUST NOT appear as durable `Event.kind`.
pub const OBJECT_ONLY_KINDS: &[&str] = &["cx.event_batch_receipt"];

/// Hard ceiling for `relaxed_window_max_ms` (T09).
pub const RELAXED_WINDOW_MAX_MS_CEILING: u64 = 300_000;

/// Minimum cursor handle length (T03 — `h.minLength` raised 16 → 22).
pub const CURSOR_HANDLE_MIN_LEN: usize = 22;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Round23Rule {
    ObjectOnlyKindAsEventKind,
    EphemeralKindAsDurableEvent,
    RelaxedWindowExceedsCeiling,
    CursorHandleBelowEntropyFloor,
    ForbiddenWireField,
}

impl Round23Rule {
    pub fn as_str(self) -> &'static str {
        match self {
            Round23Rule::ObjectOnlyKindAsEventKind => "object_only_kind_as_event_kind",
            Round23Rule::EphemeralKindAsDurableEvent => "ephemeral_kind_as_durable_event",
            Round23Rule::RelaxedWindowExceedsCeiling => "relaxed_window_exceeds_ceiling",
            Round23Rule::CursorHandleBelowEntropyFloor => "cursor_handle_below_entropy_floor",
            Round23Rule::ForbiddenWireField => "forbidden_wire_field",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Round23Finding {
    pub path: PathBuf,
    pub line: usize,
    pub column: usize,
    pub rule: Round23Rule,
    pub matched_literal: String,
    pub message: String,
}

/// Scan a single file's contents for round 2+3 structural drift.
///
/// Append findings to `out`. Skips files whose path matches a known
/// migration / changelog / interop_matrix glob so legacy snapshots and
/// migration helpers don't trip the linter.
pub fn scan_round23(path: &Path, contents: &str, out: &mut Vec<Round23Finding>) {
    if is_allowed_path(path) {
        return;
    }
    for (line_idx, raw_line) in contents.lines().enumerate() {
        scan_object_only_kind(path, line_idx, raw_line, out);
        scan_ephemeral_kind(path, line_idx, raw_line, out);
        scan_relaxed_window(path, line_idx, raw_line, out);
        scan_cursor_handle(path, line_idx, raw_line, out);
        scan_discussion_space_ref(path, line_idx, raw_line, out);
    }
}

fn is_allowed_path(path: &Path) -> bool {
    let s = path.to_string_lossy().to_ascii_lowercase();
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if name.to_ascii_lowercase().starts_with("changelog") {
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

// ── T23: object-only kind as Event.kind ─────────────────────────────────────

fn scan_object_only_kind(
    path: &Path,
    line_idx: usize,
    line: &str,
    out: &mut Vec<Round23Finding>,
) {
    for kind in OBJECT_ONLY_KINDS {
        // Heuristic: a literal `cx.event_batch_receipt` inside a context
        // that *looks like* an Event.kind assignment. We flag any time
        // the literal appears together with `kind` (case-insensitive) on
        // the same line, or together with `"kind":` JSON shape, or inside
        // a `cx.events.submit` literal in the file path.
        if let Some(col) = find_literal_token(line, kind) {
            let lower = line.to_ascii_lowercase();
            let looks_like_kind_position = lower.contains("kind")
                || lower.contains("event.kind")
                || lower.contains("\"kind\":")
                || lower.contains("events.submit");
            if looks_like_kind_position {
                out.push(Round23Finding {
                    path: path.to_path_buf(),
                    line: line_idx + 1,
                    column: col + 1,
                    rule: Round23Rule::ObjectOnlyKindAsEventKind,
                    matched_literal: (*kind).to_string(),
                    message: format!(
                        "`{kind}` is object-only (round 2+3 T23); MUST NOT appear as Event.kind"
                    ),
                });
            }
        }
    }
}

// ── T02: ephemeral kind as durable Event ────────────────────────────────────

fn scan_ephemeral_kind(
    path: &Path,
    line_idx: usize,
    line: &str,
    out: &mut Vec<Round23Finding>,
) {
    for kind in EPHEMERAL_ONLY_KINDS {
        if let Some(col) = find_literal_token(line, kind) {
            let lower = line.to_ascii_lowercase();
            // Surface when the literal appears together with `events.submit`,
            // `Event.kind`, or `cx.events.submit` on the same line.
            let looks_durable_submit = lower.contains("events.submit")
                || lower.contains("cx.events.submit")
                || lower.contains("event.kind")
                || (lower.contains("\"kind\":") && !lower.contains("ephemeral"));
            if looks_durable_submit {
                out.push(Round23Finding {
                    path: path.to_path_buf(),
                    line: line_idx + 1,
                    column: col + 1,
                    rule: Round23Rule::EphemeralKindAsDurableEvent,
                    matched_literal: (*kind).to_string(),
                    message: format!(
                        "`{kind}` is `wire_scope=ephemeral_event` (round 2+3 T02); \
                         MUST NOT be submitted via `cx.events.submit` as a durable Event. \
                         Use `cx.schema.ephemeral_envelope.v1` (broadcast) or \
                         `cx.schema.device_message.v1` (point-to-point)."
                    ),
                });
            }
        }
    }
}

// ── T09: relaxed_window_max_ms ceiling ──────────────────────────────────────

fn scan_relaxed_window(
    path: &Path,
    line_idx: usize,
    line: &str,
    out: &mut Vec<Round23Finding>,
) {
    // Match the field-name token then look for a numeric literal in the
    // remainder of the line. We accept `=`, `:`, and `=>` separators so we
    // cover both Rust struct init and JSON/YAML shapes.
    let token = "relaxed_window_max_ms";
    let Some(idx) = line.find(token) else { return };
    let rest = &line[idx + token.len()..];
    // Try to pull the first integer literal after the separator.
    let mut number = String::new();
    let mut saw_separator = false;
    for ch in rest.chars() {
        if !saw_separator {
            if matches!(ch, '=' | ':' | '>' | ' ' | '\t' | '"') {
                saw_separator |= matches!(ch, '=' | ':');
                continue;
            }
            // Some other char before separator — abort.
            if !ch.is_ascii_whitespace() {
                break;
            }
        } else if ch.is_ascii_digit() || ch == '_' {
            number.push(ch);
        } else if !number.is_empty() {
            break;
        } else if !ch.is_ascii_whitespace() && ch != '"' {
            break;
        }
    }
    if number.is_empty() {
        return;
    }
    let cleaned: String = number.chars().filter(|c| *c != '_').collect();
    if let Ok(value) = cleaned.parse::<u64>() {
        if value > RELAXED_WINDOW_MAX_MS_CEILING {
            out.push(Round23Finding {
                path: path.to_path_buf(),
                line: line_idx + 1,
                column: idx + 1,
                rule: Round23Rule::RelaxedWindowExceedsCeiling,
                matched_literal: format!("relaxed_window_max_ms={value}"),
                message: format!(
                    "`relaxed_window_max_ms={value}` exceeds round 2+3 T09 hard ceiling \
                     {RELAXED_WINDOW_MAX_MS_CEILING}; reducer MUST reject with \
                     `relaxed_window_exceeds_ceiling`."
                ),
            });
        }
    }
}

// ── T03: cursor handle entropy floor ────────────────────────────────────────

fn scan_cursor_handle(
    path: &Path,
    line_idx: usize,
    line: &str,
    out: &mut Vec<Round23Finding>,
) {
    // Heuristic: look for `"h":"..."` or `h = "..."` shaped literals. The
    // handle should be ≥22 chars of base64url-ish alphabet. We only flag
    // when the value looks deliberately structured as a handle (we don't
    // want to flag arbitrary `h="x"` debug code).
    //
    // We accept: starts with letter/digit/+/-, contains only base64url
    // alphabet [A-Za-z0-9_-], length is between 6 and 21 (i.e. plausibly
    // a handle but below the floor).
    let candidates = extract_cursor_handle_candidates(line);
    for (col, handle) in candidates {
        if handle.len() >= CURSOR_HANDLE_MIN_LEN {
            continue;
        }
        if handle.len() < 6 {
            // Too short to plausibly be a handle; skip noise.
            continue;
        }
        if !handle
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            continue;
        }
        out.push(Round23Finding {
            path: path.to_path_buf(),
            line: line_idx + 1,
            column: col + 1,
            rule: Round23Rule::CursorHandleBelowEntropyFloor,
            matched_literal: handle.clone(),
            message: format!(
                "cursor handle literal `{handle}` is {} chars; round 2+3 T03 raised \
                 `h.minLength` to {CURSOR_HANDLE_MIN_LEN}.",
                handle.len()
            ),
        });
    }
}

fn extract_cursor_handle_candidates(line: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    // Look for `"h":"..."` JSON shape.
    let needle = "\"h\":\"";
    let mut start = 0usize;
    while let Some(pos) = line[start..].find(needle) {
        let abs = start + pos + needle.len();
        if let Some(end_rel) = line[abs..].find('"') {
            let handle = &line[abs..abs + end_rel];
            out.push((abs, handle.to_string()));
            start = abs + end_rel + 1;
        } else {
            break;
        }
    }
    out
}

// ── Forbidden wire field: discussion_space_ref ──────────────────────────────

fn scan_discussion_space_ref(
    path: &Path,
    line_idx: usize,
    line: &str,
    out: &mut Vec<Round23Finding>,
) {
    let token = "discussion_space_ref";
    if let Some(col) = find_literal_token(line, token) {
        out.push(Round23Finding {
            path: path.to_path_buf(),
            line: line_idx + 1,
            column: col + 1,
            rule: Round23Rule::ForbiddenWireField,
            matched_literal: token.to_string(),
            message: format!(
                "`{token}` is forbidden on the round 2+3 wire (Realm/Space inversion); \
                 use `discussion_realm_ref`."
            ),
        });
    }
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

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_event_batch_receipt_as_event_kind() {
        let mut out = vec![];
        scan_round23(
            Path::new("src/foo.rs"),
            r#"let kind = "cx.event_batch_receipt";"#,
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule, Round23Rule::ObjectOnlyKindAsEventKind);
    }

    #[test]
    fn flags_ephemeral_kind_in_events_submit() {
        let mut out = vec![];
        scan_round23(
            Path::new("src/foo.rs"),
            r#"client.cx.events.submit(&[Event{ kind: "cx.presence", ... }]);"#,
            &mut out,
        );
        assert!(
            out.iter()
                .any(|f| f.rule == Round23Rule::EphemeralKindAsDurableEvent)
        );
    }

    #[test]
    fn flags_relaxed_window_over_ceiling() {
        let mut out = vec![];
        scan_round23(
            Path::new("src/policy.rs"),
            r#"relaxed_window_max_ms: 400_000,"#,
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule, Round23Rule::RelaxedWindowExceedsCeiling);
    }

    #[test]
    fn does_not_flag_relaxed_window_at_ceiling() {
        let mut out = vec![];
        scan_round23(
            Path::new("src/policy.rs"),
            r#"relaxed_window_max_ms = 300000,"#,
            &mut out,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn flags_short_cursor_handle() {
        let mut out = vec![];
        scan_round23(
            Path::new("src/cursor.rs"),
            "let blob = r##\"{\"h\":\"shortx12\",\"x\":1,\"v\":\"1\"}\"##;",
            &mut out,
        );
        assert!(
            out.iter()
                .any(|f| f.rule == Round23Rule::CursorHandleBelowEntropyFloor)
        );
    }

    #[test]
    fn does_not_flag_full_length_cursor_handle() {
        let mut out = vec![];
        scan_round23(
            Path::new("src/cursor.rs"),
            "\"h\":\"aaaaaaaaaaaaaaaaaaaaaaaa\"",
            &mut out,
        );
        assert!(
            !out.iter()
                .any(|f| f.rule == Round23Rule::CursorHandleBelowEntropyFloor)
        );
    }

    #[test]
    fn flags_discussion_space_ref() {
        let mut out = vec![];
        scan_round23(
            Path::new("src/wire.rs"),
            "let json = r##\"{\"discussion_space_ref\":\"cx:realm:...\"}\"##;",
            &mut out,
        );
        assert!(out.iter().any(|f| f.rule == Round23Rule::ForbiddenWireField));
    }

    #[test]
    fn changelog_path_is_skipped() {
        let mut out = vec![];
        scan_round23(
            Path::new("CHANGELOG.md"),
            "Removed cx.event_batch_receipt as Event.kind.",
            &mut out,
        );
        assert!(out.is_empty());
    }
}
