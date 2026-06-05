//! Repo-level structural protocol-drift lint rules.
//!
//! The existing [`crate::literal_scanner`] handles identifier-level drift
//! (removed event kinds, forbidden wire fields, renames). This module adds
//! the structural drift rules that don't fit the "identifier appeared in
//! source" shape — they require looking at *where* a literal appears,
//! *which kind* it is, or *what range* a numeric value falls into.
//!
//! Rules are grouped below by the protocol surface they guard. They are
//! intentionally conservative (false negatives are acceptable; false
//! positives must remain rare). Spec-side counterparts live in
//! `cokret-spec/tools/lint_artifacts.py::check_*`.
//!
//! ## DID method segment
//! * **`LegacyDidMethodSegment`** — DID strings whose method-name segment (between `did:` and the
//!   next `:`) contains any of `.`, `-`, `_`. Spec tightened the regex to `^did:[a-z0-9]+:[^\s]+$`.
//!
//! ## events.subscribe payload typing
//! * **`EventsSubscribeStringPayload`** — the payload of `ck.self.events.subscribe` is now the
//!   typed `EventsSubscribeFrame` object; any literal where the payload is declared as / typed as
//!   `string` (or `String` / `&str`) is a violation.
//!
//! ## cross_signing.publish CAS
//! * **`CrossSigningPublishMissingExpectedPreviousGeneration`** — a `ck.cross_signing.publish`
//!   payload constructed inline without a visible `expected_previous_generation` field.
//!
//! ## audit policy digest arity
//! * **`AuditPolicyVersionHashFewerThanFourArguments`** — calls to
//!   `compute_audit_policy_version_digest(...)` whose argument list has fewer than 4 arguments.
//!
//! ## event-kind envelope split
//! * **`ObjectOnlyKindAsEventKind`** — `ck.event_batch_receipt` is object-only; if it appears as
//!   `Event.kind` it is a violation.
//! * **`EphemeralKindAsDurableEvent`** — 12 `wire_scope=ephemeral_event` kinds MUST NOT be durable
//!   events.
//!
//! ## policy window ceiling
//! * **`RelaxedWindowExceedsCeiling`** — any literal `relaxed_window_max_ms` above 300_000 ms.
//!
//! ## cursor handle entropy + forbidden wire field
//! * **`CursorHandleBelowEntropyFloor`** — cursor handle literals shorter than 22 chars.
//! * **`ForbiddenWireField`** — the hard-removed `discussion_space_ref` / `discussion_realm_ref`.
//!
//! A source line (or one of the prior few non-blank lines) carrying the
//! [`PROTOCOL_DRIFT_ALLOW_MARKER`] suppresses a finding — for fixtures and
//! negative tests that intentionally exercise a pre-tightening shape.

use std::path::{Path, PathBuf};

use serde::Serialize;

/// New DID method-segment regex. Pinned here so a drift produces a visible
/// diff. The scanner does not run regex — it does a structural
/// per-character check — but the pin keeps the spec reference live.
pub const DID_METHOD_SEGMENT_REGEX: &str = r"^did:[a-z0-9]+:[^\s]+$";

/// Twelve event kinds that are *ephemeral only* — they MUST NOT be
/// submitted via `ck.self.events.submit` as durable events.
pub const EPHEMERAL_ONLY_KINDS: &[&str] = &[
    "ck.call.signal",
    "ck.presence",
    "ck.typing",
    "ck.receipt.read",
    "ck.key.verification.start",
    "ck.key.verification.ready",
    "ck.key.verification.accept",
    "ck.key.verification.key",
    "ck.key.verification.mac",
    "ck.key.verification.done",
    "ck.key.verification.cancel",
    "ck.key.verification.request",
];

/// Object-only kinds that MUST NOT appear as durable `Event.kind`.
pub const OBJECT_ONLY_KINDS: &[&str] = &["ck.event_batch_receipt"];

/// Hard ceiling for `relaxed_window_max_ms`.
pub const RELAXED_WINDOW_MAX_MS_CEILING: u64 = 300_000;

/// Minimum cursor handle length (`h.minLength` raised 16 → 22).
pub const CURSOR_HANDLE_MIN_LEN: usize = 22;

/// Marker comment that a source line intentionally exercises a
/// pre-tightening wire shape (e.g. a negative regex test asserting that the
/// old form is rejected). When the marker appears on the same line as a
/// finding *or* on one of the immediately preceding non-blank lines, the
/// scanner suppresses the finding.
pub const PROTOCOL_DRIFT_ALLOW_MARKER: &str = "DRIFT-ALLOW";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolDriftRule {
    LegacyDidMethodSegment,
    EventsSubscribeStringPayload,
    CrossSigningPublishMissingExpectedPreviousGeneration,
    AuditPolicyVersionHashFewerThanFourArguments,
    ObjectOnlyKindAsEventKind,
    EphemeralKindAsDurableEvent,
    RelaxedWindowExceedsCeiling,
    CursorHandleBelowEntropyFloor,
    ForbiddenWireField,
}

impl ProtocolDriftRule {
    pub fn as_str(self) -> &'static str {
        match self {
            ProtocolDriftRule::LegacyDidMethodSegment => "legacy_did_method_segment",
            ProtocolDriftRule::EventsSubscribeStringPayload => "events_subscribe_string_payload",
            ProtocolDriftRule::CrossSigningPublishMissingExpectedPreviousGeneration => {
                "cross_signing_publish_missing_expected_previous_generation"
            }
            ProtocolDriftRule::AuditPolicyVersionHashFewerThanFourArguments => {
                "audit_policy_version_digest_fewer_than_four_arguments"
            }
            ProtocolDriftRule::ObjectOnlyKindAsEventKind => "object_only_kind_as_event_kind",
            ProtocolDriftRule::EphemeralKindAsDurableEvent => "ephemeral_kind_as_durable_event",
            ProtocolDriftRule::RelaxedWindowExceedsCeiling => "relaxed_window_exceeds_ceiling",
            ProtocolDriftRule::CursorHandleBelowEntropyFloor => "cursor_handle_below_entropy_floor",
            ProtocolDriftRule::ForbiddenWireField => "forbidden_wire_field",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ProtocolDriftFinding {
    pub path: PathBuf,
    pub line: usize,
    pub column: usize,
    pub rule: ProtocolDriftRule,
    pub matched_literal: String,
    pub message: String,
}

/// Walk `path` line-by-line and emit findings for every protocol-drift
/// rule, then suppress any finding whose line — or one of the prior
/// `LOOKBACK` non-blank lines — carries the [`PROTOCOL_DRIFT_ALLOW_MARKER`].
pub fn scan_protocol_drift(path: &Path, contents: &str, out: &mut Vec<ProtocolDriftFinding>) {
    if is_allowed_path(path) {
        return;
    }
    let lines: Vec<&str> = contents.lines().collect();
    let mut new_findings: Vec<ProtocolDriftFinding> = Vec::new();
    for (line_idx, line) in lines.iter().enumerate() {
        scan_legacy_did(path, line_idx, line, &mut new_findings);
        scan_events_subscribe_string_payload(path, line_idx, line, &mut new_findings);
        scan_cross_signing_publish_payload(path, line_idx, line, &mut new_findings);
        scan_audit_policy_version_digest_call(path, line_idx, line, &mut new_findings);
        scan_object_only_kind(path, line_idx, line, &mut new_findings);
        scan_ephemeral_kind(path, line_idx, line, &mut new_findings);
        scan_relaxed_window(path, line_idx, line, &mut new_findings);
        scan_cursor_handle(path, line_idx, line, &mut new_findings);
        scan_discussion_space_ref(path, line_idx, line, &mut new_findings);
    }
    const LOOKBACK: usize = 3;
    for f in new_findings {
        let cur = lines.get(f.line - 1).copied().unwrap_or("");
        let mut allowed = cur.contains(PROTOCOL_DRIFT_ALLOW_MARKER);
        if !allowed && f.line >= 2 {
            let mut found = 0usize;
            let mut k = f.line - 2;
            loop {
                let l = lines.get(k).copied().unwrap_or("");
                if !l.trim().is_empty() {
                    if l.contains(PROTOCOL_DRIFT_ALLOW_MARKER) {
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

// ── DID method segment ───────────────────────────────────────────────────

fn scan_legacy_did(path: &Path, line_idx: usize, line: &str, out: &mut Vec<ProtocolDriftFinding>) {
    let bytes = line.as_bytes();
    let needle = b"did:";
    let mut i = 0usize;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] != needle {
            i += 1;
            continue;
        }
        let prev_ok = i == 0
            || matches!(
                bytes[i - 1],
                b'"' | b'\''
                    | b'('
                    | b'['
                    | b' '
                    | b'\t'
                    | b'`'
                    | b','
                    | b'='
                    | b'>'
                    | b'/'
                    | b'#'
                    | b'{'
                    | b'\\'
                    | b':'
                    | b'+'
            );
        if !prev_ok {
            i += 1;
            continue;
        }
        let method_start = i + needle.len();
        let mut j = method_start;
        let mut saw_terminator = false;
        let mut violation_char: Option<u8> = None;
        while j < bytes.len() {
            let b = bytes[j];
            if b == b':' {
                saw_terminator = true;
                break;
            }
            if !(b.is_ascii_lowercase() || b.is_ascii_digit()) {
                if matches!(b, b'.' | b'-' | b'_') {
                    violation_char = Some(b);
                } else {
                    break;
                }
            }
            j += 1;
        }
        if let (true, Some(v_char)) = (saw_terminator, violation_char) {
            let method = std::str::from_utf8(&bytes[method_start..j]).unwrap_or("?");
            out.push(ProtocolDriftFinding {
                path: path.to_path_buf(),
                line: line_idx + 1,
                column: i + 1,
                rule: ProtocolDriftRule::LegacyDidMethodSegment,
                matched_literal: format!("did:{method}:"),
                message: format!(
                    "DID method-name segment `{method}` contains a forbidden char \
                     ({:?}); spec tightened the regex to `{DID_METHOD_SEGMENT_REGEX}` \
                     (method segment is lowercase-alphanumeric only).",
                    v_char as char,
                ),
            });
            i = j + 1;
            continue;
        }
        i = method_start;
    }
}

// ── events.subscribe payload typed as string ─────────────────────────────
// DRIFT-ALLOW: section header comment

fn scan_events_subscribe_string_payload(
    path: &Path,
    line_idx: usize,
    line: &str,
    out: &mut Vec<ProtocolDriftFinding>,
) {
    // DRIFT-ALLOW: this is the rule's own search token, not a payload declaration.
    let token = "ck.self.events.subscribe";
    let Some(col) = line.find(token) else { return };
    let lower = line.to_ascii_lowercase();
    let migration_phrase = lower.contains("no longer a string")
        || lower.contains("eventssubscribeframe")
        || lower.contains("must not be a string")
        || lower.contains("not a string");
    if migration_phrase {
        return;
    }
    let mentions_string_type = contains_type_token(line, "String")
        || contains_type_token(line, "string")
        || contains_type_token(line, "&str");
    if !mentions_string_type {
        return;
    }
    out.push(ProtocolDriftFinding {
        path: path.to_path_buf(),
        line: line_idx + 1,
        column: col + 1,
        rule: ProtocolDriftRule::EventsSubscribeStringPayload,
        matched_literal: token.to_string(),
        message: format!(
            "`{token}` payload is typed as a string on this line; spec requires the \
             typed `EventsSubscribeFrame {{ kind: <event|frontier|heartbeat\
             |catchup_complete|epoch_rotation|dropped|resync_required|unauthorized> }}`."
        ),
    });
}

fn contains_type_token(line: &str, token: &str) -> bool {
    let bytes = line.as_bytes();
    let tbytes = token.as_bytes();
    let tlen = tbytes.len();
    if tlen == 0 || bytes.len() < tlen {
        return false;
    }
    let mut i = 0;
    while i + tlen <= bytes.len() {
        if &bytes[i..i + tlen] == tbytes {
            let prev_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
            let next = bytes.get(i + tlen).copied();
            let next_ok = match next {
                None => true,
                Some(b) => !is_ident_byte(b),
            };
            if prev_ok && next_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

// ── cross_signing.publish payload missing expected_previous_generation ───

fn scan_cross_signing_publish_payload(
    path: &Path,
    line_idx: usize,
    line: &str,
    out: &mut Vec<ProtocolDriftFinding>,
) {
    // DRIFT-ALLOW: this is the rule's own search token, not a payload construction.
    let token = "ck.cross_signing.publish";
    let Some(col) = line.find(token) else { return };
    let lower = line.to_ascii_lowercase();
    let mentions_payload_shape = lower.contains("payload")
        || lower.contains("publish_payload")
        || lower.contains("crosssigningpublishpayload")
        || lower.contains("{ ")
        || lower.contains("={")
        || lower.contains(": {");
    if !mentions_payload_shape {
        return;
    }
    if line.contains("expected_previous_generation") {
        return;
    }
    out.push(ProtocolDriftFinding {
        path: path.to_path_buf(),
        line: line_idx + 1,
        column: col + 1,
        rule: ProtocolDriftRule::CrossSigningPublishMissingExpectedPreviousGeneration,
        matched_literal: token.to_string(),
        message: format!(
            "`{token}` payload constructed without `expected_previous_generation`; \
             spec made the CAS contract `(principal_id, expected_previous_generation)` \
             and the new field is REQUIRED. Old two-tuple form is a hard wire-break.",
        ),
    });
}

// ── compute_audit_policy_version_digest arity < 4 ────────────────────────

fn scan_audit_policy_version_digest_call(
    path: &Path,
    line_idx: usize,
    line: &str,
    out: &mut Vec<ProtocolDriftFinding>,
) {
    let token = "compute_audit_policy_version_digest";
    let Some(col) = line.find(token) else { return };
    let rest = &line[col + token.len()..];
    let Some(paren_idx_rel) = rest.find('(') else {
        return;
    };
    if !rest[..paren_idx_rel].chars().all(char::is_whitespace) {
        return;
    }
    let after_paren = &rest[paren_idx_rel + 1..];
    let mut depth = 1i32;
    let mut idx = 0usize;
    let mut group = String::new();
    for ch in after_paren.chars() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        group.push(ch);
        idx += ch.len_utf8();
        if idx > 4096 {
            return;
        }
    }
    if depth != 0 {
        return;
    }
    let arg_count = count_top_level_args(&group);
    if arg_count < 4 {
        out.push(ProtocolDriftFinding {
            path: path.to_path_buf(),
            line: line_idx + 1,
            column: col + 1,
            rule: ProtocolDriftRule::AuditPolicyVersionHashFewerThanFourArguments,
            matched_literal: format!("{token}({group})"),
            message: format!(
                "`{token}` called with {arg_count} argument(s); spec tightened the \
                 digest input to `(realm_id, trust_domain, audit_disclosure, \
                 audit_assurance)` — four arguments are REQUIRED. Old two-argument \
                 form is a hard wire-break.",
            ),
        });
    }
}

fn count_top_level_args(group: &str) -> usize {
    if group.trim().is_empty() {
        return 0;
    }
    let mut depth_paren = 0i32;
    let mut depth_brace = 0i32;
    let mut depth_bracket = 0i32;
    let mut depth_angle = 0i32;
    let mut in_string: Option<char> = None;
    let mut count = 1usize;
    let mut prev: Option<char> = None;
    for ch in group.chars() {
        if let Some(quote) = in_string {
            if ch == quote && prev != Some('\\') {
                in_string = None;
            }
            prev = Some(ch);
            continue;
        }
        match ch {
            '"' | '\'' => in_string = Some(ch),
            '(' => depth_paren += 1,
            ')' => depth_paren -= 1,
            '{' => depth_brace += 1,
            '}' => depth_brace -= 1,
            '[' => depth_bracket += 1,
            ']' => depth_bracket -= 1,
            '<' => depth_angle += 1,
            '>' => depth_angle -= 1,
            ',' if depth_paren == 0
                && depth_brace == 0
                && depth_bracket == 0
                && depth_angle == 0 =>
            {
                count += 1;
            }
            _ => {}
        }
        prev = Some(ch);
    }
    count
}

// ── object-only kind as Event.kind ───────────────────────────────────────

fn scan_object_only_kind(
    path: &Path,
    line_idx: usize,
    line: &str,
    out: &mut Vec<ProtocolDriftFinding>,
) {
    for kind in OBJECT_ONLY_KINDS {
        if let Some(col) = find_literal_token(line, kind) {
            let lower = line.to_ascii_lowercase();
            let looks_like_kind_position = lower.contains("kind")
                || lower.contains("event.kind")
                || lower.contains("\"kind\":")
                || lower.contains("events.submit");
            if looks_like_kind_position {
                out.push(ProtocolDriftFinding {
                    path: path.to_path_buf(),
                    line: line_idx + 1,
                    column: col + 1,
                    rule: ProtocolDriftRule::ObjectOnlyKindAsEventKind,
                    matched_literal: (*kind).to_string(),
                    message: format!("`{kind}` is object-only; MUST NOT appear as Event.kind"),
                });
            }
        }
    }
}

// ── ephemeral kind as durable Event ──────────────────────────────────────

fn scan_ephemeral_kind(
    path: &Path,
    line_idx: usize,
    line: &str,
    out: &mut Vec<ProtocolDriftFinding>,
) {
    for kind in EPHEMERAL_ONLY_KINDS {
        if let Some(col) = find_literal_token(line, kind) {
            let lower = line.to_ascii_lowercase();
            let looks_durable_submit = lower.contains("events.submit")
                || lower.contains("ck.self.events.submit")
                || lower.contains("event.kind")
                || (lower.contains("\"kind\":") && !lower.contains("ephemeral"));
            if looks_durable_submit {
                out.push(ProtocolDriftFinding {
                    path: path.to_path_buf(),
                    line: line_idx + 1,
                    column: col + 1,
                    rule: ProtocolDriftRule::EphemeralKindAsDurableEvent,
                    matched_literal: (*kind).to_string(),
                    message: format!(
                        "`{kind}` is `wire_scope=ephemeral_event`; MUST NOT be submitted \
                         via `ck.self.events.submit` as a durable Event. Use \
                         `ck.schema.ephemeral_envelope.v1` (broadcast) or \
                         `ck.schema.device_message.v1` (point-to-point)."
                    ),
                });
            }
        }
    }
}

// ── relaxed_window_max_ms ceiling ────────────────────────────────────────

fn scan_relaxed_window(
    path: &Path,
    line_idx: usize,
    line: &str,
    out: &mut Vec<ProtocolDriftFinding>,
) {
    let token = "relaxed_window_max_ms";
    let Some(idx) = line.find(token) else { return };
    let rest = &line[idx + token.len()..];
    let mut number = String::new();
    let mut saw_separator = false;
    for ch in rest.chars() {
        if !saw_separator {
            if matches!(ch, '=' | ':' | '>' | ' ' | '\t' | '"') {
                saw_separator |= matches!(ch, '=' | ':');
                continue;
            }
            if !ch.is_ascii_whitespace() {
                break;
            }
        } else if ch.is_ascii_digit() || ch == '_' {
            number.push(ch);
        } else if !number.is_empty() || (!ch.is_ascii_whitespace() && ch != '"') {
            break;
        }
    }
    if number.is_empty() {
        return;
    }
    let cleaned: String = number.chars().filter(|c| *c != '_').collect();
    if let Ok(value) = cleaned.parse::<u64>() {
        if value > RELAXED_WINDOW_MAX_MS_CEILING {
            out.push(ProtocolDriftFinding {
                path: path.to_path_buf(),
                line: line_idx + 1,
                column: idx + 1,
                rule: ProtocolDriftRule::RelaxedWindowExceedsCeiling,
                matched_literal: format!("relaxed_window_max_ms={value}"),
                message: format!(
                    "`relaxed_window_max_ms={value}` exceeds hard ceiling \
                     {RELAXED_WINDOW_MAX_MS_CEILING}; reducer MUST reject with \
                     `relaxed_window_exceeds_ceiling`."
                ),
            });
        }
    }
}

// ── cursor handle entropy floor ──────────────────────────────────────────

fn scan_cursor_handle(
    path: &Path,
    line_idx: usize,
    line: &str,
    out: &mut Vec<ProtocolDriftFinding>,
) {
    let candidates = extract_cursor_handle_candidates(line);
    for (col, handle) in candidates {
        if handle.len() >= CURSOR_HANDLE_MIN_LEN {
            continue;
        }
        if handle.len() < 6 {
            continue;
        }
        if !handle
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            continue;
        }
        out.push(ProtocolDriftFinding {
            path: path.to_path_buf(),
            line: line_idx + 1,
            column: col + 1,
            rule: ProtocolDriftRule::CursorHandleBelowEntropyFloor,
            matched_literal: handle.clone(),
            message: format!(
                "cursor handle literal `{handle}` is {} chars; spec raised \
                 `h.minLength` to {CURSOR_HANDLE_MIN_LEN}.",
                handle.len()
            ),
        });
    }
}

fn extract_cursor_handle_candidates(line: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
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

// ── forbidden wire field: discussion_space_ref ───────────────────────────

fn scan_discussion_space_ref(
    path: &Path,
    line_idx: usize,
    line: &str,
    out: &mut Vec<ProtocolDriftFinding>,
) {
    let token = "discussion_space_ref";
    if let Some(col) = find_literal_token(line, token) {
        out.push(ProtocolDriftFinding {
            path: path.to_path_buf(),
            line: line_idx + 1,
            column: col + 1,
            rule: ProtocolDriftRule::ForbiddenWireField,
            matched_literal: token.to_string(),
            message: format!(
                "`{token}` is forbidden on the wire; \
                 CKP-0007 also hard-removed its successor `discussion_realm_ref`. \
                 Use `scope_circle_id` (Flow / Space / Morph)."
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

    fn scan(line: &str) -> Vec<ProtocolDriftFinding> {
        let mut out = vec![];
        scan_protocol_drift(Path::new("src/foo.rs"), line, &mut out);
        out
    }

    #[test]
    fn does_not_flag_legal_did_web() {
        let f = scan(r#"let did = "did:web:alice.example";"#);
        assert!(
            !f.iter()
                .any(|r| r.rule == ProtocolDriftRule::LegacyDidMethodSegment),
            "legal did:web should not trip the linter: {f:?}"
        );
    }

    #[test]
    fn does_not_flag_did_webvh() {
        let f = scan(r#"let did = "did:webvh:alice.example";"#);
        assert!(
            !f.iter()
                .any(|r| r.rule == ProtocolDriftRule::LegacyDidMethodSegment)
        );
    }

    #[test]
    fn flags_events_subscribe_with_string_type() {
        // DRIFT-ALLOW: scanner self-test asserts the rule fires on a pre-tightening stringly
        // subscribe.
        let f =
            scan("fn handle_cx_events_subscribe(payload: String) {} // ck.self.events.subscribe");
        assert!(
            f.iter()
                .any(|r| r.rule == ProtocolDriftRule::EventsSubscribeStringPayload)
        );
    }

    #[test]
    fn does_not_flag_events_subscribe_with_typed_frame() {
        let f = scan("fn handle_cx_events_subscribe(payload: EventsSubscribeFrame) {}");
        assert!(
            !f.iter()
                .any(|r| r.rule == ProtocolDriftRule::EventsSubscribeStringPayload)
        );
    }

    #[test]
    fn flags_cross_signing_publish_payload_without_expected_previous() {
        // DRIFT-ALLOW: scanner self-test asserts the rule fires on a pre-tightening CAS payload.
        let f = scan(r#"submit("ck.cross_signing.publish", payload: { principal_id: pid })"#);
        assert!(
            f.iter().any(|r| r.rule
                == ProtocolDriftRule::CrossSigningPublishMissingExpectedPreviousGeneration)
        );
    }

    #[test]
    fn does_not_flag_cross_signing_publish_with_expected_previous() {
        let f = scan(
            r#"submit("ck.cross_signing.publish", payload: { principal_id: pid, expected_previous_generation: 1 })"#,
        );
        assert!(
            !f.iter().any(|r| r.rule
                == ProtocolDriftRule::CrossSigningPublishMissingExpectedPreviousGeneration)
        );
    }

    #[test]
    fn flags_compute_audit_policy_version_digest_two_args() {
        // DRIFT-ALLOW: scanner self-test asserts the rule fires on a pre-tightening two-arg call.
        let f = scan("compute_audit_policy_version_digest(disclosure, assurance)");
        assert!(
            f.iter()
                .any(|r| r.rule == ProtocolDriftRule::AuditPolicyVersionHashFewerThanFourArguments)
        );
    }

    #[test]
    fn does_not_flag_compute_audit_policy_version_digest_four_args() {
        let f = scan(
            "compute_audit_policy_version_digest(realm_id, trust_domain, disclosure, assurance)",
        );
        assert!(
            !f.iter()
                .any(|r| r.rule == ProtocolDriftRule::AuditPolicyVersionHashFewerThanFourArguments),
            "four-arg call must not be flagged: {f:?}"
        );
    }

    #[test]
    fn handles_compute_audit_policy_version_digest_nested_args() {
        let f = scan(
            "compute_audit_policy_version_digest(realm.id(), domain.clone(), disclosure, assurance)",
        );
        assert!(
            !f.iter()
                .any(|r| r.rule == ProtocolDriftRule::AuditPolicyVersionHashFewerThanFourArguments),
            "nested call arguments must not be miscounted: {f:?}"
        );
    }

    #[test]
    fn flags_event_batch_receipt_as_event_kind() {
        let f = scan(r#"let kind = "ck.event_batch_receipt";"#);
        assert!(
            f.iter()
                .any(|r| r.rule == ProtocolDriftRule::ObjectOnlyKindAsEventKind)
        );
    }

    #[test]
    fn flags_ephemeral_kind_in_events_submit() {
        let f = scan(r#"client.ck.events.submit(&[Event{ kind: "ck.presence", ... }]);"#);
        assert!(
            f.iter()
                .any(|r| r.rule == ProtocolDriftRule::EphemeralKindAsDurableEvent)
        );
    }

    #[test]
    fn flags_relaxed_window_over_ceiling() {
        let f = scan(r#"relaxed_window_max_ms: 400_000,"#);
        assert!(
            f.iter()
                .any(|r| r.rule == ProtocolDriftRule::RelaxedWindowExceedsCeiling)
        );
    }

    #[test]
    fn does_not_flag_relaxed_window_at_ceiling() {
        let f = scan(r#"relaxed_window_max_ms = 300000,"#);
        assert!(
            !f.iter()
                .any(|r| r.rule == ProtocolDriftRule::RelaxedWindowExceedsCeiling)
        );
    }

    #[test]
    fn flags_short_cursor_handle() {
        let f = scan("let blob = r##\"{\"h\":\"shortx12\",\"x\":1,\"v\":\"1\"}\"##;");
        assert!(
            f.iter()
                .any(|r| r.rule == ProtocolDriftRule::CursorHandleBelowEntropyFloor)
        );
    }

    #[test]
    fn does_not_flag_full_length_cursor_handle() {
        let f = scan("\"h\":\"aaaaaaaaaaaaaaaaaaaaaaaa\"");
        assert!(
            !f.iter()
                .any(|r| r.rule == ProtocolDriftRule::CursorHandleBelowEntropyFloor)
        );
    }

    #[test]
    fn flags_discussion_space_ref() {
        let f = scan("let json = r##\"{\"discussion_space_ref\":\"ck:realm:...\"}\"##;");
        assert!(
            f.iter()
                .any(|r| r.rule == ProtocolDriftRule::ForbiddenWireField)
        );
    }

    #[test]
    fn changelog_path_is_skipped() {
        let mut out = vec![];
        scan_protocol_drift(
            Path::new("CHANGELOG.md"),
            r#"Removed support for did:web.alpha:..."#, // DRIFT-ALLOW: scanner self-test fixture
            &mut out,
        );
        assert!(out.is_empty());
    }
}
