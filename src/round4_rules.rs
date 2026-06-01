//! Round 4 — structural drift rules introduced by the
//! `contrix-spec` change set bracketed by commits
//! `7446832..a77b9958e3c6535a39bf468d661a23ae5d38cb10` (chore: close
//! protocol review findings → align consent cell bottom wording).
//!
//! Four heuristic literal-scanner rules ride here. They are intentionally
//! conservative (false negatives are acceptable; false positives must
//! remain rare). Spec-side counterparts live in
//! `contrix-spec/tools/lint_artifacts.py::check_*`.
//!
//! 1. **`LegacyDidMethodSegment`** — DID strings whose method-name segment (between `did:` and the
//!    next `:`) contains any of `.`, `-`, `_`, `:`. Spec tightened the regex to
//!    `^did:[a-z0-9]+:[^\s]+$`.
//!
//! 2. **`EventsSubscribeStringPayload`** — the payload of `cx.events.subscribe` is now the typed
//!    `EventsSubscribeFrame` object; any literal where the payload is declared as / typed as
//!    `string` (or `String` / `&str`) is a violation.
//!
//! 3. **`CrossSigningPublishWithoutExpectedPreviousGeneration`** — a `cx.cross_signing.publish`
//!    payload constructed inline without a  ROUND4-ALLOW: docstring describes the rule itself.
//!    visible `expected_previous_generation` field. The new CAS contract requires it (round-4
//!    7fae9ba).
//!
//! 4. **`AuditPolicyVersionHashFewerThanFourArguments`** — calls to
//!    `compute_audit_policy_version_digest(...)` whose argument list has  ROUND4-ALLOW: docstring
//!    describes the rule, the `(...)` is a placeholder not a real call. fewer than 4 arguments.
//!    Spec tightened the function signature to `(realm_id, trust_domain, audit_disclosure,
//!    audit_assurance)`.

use std::path::{Path, PathBuf};

use serde::Serialize;

/// New DID method-segment regex (round 4 / f9bd7eb). Pinned here so a
/// drift produces a visible diff. The cotest scanner does not run regex —
/// it does a structural per-character check — but the pin keeps the spec
/// reference live in source.
pub const DID_METHOD_SEGMENT_REGEX: &str = r"^did:[a-z0-9]+:[^\s]+$";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Round4Rule {
    LegacyDidMethodSegment,
    EventsSubscribeStringPayload,
    CrossSigningPublishMissingExpectedPreviousGeneration,
    AuditPolicyVersionHashFewerThanFourArguments,
}

impl Round4Rule {
    pub fn as_str(self) -> &'static str {
        match self {
            Round4Rule::LegacyDidMethodSegment => "legacy_did_method_segment",
            Round4Rule::EventsSubscribeStringPayload => "events_subscribe_string_payload",
            Round4Rule::CrossSigningPublishMissingExpectedPreviousGeneration => {
                "cross_signing_publish_missing_expected_previous_generation"
            }
            Round4Rule::AuditPolicyVersionHashFewerThanFourArguments => {
                "audit_policy_version_digest_fewer_than_four_arguments"
            }
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Round4Finding {
    pub path: PathBuf,
    pub line: usize,
    pub column: usize,
    pub rule: Round4Rule,
    pub matched_literal: String,
    pub message: String,
}

/// Marker comment that a source line intentionally exercises a
/// pre-round-4 wire shape (e.g. a negative regex test asserting that the
/// old form is rejected). When the marker appears on the same line as a
/// finding *or* on the immediately preceding non-blank line, the scanner
/// suppresses the finding.
pub const ROUND4_ALLOW_MARKER: &str = "ROUND4-ALLOW";

/// Walk `path` line-by-line and emit findings for every Round-4 rule.
pub fn scan_round4(path: &Path, contents: &str, out: &mut Vec<Round4Finding>) {
    if is_allowed_path(path) {
        return;
    }
    let lines: Vec<&str> = contents.lines().collect();
    let mut new_findings: Vec<Round4Finding> = Vec::new();
    for (line_idx, line) in lines.iter().enumerate() {
        scan_legacy_did(path, line_idx, line, &mut new_findings);
        scan_events_subscribe_string_payload(path, line_idx, line, &mut new_findings);
        scan_cross_signing_publish_payload(path, line_idx, line, &mut new_findings);
        scan_audit_policy_version_digest_call(path, line_idx, line, &mut new_findings);
    }
    // Suppress findings whose line — or any of the prior `LOOKBACK`
    // non-blank lines — contains the `ROUND4-ALLOW` marker. Walking back
    // past blanks plus a small lookback budget lets the marker sit on a
    // comment line a couple of lines above the offending literal (e.g.
    // above a multi-line `return Err(\n   "..."\n)` block).
    const LOOKBACK: usize = 3;
    for f in new_findings {
        let cur = lines.get(f.line - 1).copied().unwrap_or("");
        let mut allowed = cur.contains(ROUND4_ALLOW_MARKER);
        if !allowed && f.line >= 2 {
            let mut found = 0usize;
            let mut k = f.line - 2;
            loop {
                let l = lines.get(k).copied().unwrap_or("");
                if !l.trim().is_empty() {
                    if l.contains(ROUND4_ALLOW_MARKER) {
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

// ── Rule 1: legacy DID method segment ───────────────────────────────────────

fn scan_legacy_did(path: &Path, line_idx: usize, line: &str, out: &mut Vec<Round4Finding>) {
    // For every occurrence of `did:` find the next `:` and inspect the
    // method-name segment between them. If it contains any char outside
    // [a-z0-9], flag.
    let bytes = line.as_bytes();
    let needle = b"did:";
    let mut i = 0usize;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] != needle {
            i += 1;
            continue;
        }
        // Boundary check: ensure not part of a larger ident (e.g.
        // `xdid:`). Allow start-of-line, non-ident char, or a quote.
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
        // Find the next `:` — that's the end of the method segment.
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
                    // Don't break: still find the colon if we can, so
                    // we can describe the method segment.
                } else {
                    // Any other char (whitespace, punctuation) means we
                    // hit the end of a "did:..." literal without a method
                    // separator. Skip — that's a different lint.
                    break;
                }
            }
            j += 1;
        }
        if let (true, Some(v_char)) = (saw_terminator, violation_char) {
            let method = std::str::from_utf8(&bytes[method_start..j]).unwrap_or("?");
            out.push(Round4Finding {
                path: path.to_path_buf(),
                line: line_idx + 1,
                column: i + 1,
                rule: Round4Rule::LegacyDidMethodSegment,
                matched_literal: format!("did:{method}:"),
                message: format!(
                    "DID method-name segment `{method}` contains a forbidden char \
                     ({:?}); round-4 spec tightened the regex to `{DID_METHOD_SEGMENT_REGEX}` \
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

// ── Rule 2: cx.events.subscribe payload typed as string ───────────────────── ROUND4-ALLOW:
// section header comment

fn scan_events_subscribe_string_payload(
    path: &Path,
    line_idx: usize,
    line: &str,
    out: &mut Vec<Round4Finding>,
) {
    // Heuristic: a line mentioning `cx.events.subscribe` *and* one of
    // `string` / `String` / `&str` (as a Rust / TS / JSON type token) is a
    // suspicious declaration. We deliberately keep the match local to a
    // single line to avoid scanning context cost — the round-4 wire break
    // is type-level so multi-line declarations should still surface a
    // signature on at least one line.
    // ROUND4-ALLOW: this is the rule's own search token, not a payload declaration.
    let token = "cx.events.subscribe";
    let Some(col) = line.find(token) else { return };
    // Allowlist: doc-comment / prose that explicitly says the payload is
    // *no longer* a string. We don't want to fire on the canonical
    // migration note.
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
    out.push(Round4Finding {
        path: path.to_path_buf(),
        line: line_idx + 1,
        column: col + 1,
        rule: Round4Rule::EventsSubscribeStringPayload,
        matched_literal: token.to_string(),
        message: format!(
            "`{token}` payload is typed as a string on this line; round-4 spec \
             requires the typed `EventsSubscribeFrame {{ kind: <event|frontier|heartbeat\
             |catchup_complete|epoch_rotation|dropped|resync_required|unauthorized> }}` \
             (see contrix-spec commit 58c5926 / d74bb75).",
        ),
    });
}

fn contains_type_token(line: &str, token: &str) -> bool {
    // Match `token` only at a non-ident boundary (so `someString` is not a
    // hit, but `: String` / `: string` / `Vec<&str>` are).
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

// ── Rule 3: cross_signing.publish payload missing expected_previous_generation ──

fn scan_cross_signing_publish_payload(
    path: &Path,
    line_idx: usize,
    line: &str,
    out: &mut Vec<Round4Finding>,
) {
    // Heuristic: line mentions `cx.cross_signing.publish` *and* looks
    // like a payload literal (presence of `{` / `=` / `: {` on the same
    // line) but the line does not contain `expected_previous_generation`.
    // Surface as a violation that pins the CAS upgrade.
    // ROUND4-ALLOW: this is the rule's own search token, not a payload construction.
    let token = "cx.cross_signing.publish";
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
    // Tag-only comments / doc-strings that explicitly call out the CAS
    // contract are fine; require the field name *somewhere* on the line.
    if line.contains("expected_previous_generation") {
        return;
    }
    out.push(Round4Finding {
        path: path.to_path_buf(),
        line: line_idx + 1,
        column: col + 1,
        rule: Round4Rule::CrossSigningPublishMissingExpectedPreviousGeneration,
        matched_literal: token.to_string(),
        message: format!(
            "`{token}` payload constructed without `expected_previous_generation`; \
             round-4 spec (contrix-spec 7fae9ba) made the CAS contract \
             `(principal_id, expected_previous_generation)` and the new field is REQUIRED. \
             Old two-tuple form is a hard wire-break.",
        ),
    });
}

// ── Rule 4: compute_audit_policy_version_digest arity < 4 ─────────────────────

fn scan_audit_policy_version_digest_call(
    path: &Path,
    line_idx: usize,
    line: &str,
    out: &mut Vec<Round4Finding>,
) {
    let token = "compute_audit_policy_version_digest";
    let Some(col) = line.find(token) else { return };
    let rest = &line[col + token.len()..];
    // Find the opening `(` ignoring whitespace.
    let Some(paren_idx_rel) = rest.find('(') else {
        return;
    };
    // If there is anything other than whitespace between `token` and `(`,
    // it's not a direct call (e.g. trailing `::<...>`) — be conservative
    // and skip.
    if !rest[..paren_idx_rel].chars().all(char::is_whitespace) {
        return;
    }
    // Extract the parenthesised group (single-line only — for round-4 we
    // accept false negatives on multi-line call expressions).
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
        // Bound: don't walk past 4096 chars on a single line.
        if idx > 4096 {
            return;
        }
    }
    if depth != 0 {
        // Open-ended call — bail.
        return;
    }
    let arg_count = count_top_level_args(&group);
    if arg_count < 4 {
        out.push(Round4Finding {
            path: path.to_path_buf(),
            line: line_idx + 1,
            column: col + 1,
            rule: Round4Rule::AuditPolicyVersionHashFewerThanFourArguments,
            matched_literal: format!("{token}({group})"),
            message: format!(
                "`{token}` called with {arg_count} argument(s); round-4 spec \
                 (contrix-spec 7fae9ba) tightened the digest input to \
                 `(realm_id, trust_domain, audit_disclosure, audit_assurance)` — \
                 four arguments are REQUIRED. Old two-argument form is a hard wire-break.",
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

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(line: &str) -> Vec<Round4Finding> {
        let mut out = vec![];
        scan_round4(Path::new("src/foo.rs"), line, &mut out);
        out
    }

    #[test]
    fn does_not_flag_legal_did_web() {
        let f = scan(r#"let did = "did:web:alice.example";"#);
        assert!(
            !f.iter()
                .any(|r| r.rule == Round4Rule::LegacyDidMethodSegment),
            "legal did:web should not trip the linter: {f:?}"
        );
    }

    #[test]
    fn does_not_flag_did_webvh() {
        let f = scan(r#"let did = "did:webvh:alice.example";"#);
        assert!(
            !f.iter()
                .any(|r| r.rule == Round4Rule::LegacyDidMethodSegment)
        );
    }

    #[test]
    fn flags_events_subscribe_with_string_type() {
        // ROUND4-ALLOW: scanner self-test asserts the rule fires on a pre-round-4 stringly
        // subscribe.
        let f = scan("fn handle_cx_events_subscribe(payload: String) {} // cx.events.subscribe");
        assert!(
            f.iter()
                .any(|r| r.rule == Round4Rule::EventsSubscribeStringPayload)
        );
    }

    #[test]
    fn does_not_flag_events_subscribe_with_typed_frame() {
        let f = scan("fn handle_cx_events_subscribe(payload: EventsSubscribeFrame) {}");
        assert!(
            !f.iter()
                .any(|r| r.rule == Round4Rule::EventsSubscribeStringPayload)
        );
    }

    #[test]
    fn flags_cross_signing_publish_payload_without_expected_previous() {
        // ROUND4-ALLOW: scanner self-test asserts the rule fires on a pre-round-4 CAS payload.
        let f = scan(r#"submit("cx.cross_signing.publish", payload: { principal_id: pid })"#);
        assert!(
            f.iter()
                .any(|r| r.rule == Round4Rule::CrossSigningPublishMissingExpectedPreviousGeneration)
        );
    }

    #[test]
    fn does_not_flag_cross_signing_publish_with_expected_previous() {
        let f = scan(
            r#"submit("cx.cross_signing.publish", payload: { principal_id: pid, expected_previous_generation: 1 })"#,
        );
        assert!(
            !f.iter()
                .any(|r| r.rule == Round4Rule::CrossSigningPublishMissingExpectedPreviousGeneration)
        );
    }

    #[test]
    fn flags_compute_audit_policy_version_digest_two_args() {
        // ROUND4-ALLOW: scanner self-test asserts the rule fires on a pre-round-4 two-arg call.
        let f = scan("compute_audit_policy_version_digest(disclosure, assurance)");
        assert!(
            f.iter()
                .any(|r| r.rule == Round4Rule::AuditPolicyVersionHashFewerThanFourArguments)
        );
    }

    #[test]
    fn does_not_flag_compute_audit_policy_version_digest_four_args() {
        let f = scan(
            "compute_audit_policy_version_digest(realm_id, trust_domain, disclosure, assurance)",
        );
        assert!(
            !f.iter()
                .any(|r| r.rule == Round4Rule::AuditPolicyVersionHashFewerThanFourArguments),
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
                .any(|r| r.rule == Round4Rule::AuditPolicyVersionHashFewerThanFourArguments),
            "nested call arguments must not be miscounted: {f:?}"
        );
    }

    #[test]
    fn changelog_path_is_skipped() {
        let mut out = vec![];
        scan_round4(
            Path::new("CHANGELOG.md"),
            r#"Removed support for did:web.alpha:..."#, // ROUND4-ALLOW: scanner self-test fixture
            &mut out,
        );
        assert!(out.is_empty());
    }
}
