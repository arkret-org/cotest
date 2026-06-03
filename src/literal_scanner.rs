//! Repo-level literal scanner for Cokret v1 protocol-drift detection.
//!
//! Loads removed / deprecated / forbidden artifact registries from
//! `cokret-spec/spec/v1/artifacts/registry/*.json` (path overridable via
//! `COKRET_SPEC_DIR`) and walks a downstream tree looking for occurrences of:
//!
//! * `cx.*` event-kind or operation-id literals listed as removed
//! * profile ids listed as deprecated
//! * wire field names listed as forbidden (in JSON or Rust string literals)
//! * model terms listed as forbidden (in Rust identifiers / Markdown prose)
//!
//! Findings are emitted as a structured [`Finding`] record. Each finding can
//! be marked `allowed_context_match=true` if it falls under one of the
//! supported allowlist mechanisms:
//!
//! * **Path glob** — file path matches one of `**/compat/**`, `**/interop_matrix/**`,
//!   `**/legacy_negative/**`, `**/legacy_migration/**`, `**/changelog/**`, `**/CHANGELOG*`,
//!   `**/migrations/**`.
//! * **Magic comment** — anywhere in the file, a line `// cokret-allow: <artifact_id>` (or `#
//!   cokret-allow: ...` / `<!-- cokret-allow: ... -->`) exempts that specific id.
//! * **Wildcard magic comment** — `// cokret-allow: *` exempts every artifact inside that file (use
//!   sparingly; only for whole-file legacy fixtures).
//!
//! The scanner is intentionally a single-crate module so the binary
//! [`literal_scanner`] and integration smoke tests can both reach it through
//! `cotest::literal_scanner`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

// ── Artifact registry shapes ────────────────────────────────────────────────

/// Logical category of a registry file. Used to drive context-aware matching
/// (e.g. wire-field names are only matched in JSON / string literals, model
/// terms are matched in prose / identifiers).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum ArtifactSource {
    RemovedEventKinds,
    DeprecatedProfileIds,
    RemovedOperationIds,
    ForbiddenWireFields,
    ForbiddenModelTerms,
    Renames,
}

impl ArtifactSource {
    pub fn registry_file(self) -> &'static str {
        match self {
            ArtifactSource::RemovedEventKinds => "removed-event-kinds.json",
            ArtifactSource::DeprecatedProfileIds => "deprecated-profile-ids.json",
            ArtifactSource::RemovedOperationIds => "removed-operation-ids.json",
            ArtifactSource::ForbiddenWireFields => "forbidden-wire-fields.json",
            ArtifactSource::ForbiddenModelTerms => "forbidden-model-terms.json",
            ArtifactSource::Renames => "renames.json",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ArtifactSource::RemovedEventKinds => "removed_event_kinds",
            ArtifactSource::DeprecatedProfileIds => "deprecated_profile_ids",
            ArtifactSource::RemovedOperationIds => "removed_operation_ids",
            ArtifactSource::ForbiddenWireFields => "forbidden_wire_fields",
            ArtifactSource::ForbiddenModelTerms => "forbidden_model_terms",
            ArtifactSource::Renames => "renames",
        }
    }

    pub fn all() -> [ArtifactSource; 6] {
        [
            ArtifactSource::RemovedEventKinds,
            ArtifactSource::DeprecatedProfileIds,
            ArtifactSource::RemovedOperationIds,
            ArtifactSource::ForbiddenWireFields,
            ArtifactSource::ForbiddenModelTerms,
            ArtifactSource::Renames,
        ]
    }
}

#[derive(Clone, Debug, Deserialize)]
struct RegistryFile {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    entries: Vec<RegistryEntry>,
}

#[derive(Clone, Debug, Deserialize)]
struct RegistryEntry {
    id: String,
    #[serde(default)]
    rejection_level: String,
    #[serde(default)]
    replacement: Option<String>,
    #[serde(default)]
    allowed_contexts: Vec<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    kind_class: Option<String>,
    #[serde(default)]
    context: Option<String>,
}

/// One normalized rule loaded from a registry file.
#[derive(Clone, Debug)]
pub struct ArtifactRule {
    pub artifact_source: ArtifactSource,
    pub id: String,
    pub rejection_level: String,
    pub replacement: Option<String>,
    pub allowed_contexts: Vec<String>,
    pub notes: Option<String>,
    pub kind_class: Option<String>,
    pub context: Option<String>,
}

impl ArtifactRule {
    fn from_entry(source: ArtifactSource, entry: RegistryEntry) -> Self {
        Self {
            artifact_source: source,
            id: entry.id,
            rejection_level: entry.rejection_level,
            replacement: entry.replacement,
            allowed_contexts: entry.allowed_contexts,
            notes: entry.notes,
            kind_class: entry.kind_class,
            context: entry.context,
        }
    }
}

// ── Loader ──────────────────────────────────────────────────────────────────

/// Resolve the spec directory. Honors `COKRET_SPEC_DIR` env var first, then
/// falls back to `<cotest crate root>/../cokret-spec`.
pub fn resolve_spec_dir() -> PathBuf {
    if let Some(value) = std::env::var_os("COKRET_SPEC_DIR") {
        return PathBuf::from(value);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("cokret-spec")
}

/// Build the absolute path to the `registry/` directory containing the
/// drift-detection JSON files.
pub fn resolve_registry_dir() -> PathBuf {
    let spec_dir = resolve_spec_dir();
    let nested = spec_dir
        .join("spec")
        .join("v1")
        .join("artifacts")
        .join("registry");
    if nested.is_dir() {
        return nested;
    }
    // Some downstream callers may already pass the artifacts/registry path.
    let direct = spec_dir.join("registry");
    if direct.is_dir() {
        return direct;
    }
    nested
}

/// Load all six drift-detection artifacts from the registry directory.
pub fn load_all_rules() -> Result<Vec<ArtifactRule>> {
    load_all_rules_from(&resolve_registry_dir())
}

/// Load all six drift-detection artifacts from a caller-supplied directory.
pub fn load_all_rules_from(registry_dir: &Path) -> Result<Vec<ArtifactRule>> {
    let mut rules = Vec::new();
    for source in ArtifactSource::all() {
        let path = registry_dir.join(source.registry_file());
        if !path.is_file() {
            // Missing artifact is not fatal — emit nothing for that source.
            // The CLI surfaces the empty load via `--format json` summary.
            continue;
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let file: RegistryFile = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let _ = file.kind; // accepted but not used for routing
        for entry in file.entries {
            rules.push(ArtifactRule::from_entry(source, entry));
        }
    }
    Ok(rules)
}

// ── Findings ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub path: PathBuf,
    pub line: usize,
    pub column: usize,
    pub matched_token: String,
    pub artifact_source: String,
    pub artifact_id: String,
    pub rejection_level: String,
    pub replacement: Option<String>,
    pub allowed_context_match: bool,
    pub allowed_context_reason: Option<String>,
    pub file_kind: FileKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Rust,
    Typescript,
    Json,
    Markdown,
    Other,
}

impl FileKind {
    fn from_path(path: &Path) -> Self {
        match path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
        {
            Some("rs") => FileKind::Rust,
            Some("ts" | "tsx") => FileKind::Typescript,
            Some("json") => FileKind::Json,
            Some("md") => FileKind::Markdown,
            _ => FileKind::Other,
        }
    }
}

// ── Scanner core ────────────────────────────────────────────────────────────

/// Public entry point: walk `root` recursively, scan every supported file,
/// return all findings (both raw and allowlisted).
pub fn scan_tree(root: &Path, rules: &[ArtifactRule]) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    walk(root, &mut |file_path| {
        let file_kind = FileKind::from_path(file_path);
        if matches!(file_kind, FileKind::Other) {
            return Ok(());
        }
        let raw = match fs::read_to_string(file_path) {
            Ok(s) => s,
            // Skip binary / non-utf8 files silently.
            Err(_) => return Ok(()),
        };
        scan_file_contents(file_path, file_kind, &raw, rules, &mut out);
        Ok(())
    })?;
    Ok(out)
}

/// Walk `root` and scan for structural protocol-drift rules (see
/// [`crate::protocol_drift_rules`]). Covers DID method-segment tightening,
/// EventsSubscribe payload typing, cross_signing.publish CAS,
/// audit_policy_version_digest arity, object/ephemeral event-kind split,
/// relaxed_window ceiling, cursor handle entropy, and forbidden wire
/// fields. Independent of the artifact-registry-driven path; both can be
/// invoked by callers that want full coverage.
pub fn scan_tree_protocol_drift(
    root: &Path,
) -> Result<Vec<crate::protocol_drift_rules::ProtocolDriftFinding>> {
    let mut out = Vec::new();
    walk(root, &mut |file_path| {
        let file_kind = FileKind::from_path(file_path);
        if matches!(file_kind, FileKind::Other) {
            return Ok(());
        }
        let raw = match fs::read_to_string(file_path) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };
        crate::protocol_drift_rules::scan_protocol_drift(file_path, &raw, &mut out);
        Ok(())
    })?;
    Ok(out)
}

/// Walk `root` and scan for circle-rollout (CXP-0007) structural drift
/// rules (see [`crate::circle_rules`]). Detects the hard-removed
/// `discussion_realm_ref` field and any unknown `cx.circle.*` literal that
/// is not on the 7-event-kind / 6-capability-action allowlist.
pub fn scan_tree_circle(root: &Path) -> Result<Vec<crate::circle_rules::CircleFinding>> {
    let mut out = Vec::new();
    walk(root, &mut |file_path| {
        let file_kind = FileKind::from_path(file_path);
        if matches!(file_kind, FileKind::Other) {
            return Ok(());
        }
        let raw = match fs::read_to_string(file_path) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };
        crate::circle_rules::scan_circle(file_path, &raw, &mut out);
        Ok(())
    })?;
    Ok(out)
}

fn walk<F>(root: &Path, visit: &mut F) -> Result<()>
where
    F: FnMut(&Path) -> Result<()>,
{
    if !root.exists() {
        return Err(anyhow!("scan root does not exist: {}", root.display()));
    }
    if root.is_file() {
        return visit(root);
    }
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if should_skip_dir(&dir) {
            continue;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let ty = match entry.file_type() {
                Ok(ty) => ty,
                Err(_) => continue,
            };
            if ty.is_dir() {
                stack.push(path);
            } else if ty.is_file() {
                visit(&path)?;
            }
        }
    }
    Ok(())
}

/// Skip noisy / generated directories that would only produce false positives.
fn should_skip_dir(dir: &Path) -> bool {
    let name = match dir.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };
    matches!(
        name,
        "target"
            | "node_modules"
            | ".git"
            | "dist"
            | "build"
            | ".next"
            | ".turbo"
            | "coverage"
            | ".cargo"
            | "test-results"
            | "playwright-report"
            | "trace-kanban"
    )
}

/// Allowed-context path globs. These are *file path* signals — anything below
/// one of these directories is treated as a compliant context.
const ALLOWED_PATH_GLOBS: &[(&str, &str)] = &[
    ("/compat/", "interop_module"),
    ("\\compat\\", "interop_module"),
    ("/interop_matrix/", "interop_module"),
    ("\\interop_matrix\\", "interop_module"),
    ("/interop/", "interop_module"),
    ("\\interop\\", "interop_module"),
    ("/legacy_negative/", "negative_test"),
    ("\\legacy_negative\\", "negative_test"),
    ("/legacy_migration/", "legacy_migration"),
    ("\\legacy_migration\\", "legacy_migration"),
    ("/migrations/", "legacy_migration"),
    ("\\migrations\\", "legacy_migration"),
    ("/changelog/", "changelog"),
    ("\\changelog\\", "changelog"),
];

fn allowed_path_reason(path: &Path) -> Option<&'static str> {
    let s = path.to_string_lossy();
    let lower = s.to_ascii_lowercase();
    // Match CHANGELOG.md anywhere by filename.
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let n = name.to_ascii_lowercase();
        if n.starts_with("changelog") {
            return Some("changelog");
        }
    }
    for (needle, reason) in ALLOWED_PATH_GLOBS {
        if lower.contains(*needle) {
            return Some(*reason);
        }
    }
    let _ = s; // keep `s` alive (unused once lowercased)
    None
}

/// Extract magic-comment allowlist tokens from the file's contents. Recognizes
/// `// cokret-allow:`, `# cokret-allow:`, `<!-- cokret-allow:`. A bare `*`
/// means the entire file is allowlisted.
fn magic_allow_tokens(contents: &str) -> BTreeSet<String> {
    let mut tokens = BTreeSet::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        let payload = if let Some(rest) = trimmed.strip_prefix("// cokret-allow:") {
            Some(rest.trim().trim_end_matches("*/").trim())
        } else if let Some(rest) = trimmed.strip_prefix("# cokret-allow:") {
            Some(rest.trim())
        } else if let Some(rest) = trimmed.strip_prefix("<!-- cokret-allow:") {
            Some(rest.trim().trim_end_matches("-->").trim())
        } else {
            trimmed
                .strip_prefix("/* cokret-allow:")
                .map(|rest| rest.trim().trim_end_matches("*/").trim())
        };
        if let Some(payload) = payload {
            for tok in payload.split(',') {
                let t = tok.trim();
                if !t.is_empty() {
                    tokens.insert(t.to_string());
                }
            }
        }
    }
    tokens
}

/// Decide whether a rule applies to the given file kind. Some artifact
/// categories are pointless to match in certain file types.
fn rule_applies_to(rule: &ArtifactRule, kind: FileKind) -> bool {
    match rule.artifact_source {
        ArtifactSource::RemovedEventKinds
        | ArtifactSource::DeprecatedProfileIds
        | ArtifactSource::RemovedOperationIds => {
            // `cx.*` literals can appear in code, JSON, and docs.
            matches!(
                kind,
                FileKind::Rust | FileKind::Typescript | FileKind::Json | FileKind::Markdown
            )
        }
        ArtifactSource::ForbiddenWireFields => {
            // Field-name drift is most visible in JSON wire / Rust string
            // literals. We also surface them in TS to catch SDK bindings.
            matches!(kind, FileKind::Rust | FileKind::Typescript | FileKind::Json)
        }
        ArtifactSource::ForbiddenModelTerms => {
            // Prose terms live in markdown, identifiers in Rust / TS code.
            matches!(
                kind,
                FileKind::Rust | FileKind::Typescript | FileKind::Markdown
            )
        }
        ArtifactSource::Renames => {
            // Renames are a meta-mapping; only check the *legacy* form here.
            matches!(
                kind,
                FileKind::Rust | FileKind::Typescript | FileKind::Json | FileKind::Markdown
            )
        }
    }
}

/// Scan a single file's contents and append findings.
pub fn scan_file_contents(
    path: &Path,
    file_kind: FileKind,
    contents: &str,
    rules: &[ArtifactRule],
    out: &mut Vec<Finding>,
) {
    let allowed_path = allowed_path_reason(path);
    let magic = magic_allow_tokens(contents);
    let whole_file_allow = magic.contains("*");

    // Pre-index rules by source × id for fast deduplication when the same id
    // appears in multiple artifact files (e.g. removed-event-kinds *and*
    // renames). For finding emission we want one row per (rule, location).
    let applicable: Vec<&ArtifactRule> = rules
        .iter()
        .filter(|r| rule_applies_to(r, file_kind))
        .collect();

    // To avoid double-counting when the same `id` appears across artifacts,
    // group by id but remember each source's metadata.
    let mut by_id: BTreeMap<&str, Vec<&ArtifactRule>> = BTreeMap::new();
    for r in &applicable {
        by_id.entry(r.id.as_str()).or_default().push(*r);
    }

    for (line_idx, line) in contents.lines().enumerate() {
        for (id, rules_for_id) in &by_id {
            if let Some(col) = find_token(line, id, file_kind) {
                // For each artifact-source that contributed this id, emit a
                // finding. This keeps cross-artifact provenance visible.
                let mut emitted_sources: BTreeSet<ArtifactSource> = BTreeSet::new();
                for r in rules_for_id {
                    if !emitted_sources.insert(r.artifact_source) {
                        continue;
                    }
                    let (allowed, reason) =
                        decide_allowlist(r, allowed_path, &magic, whole_file_allow);
                    out.push(Finding {
                        path: path.to_path_buf(),
                        line: line_idx + 1,
                        column: col + 1,
                        matched_token: (*id).to_string(),
                        artifact_source: r.artifact_source.as_str().to_string(),
                        artifact_id: r.id.clone(),
                        rejection_level: r.rejection_level.clone(),
                        replacement: r.replacement.clone(),
                        allowed_context_match: allowed,
                        allowed_context_reason: reason,
                        file_kind,
                    });
                }
            }
        }
    }
}

fn decide_allowlist(
    rule: &ArtifactRule,
    allowed_path: Option<&'static str>,
    magic: &BTreeSet<String>,
    whole_file_allow: bool,
) -> (bool, Option<String>) {
    if whole_file_allow {
        return (true, Some("magic_comment_wildcard".to_string()));
    }
    if magic.contains(&rule.id) {
        return (true, Some(format!("magic_comment:{}", rule.id)));
    }
    if let Some(reason) = allowed_path {
        // Honor only contexts the artifact entry actually permits. If the
        // entry's allowed_contexts is empty (older schema), fall back to
        // accepting any path-based allowlist.
        if rule.allowed_contexts.is_empty() || rule.allowed_contexts.iter().any(|c| c == reason) {
            return (true, Some(format!("path_glob:{reason}")));
        }
    }
    (false, None)
}

/// Find `token` inside `line` using rules appropriate for the file kind.
/// Returns the 0-based byte column of the first match, or `None`.
///
/// Token matching rules:
///
/// * For tokens beginning with `cx.` we require either start-of-line, or that the preceding
///   character is not an ASCII identifier character (so `mycx.flow.track.member` does not match).
/// * For multi-word tokens that contain a space (e.g. `track members`) we do case-insensitive
///   substring search.
/// * For everything else we do a strict substring search.
fn find_token(line: &str, token: &str, _kind: FileKind) -> Option<usize> {
    if token.is_empty() {
        return None;
    }
    if token.starts_with("cx.") {
        return find_cx_literal(line, token);
    }
    if token.contains(' ') {
        // Case-insensitive prose match.
        let l = line.to_ascii_lowercase();
        let t = token.to_ascii_lowercase();
        return l.find(&t);
    }
    // Identifier / field-name style — require a non-identifier boundary.
    find_identifier(line, token)
}

fn find_cx_literal(line: &str, token: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let tlen = token.len();
    let mut i = 0;
    while i + tlen <= bytes.len() {
        if &bytes[i..i + tlen] == token.as_bytes() {
            // Require the preceding byte to not be an identifier char.
            let prev_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
            // And the following byte must not extend the identifier further
            // (we want `cx.flow.track.member` but not `cx.flow.track.member.x`
            // — except when token already ends in something matched literally
            // by the registry id). We use: trailing char must not be ident,
            // dot is allowed only if the token already ends with `.`.
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

fn find_identifier(line: &str, token: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let tlen = token.len();
    if tlen == 0 {
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

// ── Reporting ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub root: PathBuf,
    pub registry_dir: PathBuf,
    pub rules_loaded: usize,
    pub findings: Vec<Finding>,
}

impl ScanReport {
    pub fn violations(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| !f.allowed_context_match)
    }

    pub fn has_violations(&self) -> bool {
        self.violations().next().is_some()
    }

    pub fn render_text(&self) -> String {
        use std::fmt::Write as _;
        // Header is small; each finding renders to ~128 bytes on average.
        let mut out = String::with_capacity(128 + self.findings.len() * 128);
        let _ = writeln!(
            out,
            "literal_scanner: root={} registry={} rules={} findings={}",
            self.root.display(),
            self.registry_dir.display(),
            self.rules_loaded,
            self.findings.len()
        );
        let mut violations = 0usize;
        let mut allowed = 0usize;
        for f in &self.findings {
            if f.allowed_context_match {
                allowed += 1;
                let _ = writeln!(
                    out,
                    "  [allowed:{}] {}:{}:{} {} ({} :: {})",
                    f.allowed_context_reason.as_deref().unwrap_or("?"),
                    f.path.display(),
                    f.line,
                    f.column,
                    f.matched_token,
                    f.artifact_source,
                    f.rejection_level
                );
            } else {
                violations += 1;
                let _ = write!(
                    out,
                    "  [VIOLATION:{}] {}:{}:{} {}",
                    f.rejection_level,
                    f.path.display(),
                    f.line,
                    f.column,
                    f.matched_token,
                );
                if let Some(r) = f.replacement.as_ref() {
                    let _ = write!(out, " -> {r}");
                }
                out.push('\n');
            }
        }
        let _ = writeln!(out, "summary: violations={violations} allowed={allowed}");
        out
    }

    pub fn render_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// Top-level convenience: load rules from the default registry and scan
/// `root`.
pub fn scan_default(root: &Path) -> Result<ScanReport> {
    let registry_dir = resolve_registry_dir();
    let rules = load_all_rules_from(&registry_dir)?;
    let findings = scan_tree(root, &rules)?;
    Ok(ScanReport {
        root: root.to_path_buf(),
        registry_dir,
        rules_loaded: rules.len(),
        findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_rules() -> Vec<ArtifactRule> {
        vec![
            ArtifactRule {
                artifact_source: ArtifactSource::RemovedEventKinds,
                id: "cx.flow.track.member".to_string(),
                rejection_level: "hard_reject".to_string(),
                replacement: None,
                allowed_contexts: vec![
                    "negative_test".into(),
                    "changelog".into(),
                    "legacy_migration".into(),
                ],
                notes: None,
                kind_class: None,
                context: None,
            },
            ArtifactRule {
                artifact_source: ArtifactSource::ForbiddenModelTerms,
                id: "flow_branch".to_string(),
                rejection_level: "hard_reject".to_string(),
                replacement: Some("flow_track".into()),
                allowed_contexts: vec!["legacy_migration".into()],
                notes: None,
                kind_class: None,
                context: None,
            },
        ]
    }

    #[test]
    fn detects_cx_literal_in_rust_string() {
        let mut out = vec![];
        scan_file_contents(
            Path::new("src/foo.rs"),
            FileKind::Rust,
            r#"let kind = "cx.flow.track.member";"#,
            &dummy_rules(),
            &mut out,
        );
        assert_eq!(out.len(), 1, "expected single finding, got {out:?}");
        assert_eq!(out[0].matched_token, "cx.flow.track.member");
        assert!(!out[0].allowed_context_match);
    }

    #[test]
    fn magic_allow_exempts_finding() {
        let mut out = vec![];
        scan_file_contents(
            Path::new("src/foo.rs"),
            FileKind::Rust,
            "// cokret-allow: cx.flow.track.member\nlet k = \"cx.flow.track.member\";\n",
            &dummy_rules(),
            &mut out,
        );
        // The magic-allow line itself contains the literal too, so we may see
        // 1 or 2 findings depending on whether magic-comment lines are
        // suppressed. What matters is that *every* finding is allowlisted.
        assert!(!out.is_empty(), "expected at least one finding");
        assert!(
            out.iter().all(|f| f.allowed_context_match),
            "all findings should be allowlisted: {out:?}"
        );
    }

    #[test]
    fn cx_prefix_does_not_match_inside_other_ident() {
        let mut out = vec![];
        scan_file_contents(
            Path::new("src/foo.rs"),
            FileKind::Rust,
            "let xcx_flow_track_member = 1;\n",
            &dummy_rules(),
            &mut out,
        );
        assert!(out.is_empty(), "false positive on substring: {out:?}");
    }

    #[test]
    fn flow_branch_identifier_detected() {
        let mut out = vec![];
        scan_file_contents(
            Path::new("src/foo.rs"),
            FileKind::Rust,
            "pub struct flow_branch { id: u32 }\n",
            &dummy_rules(),
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].matched_token, "flow_branch");
    }

    #[test]
    fn path_glob_allows_legacy_migration() {
        let mut out = vec![];
        scan_file_contents(
            Path::new("crates/legacy_migration/foo.rs"),
            FileKind::Rust,
            r#"let kind = "cx.flow.track.member";"#,
            &dummy_rules(),
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert!(out[0].allowed_context_match);
        assert_eq!(
            out[0].allowed_context_reason.as_deref(),
            Some("path_glob:legacy_migration")
        );
    }

    #[test]
    fn changelog_filename_allowlisted() {
        let mut out = vec![];
        scan_file_contents(
            Path::new("CHANGELOG.md"),
            FileKind::Markdown,
            "Removed cx.flow.track.member in v1.\n",
            &dummy_rules(),
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert!(out[0].allowed_context_match);
    }
}
