//! Static guard for `/_cokret/*` path literals.
//!
//! cotest is allowed to exercise the protocol namespace only when the path is
//! present in the authoritative OpenAPI document. Existing soland-specific
//! legacy surfaces are explicitly allowlisted so the gate blocks new drift
//! without forcing a flag-day migration of all historical e2e fixtures.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::literal_scanner::{FileKind, resolve_spec_dir};

#[derive(Debug, Deserialize)]
struct OpenApiDocument {
    paths: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Clone, Debug)]
struct PathTemplate {
    raw: String,
    segments: Vec<PathSegment>,
}

#[derive(Clone, Debug)]
enum PathSegment {
    Literal(String),
    Param,
}

impl PathTemplate {
    fn parse(raw: &str) -> Self {
        let segments = raw
            .trim_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|segment| {
                if segment.starts_with('{') && segment.ends_with('}') {
                    PathSegment::Param
                } else {
                    PathSegment::Literal(segment.to_string())
                }
            })
            .collect();
        Self {
            raw: raw.to_string(),
            segments,
        }
    }

    fn matches(&self, path: &str) -> bool {
        let candidate: Vec<&str> = path
            .trim_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        if candidate.len() != self.segments.len() {
            return false;
        }
        self.segments
            .iter()
            .zip(candidate)
            .all(|(template, segment)| match template {
                PathSegment::Literal(expected) => expected == segment,
                PathSegment::Param => !segment.is_empty(),
            })
    }
}

#[derive(Clone, Debug)]
pub struct OpenApiPathSet {
    templates: Vec<PathTemplate>,
}

impl OpenApiPathSet {
    pub fn from_paths<I, S>(paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let templates = paths
            .into_iter()
            .map(|path| PathTemplate::parse(path.as_ref()))
            .collect();
        Self { templates }
    }

    pub fn matches(&self, path: &str) -> Option<&str> {
        self.templates
            .iter()
            .find(|template| template.matches(path))
            .map(|template| template.raw.as_str())
    }

    pub fn len(&self) -> usize {
        self.templates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }
}

pub fn resolve_openapi_path() -> PathBuf {
    let spec_dir = resolve_spec_dir();
    let nested = spec_dir
        .join("spec")
        .join("v1")
        .join("artifacts")
        .join("openapi")
        .join("cokret-service-api.openapi.yaml");
    if nested.is_file() {
        return nested;
    }
    let direct = spec_dir
        .join("artifacts")
        .join("openapi")
        .join("cokret-service-api.openapi.yaml");
    if direct.is_file() {
        return direct;
    }
    nested
}

pub fn load_canonical_openapi_paths() -> Result<OpenApiPathSet> {
    load_openapi_paths_from(&resolve_openapi_path())
}

pub fn load_openapi_paths_from(path: &Path) -> Result<OpenApiPathSet> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let doc: OpenApiDocument = serde_yaml::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    if doc.paths.is_empty() {
        return Err(anyhow!("OpenAPI paths map is empty: {}", path.display()));
    }
    Ok(OpenApiPathSet::from_paths(doc.paths.keys()))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CokretPathFinding {
    pub path: PathBuf,
    pub line: usize,
    pub column: usize,
    pub matched_path: String,
    pub normalized_path: String,
    pub openapi_match: Option<String>,
    pub allowed_legacy_match: bool,
    pub allowed_legacy_reason: Option<String>,
    pub file_kind: FileKind,
}

impl CokretPathFinding {
    pub fn is_violation(&self) -> bool {
        self.openapi_match.is_none() && !self.allowed_legacy_match
    }
}

#[derive(Clone, Copy, Debug)]
struct LegacyPathAllowRule {
    prefix: &'static str,
    reason: &'static str,
}

const LEGACY_PATH_ALLOWLIST: &[LegacyPathAllowRule] = &[
    LegacyPathAllowRule {
        prefix: "/_cokret/self/actors",
        reason: "legacy_soland_actor_projection_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/authz/grants",
        reason: "legacy_soland_authz_grants_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/account",
        reason: "legacy_soland_account_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/agents",
        reason: "legacy_soland_agent_extension_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/applets",
        reason: "legacy_soland_applet_extension_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/calls",
        reason: "legacy_soland_call_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/circles",
        reason: "legacy_soland_circle_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/device_messages/describe",
        reason: "legacy_soland_device_messages_describe",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/invites/third-party",
        reason: "legacy_soland_third_party_invite_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/messages",
        reason: "legacy_soland_message_shortcut_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/missing",
        reason: "negative_probe_path",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/__definitely_does_not_exist__",
        reason: "negative_probe_path",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/moderation",
        reason: "legacy_soland_moderation_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/moves",
        reason: "legacy_soland_move_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/operations",
        reason: "legacy_soland_registry_drift_probe",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/server",
        reason: "legacy_soland_registry_drift_probe",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/realms",
        reason: "legacy_soland_realm_crud",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/realm",
        reason: "legacy_soland_realm_state_fixme",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/blob/put",
        reason: "legacy_soland_blob_put_alias",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/flows",
        reason: "legacy_soland_flow_projection",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/views",
        reason: "legacy_soland_view_projection",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/relations",
        reason: "legacy_soland_relation_projection",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/objects",
        reason: "legacy_soland_object_projection",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/devices",
        reason: "legacy_soland_device_lifecycle",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/webrtc",
        reason: "legacy_soland_webrtc_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/organizations",
        reason: "legacy_soland_organization_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/org",
        reason: "legacy_soland_org_state_fixme",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/schemas",
        reason: "legacy_soland_schema_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/push_rules",
        reason: "legacy_soland_realtime_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/typing",
        reason: "legacy_soland_realtime_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/conformance",
        reason: "legacy_soland_conformance_debug_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/root/identity",
        reason: "legacy_starid_identity_path_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/root/webvh",
        reason: "legacy_starid_webvh_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/find/directory/circles",
        reason: "legacy_soland_circle_directory_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/find/directory/search-flows",
        reason: "legacy_soland_flow_directory_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/find/directory/spaces",
        reason: "legacy_soland_space_directory_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/peer/peer/events",
        reason: "legacy_federation_doc_typo_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/gate/auth",
        reason: "legacy_coauth_gate_auth_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/keys/recovery",
        reason: "legacy_soland_recovery_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/keys/keypackages/welcomes/pending",
        reason: "legacy_soland_keypackage_welcome_surface",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/self/snapshot",
        reason: "legacy_soland_snapshot_surface_reference",
    },
    LegacyPathAllowRule {
        prefix: "/_cokret/gate/account/session-grants/introspect",
        reason: "legacy_coauth_gate_introspection_surface",
    },
];

pub fn scan_tree_cokret_paths(
    root: &Path,
    openapi_paths: &OpenApiPathSet,
) -> Result<Vec<CokretPathFinding>> {
    let mut out = Vec::new();
    walk(root, &mut |file_path| {
        if should_skip_file(file_path) {
            return Ok(());
        }
        let file_kind = FileKind::from_path(file_path);
        if matches!(file_kind, FileKind::Other) {
            return Ok(());
        }
        let raw = match fs::read_to_string(file_path) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };
        scan_file_cokret_paths(file_path, file_kind, &raw, openapi_paths, &mut out);
        Ok(())
    })?;
    Ok(out)
}

pub fn scan_file_cokret_paths(
    path: &Path,
    file_kind: FileKind,
    contents: &str,
    openapi_paths: &OpenApiPathSet,
    out: &mut Vec<CokretPathFinding>,
) {
    for (line_idx, line) in contents.lines().enumerate() {
        for candidate in extract_cokret_paths(line) {
            let normalized = normalize_path(&candidate.path);
            if normalized.is_empty() {
                continue;
            }
            if is_namespace_reference(&normalized) || has_unbalanced_brace(&normalized) {
                continue;
            }
            let openapi_match = openapi_paths.matches(&normalized).map(ToOwned::to_owned);
            let (allowed_legacy_match, allowed_legacy_reason) = legacy_allow_reason(&normalized)
                .map_or((false, None), |reason| (true, Some(reason.to_string())));
            out.push(CokretPathFinding {
                path: path.to_path_buf(),
                line: line_idx + 1,
                column: candidate.column + 1,
                matched_path: candidate.path,
                normalized_path: normalized,
                openapi_match,
                allowed_legacy_match,
                allowed_legacy_reason,
                file_kind,
            });
        }
    }
}

fn legacy_allow_reason(path: &str) -> Option<&'static str> {
    LEGACY_PATH_ALLOWLIST
        .iter()
        .find(|rule| path == rule.prefix || path.starts_with(&format!("{}/", rule.prefix)))
        .map(|rule| rule.reason)
}

fn is_namespace_reference(path: &str) -> bool {
    matches!(
        path,
        "/_cokret"
            | "/_cokret/self"
            | "/_cokret/peer"
            | "/_cokret/root"
            | "/_cokret/root/identity"
            | "/_cokret/edge"
            | "/_cokret/find"
            | "/_cokret/find/directory"
            | "/_cokret/gate"
    )
}

fn has_unbalanced_brace(path: &str) -> bool {
    path.bytes().filter(|b| *b == b'{').count() != path.bytes().filter(|b| *b == b'}').count()
}

#[derive(Clone, Debug)]
struct ExtractedPath {
    column: usize,
    path: String,
}

fn extract_cokret_paths(line: &str) -> Vec<ExtractedPath> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = line[offset..].find("/_cokret") {
        let start = offset + relative;
        let tail = &line[start..];
        let end = tail
            .char_indices()
            .find_map(|(idx, ch)| (!is_path_char(ch)).then_some(idx))
            .unwrap_or(tail.len());
        if end > 0 {
            out.push(ExtractedPath {
                column: start,
                path: tail[..end].to_string(),
            });
        }
        offset = start + end.max(1);
        if offset >= line.len() {
            break;
        }
    }
    out
}

fn is_path_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric()
        || matches!(
            ch,
            '/' | '_'
                | '-'
                | '.'
                | ':'
                | '%'
                | '{'
                | '}'
                | '$'
                | '('
                | ')'
                | '['
                | ']'
                | '?'
                | '&'
                | '='
                | '+'
                | '~'
        )
}

fn normalize_path(raw: &str) -> String {
    let without_query = raw.split_once('?').map_or(raw, |(path, _)| path);
    without_query
        .trim_end_matches(|ch: char| matches!(ch, '.' | ',' | ';' | ':' | ')' | '`' | '"' | '\''))
        .trim_end_matches('/')
        .to_string()
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
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if should_skip_dir(&dir) {
            continue;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
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

fn should_skip_dir(dir: &Path) -> bool {
    let Some(name) = dir.file_name().and_then(|n| n.to_str()) else {
        return false;
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

fn should_skip_file(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|n| n.to_str()),
        Some("cokret_path_rules.rs" | "cokret_path_namespace_gate.rs")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_paths() -> OpenApiPathSet {
        OpenApiPathSet::from_paths([
            "/_cokret/describe",
            "/_cokret/self/events",
            "/_cokret/self/events/{event_id}",
        ])
    }

    #[test]
    fn openapi_exact_path_is_not_violation() {
        let mut out = Vec::new();
        scan_file_cokret_paths(
            Path::new("e2e/test.ts"),
            FileKind::Typescript,
            "await request.get(`${base}/_cokret/self/events?limit=20`);",
            &spec_paths(),
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert!(!out[0].is_violation(), "{out:?}");
        assert_eq!(
            out[0].openapi_match.as_deref(),
            Some("/_cokret/self/events")
        );
    }

    #[test]
    fn openapi_template_path_is_not_violation() {
        let mut out = Vec::new();
        scan_file_cokret_paths(
            Path::new("src/scenario.rs"),
            FileKind::Rust,
            r#"server.url("/_cokret/self/events/ck:event:abc")"#,
            &spec_paths(),
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert!(!out[0].is_violation(), "{out:?}");
        assert_eq!(
            out[0].openapi_match.as_deref(),
            Some("/_cokret/self/events/{event_id}")
        );
    }

    #[test]
    fn legacy_surface_is_allowed_but_visible() {
        let mut out = Vec::new();
        scan_file_cokret_paths(
            Path::new("e2e/webrtc.ts"),
            FileKind::Typescript,
            "await request.post(`${base}/_cokret/self/webrtc/sessions`);",
            &spec_paths(),
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert!(out[0].openapi_match.is_none());
        assert!(out[0].allowed_legacy_match);
        assert!(!out[0].is_violation());
    }

    #[test]
    fn new_non_spec_path_is_violation() {
        let mut out = Vec::new();
        scan_file_cokret_paths(
            Path::new("e2e/new.ts"),
            FileKind::Typescript,
            "await request.post(`${base}/_cokret/self/new-product-surface`);",
            &spec_paths(),
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert!(out[0].is_violation(), "{out:?}");
    }
}
