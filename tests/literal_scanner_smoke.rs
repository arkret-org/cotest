//! Smoke tests for the repo-level literal scanner.
//!
//! These tests build small in-tmpdir fixture trees, point the scanner at
//! them with a synthetic registry dir, and assert violation / allowlist
//! behavior end-to-end (no cokret-spec fetch required).

use std::fs;
use std::path::PathBuf;

use cotest::literal_scanner::{load_all_rules_from, scan_tree};

fn write(path: &std::path::Path, body: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("mkdir");
    }
    fs::write(path, body).expect("write fixture");
}

fn synthetic_registry(dir: &std::path::Path) {
    fs::create_dir_all(dir).expect("mkdir registry");
    write(
        &dir.join("removed-event-kinds.json"),
        r#"{
  "version": 1,
  "kind": "removed_event_kinds",
  "entries": [
    {
      "id": "cx.flow.track.member",
      "rejection_level": "hard_reject",
      "replacement": null,
      "allowed_contexts": ["changelog", "legacy_migration", "negative_test"],
      "notes": "Smoke fixture."
    },
    {
      "id": "cx.space.delivery_binding_policy",
      "rejection_level": "hard_reject",
      "replacement": "cx.realm.delivery_binding_policy",
      "allowed_contexts": ["changelog", "legacy_migration", "negative_test"],
      "notes": "delivery-binding policy attaches to the Realm security boundary, not the Space container."
    }
  ]
}"#,
    );
    // Stub the other five files as empty entries so loader is happy even
    // when only one artifact is exercised.
    for name in [
        "deprecated-profile-ids.json",
        "removed-operation-ids.json",
        "forbidden-wire-fields.json",
        "forbidden-model-terms.json",
        "renames.json",
    ] {
        write(
            &dir.join(name),
            r#"{ "version": 1, "kind": "stub", "entries": [] }"#,
        );
    }
}

fn tmpdir(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    path.push(format!("cotest-lit-{label}-{pid}-{nanos}"));
    fs::create_dir_all(&path).expect("mktmp");
    path
}

#[test]
fn detects_removed_event_kind_literal() {
    let base = tmpdir("violation");
    let registry = base.join("registry");
    synthetic_registry(&registry);

    let tree = base.join("downstream");
    write(
        &tree.join("src").join("foo.rs"),
        r#"
pub fn removed_kind() -> &'static str {
    "cx.flow.track.member"
}
"#,
    );

    let rules = load_all_rules_from(&registry).expect("load rules");
    let findings = scan_tree(&tree, &rules).expect("scan");
    assert!(
        !findings.is_empty(),
        "expected at least one finding, got none"
    );
    let violations: Vec<_> = findings
        .iter()
        .filter(|f| !f.allowed_context_match)
        .collect();
    assert!(
        !violations.is_empty(),
        "expected unallowed violation, got: {findings:#?}"
    );
    assert!(
        violations
            .iter()
            .any(|f| f.matched_token == "cx.flow.track.member")
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn magic_allow_comment_exempts_finding() {
    let base = tmpdir("magic");
    let registry = base.join("registry");
    synthetic_registry(&registry);

    let tree = base.join("downstream");
    write(
        &tree.join("src").join("allowed.rs"),
        r#"// cokret-allow: cx.flow.track.member
//
// Intentionally references the removed kind to assert allowlist behavior.
pub const REMOVED: &str = "cx.flow.track.member";
"#,
    );

    let rules = load_all_rules_from(&registry).expect("load rules");
    let findings = scan_tree(&tree, &rules).expect("scan");
    assert!(!findings.is_empty(), "expected finding (allowlisted)");
    assert!(
        findings.iter().all(|f| f.allowed_context_match),
        "all findings should be allowlisted, got: {findings:#?}"
    );

    let _ = fs::remove_dir_all(&base);
}
