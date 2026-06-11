//! Static namespace gate for cotest-owned `/_cokret/*` literals.
//!
//! The protocol namespace must track the authoritative OpenAPI path set.
//! Historical soland-specific surfaces are visible but explicitly allowlisted
//! in `cokret_path_rules`; any new non-spec path fails this test.

use std::path::PathBuf;

use cotest::cokret_path_rules::{load_canonical_openapi_paths, scan_tree_cokret_paths};

#[test]
fn cotest_cokret_paths_match_openapi_or_legacy_allowlist() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let openapi_paths = load_canonical_openapi_paths().expect("load canonical OpenAPI paths");
    assert!(
        !openapi_paths.is_empty(),
        "OpenAPI path set must not be empty"
    );

    let roots = [
        manifest_dir.join("src"),
        manifest_dir.join("tests"),
        manifest_dir.join("e2e"),
    ];
    let mut findings = Vec::new();
    for root in roots {
        if root.exists() {
            findings.extend(scan_tree_cokret_paths(&root, &openapi_paths).expect("scan tree"));
        }
    }

    let violations: Vec<_> = findings
        .iter()
        .filter(|finding| finding.is_violation())
        .collect();
    assert!(
        violations.is_empty(),
        "new non-spec /_cokret paths must be added to OpenAPI or explicitly allowlisted: {violations:#?}"
    );
}
