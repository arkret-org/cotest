//! One-shot scan driver for the round-4 structural-drift rules across
//! the 10 implementer projects.
//!
//! Task C2 in `_todos.md`: run the literal scanner over the 10 sibling
//! project roots, surface every violation, drive them to zero (or
//! `ROUND4-ALLOW`-tagged with justification).
//!
//! Invoked manually via:
//!
//! ```text
//! cargo test --test round4_external_scan -- --ignored --nocapture
//! ```
//!
//! Marked `#[ignore]` so it does not run on regular `cargo test`. Lives
//! under `tests/` so it can reach the public scanner via
//! `cotest::literal_scanner::scan_tree_round4` without a separate binary
//! target.

use std::path::PathBuf;

use cotest::literal_scanner::scan_tree_round4;

#[test]
#[ignore = "manual: cargo test --test round4_external_scan -- --ignored --nocapture"]
fn round4_external_scan_all_projects() {
    let dev_root = std::env::var("CONTRIX_DEV_ROOT")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"D:\Works\contrix-dev"));
    assert!(
        dev_root.exists(),
        "dev root does not exist: {}",
        dev_root.display()
    );

    // The 10 implementer projects covered by Round 4. Order matches the
    // C2 task listing in `_todos.md`.
    let projects = [
        "contrix-rust-sdk",
        "soland",
        "coauth",
        "sodmin",
        "floria",
        "chime",
        "yougen",
        "cotest",
        "teabay",
        "starid",
    ];

    let mut total_findings = 0usize;
    let mut per_project: Vec<(String, usize)> = Vec::new();
    for proj in projects {
        let root = dev_root.join(proj);
        if !root.exists() {
            eprintln!("[skip] {proj}: not present");
            per_project.push((proj.to_string(), 0));
            continue;
        }
        let findings = scan_tree_round4(&root).expect("scan must not fail");
        if findings.is_empty() {
            println!("[clean] {proj}");
        } else {
            println!("[FINDINGS={}] {proj}:", findings.len());
            for f in &findings {
                println!(
                    "  {}:{}:{} [{}] {} -- {}",
                    f.path.display(),
                    f.line,
                    f.column,
                    f.rule.as_str(),
                    f.matched_literal,
                    f.message
                );
            }
        }
        per_project.push((proj.to_string(), findings.len()));
        total_findings += findings.len();
    }

    println!();
    println!("ROUND-4 PER-PROJECT SUMMARY:");
    for (proj, count) in &per_project {
        println!("  {proj:>20} : {count}");
    }
    println!("ROUND-4 SCAN TOTAL FINDINGS={total_findings}");

    assert_eq!(
        total_findings, 0,
        "round-4 scan must finish with zero violations; see per-project listing above",
    );
}
