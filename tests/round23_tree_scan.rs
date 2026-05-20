//! One-shot scan driver for the round 2+3 structural-drift rules.
//!
//! Invoked manually via `cargo test --test round23_tree_scan -- --ignored
//! --nocapture` — it walks the contrix-dev tree from
//! `D:\Works\contrix-dev` (or the directory in `CONTRIX_DEV_ROOT`) and
//! reports any [`Round23Finding`] residual violations from sibling
//! projects (excluding `contrix-spec`, `cotest` itself, and noisy
//! build/target dirs).
//!
//! Marked `#[ignore]` so it does not run on regular `cargo test`. Lives
//! under `tests/` so it has access to the public scanner without
//! needing a separate binary target.

use std::path::PathBuf;

use cotest::literal_scanner::scan_tree_round23;

#[test]
#[ignore = "manual: cargo test --test round23_tree_scan -- --ignored --nocapture"]
fn round23_tree_scan_other_projects() {
    let dev_root = std::env::var("CONTRIX_DEV_ROOT")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"D:\Works\contrix-dev"));
    assert!(
        dev_root.exists(),
        "dev root does not exist: {}",
        dev_root.display()
    );

    let projects = [
        "soland",
        "floria",
        "chime",
        "yougen",
        "teabay",
        "coauth",
        "sodmin",
        "starid",
        "contrix-rust-sdk",
        "e2e",
        "logos",
    ];

    let mut total_findings = 0usize;
    for proj in projects {
        let root = dev_root.join(proj);
        if !root.exists() {
            eprintln!("[skip] {proj}: not present");
            continue;
        }
        let findings = scan_tree_round23(&root).expect("scan must not fail");
        if findings.is_empty() {
            println!("[clean] {proj}");
        } else {
            println!("[FINDINGS={}] {proj}:", findings.len(), proj = proj);
            for f in &findings {
                println!(
                    "  {}:{}:{} {} [{}] {}",
                    f.path.display(),
                    f.line,
                    f.column,
                    f.rule.as_str(),
                    f.matched_literal,
                    f.message
                );
            }
        }
        total_findings += findings.len();
    }
    println!("\nTOTAL round23 findings across other projects: {total_findings}");
}
