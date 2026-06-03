//! Protocol-drift literal-scanner unit smoke. These tests build synthetic
//! tiny fixture trees in `tempdir`, scan them, and assert the right
//! findings appear. The walk-the-tree driver (`scan_tree_protocol_drift`)
//! is also exercised via a one-shot manual cross-project scan, marked
//! `#[ignore]` so it does not run on regular `cargo test`.

use std::fs;
use std::path::PathBuf;

use cotest::literal_scanner::scan_tree_protocol_drift;
use cotest::protocol_drift_rules::ProtocolDriftRule;

fn tmpdir(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    path.push(format!("cotest-drift-{label}-{pid}-{nanos}"));
    fs::create_dir_all(&path).expect("mktmp");
    path
}

fn write(path: &std::path::Path, body: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("mkdir");
    }
    fs::write(path, body).expect("write fixture");
}

#[test]
fn scan_tree_flags_compute_audit_policy_version_digest_two_args() {
    let base = tmpdir("audit");
    let tree = base.join("downstream");
    // Construct the synthetic fixture text at runtime so the source line
    // of *this* test file doesn't itself contain a flag-able two-arg
    // `compute_audit_policy_version_digest` call expression.
    let fn_name = "compute_audit_policy_version_digest";
    let fixture = format!("fn x() {{ {fn_name}(disclosure, assurance); }}");
    write(&tree.join("src").join("audit.rs"), &fixture);
    let findings = scan_tree_protocol_drift(&tree).expect("scan");
    assert!(
        findings
            .iter()
            .any(|f| f.rule == ProtocolDriftRule::AuditPolicyVersionHashFewerThanFourArguments),
        "expected audit_policy_version_digest arity finding: {findings:?}",
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn scan_tree_does_not_flag_legal_did_web() {
    let base = tmpdir("did-ok");
    let tree = base.join("downstream");
    write(
        &tree.join("src").join("foo.rs"),
        r#"pub const ALICE: &str = "did:web:alice.example";"#,
    );
    let findings = scan_tree_protocol_drift(&tree).expect("scan");
    assert!(
        !findings
            .iter()
            .any(|f| f.rule == ProtocolDriftRule::LegacyDidMethodSegment),
        "legal did:web must not be flagged: {findings:?}",
    );
    let _ = fs::remove_dir_all(&base);
}

/// Gating: manual operator scan over sibling project trees — needs
/// `CONTRIX_DEV_ROOT` set; not a CI gate.
#[test]
#[ignore = "manual: cargo test --test protocol_drift_smoke -- --ignored protocol_drift_tree_scan_other_projects --nocapture"]
fn protocol_drift_tree_scan_other_projects() {
    let dev_root = std::env::var("CONTRIX_DEV_ROOT")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"D:\Works\cokret-dev"));
    if !dev_root.exists() {
        eprintln!("[skip] dev root does not exist: {}", dev_root.display());
        return;
    }
    let projects = [
        "soland",
        "floria",
        "chime",
        "yougen",
        "teabay",
        "coauth",
        "sodmin",
        "starid",
        "cokret-rust-sdk",
    ];
    let mut total = 0usize;
    for proj in projects {
        let root = dev_root.join(proj);
        if !root.exists() {
            eprintln!("[skip] {proj}: not present");
            continue;
        }
        let findings = scan_tree_protocol_drift(&root).expect("scan must not fail");
        if findings.is_empty() {
            println!("[clean] {proj}");
        } else {
            println!("[FINDINGS={}] {proj}:", findings.len());
            for f in &findings {
                println!(
                    "  {}:{}:{} [{}] {}",
                    f.path.display(),
                    f.line,
                    f.column,
                    f.rule.as_str(),
                    f.message,
                );
            }
            total += findings.len();
        }
    }
    println!("PROTOCOL-DRIFT SCAN TOTAL FINDINGS={total}");
}
