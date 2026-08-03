use std::fs;
use std::path::{Path, PathBuf};

fn rust_sources(root: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).expect("read source directory") {
        let path = entry.expect("read source entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn http_json_bodies_cannot_start_from_an_untyped_json_macro() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    rust_sources(&manifest.join("src"), &mut sources);
    rust_sources(&manifest.join("tests"), &mut sources);

    let direct_json = [".json(&", "json!("].concat();
    let qualified_json = [".json(&serde_json::", "json!("].concat();
    let mut violations = Vec::new();
    for path in sources {
        let source = fs::read_to_string(&path).expect("read Rust source");
        for (index, line) in source.lines().enumerate() {
            if line.contains(&direct_json) || line.contains(&qualified_json) {
                violations.push(format!(
                    "{}:{}: {}",
                    path.strip_prefix(manifest).unwrap_or(&path).display(),
                    index + 1,
                    line.trim()
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "HTTP protocol bodies must use SDK request types. Wire-negative cases must mutate a legal SDK baseline through wire_negative_from_sdk, and removed/non-protocol probes must use NonProtocolTestBody:\n{}",
        violations.join("\n")
    );
}
