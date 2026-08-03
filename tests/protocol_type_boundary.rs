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

#[test]
fn authored_events_remain_sdk_events_until_the_submission_wrapper() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let builder = fs::read_to_string(manifest.join("src/harness/event_builder.rs"))
        .expect("read Event builder source");
    for function in [
        "event_envelope",
        "event_envelope_with_signing_seed",
        "event_envelope_with_signing_seed_and_verification_method",
        "event_envelope_at_frontier_with_signing_seed",
        "event_envelope_with_chain",
        "event_envelope_with_causal_refs",
    ] {
        let start = builder
            .find(&format!("fn {function}"))
            .unwrap_or_else(|| panic!("missing {function}"));
        let signature = builder[start..]
            .split_once('{')
            .map(|(signature, _)| signature)
            .expect("function signature has a body");
        assert!(
            signature.contains("-> Event"),
            "{function} must return the SDK Event type, not an untyped JSON value: {signature}"
        );
    }

    let publication =
        fs::read_to_string(manifest.join("src/publication.rs")).expect("read publication helpers");
    assert!(
        !publication.contains("initial_submission_value"),
        "normal Event publication must not decode an arbitrary JSON value at the HTTP boundary"
    );
}
