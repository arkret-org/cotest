//! DID-P1-C01 — self-test for the counting DID authority.
//!
//! Boots `e2e/mocks/mock-did-host.mjs` on an ephemeral port, drives it through
//! [`cotest::scenarios::_helpers::did_host::DidHostClient`], and pins the
//! contract the DID-P1-C02 scenario matrix depends on:
//!
//!   * every document / log / witness fetch increments the per-DID counters
//!   * `POST /inspect/reset` really zeroes them
//!   * control-plane calls (`/control/*`, `/inspect/*`) are NOT counted, so a scenario's own
//!     bookkeeping cannot pollute the measurement
//!   * `expect_no_additional_authority_calls` passes for a no-op and fails for an operation that
//!     does fetch
//!   * `/control/rotate` swaps the served document without minting new keys
//!
//! Self-contained on purpose: it spawns the mock itself rather than requiring
//! `scripts/run-joint-e2e.ps1`, so it runs in the plain `cargo test` lane. It
//! skips (rather than fails) when `node` is unavailable, matching the
//! `try_spawn` convention used for the sibling service binaries.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use cotest::scenarios::_helpers::did_host::DidHostClient;

/// Kills the mock on drop so a failing assertion cannot leak a node process.
struct MockDidHost {
    child: Child,
    base_url: String,
}

impl Drop for MockDidHost {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn node_available() -> bool {
    Command::new("node")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Spawn the mock on an ephemeral port and read the bound URL back off its
/// startup line (`[mock-did-host] listening on http://127.0.0.1:<port> …`).
fn spawn_mock_did_host() -> Option<MockDidHost> {
    if !node_available() {
        eprintln!("skipping: `node` is not on PATH");
        return None;
    }
    let mocks_dir = repo_root().join("e2e").join("mocks");
    let script = mocks_dir.join("mock-did-host.mjs");
    assert!(
        script.is_file(),
        "missing mock script at {}",
        script.display()
    );

    let mut child = Command::new("node")
        .arg(&script)
        .current_dir(&mocks_dir)
        .env("MOCK_DID_HOST_PORT", "0")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mock-did-host.mjs");

    let stderr = child.stderr.take().expect("mock-did-host stderr piped");
    let mut reader = BufReader::new(stderr);
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                if let Some(url) = line.split_whitespace().find(|t| t.starts_with("http://")) {
                    return Some(MockDidHost {
                        child,
                        base_url: url.trim().to_owned(),
                    });
                }
            }
            Err(_) => break,
        }
    }
    let _ = child.kill();
    // `kill` only signals; without the reap the failing run leaves a zombie
    // behind (the success path reaps through `MockDidHost::drop`).
    let _ = child.wait();
    panic!("mock-did-host did not report a listen address within 20s (last line: {line:?})");
}

/// Fetch a URL and return the status, so the test can count fetches without
/// going through any SDK resolver.
async fn fetch_status(http: &reqwest::Client, url: &str) -> u16 {
    http.get(url)
        .send()
        .await
        .unwrap_or_else(|error| panic!("GET {url} failed: {error}"))
        .status()
        .as_u16()
}

#[tokio::test]
async fn mock_did_host_counts_reset_and_rotate() {
    let Some(mock) = spawn_mock_did_host() else {
        return;
    };
    let client = DidHostClient::new(&mock.base_url).expect("build DidHostClient");
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build probe client");

    // A did:webvh subject preseeded from tests/fixtures/_shared/_canonical_dids.json.
    let dids = client.list_dids().await.expect("list registered DIDs");
    assert!(
        !dids.is_empty(),
        "mock-did-host preseeded no DIDs — check the fixture path"
    );
    let subject = dids
        .iter()
        .find(|entry| entry.method == "did:webvh")
        .expect("a did:webvh subject is preseeded");
    let document_url = format!("{}{}/did.json", mock.base_url, subject.base_path);
    let log_url = format!("{}{}/did.jsonl", mock.base_url, subject.base_path);

    // Baseline: nothing fetched yet.
    client.reset_counts().await.expect("reset counters");
    assert_eq!(
        client
            .authority_network_call_count(None)
            .await
            .expect("baseline count"),
        0,
        "counters must start at zero after reset"
    );

    // Two fetches of the same document => count 2.
    assert_eq!(fetch_status(&http, &document_url).await, 200);
    assert_eq!(fetch_status(&http, &document_url).await, 200);
    let counts = client.counts(None).await.expect("counts after two fetches");
    let subject_counts = counts.for_did(&subject.did);
    assert_eq!(
        subject_counts.document, 2,
        "two document fetches must count as 2, got {subject_counts:?}"
    );
    assert_eq!(subject_counts.total, 2);
    assert_eq!(counts.total, 2, "aggregate total must agree");

    // Purposes are counted separately.
    assert_eq!(fetch_status(&http, &log_url).await, 200);
    let counts = client
        .counts(Some(&subject.did))
        .await
        .expect("counts by DID");
    let subject_counts = counts.for_did(&subject.did);
    assert_eq!(subject_counts.document, 2);
    assert_eq!(subject_counts.log, 1);
    assert_eq!(subject_counts.total, 3);

    // Reset really zeroes them.
    client.reset_counts().await.expect("reset counters");
    assert_eq!(
        client
            .authority_network_call_count(None)
            .await
            .expect("count after reset"),
        0,
        "POST /inspect/reset must zero every counter"
    );

    // Control-plane traffic must not be counted, otherwise the assertion
    // wrapper would measure its own bookkeeping.
    client.list_dids().await.expect("list DIDs again");
    client.counts(None).await.expect("read counts");
    assert_eq!(
        client
            .authority_network_call_count(None)
            .await
            .expect("count after control-plane calls"),
        0,
        "/control/* and /inspect/* must never increment the fetch counters"
    );

    // The C02 workhorse: a no-op body makes zero authority calls…
    client
        .expect_no_additional_authority_calls(None, "no-op body", || async { Ok(()) })
        .await
        .expect("a no-op must pass the zero-additional-calls assertion");

    // …and an operation that does fetch is caught.
    let caught = client
        .expect_no_additional_authority_calls(None, "fetching body", || async {
            assert_eq!(fetch_status(&http, &document_url).await, 200);
            Ok(())
        })
        .await;
    assert!(
        caught.is_err(),
        "an operation that fetches the authority MUST fail the zero-additional-calls assertion"
    );

    // Rotation swaps the served document without re-registering the DID.
    let before = subject.version_id.clone();
    let rotated = client.rotate(&subject.did).await.expect("rotate to v2");
    assert_ne!(
        rotated.version_id, before,
        "rotate must change the versionId"
    );
    assert_eq!(rotated.version_index, subject.version_index + 1);
    let body = http
        .get(&document_url)
        .send()
        .await
        .expect("fetch rotated document")
        .text()
        .await
        .expect("rotated document body");
    assert!(
        body.contains("#key-2"),
        "rotated document must expose the second preset key, got {body}"
    );

    // Deactivation is observable in the document.
    client
        .deactivate(&subject.did)
        .await
        .expect("deactivate subject");
    let body = http
        .get(&document_url)
        .send()
        .await
        .expect("fetch deactivated document")
        .text()
        .await
        .expect("deactivated document body");
    assert!(
        body.contains("\"deactivated\":true"),
        "deactivated document must carry deactivated:true, got {body}"
    );

    // Forced failures still count as authority calls — a service hammering a
    // failing authority must not look like "zero network calls".
    client
        .reset_documents()
        .await
        .expect("restore documents to version 0");
    client
        .force_status(&subject.did, Some(503))
        .await
        .expect("force 503");
    client.reset_counts().await.expect("reset counters");
    assert_eq!(fetch_status(&http, &document_url).await, 503);
    assert_eq!(
        client
            .authority_network_call_count(Some(&subject.did))
            .await
            .expect("count after forced failure"),
        1,
        "a failed fetch is still an authority network call"
    );
}

#[tokio::test]
async fn counting_did_resolver_counts_in_process_resolutions() {
    use arkret::identity::{DidDocument, DidResolver};
    use arkret_wire::DidFullId;
    use cotest::scenarios::_helpers::did_host::CountingDidResolver;

    let did = DidFullId::new("did:web:alice.example".to_owned()).expect("parse DID");
    let resolver = CountingDidResolver::new().with_document(DidDocument::new(
        did.clone(),
        "did:web:alice.example#key-1",
        "z6MkfixtureAlicePublicKeyMultibase",
    ));

    assert_eq!(resolver.total_calls(), 0);
    assert!(resolver.supports(&did));

    resolver.resolve_did(&did).expect("first resolution hits");
    resolver.resolve_did(&did).expect("second resolution hits");
    assert_eq!(resolver.calls_for(did.as_str()), 2);
    assert_eq!(resolver.total_calls(), 2);

    // Misses are counted too — a resolver call that fails is still a call.
    let missing = DidFullId::new("did:web:nobody.example".to_owned()).expect("parse DID");
    assert!(resolver.resolve_did(&missing).is_err());
    assert_eq!(resolver.calls_for(missing.as_str()), 1);
    assert_eq!(resolver.total_calls(), 3);

    resolver.reset();
    assert_eq!(resolver.total_calls(), 0);
    assert!(resolver.snapshot().is_empty());
}
