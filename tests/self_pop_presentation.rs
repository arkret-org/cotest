//! SPEC-CR-001 — RFC 9421 sender-constrained (PoP) presentation on the
//! `/_arkret/self/*` surface (api-conventions.md §3.2 / service-http-binding.md
//! §2.5).
//!
//! This is the protocol-level conformance vector for the joint client/server
//! PoP path: a client signs a self request with its `ak.session.grant`
//! session key; the Station verifies it with the shared SDK verifier.
//! It exercises the same construction inkson produces and soland accepts, and
//! pins the negative cases (tampered body, expired window, over-long window,
//! wrong key) that MUST be rejected.

use arkret_signatures::http_signature::{
    ContentDigest, ContentDigestAlgorithm, HttpSignatureScenario, SignatureInput,
    SignatureVerificationPolicy, SignedRequestParts, canonical_message,
    http_signature_scenario_components, public_key_from_bytes, sign_message,
    verify_signed_http_message,
};
use ed25519_dalek::{SigningKey, VerifyingKey};

const OPERATION_ID: &str = "ak.self.events.command.submit.v1";

struct SignedRequest {
    method: String,
    target_uri: String,
    authority: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Sign a self request exactly as the client (inkson) does: cover
/// `@method`/`@target-uri`/`@authority` plus `content-digest` over the body.
fn sign_self_request(
    signing_key: &SigningKey,
    key_id: &str,
    method: &str,
    body: &[u8],
    created: i64,
    expires: i64,
) -> SignedRequest {
    let mut applicable_components = Vec::new();
    let mut headers = vec![("arkret-operation".to_owned(), OPERATION_ID.to_owned())];
    let digest = if body.is_empty() {
        None
    } else {
        let digest = ContentDigest::compute(body, ContentDigestAlgorithm::Sha256);
        applicable_components.push("content-digest");
        headers.push(("content-digest".to_owned(), digest.wire_value.clone()));
        Some(digest.wire_value)
    };
    let covered = http_signature_scenario_components(
        HttpSignatureScenario::ClientSessionPopV1,
        &applicable_components,
    )
    .expect("client session PoP scenario is generated");
    let names = covered
        .iter()
        .map(|component| format!("\"{}\"", component.canonical_name()))
        .collect::<Vec<_>>();
    let params_value = format!(
        "({});created={created};expires={expires};keyid=\"{key_id}\";alg=\"ed25519\"",
        names.join(" ")
    );
    let signature_input = SignatureInput {
        label: "sig1".to_owned(),
        covered_components: covered,
        created,
        expires,
        key_id: key_id.to_owned(),
        algorithm: "ed25519".to_owned(),
        params_value: params_value.clone(),
    };
    let parts = SignedRequestParts {
        method: method.to_owned(),
        target_uri: URI.to_owned(),
        authority: AUTHORITY.to_owned(),
        path: PATH.to_owned(),
        headers: vec![("arkret-operation".to_owned(), OPERATION_ID.to_owned())],
        body_digest: digest,
    };
    let canonical = canonical_message(&parts, &signature_input).expect("canonical");
    let signature = sign_message(&canonical, signing_key);
    headers.push(("signature-input".to_owned(), format!("sig1={params_value}")));
    headers.push(("signature".to_owned(), format!("sig1=:{signature}:")));
    SignedRequest {
        method: method.to_owned(),
        target_uri: URI.to_owned(),
        authority: AUTHORITY.to_owned(),
        path: PATH.to_owned(),
        headers,
        body: body.to_vec(),
    }
}

/// The verification soland's `session_pop` hoop performs: SDK verify (covered
/// components + content-digest + the registry-generated freshness window).
fn verify_self_pop(req: &SignedRequest, public_key: &VerifyingKey, now: i64) -> Result<(), String> {
    let applicable_components = if req.body.is_empty() {
        Vec::new()
    } else {
        vec!["content-digest"]
    };
    let policy = SignatureVerificationPolicy::for_scenario(
        HttpSignatureScenario::ClientSessionPopV1,
        &applicable_components,
    )
    .map_err(|error| format!("policy: {error}"))?;

    verify_signed_http_message(
        &req.method,
        &req.target_uri,
        &req.authority,
        &req.path,
        req.headers.iter().map(|(n, v)| (n.as_str(), v.as_str())),
        &req.body,
        public_key,
        &policy,
        now,
    )
    .map_err(|error| format!("verify: {error}"))?;
    Ok(())
}

fn test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

const URI: &str = "https://soland.example.com/_arkret/self/events";
const AUTHORITY: &str = "soland.example.com";
const PATH: &str = "/_arkret/self/events";

#[test]
fn signed_self_write_is_accepted() {
    let key = test_key(7);
    let now = 1_716_000_000;
    let body = br#"{"hello":"world"}"#;
    let req = sign_self_request(&key, "kid-1", "POST", body, now, now + 120);
    verify_self_pop(&req, &key.verifying_key(), now).expect("valid PoP accepted");
}

#[test]
fn signed_self_read_without_body_is_accepted() {
    let key = test_key(8);
    let now = 1_716_000_000;
    let req = sign_self_request(&key, "kid-1", "GET", b"", now, now + 120);
    verify_self_pop(&req, &key.verifying_key(), now).expect("body-less signed GET accepted");
}

#[test]
fn tampered_body_is_rejected() {
    let key = test_key(7);
    let now = 1_716_000_000;
    let mut req = sign_self_request(
        &key,
        "kid-1",
        "POST",
        br#"{"hello":"world"}"#,
        now,
        now + 120,
    );
    req.body = br#"{"hello":"tampered"}"#.to_vec();
    assert!(verify_self_pop(&req, &key.verifying_key(), now).is_err());
}

#[test]
fn expired_window_is_rejected() {
    let key = test_key(7);
    let signed_at = 1_716_000_000;
    let req = sign_self_request(
        &key,
        "kid-1",
        "POST",
        br#"{"a":1}"#,
        signed_at,
        signed_at + 120,
    );
    // Now is well past `expires` + skew.
    assert!(verify_self_pop(&req, &key.verifying_key(), signed_at + 1_000).is_err());
}

#[test]
fn over_long_window_is_rejected() {
    let key = test_key(7);
    let now = 1_716_000_000;
    let req = sign_self_request(&key, "kid-1", "POST", br#"{"a":1}"#, now, now + 3_600);
    assert!(verify_self_pop(&req, &key.verifying_key(), now).is_err());
}

#[test]
fn wrong_key_is_rejected() {
    let signer = test_key(7);
    let attacker_view = test_key(9);
    let now = 1_716_000_000;
    let req = sign_self_request(&signer, "kid-1", "POST", br#"{"a":1}"#, now, now + 120);
    assert!(verify_self_pop(&req, &attacker_view.verifying_key(), now).is_err());
}

#[test]
fn public_key_from_bytes_roundtrips() {
    let key = test_key(7);
    let parsed = public_key_from_bytes(&key.verifying_key().to_bytes()).expect("valid key");
    assert_eq!(parsed.to_bytes(), key.verifying_key().to_bytes());
}
