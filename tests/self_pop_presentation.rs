//! SPEC-CR-001 — RFC 9421 sender-constrained (PoP) presentation on the
//! `/_cokret/self/*` surface (api-conventions.md §3.2 / service-http-binding.md
//! §2.5).
//!
//! This is the protocol-level conformance vector for the joint client/server
//! PoP path: a client signs a self request with its `ck.session.grant`
//! session key; the Principal Server verifies it with the shared SDK verifier.
//! It exercises the same construction yougen produces and soland accepts, and
//! pins the negative cases (tampered body, expired window, over-long window,
//! wrong key) that MUST be rejected.

use cokret_signatures::http_signature::{
    Component, ContentDigest, ContentDigestAlgorithm, Ed25519SigningKey, SignatureInput,
    SignatureVerificationPolicy, SignedRequestParts, canonical_message, public_key_from_bytes,
    sign_message, verify_signed_http_message,
};

const MAX_WINDOW_SECONDS: i64 = 300;
const SKEW_SECONDS: i64 = 30;

struct SignedRequest {
    method: String,
    target_uri: String,
    authority: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Sign a self request exactly as the client (yougen) does: cover
/// `@method`/`@target-uri`/`@authority` plus `content-digest` over the body.
fn sign_self_request(
    signing_key: &Ed25519SigningKey,
    key_id: &str,
    method: &str,
    target_uri: &str,
    authority: &str,
    path: &str,
    body: &[u8],
    created: i64,
    expires: i64,
) -> SignedRequest {
    let mut covered = vec![Component::Method, Component::TargetUri, Component::Authority];
    let mut names = vec!["\"@method\"", "\"@target-uri\"", "\"@authority\""];
    let mut headers: Vec<(String, String)> = Vec::new();
    let digest = if body.is_empty() {
        None
    } else {
        let digest = ContentDigest::compute(body, ContentDigestAlgorithm::Sha256);
        covered.push(Component::Header("content-digest".to_owned()));
        names.push("\"content-digest\"");
        headers.push(("content-digest".to_owned(), digest.wire_value.clone()));
        Some(digest.wire_value)
    };
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
        target_uri: target_uri.to_owned(),
        authority: authority.to_owned(),
        path: path.to_owned(),
        headers: Vec::new(),
        body_digest: digest,
    };
    let canonical = canonical_message(&parts, &signature_input).expect("canonical");
    let signature = sign_message(&canonical, signing_key);
    headers.push(("signature-input".to_owned(), format!("sig1={params_value}")));
    headers.push(("signature".to_owned(), format!("sig1=:{signature}:")));
    SignedRequest {
        method: method.to_owned(),
        target_uri: target_uri.to_owned(),
        authority: authority.to_owned(),
        path: path.to_owned(),
        headers,
        body: body.to_vec(),
    }
}

/// The verification soland's `session_pop` hoop performs: SDK verify (covered
/// components + content-digest + created/expires sanity) plus the 300s window
/// upper bound.
fn verify_self_pop(
    req: &SignedRequest,
    public_key: &cokret_signatures::http_signature::Ed25519PublicKey,
    now: i64,
) -> Result<(), String> {
    let policy = if req.body.is_empty() {
        SignatureVerificationPolicy::new(vec![
            Component::Method,
            Component::TargetUri,
            Component::Authority,
        ])
        .require_content_digest(false)
    } else {
        SignatureVerificationPolicy::service_ingest().require_content_digest(true)
    }
    .max_clock_skew_seconds(SKEW_SECONDS);

    let verified = verify_signed_http_message(
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
    if verified.signature_input.expires - verified.signature_input.created > MAX_WINDOW_SECONDS {
        return Err("window exceeds 300s".to_owned());
    }
    Ok(())
}

fn test_key(seed: u8) -> Ed25519SigningKey {
    cokret_signatures::http_signature::signing_key_from_seed(&[seed; 32])
}

const URI: &str = "https://soland.example.com/_cokret/self/events";
const AUTHORITY: &str = "soland.example.com";
const PATH: &str = "/_cokret/self/events";

#[test]
fn signed_self_write_is_accepted() {
    let key = test_key(7);
    let now = 1_716_000_000;
    let body = br#"{"hello":"world"}"#;
    let req = sign_self_request(
        &key, "kid-1", "POST", URI, AUTHORITY, PATH, body, now, now + 120,
    );
    verify_self_pop(&req, &key.verifying_key(), now).expect("valid PoP accepted");
}

#[test]
fn signed_self_read_without_body_is_accepted() {
    let key = test_key(8);
    let now = 1_716_000_000;
    let req = sign_self_request(&key, "kid-1", "GET", URI, AUTHORITY, PATH, b"", now, now + 120);
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
        URI,
        AUTHORITY,
        PATH,
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
        URI,
        AUTHORITY,
        PATH,
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
    let req = sign_self_request(
        &key,
        "kid-1",
        "POST",
        URI,
        AUTHORITY,
        PATH,
        br#"{"a":1}"#,
        now,
        now + 3_600,
    );
    assert!(verify_self_pop(&req, &key.verifying_key(), now).is_err());
}

#[test]
fn wrong_key_is_rejected() {
    let signer = test_key(7);
    let attacker_view = test_key(9);
    let now = 1_716_000_000;
    let req = sign_self_request(
        &signer,
        "kid-1",
        "POST",
        URI,
        AUTHORITY,
        PATH,
        br#"{"a":1}"#,
        now,
        now + 120,
    );
    assert!(verify_self_pop(&req, &attacker_view.verifying_key(), now).is_err());
}

#[test]
fn public_key_from_bytes_roundtrips() {
    let key = test_key(7);
    let parsed = public_key_from_bytes(&key.verifying_key().to_bytes()).expect("valid key");
    assert_eq!(parsed.to_bytes(), key.verifying_key().to_bytes());
}
