//! DID-P1-C02 — the joint call-count contract.
//!
//! Every test here records **both** DID-boundary numbers for the operation it
//! drives (`authority_network_call_count` from
//! `coland_did_resolve_total{source="network"}`, `signature_verify_count` from
//! `coland_signature_verify_total`), because either one alone is trivially
//! satisfiable by a broken server.
//!
//! Skips (not passes) when coland's metrics listener is unreachable for the
//! spawn mode in use; see `cotest::scenarios::did_boundary_call_counts` for the
//! coverage boundary and for which matrix rows are deliberately not asserted
//! here.

use cotest::scenarios::did_boundary_call_counts::{
    a_reused_binding_still_rejects_a_bad_signature_run, repeated_requests_under_one_binding_run,
    two_ordinary_events_under_one_key_epoch_run, unknown_issuer_fails_closed_run,
};

/// DID-P1-C02 row 2: two ordinary Events under one key epoch verify twice and
/// resolve zero times.
#[tokio::test(flavor = "multi_thread")]
async fn two_ordinary_events_under_one_key_epoch() {
    two_ordinary_events_under_one_key_epoch_run().await.unwrap();
}

/// DID-P1-C02 row 2, negative: reusing the binding does not weaken the
/// signature check, and a bad signature does not provoke a "resolve to be safe"
/// authority call.
#[tokio::test(flavor = "multi_thread")]
async fn a_reused_binding_still_rejects_a_bad_signature() {
    a_reused_binding_still_rejects_a_bad_signature_run()
        .await
        .unwrap();
}

/// DID-P1-C02 row 3 (coland request face): N ordinary requests cost N
/// verifications and zero authority calls.
#[tokio::test(flavor = "multi_thread")]
async fn repeated_requests_under_one_binding() {
    repeated_requests_under_one_binding_run().await.unwrap();
}

/// DID-P1-C02 row 8: an issuer this server never admitted fails closed.
#[tokio::test(flavor = "multi_thread")]
async fn unknown_issuer_fails_closed() {
    unknown_issuer_fails_closed_run().await.unwrap();
}
