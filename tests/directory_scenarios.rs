//! Integration entrypoints for the directory / anti-enumeration
//! scenarios (P2F.4). Each test drives a pure-Rust helper that models
//! the spec contract; the live teabay binding will be exercised by P5.

use cotest::scenarios::directory::{
    anti_enumeration_buckets::anti_enumeration_buckets_run,
    circle_not_indexed::circle_not_indexed_run, latency_jitter::latency_jitter_run,
    takedown_audit_log::takedown_audit_log_run,
};

#[tokio::test]
async fn directory_anti_enumeration_buckets() {
    anti_enumeration_buckets_run()
        .await
        .expect("anti_enumeration_buckets scenario");
}

#[tokio::test]
async fn directory_latency_jitter() {
    latency_jitter_run().await.expect("latency_jitter scenario");
}

#[tokio::test]
async fn directory_takedown_audit_log() {
    takedown_audit_log_run()
        .await
        .expect("takedown_audit_log scenario");
}

#[tokio::test]
async fn directory_circle_not_indexed() {
    circle_not_indexed_run()
        .await
        .expect("circle_not_indexed scenario");
}
