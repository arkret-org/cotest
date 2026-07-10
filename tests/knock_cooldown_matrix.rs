//! CT-4 — Knock + member.application + cooldown matrix (entrypoint).
//!
//! Marked `#[ignore]` because the test depends on soland reducer support
//! for `ak.realm.join_rule="knock"`, `member.application` /
//! `member.application.review` event kinds, and the §3.11 anti-abuse
//! enforcement (cooldown_after_reject, application_ttl,
//! max_open_applications_per_actor) — none of which currently land in
//! soland's event-kind dispatcher.
//!
//! See `cotest::scenarios::knock_cooldown_matrix` for the full matrix
//! sketch and the prerequisite blocker list.
//!
//! Run with:
//!
//!   cargo test --test knock_cooldown_matrix -- --ignored

use anyhow::Result;
use serial_test::serial;

/// Gating: needs soland reducer support for `ak.realm.join_rule="knock"`,
/// `member.application` + review event kinds, and §3.11 anti-abuse
/// enforcement (`cooldown_after_reject`, `application_ttl`,
/// `max_open_applications_per_actor`).
/// Issue: CT-4 (knock cooldown matrix)
/// Tier: live
#[tokio::test]
#[ignore = "needs soland reducer support for knock join_rule + member.application + cooldown/TTL/max_open enforcement (see CT-4)"]
#[serial]
async fn knock_cooldown_matrix() -> Result<()> {
    cotest::scenarios::knock_cooldown_matrix::knock_cooldown_matrix_run().await
}
