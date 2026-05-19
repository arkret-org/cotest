//! R3.4 — `security_class=high_assurance` Realm federation policy
//! contract test (cotest entry point).
//!
//! Drives the unit-style scenario in
//! [`cotest::scenarios::high_assurance_realm_policy`]. The scenario
//! exercises the SDK invariant validator on `contrix_core::Space`; the
//! reducer-side integration test lives at
//! `soland/tests/high_assurance_policy.rs`. Together they pin the
//! contract that any Realm with `security_class=high_assurance` MUST
//! keep `federation_policy ∈ {closed, restricted, quarantine}`.

use anyhow::Result;

use cotest::scenarios::high_assurance_realm_policy::{
    run_high_assurance_accepts_closed_restricted_quarantine,
    run_high_assurance_rejects_open_federation, run_standard_realm_accepts_open_federation,
};

#[test]
fn high_assurance_rejects_open_federation() -> Result<()> {
    run_high_assurance_rejects_open_federation()
}

#[test]
fn high_assurance_accepts_closed_restricted_quarantine() -> Result<()> {
    run_high_assurance_accepts_closed_restricted_quarantine()
}

#[test]
fn standard_realm_accepts_open_federation() -> Result<()> {
    run_standard_realm_accepts_open_federation()
}
