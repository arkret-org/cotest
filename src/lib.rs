//! Complement-style black-box conformance harness for Arkret servers.
//!
//! `cotest` keeps the executable harness and scenario logic in the main crate.
//! Integration test files are intentionally thin entrypoints.

// Doc-comment formatting in this crate uses heavily indented continuation
// lines, ASCII tables, and free-form bullet structures that pre-date
// clippy's CommonMark-strict lints. The substance is correct; reflowing
// hundreds of comments would create churn without changing behavior.
#![allow(clippy::doc_lazy_continuation, clippy::doc_overindented_list_items)]

pub mod conformance;
pub mod fixtures;
pub mod fuzz;
pub mod harness;
pub mod profile_validator;
pub mod publication;
pub mod scenarios;
pub mod transcripts;

pub const HARNESS_NAME: &str = "cotest";

/// A fixture verification method as the SDK's `arkret_wire::DidUrl`.
///
/// `zh/identity/did-usage-and-verification.md` §2.2 requires every
/// `verification_method` to be a DID URL with a `#fragment`; a bare DID is a
/// fixture bug, not something the type should be widened to accept. Fixture
/// values are compile-time constants of this harness, so a violation is a
/// programming error and panics here rather than being threaded through every
/// builder's error type.
#[track_caller]
pub fn fixture_did_url(value: impl Into<String>) -> arkret_wire::DidUrl {
    let value = value.into();
    arkret_wire::DidUrl::new(value.clone())
        .unwrap_or_else(|error| panic!("cotest fixture verification method {value:?}: {error}"))
}
