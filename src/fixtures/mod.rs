//! Reusable test fixtures for cotest scenarios.
//!
//! Each fixture in this module reduces per-scenario boilerplate. The first
//! addition is [`TestActorBuilder`] — a fluent builder for the common
//! "register actor + login + pre-seed spaces" preamble that nearly every
//! scenario repeats.
//!
//! These helpers intentionally live above `crate::scenarios` so they can be
//! reused from both scenario code and integration test files in
//! `tests/`.

pub mod builders;
pub mod scaffold;

pub use builders::TestActorBuilder;
pub use scaffold::{MultiScaffold, TestScaffold};
