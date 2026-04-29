//! Complement-style black-box conformance harness for Contrix servers.
//!
//! `cotest` keeps the executable harness and scenario logic in the main crate.
//! Integration test files are intentionally thin entrypoints.

pub mod conformance;
pub mod harness;
pub mod scenarios;

pub const HARNESS_NAME: &str = "cotest";
