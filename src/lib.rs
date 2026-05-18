//! Complement-style black-box conformance harness for Contrix servers.
//!
//! `cotest` keeps the executable harness and scenario logic in the main crate.
//! Integration test files are intentionally thin entrypoints.

pub mod conformance;
pub mod fixtures;
pub mod fuzz;
pub mod harness;
pub mod scenarios;
pub mod transcripts;

pub const HARNESS_NAME: &str = "cotest";
