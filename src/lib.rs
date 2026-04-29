//! External conformance and interoperability harness for Contrix servers.
//!
//! The executable behavior lives in integration tests so the harness can start
//! real server processes and exercise them only through public HTTP contracts.

pub const HARNESS_NAME: &str = "cotest";
