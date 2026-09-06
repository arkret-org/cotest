//! Shared test support for Cotest, on a build edge that excludes the UI and
//! server implementation crates.
//!
//! Today this crate exists to give `cotest-wire` a package whose dependency
//! graph is SDK-only; the binary itself is self-contained and imports nothing
//! from here. The canonical provisioning module described in
//! `arkret-work/work/active/2026-09-06-1725-…` lands here next, at which point
//! this file stops being empty.
//!
//! What must stay true as it grows: the dependency direction is
//! `cotest` / test tooling -> `cotest-test-support` -> Garth / SDK. This crate
//! never depends back on the root `cotest` package, on `inkson`, on Dioxus, or
//! on the `soland-*` implementation crates. Process and container lifecycles
//! stay in the runner and in `_helpers/coauth_bootstrap.rs`; this crate is
//! handed endpoints, identities and trust material, and never starts a service.

#![deny(unsafe_code)]
