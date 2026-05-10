//! Shared scenario helpers extracted from large submodules during the round 28
//! Q1 refactor. Code here is identical to what previously lived inline in
//! individual scenario files; the move keeps each scenario submodule
//! single-responsibility while retaining the original semantics.

pub mod bridge;
pub mod coauth_bootstrap;
pub mod external_binary;
pub mod floria_bootstrap;
