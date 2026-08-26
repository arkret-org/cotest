//! Shared scenario helpers extracted from large submodules during the round 28
//! refactor. Code here is identical to what previously lived inline in
//! individual scenario files; the move keeps each scenario submodule
//! single-responsibility while retaining the original semantics.

pub mod bridge;
pub mod coauth_bootstrap;
pub mod did_host;
pub mod external_binary;
pub mod floria_bootstrap;
pub mod health;
pub mod http;
pub mod joint_service_bootstrap;
pub mod mock_http;
pub mod protocol_values;
pub mod service_metrics;
