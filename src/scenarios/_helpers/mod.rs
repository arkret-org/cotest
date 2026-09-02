//! Scenario helpers shared by more than one scenario submodule.
//!
//! Anything used by a single scenario stays inline in that scenario; this
//! module exists so the scenario submodules stay single-responsibility.

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
