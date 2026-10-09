//! Inkson-dependent production-client conformance. Dependency direction is client -> server
//! harness.
pub use cotest::{harness, publication, transcripts};
pub mod conformance {
    pub use cotest::conformance::*;
    pub mod account_blocklist_projection;
    pub mod webrtc_media_plaintext;
    pub use account_blocklist_projection::*;
    pub use webrtc_media_plaintext::*;
    pub mod named_suite_audit;
    pub use named_suite_audit::{inspect_named_suite_execution, run_named_suite_audit};
}
pub mod scenarios {
    pub use cotest::scenarios::{
        _helpers, bridge_contracts, cross_station_mls_welcome, human_device_producer_live,
        identity_test_support, invite_create_and_dispatch, message_mls_cross_station_live,
        security_rotation_live, strand_watch_live,
    };
    mod client_observers;
    pub mod direct_conversation_founding_live {
        pub use cotest::scenarios::direct_conversation_founding_live::blocklist_dm_binding_snapshot_live;

        pub use super::client_observers::{
            blocklist_case5_dm_history_and_contact_terminal_live,
            blocklist_contact_first_dm_pending_request_live, blocklist_dm_retained_receipt_live,
        };
    }
    pub mod mls_lifecycle_live {
        pub use cotest::scenarios::mls_lifecycle_live::*;

        pub use super::client_observers::{
            run_blocklist_automatic_receipt_live, run_blocklist_call_invite_live,
        };
    }
    pub mod protocol_payloads {
        pub use cotest::scenarios::protocol_payloads::*;
        mod snapshot_head_disclosure;
        pub use snapshot_head_disclosure::*;
    }
    pub mod calendar_rsvp_convergence;
    pub mod invite_frozen_prestate_live;
    pub mod kanban_identity_boundary;
    pub mod websocket_live;
}
