use anyhow::Result;
use cotest::conformance::{
    NamedSuiteAuditReport, inspect_named_suite_execution_with_clients,
    run_named_suite_audit_with_clients,
};

use super::{
    ACCOUNT_BLOCKLIST_PROJECTION_ENTRYPOINT, WEBRTC_MEDIA_PLAINTEXT_ENTRYPOINT,
    run_account_blocklist_projection_suite, run_webrtc_media_plaintext_suite,
};
/// The combined claim gate requires every current server/SDK and production-client suite.
pub fn run_named_suite_audit() -> Result<NamedSuiteAuditReport> {
    run_named_suite_audit_with_clients(&[
        (
            ACCOUNT_BLOCKLIST_PROJECTION_ENTRYPOINT,
            run_account_blocklist_projection_suite,
        ),
        (
            WEBRTC_MEDIA_PLAINTEXT_ENTRYPOINT,
            run_webrtc_media_plaintext_suite,
        ),
    ])
}

/// Execute the combined registry while retaining every incomplete obligation.
pub fn inspect_named_suite_execution() -> Result<NamedSuiteAuditReport> {
    inspect_named_suite_execution_with_clients(&[
        (
            ACCOUNT_BLOCKLIST_PROJECTION_ENTRYPOINT,
            run_account_blocklist_projection_suite,
        ),
        (
            WEBRTC_MEDIA_PLAINTEXT_ENTRYPOINT,
            run_webrtc_media_plaintext_suite,
        ),
    ])
}
