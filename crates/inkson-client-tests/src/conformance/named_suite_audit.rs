use anyhow::Result;
use cotest::conformance::{NamedSuiteAuditReport, run_named_suite_audit_with_clients};

use super::{
    ACCOUNT_BLOCKLIST_PROJECTION_ENTRYPOINT, WEBRTC_MEDIA_PLAINTEXT_ENTRYPOINT,
    run_account_blocklist_projection_suite, run_webrtc_media_plaintext_suite,
};
/// The mandatory combined registry executes all 52 server/SDK and two production-client suites.
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
