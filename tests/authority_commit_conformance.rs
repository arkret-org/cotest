//! Authority commit-log conformance entrypoint.
//!
//! Executes `ak.vector.authority_commit.independent_streams.v1` against the
//! SDK's commit-log types: per-stream single chains with strictly incrementing
//! positions, three independent streams with no Realm-global order, the closed
//! `EventCommitSubmission` boundary, bootstrap against the current governance
//! Station, planned handoff (including the refusal of writes from the
//! superseded generation), the atomic MLS Commit-plus-Welcome transaction,
//! irreversible MLS activation, and recovery completion as two consecutive
//! `CommittedEventRef`s in one PCR Realm stream.

use anyhow::Result;
use cotest::conformance::{
    VECTOR_ID_AUTHORITY_COMMIT_INDEPENDENT_STREAMS, run_authority_commit_suite,
};

#[test]
fn authority_commit_independent_streams_vector_executes() -> Result<()> {
    run_authority_commit_suite()
}

#[test]
fn authority_commit_vector_id_is_the_registered_one() {
    assert_eq!(
        VECTOR_ID_AUTHORITY_COMMIT_INDEPENDENT_STREAMS,
        "ak.vector.authority_commit.independent_streams.v1"
    );
}
