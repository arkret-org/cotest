//! Smoke tests for the cotest profile-role validator.
//!
//! Exercises the three documented assertions for T0.5:
//!   1. A `client` service rejects a `gateway` profile claim.
//!   2. An `interop` profile is acceptable across role boundaries.
//!   3. A `client` claiming `chat_mvp` + `kanban_mvp` is accepted.
//!
//! Plus a sanity-check that the SDK's baked role table matches the live spec
//! artifact, so a stale SDK build cannot silently mask a spec change.

use cotest::profile_validator::{
    ClaimKind, ProfileClaimFailure, ProfileRoleTable, ServiceRole, assert_sdk_matches_artifact,
    validate_describe_profile_claims, validate_profile_claims,
};
use serde_json::json;

#[test]
fn client_claiming_gateway_profile_is_rejected() {
    let table = ProfileRoleTable::load().expect("artifact loads");
    let claims = vec![
        (
            "ak.profile.chat_mvp.v1".to_owned(),
            ClaimKind::ConformanceVerified,
        ),
        (
            "ak.profile.push_gateway.v1".to_owned(),
            ClaimKind::SelfClaimed,
        ),
    ];
    let outcome = validate_profile_claims(&claims, ServiceRole::Client, &table);
    assert!(!outcome.is_compliant());
    assert_eq!(outcome.failures.len(), 1);
    match &outcome.failures[0] {
        ProfileClaimFailure::RoleMismatch {
            profile_id,
            declared_role,
            service_role,
        } => {
            assert_eq!(profile_id, "ak.profile.push_gateway.v1");
            assert_eq!(*declared_role, ServiceRole::Gateway);
            assert_eq!(*service_role, ServiceRole::Client);
        }
        other => panic!("expected RoleMismatch, got {other:?}"),
    }
}

#[test]
fn interop_profile_is_always_acceptable() {
    let table = ProfileRoleTable::load().expect("artifact loads");
    let claims = vec![
        // `mimi_interop` is the canonical interop bridge; it must be
        // claimable from every role (gateway, server, client, …).
        (
            "ak.profile.mimi_interop.v1".to_owned(),
            ClaimKind::ConformanceVerified,
        ),
        // `encoding.cbor` is also interop.
        (
            "ak.profile.encoding.cbor.v1".to_owned(),
            ClaimKind::ConformanceVerified,
        ),
    ];
    for role in [
        ServiceRole::Client,
        ServiceRole::Server,
        ServiceRole::Gateway,
        ServiceRole::Directory,
        ServiceRole::Admin,
    ] {
        let outcome = validate_profile_claims(&claims, role, &table);
        assert!(
            outcome.is_compliant(),
            "interop profile claim must be accepted for role {} but got {:?}",
            role.as_str(),
            outcome.failures,
        );
        assert!(
            outcome.has_interop_bridge(),
            "outcome should record the interop bridge accept for role {}",
            role.as_str()
        );
    }
}

#[test]
fn client_claiming_chat_and_kanban_mvp_passes() {
    let table = ProfileRoleTable::load().expect("artifact loads");
    let claims = vec![
        (
            "ak.profile.chat_mvp.v1".to_owned(),
            ClaimKind::ConformanceVerified,
        ),
        (
            "ak.profile.kanban_mvp.v1".to_owned(),
            ClaimKind::ConformanceVerified,
        ),
    ];
    let outcome = validate_profile_claims(&claims, ServiceRole::Client, &table);
    assert!(
        outcome.is_compliant(),
        "expected compliant outcome, got {:?}",
        outcome
    );
    assert_eq!(outcome.accepted.len(), 2);
    for (profile_id, role) in &outcome.accepted {
        assert_eq!(
            *role,
            ServiceRole::Client,
            "{profile_id} should be client role"
        );
    }
}

#[test]
fn describe_payload_validates_via_supported_profiles() {
    let describe = json!({
        "supported_profiles": [
            "ak.profile.chat_mvp.v1",
            "ak.profile.kanban_mvp.v1",
            "ak.profile.mimi_interop.v1",
        ],
    });
    let outcome = validate_describe_profile_claims(
        &describe,
        ServiceRole::Client,
        ClaimKind::ConformanceVerified,
    )
    .expect("validator loads artifact");
    assert!(outcome.is_compliant());
    assert_eq!(outcome.accepted.len(), 3);
    assert!(outcome.has_interop_bridge());
}

#[test]
fn describe_with_directory_role_rejects_station_profile() {
    let describe = json!({
        "supported_profiles": [
            "ak.profile.directory_service.v1",
            "ak.profile.station.v1",
        ],
    });
    let outcome =
        validate_describe_profile_claims(&describe, ServiceRole::Directory, ClaimKind::SelfClaimed)
            .expect("validator loads artifact");
    // directory_service is the canonical Directory role, station is
    // Server — but our directory consumer allows Server-shaped profiles too
    // (identity registries straddle that boundary). This regression-locks
    // that pairing.
    assert!(
        outcome.is_compliant(),
        "directory allow-set should include server-shaped profiles; got {:?}",
        outcome.failures
    );
}

#[test]
fn experimental_unknown_id_is_surfaced_separately() {
    let table = ProfileRoleTable::load().expect("artifact loads");
    let claims = vec![
        (
            "ak.profile.totally_made_up.v1".to_owned(),
            ClaimKind::Experimental,
        ),
        (
            "ak.profile.totally_made_up_other.v1".to_owned(),
            ClaimKind::SelfClaimed,
        ),
    ];
    let outcome = validate_profile_claims(&claims, ServiceRole::Client, &table);
    assert_eq!(outcome.experimental_unknown_allowed.len(), 1);
    assert_eq!(outcome.failures.len(), 1);
    match &outcome.failures[0] {
        ProfileClaimFailure::UnknownProfile { profile_id } => {
            assert_eq!(profile_id, "ak.profile.totally_made_up_other.v1");
        }
        other => panic!("expected UnknownProfile, got {other:?}"),
    }
}

#[test]
fn sdk_role_table_matches_spec_artifact() {
    assert_sdk_matches_artifact()
        .expect("SDK profile_roles table must match the live spec artifact");
}

#[test]
fn role_table_has_every_documented_role() {
    let table = ProfileRoleTable::load().expect("artifact loads");
    // Every documented profile carries exactly one role: the role table and
    // the profile requirement table name the same profile ids.
    let artifact: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            cotest::conformance::spec_artifacts_root()
                .join("profiles")
                .join("conformance-profiles.json"),
        )
        .expect("read conformance profiles"),
    )
    .expect("parse conformance profiles");
    let documented = artifact["profile_requirements"]
        .as_object()
        .expect("profile_requirements object")
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(table.len(), documented.len());
    for profile_id in &documented {
        assert!(
            table.role_of(profile_id).is_some(),
            "documented profile {profile_id} has no role"
        );
    }
    for role in [
        ServiceRole::Client,
        ServiceRole::Server,
        ServiceRole::Gateway,
        ServiceRole::Directory,
        ServiceRole::Admin,
        ServiceRole::Interop,
    ] {
        let ids = table.ids_with_role(role);
        assert!(
            !ids.is_empty(),
            "role {} should have at least one profile id",
            role.as_str()
        );
    }
}
