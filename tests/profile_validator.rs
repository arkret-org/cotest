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
    ClaimKind, ProfileClaimFailure, ProfileRoleTable, ServiceRole,
    assert_sdk_matches_artifact, validate_describe_profile_claims, validate_profile_claims,
};
use serde_json::json;

#[test]
fn client_claiming_gateway_profile_is_rejected() {
    let table = ProfileRoleTable::load().expect("artifact loads");
    let claims = vec![
        ("cx.profile.chat_mvp.v1".to_owned(), ClaimKind::CotestVerified),
        ("cx.profile.push_gateway.v1".to_owned(), ClaimKind::SelfClaimed),
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
            assert_eq!(profile_id, "cx.profile.push_gateway.v1");
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
            "cx.profile.mimi_interop.v1".to_owned(),
            ClaimKind::CotestVerified,
        ),
        // `matrix_compat` is also interop.
        (
            "cx.profile.matrix_compat.v1".to_owned(),
            ClaimKind::CotestVerified,
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
        ("cx.profile.chat_mvp.v1".to_owned(), ClaimKind::CotestVerified),
        ("cx.profile.kanban_mvp.v1".to_owned(), ClaimKind::CotestVerified),
    ];
    let outcome = validate_profile_claims(&claims, ServiceRole::Client, &table);
    assert!(outcome.is_compliant(), "expected compliant outcome, got {:?}", outcome);
    assert_eq!(outcome.accepted.len(), 2);
    for (profile_id, role) in &outcome.accepted {
        assert_eq!(*role, ServiceRole::Client, "{profile_id} should be client role");
    }
}

#[test]
fn describe_payload_validates_via_supported_profiles() {
    let describe = json!({
        "supported_profiles": [
            "cx.profile.chat_mvp.v1",
            "cx.profile.kanban_mvp.v1",
            "cx.profile.mimi_interop.v1",
        ],
    });
    let outcome = validate_describe_profile_claims(
        &describe,
        ServiceRole::Client,
        ClaimKind::CotestVerified,
    )
    .expect("validator loads artifact");
    assert!(outcome.is_compliant());
    assert_eq!(outcome.accepted.len(), 3);
    assert!(outcome.has_interop_bridge());
}

#[test]
fn describe_with_directory_role_rejects_principal_server_profile() {
    let describe = json!({
        "supported_profiles": [
            "cx.profile.directory_service.v1",
            "cx.profile.principal_server.v1",
        ],
    });
    let outcome = validate_describe_profile_claims(
        &describe,
        ServiceRole::Directory,
        ClaimKind::SelfClaimed,
    )
    .expect("validator loads artifact");
    // directory_service is the canonical Directory role, principal_server is
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
            "cx.profile.totally_made_up.v999".to_owned(),
            ClaimKind::Experimental,
        ),
        (
            "cx.profile.totally_made_up_v2.v999".to_owned(),
            ClaimKind::SelfClaimed,
        ),
    ];
    let outcome = validate_profile_claims(&claims, ServiceRole::Client, &table);
    assert_eq!(outcome.experimental_unknown_allowed.len(), 1);
    assert_eq!(outcome.failures.len(), 1);
    match &outcome.failures[0] {
        ProfileClaimFailure::UnknownProfile { profile_id } => {
            assert_eq!(profile_id, "cx.profile.totally_made_up_v2.v999");
        }
        other => panic!("expected UnknownProfile, got {other:?}"),
    }
}

#[test]
fn sdk_role_table_matches_spec_artifact() {
    assert_sdk_matches_artifact().expect("SDK profile_roles table must match the live spec artifact");
}

#[test]
fn role_table_has_every_documented_role() {
    let table = ProfileRoleTable::load().expect("artifact loads");
    assert!(table.len() >= 80, "expected >=80 roles, got {}", table.len());
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
