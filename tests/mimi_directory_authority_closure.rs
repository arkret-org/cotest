use arkret_models_collaboration::mimi_operations::MimiReportAbuseRequestBody;
use arkret_wire::{CommitStreamRef, CommittedEventRef, EventId, RealmCommitId, RealmId, ScopeRef};
use serde_json::json;

#[test]
fn mimi_report_requires_closed_exact_actor_authority() {
    let realm_id = RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI").unwrap();
    let reference = |byte, position| CommittedEventRef {
        event_id: EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32]),
        commit_id: RealmCommitId::from_digest([byte; 32]),
        stream_ref: CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        stream_position: position,
    };
    let report = json!({
        "reporter_authority": {
            "actor_id": {
                "kind": "account",
                "account_id": {
                    "principal_id": "ak:did_core:web:alice.example",
                    "station_id": "ak:did_core:web:station.example"
                }
            },
            "membership_ref": reference(0x11, 7),
            "room_binding_ref": reference(0x22, 8),
            "expires_at": "2026-09-23T13:40:00.000Z",
            "proof": {
                "kind": "detached_jws",
                "verification_method": "did:web:alice.example#device-1",
                "payload_digest": format!("sha256:{}", "0".repeat(64)),
                "created_at": "2026-09-23T13:30:00.000Z",
                "domain": "ak.mimi_reporter_authority_proof.v1",
                "audience": "ak:did_core:web:provider.example",
                "jws": "eyJhbGciOiJFZERTQSJ9..c2ln"
            }
        },
        "report_claim": {
            "realm_id": realm_id,
            "scope_ref": ScopeRef::Realm { realm_id: realm_id.clone() },
            "target_ref": EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x33; 32]),
            "report_reason_code": "spam"
        }
    });
    let mut parsed: MimiReportAbuseRequestBody = serde_json::from_value(report.clone()).unwrap();
    parsed.reporter_authority.proof.payload_digest = parsed.payload_digest().unwrap();
    parsed.validate().unwrap();
    let bound = parsed.reporter_authority_binding_bytes().unwrap();
    assert!(!bound.is_empty());
    assert_eq!(parsed.report_claim.realm_id, realm_id);
    assert_eq!(
        parsed
            .reporter_authority
            .membership_ref
            .stream_ref
            .realm_id(),
        &realm_id
    );
    assert_eq!(
        parsed
            .reporter_authority
            .room_binding_ref
            .stream_ref
            .realm_id(),
        &realm_id
    );

    parsed.report_claim.target_ref =
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x44; 32]).to_string();
    assert!(
        parsed.validate().is_err(),
        "claim mutation must invalidate proof digest"
    );
    parsed.reporter_authority.proof.payload_digest = parsed.payload_digest().unwrap();
    assert_ne!(bound, parsed.reporter_authority_binding_bytes().unwrap());

    let mut missing = report.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("reporter_authority");
    assert!(serde_json::from_value::<MimiReportAbuseRequestBody>(missing).is_err());

    let mut retired = report.clone();
    retired["report_event"] = json!({});
    assert!(serde_json::from_value::<MimiReportAbuseRequestBody>(retired).is_err());

    let mut mirrored = report;
    mirrored["reporter_id"] = json!("ak:did_core:web:alice.example");
    assert!(serde_json::from_value::<MimiReportAbuseRequestBody>(mirrored).is_err());
}
