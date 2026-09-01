use arkret_models_collaboration::history_key::DirectorySourceRefAccess;
use arkret_models_collaboration::http_bodies::{
    MimiReportAbuseRequestBody, PeerEventsResolveRequestBody,
};
use serde_json::json;

#[test]
fn mimi_report_requires_closed_exact_actor_authority() {
    let report = json!({
        "strand_id": "ak:strand:AaCQjogT126mXVYM2VaV0guWrFdS4nCOsDP-Ft0iWyKp",
        "mimi_room_uri": "mimi://provider.example/rooms/room-1",
        "realm_id": "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI",
        "target_ref": "mimi://provider.example/rooms/room-1/messages/message-1",
        "reporter_id": "ak:did_core:web:alice.example",
        "source_provider_id": "ak:did_core:web:provider.example",
        "reporter_authority": {
            "actor_id": {
                "kind": "account",
                "account_id": {
                    "principal_id": "ak:did_core:web:alice.example",
                    "station_id": "ak:did_core:web:station.example"
                }
            },
            "membership_event_id": "ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6",
            "room_binding_event_id": "ak:event:Adoyyx1AqvJH02hYxuUtpzuC-zpV8GxwFQ8XInZLbu3s",
            "expires_at": "2026-09-01T00:05:00Z",
            "proof": {
                "kind": "detached_jws",
                "verification_method": "did:web:alice.example#device-1",
                "payload_digest": format!("sha256:{}", "0".repeat(64)),
                "created_at": "2026-09-01T00:00:00Z",
                "domain": "ak:trust_domain:example.com",
                "audience": "ak:did_core:web:provider.example",
                "jws": "e30..c2ln"
            }
        },
        "report_event": {
            "event": {
                "event_id": "ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6",
                "kind": "ak.self.moderation.report",
                "realm_id": "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI",
                "scope_ref": {
                    "kind": "realm",
                    "realm_id": "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI"
                },
                "actor_id": {
                    "kind": "account",
                    "account_id": {
                        "principal_id": "ak:did_core:web:alice.example",
                        "station_id": "ak:did_core:web:station.example"
                    }
                },
                "actor_seq": 1,
                "created_at": "2026-09-01T00:00:00Z",
                "prev_refs": [],
                "refs": [],
                "requirements": {},
                "payload": {},
                "proofs": []
            }
        },
        "abuse_reason_code": "spam"
    });
    let parsed: MimiReportAbuseRequestBody = serde_json::from_value(report.clone()).unwrap();
    assert_eq!(
        parsed.reporter_authority.actor_id.signing_principal_id(),
        &parsed.reporter_id
    );

    let mut missing = report.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("reporter_authority");
    assert!(serde_json::from_value::<MimiReportAbuseRequestBody>(missing).is_err());

    let mut legacy = report;
    legacy["reporter_authority"]["holder_claim"] = json!("opaque-bearer");
    assert!(serde_json::from_value::<MimiReportAbuseRequestBody>(legacy).is_err());
}

#[test]
fn directory_carrier_is_bounded_and_exclusive_on_peer_resolve() {
    let access_value = json!({
        "kind": "directory_announce",
        "source_id": "ak:did_core:web:station.example",
        "directory_id": "ak:did_core:web:directory.example",
        "realm_id": "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI",
        "discovery_event_id": "ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6",
        "source_refs": [
            "ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6"
        ],
        "as_of": "2026-09-01T00:00:00Z",
        "expires_at": "2026-09-01T00:05:00Z",
        "proof": {
            "kind": "detached_jws",
            "verification_method": "did:web:station.example#notary-key",
            "payload_digest": format!("sha256:{}", "0".repeat(64)),
            "created_at": "2026-09-01T00:00:00Z",
            "domain": "ak:trust_domain:example.com",
            "audience": "ak:did_core:web:directory.example",
            "jws": "e30..c2ln"
        }
    });
    let access: DirectorySourceRefAccess = serde_json::from_value(access_value).unwrap();
    access.validate().unwrap();

    let request: PeerEventsResolveRequestBody = serde_json::from_value(json!({
        "realm_id": access.realm_id.clone(),
        "event_ids": access.source_refs.clone(),
        "event_digests": [],
        "directory_source_ref_access": access
    }))
    .unwrap();
    request.validate().unwrap();

    let mut unrelated = request.clone();
    unrelated.event_ids = vec![
        arkret_wire::EventId::new("ak:event:Adoyyx1AqvJH02hYxuUtpzuC-zpV8GxwFQ8XInZLbu3s").unwrap(),
    ];
    assert!(unrelated.validate().is_err());
}
