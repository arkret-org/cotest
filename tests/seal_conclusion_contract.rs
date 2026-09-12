use arkret::{
    ActorId, CellRef, Did, DidCoreId, DidUrl, Ed25519PayloadSigner, EventId, Hash,
    NotaryJoseAlgorithm, NotaryKeyKind, NotarySignerDescriptor, NotaryValue,
    PeerSealResolveRequestBody, RealmId, SealConclusionAncestryOutcome,
    SealConclusionAncestrySelector, SealConclusionAncestrySelectorKind, SealConclusionOutcome,
    SealConclusionQuery, SealConclusionSelector, SealConclusionSet, SealConclusionStatement,
    SealId, SealResolveOutcome, SealResolveSelection, sign_seal_conclusion,
    verify_seal_conclusion_set_quorum_chain,
};
use ed25519_dalek::SigningKey;
use serde_json::json;

fn seal(hex_digit: char) -> SealId {
    SealId::new(format!(
        "ak:seal:sha256:{}",
        hex_digit.to_string().repeat(64)
    ))
    .unwrap()
}

fn realm() -> RealmId {
    RealmId::new("ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1").unwrap()
}

fn ancestry_query() -> SealConclusionQuery {
    SealConclusionQuery {
        target_seal_ref: seal('b'),
        selectors: vec![SealConclusionSelector::Ancestry {
            ancestor_seal_ref: seal('a'),
        }],
        known_configuration_ref: None,
    }
}

#[test]
fn conclusion_query_round_trips_through_the_sdk_resolve_contract() {
    let query = ancestry_query();
    query.validate_structural().unwrap();
    let request = PeerSealResolveRequestBody {
        realm_id: realm(),
        selection: SealResolveSelection::ConclusionQueries {
            conclusion_queries: vec![query.clone()],
        },
        history_traversal_access: None,
    };
    request.validate().unwrap();

    let wire = serde_json::to_value(&request).unwrap();
    assert_eq!(
        wire["conclusion_queries"][0]["selectors"][0]["kind"],
        "ancestry"
    );
    assert!(wire.get("seal_refs").is_none());
    let decoded: PeerSealResolveRequestBody = serde_json::from_value(wire).unwrap();
    assert_eq!(decoded, request);
    let mut unknown = serde_json::to_value(&request).unwrap();
    unknown["unregistered"] = json!(true);
    assert!(serde_json::from_value::<PeerSealResolveRequestBody>(unknown).is_err());

    let configuration_ref =
        EventId::new("ak:event:AUf4Nwr-Lqj1RlqDi4awPbskicm37buT2CswWBfZbgLe").unwrap();
    let key = SigningKey::from_bytes(&[7; 32]);
    let verification_method = DidUrl::new("did:web:notary.example#key-1").unwrap();
    let signer = Ed25519PayloadSigner::from_did_key_seed(
        key.to_bytes(),
        Did::new("did:web:notary.example").unwrap(),
        verification_method.clone(),
    );
    let public_key = key.verifying_key().to_bytes();
    let configuration = NotaryValue::new(
        vec![NotarySignerDescriptor {
            actor_id: ActorId::service(DidCoreId::new("ak:did_core:web:notary.example").unwrap()),
            verification_method,
            key_kind: NotaryKeyKind::Ed25519Raw32,
            jose_algorithm: NotaryJoseAlgorithm::Ed25519,
            frozen_public_key_b64u: arkret::base64url_encode(public_key),
            frozen_public_key_digest: Hash::new(arkret_canonical::canonical::sha256_digest(
                public_key,
            ))
            .unwrap(),
        }],
        0,
        0,
    )
    .unwrap();
    let statement = SealConclusionStatement {
        realm_id: realm(),
        configuration_ref: configuration_ref.clone(),
        authority_seal_ref: seal('c'),
        target_seal_ref: seal('b'),
        results: vec![SealConclusionOutcome::Ancestry(
            SealConclusionAncestryOutcome {
                selector: SealConclusionAncestrySelector {
                    kind: SealConclusionAncestrySelectorKind::Ancestry,
                    ancestor_seal_ref: seal('a'),
                },
                is_ancestor: true,
            },
        )],
    };
    let certificate = sign_seal_conclusion(statement, &[&signer]).unwrap();
    let conclusion_set = SealConclusionSet {
        configuration_handoffs: vec![],
        conclusions: vec![certificate],
    };
    verify_seal_conclusion_set_quorum_chain(
        &conclusion_set,
        &realm(),
        &configuration_ref,
        &configuration,
    )
    .unwrap();
    let outcome = SealResolveOutcome::Conclusions {
        conclusion_set: Some(conclusion_set),
        missing_conclusion_queries: vec![],
    };
    outcome.validate_for_peer_request(&request).unwrap();
    assert!(outcome.clone().into_seals().is_err());
    let mut other_realm_request = request;
    other_realm_request.realm_id =
        RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
    assert!(
        outcome
            .validate_for_peer_request(&other_realm_request)
            .is_err()
    );
}

#[test]
fn conclusion_query_rejects_ambiguous_modes_and_invalid_ranges() {
    let both_modes = json!({
        "realm_id": realm(),
        "seal_refs": [seal('a')],
        "conclusion_queries": [ancestry_query()]
    });
    assert!(serde_json::from_value::<PeerSealResolveRequestBody>(both_modes).is_err());
    for invalid in [
        json!({"realm_id": realm(), "seal_refs": null}),
        json!({"realm_id": realm(), "conclusion_queries": null}),
        json!({"realm_id": realm(), "seal_refs": [seal('a')], "conclusion_queries": null}),
        json!({"realm_id": realm(), "seal_refs": [seal('a')], "history_traversal_access": null}),
    ] {
        assert!(serde_json::from_value::<PeerSealResolveRequestBody>(invalid).is_err());
    }
    let raw = json!({"realm_id": realm(), "seal_refs": [seal('a')]});
    assert!(serde_json::from_value::<arkret::SelfSealResolveRequestBody>(raw.clone()).is_ok());
    assert!(
        serde_json::from_value::<arkret_models_collaboration::http_bodies::SealResolveRequestCore>(
            raw
        )
        .is_ok()
    );

    let empty = SealResolveOutcome::Conclusions {
        conclusion_set: None,
        missing_conclusion_queries: vec![],
    };
    assert!(empty.validate_structural().is_err());

    let request = PeerSealResolveRequestBody {
        realm_id: realm(),
        selection: SealResolveSelection::ConclusionQueries {
            conclusion_queries: vec![ancestry_query()],
        },
        history_traversal_access: None,
    };
    let wrong_mode = SealResolveOutcome::Seals {
        seals: vec![],
        missing_seal_refs: vec![seal('b')],
    };
    assert!(wrong_mode.validate_for_peer_request(&request).is_err());

    let lower = CellRef::new("ak:cell:ak.component.call.state.v1:z".to_owned()).unwrap();
    let upper = CellRef::new("ak:cell:ak.component.call.state.v1:a".to_owned()).unwrap();
    let invalid_range = SealConclusionSelector::CellRange {
        lower_cell_id: lower,
        upper_cell_id: upper,
    };
    assert!(invalid_range.validate_structural().is_err());
}

#[test]
fn conclusion_request_enforces_the_complete_wire_byte_budget() {
    let selectors = (0..64)
        .map(|index| SealConclusionSelector::Cell {
            cell_id: CellRef::new(format!(
                "ak:cell:ak.component.call.state.v1:{index:02}{}",
                "a".repeat(1024)
            ))
            .unwrap(),
        })
        .collect();
    let request = PeerSealResolveRequestBody {
        realm_id: realm(),
        selection: SealResolveSelection::ConclusionQueries {
            conclusion_queries: vec![SealConclusionQuery {
                target_seal_ref: seal('a'),
                selectors,
                known_configuration_ref: None,
            }],
        },
        history_traversal_access: None,
    };
    assert!(
        request
            .validate()
            .unwrap_err()
            .to_string()
            .contains("limit_exceeded")
    );
}
