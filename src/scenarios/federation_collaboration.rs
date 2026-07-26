use std::collections::BTreeMap;

use anyhow::{Context, Result};
use arkret_bootstrap::{
    DID_INCEPTION_REF_ROLE, SelfPrincipalPcrCreateInput, build_self_principal_pcr_create,
    self_principal_bootstrap_submit_request,
};
use arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase;
use arkret_canonical::{
    canonical_json_bytes, canonical_sha256, format_timestamp_canonical, sha256_digest,
};
use arkret_identifiers::{DeviceId, Did, EventId, Hlc, RealmId, TypedTrustDomainId};
use arkret_models_crypto::{
    AlgorithmKeyRecords, KeyOperationSignature, KeyPackageClaimRecord, KeysUploadRequestBody,
    PeerKeyPackageClaimPurpose, PeerKeyPackageRequesterAuthorization,
    PeerKeyPackagesClaimAuthorizationDraft, PeerKeyPackagesClaimOutcome,
    PeerKeyPackagesClaimRequestBody, PeerKeyPackagesClaimTransportBinding,
    peer_keypackage_claim_authorization_signing_bytes,
};
use arkret_models_identity::artifacts_device_identity::{
    CrossSigningPublish, KeyFormat, PublishedKey, SubordinateSignedKey, SubordinateSignedKeyBinding,
};
use arkret_models_identity::did_document::principal_control_realm_id;
use arkret_signatures::http_signature::{
    ContentDigest, ContentDigestAlgorithm, sign_message, signing_key_from_seed,
};
use arkret_signatures::webvh::{
    PreparedPrincipalInception, PrincipalEnrollmentDelegation, PrincipalInceptionInput,
    prepare_principal_inception,
};
use arkret_wire::{Base64UrlString, Event, EventRef, NonEmptyString};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::harness::{
    ArkretServer, TestServerGroup, add_member, encrypted_envelope, expect_account_subscribe_delta,
    expect_json, expect_text, member_join_payload_with_delivery_binding,
    message_create_text_payload, realm_bootstrap_event_batch, register_account, submit_event,
};
use crate::scenarios::_helpers::federation_binding::{
    peer_events_submit_body, peer_events_submit_body_with_delivery_frontier,
};

pub(crate) const TEST_PRINCIPAL_SIGNING_KEY_SEED: [u8; 32] = [0x51; 32];

const ALICE_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-0000000000a1";
const BOB_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-0000000000bb";
const ALICE_MESSAGE_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000001";
const BOB_JOIN_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000002";
const BOB_MESSAGE_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000003";
const ALICE_DELIVERY_BINDING_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000004";
const DELIVERY_POLICY_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000006";
const E2EE_REALM_ID: &str = "ak:realm:01904100-0000-7000-8000-fedc011ab0e2";
const E2EE_DELIVERY_POLICY_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000e01";
const E2EE_BOB_JOIN_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000e02";
const E2EE_MLS_GENESIS_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000e03";
const E2EE_MLS_WELCOME_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000e04";
const E2EE_MLS_COMMIT_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000e05";
const E2EE_MESSAGE_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000e06";
const E2EE_MLS_GROUP_ID: &str = "peer_dm_mls_group";
const E2EE_MESSAGE_CIPHERTEXT: &str = "opaque_cross_server_e2ee_message";
const E2EE_MESSAGE_PLAINTEXT: &str = "cross-server e2ee plaintext must stay client-side";
const BOB_DEVICE_KEY_SEED: [u8; 32] = [187u8; 32];
const ALICE_DEVICE_KEY_SEED: [u8; 32] = [161u8; 32];
const ALICE_PCR_CREATE_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000a10";
const ALICE_DEVICE_AUTHORIZE_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000a11";

pub async fn cross_server_collaboration_strand_works() -> Result<()> {
    let group = TestServerGroup::multi("federation-collaboration", 2).await?;
    let server_a = group.server(0);
    let server_b = group.server(1);
    let alice_did = actor_did_for_service(server_a.service_id(), "alice")?;
    let bob_did = actor_did_for_service(server_b.service_id(), "bob")?;
    let alice =
        register_account(server_a, &alice_did, "@cotest-fed-alice", ALICE_DEVICE_ID).await?;
    let bob = register_account(server_b, &bob_did, "@cotest-fed-bob", BOB_DEVICE_ID).await?;
    install_test_principal_control_document(server_a, &alice_did).await?;
    install_test_principal_control_document(server_b, &bob_did).await?;
    install_test_principal_control_document(server_b, &alice_did).await?;
    install_test_principal_control_document(server_a, &bob_did).await?;

    let describe_a = expect_json(
        server_a.http().get(server_a.url("/_arkret/describe")),
        StatusCode::OK,
    )
    .await?;
    let describe_b = expect_json(
        server_b.http().get(server_b.url("/_arkret/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(describe_a["service_kind"], "principal_server");
    assert_eq!(describe_b["service_kind"], "principal_server");

    let bob_document = expect_json(
        server_a
            .http()
            .post(server_a.url("/_arkret/root/identity/resolve"))
            .json(&json!({"did": bob_did})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(bob_document["did_document"]["id"], bob_did);
    let alice_document = expect_json(
        server_b
            .http()
            .post(server_b.url("/_arkret/root/identity/resolve"))
            .json(&json!({"did": alice_did})),
        StatusCode::OK,
    )
    .await?;
    let alice_psk = format!("{alice_did}#cotest-principal-signing-key");
    anyhow::ensure!(
        alice_document["did_document"]["verificationMethod"]
            .as_array()
            .is_some_and(|methods| methods.iter().any(|method| method["id"] == alice_psk)),
        "remote Alice principal signing key is absent: {alice_document}"
    );

    let visible_services = vec![
        server_a.service_id().to_owned(),
        server_b.service_id().to_owned(),
    ];
    let realm_id = create_federated_realm(server_a, &alice, &alice_did, &visible_services).await?;
    add_member(server_a, &alice, &alice_did, &realm_id, &bob_did).await?;
    // server_a delivery-binding setup so the later b->a federation push (bob's
    // reply) clears the `delivery_binding_stale` gate: a push to a Realm the
    // receiver already hosts MUST assert a member delivery-binding frontier
    // whose `recipient_service_id = Destination-Service-ID` (federation.md
    // §4.1). Declare the policy admitting an explicit binding to server_a, then
    // bind the local owner (alice) to server_a and capture the projected
    // binding frontier (= the member.state event_id).
    submit_event(
        server_a,
        &alice,
        &alice_did,
        &realm_id,
        "ak.realm.delivery_binding_policy",
        json!({
            "realm_id": realm_id,
            "allowed_binding_sources": ["explicit"],
            "allowed_recipient_services": [server_a.service_id()]
        }),
        StatusCode::OK,
    )
    .await?;
    let alice_local_binding = submit_event(
        server_a,
        &alice,
        &alice_did,
        &realm_id,
        "ak.member.state",
        member_join_payload_with_delivery_binding(
            &realm_id,
            &alice_did,
            json!({
                "recipient_service_id": server_a.service_id(),
                "recipient_service_kind": "principal_server",
                "binding_scope": "realm",
                "binding_source": "explicit",
                "delivery_modes": ["events", "sync"],
                "service_acceptance_ref": ALICE_DELIVERY_BINDING_EVENT_ID,
                "resolved_at": "2026-05-02T00:00:00.000Z"
            }),
        )?,
        StatusCode::OK,
    )
    .await?;
    let alice_local_binding_frontier = alice_local_binding["event_id"]
        .as_str()
        .context("alice server_a binding response missing event_id")?
        .to_owned();
    let mut bootstrap_events = realm_bootstrap_event_batch(
        &alice_did,
        &realm_id,
        federated_realm_payload(&realm_id, &alice_did, &visible_services),
    )?
    .into_iter()
    .map(serde_json::from_value::<Event>)
    .collect::<Result<Vec<_>, _>>()?;
    let realm_create = bootstrap_events.remove(0);
    let founding_grant = bootstrap_events.remove(0);
    let realm_create_event_id = realm_create.event_id.clone();
    let mut delivery_policy = signed_federation_event(
        DELIVERY_POLICY_EVENT_ID,
        "ak.realm.delivery_binding_policy",
        &realm_id,
        &alice_did,
        2,
        Some(&founding_grant.event_id),
        json!({
            "realm_id": realm_id,
            "allowed_binding_sources": ["explicit"],
            "allowed_recipient_services": [server_a.service_id(), server_b.service_id()]
        }),
    )?;
    attach_delivery_policy_cell_contract(&mut delivery_policy)?;
    sign_federation_event(&mut delivery_policy)?;
    let alice_delivery_binding = signed_federation_event(
        ALICE_DELIVERY_BINDING_EVENT_ID,
        "ak.member.state",
        &realm_id,
        &alice_did,
        3,
        Some(&delivery_policy.event_id),
        member_delivery_binding_payload(&realm_id, &alice_did, server_a.service_id()),
    )?;
    let bob_join = signed_federation_event(
        BOB_JOIN_EVENT_ID,
        "ak.member.state",
        &realm_id,
        &alice_did,
        4,
        Some(&alice_delivery_binding.event_id),
        member_delivery_binding_payload(&realm_id, &bob_did, server_b.service_id()),
    )?;
    let a_to_b_body = peer_events_submit_body(
        &realm_id,
        vec![
            realm_create,
            founding_grant,
            delivery_policy,
            alice_delivery_binding,
            bob_join,
        ],
        Some("a-to-b-bootstrap-01"),
    )?;
    let a_to_b_url = server_b.url("/_arkret/peer/events");
    let pushed_to_b = expect_json(
        with_federation_trust_headers(
            server_b.http().post(&a_to_b_url).json(&a_to_b_body),
            "POST",
            &a_to_b_url,
            server_a,
            server_b,
            &a_to_b_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_json_array_contains(
        &pushed_to_b["accepted"],
        realm_create_event_id.as_str(),
        &pushed_to_b,
    );
    assert_json_array_contains(
        &pushed_to_b["accepted"],
        ALICE_DELIVERY_BINDING_EVENT_ID,
        &pushed_to_b,
    );
    assert_json_array_contains(&pushed_to_b["accepted"], BOB_JOIN_EVENT_ID, &pushed_to_b);

    let alice_message = signed_federation_event(
        ALICE_MESSAGE_EVENT_ID,
        "ak.message.create",
        &realm_id,
        &alice_did,
        5,
        Some(&EventId::new(BOB_JOIN_EVENT_ID.to_owned())?),
        message_create_text_payload(&realm_id, "hello bob from server a")?,
    )?;
    let a_to_b_delivery_frontier = vec![EventId::new(BOB_JOIN_EVENT_ID.to_owned())?];
    let message_body = peer_events_submit_body_with_delivery_frontier(
        &realm_id,
        vec![alice_message],
        &a_to_b_delivery_frontier,
        Some("a-to-b-message-01"),
    )?;
    let message_pushed = expect_json(
        with_federation_trust_headers(
            server_b.http().post(&a_to_b_url).json(&message_body),
            "POST",
            &a_to_b_url,
            server_a,
            server_b,
            &message_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_json_array_contains(
        &message_pushed["accepted"],
        ALICE_MESSAGE_EVENT_ID,
        &message_pushed,
    );

    let pulled_url = server_b.url(&format!("/_arkret/peer/events?realms={realm_id}"));
    let pulled_on_b = expect_json(
        with_federation_trust_headers_empty(
            server_b.http().get(&pulled_url),
            "GET",
            &pulled_url,
            server_a,
            server_b,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        pulled_on_b["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["event_id"] == ALICE_MESSAGE_EVENT_ID),
        "server B pull did not include alice federation message: {pulled_on_b}"
    );

    let bob_sync = expect_account_subscribe_delta(
        server_b
            .http()
            .get(server_b.url("/_arkret/self/account/subscribe?catchup=true"))
            .bearer_auth(&bob),
        StatusCode::OK,
    )
    .await?;
    assert!(
        sync_timeline_events(&bob_sync, &realm_id)?
            .iter()
            .any(|event| event_body(event) == Some("hello bob from server a")),
        "bob sync did not include alice federation message: {bob_sync}"
    );

    let bob_reply = signed_federation_event(
        BOB_MESSAGE_EVENT_ID,
        "ak.message.create",
        &realm_id,
        &bob_did,
        0,
        None,
        message_create_text_payload(&realm_id, "hello alice from server b")?,
    )?;
    let b_to_a_delivery_frontier = vec![
        arkret_identifiers::EventId::new(alice_local_binding_frontier)
            .context("invalid alice server_a binding frontier id")?,
    ];
    let b_to_a_body = peer_events_submit_body_with_delivery_frontier(
        &realm_id,
        vec![bob_reply],
        &b_to_a_delivery_frontier,
        Some("b-to-a-01"),
    )?;
    let b_to_a_url = server_a.url("/_arkret/peer/events");
    let txn = expect_json(
        with_federation_trust_headers(
            server_a.http().post(&b_to_a_url).json(&b_to_a_body),
            "POST",
            &b_to_a_url,
            server_b,
            server_a,
            &b_to_a_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_json_array_contains(&txn["accepted"], BOB_MESSAGE_EVENT_ID, &txn);
    let alice_sync = expect_account_subscribe_delta(
        server_a
            .http()
            .get(server_a.url("/_arkret/self/account/subscribe?catchup=true"))
            .bearer_auth(&alice),
        StatusCode::OK,
    )
    .await?;
    assert!(
        sync_timeline_events(&alice_sync, &realm_id)?
            .iter()
            .any(|event| event_body(event) == Some("hello alice from server b")),
        "alice sync did not include bob federation reply: {alice_sync}"
    );

    // Bootstrap Alice's PCR only on her home server and carry portable signer
    // evidence with the federated Realm batch. The destination verifies the
    // original authorization without importing Alice's PCR or creating a
    // shadow local identity.
    let bob_device_key = SigningKey::from_bytes(&BOB_DEVICE_KEY_SEED);
    authorize_device_public_key(server_b, &bob, &bob_did, BOB_DEVICE_ID, &bob_device_key).await?;
    upload_test_keypackage(server_b, &bob, &bob_did, BOB_DEVICE_ID, &bob_device_key).await?;
    let alice_device_key = SigningKey::from_bytes(&ALICE_DEVICE_KEY_SEED);
    let alice_signer_evidence = bootstrap_test_device_authorization(
        server_a,
        &alice,
        &alice_did,
        ALICE_DEVICE_ID,
        &alice_device_key,
    )
    .await?;

    let mut e2ee_bootstrap = realm_bootstrap_event_batch(
        &alice_did,
        E2EE_REALM_ID,
        federated_e2ee_realm_payload(E2EE_REALM_ID, &alice_did),
    )?
    .into_iter()
    .map(serde_json::from_value::<Event>)
    .collect::<Result<Vec<_>, _>>()?;
    let e2ee_realm_create = e2ee_bootstrap.remove(0);
    let e2ee_founding_grant = e2ee_bootstrap.remove(0);
    let e2ee_realm_create_event_id = e2ee_realm_create.event_id.clone();
    let mut e2ee_delivery_policy = signed_federation_event(
        E2EE_DELIVERY_POLICY_EVENT_ID,
        "ak.realm.delivery_binding_policy",
        E2EE_REALM_ID,
        &alice_did,
        2,
        Some(&e2ee_founding_grant.event_id),
        json!({
            "realm_id": E2EE_REALM_ID,
            "allowed_binding_sources": ["explicit"],
            "allowed_recipient_services": [server_b.service_id()]
        }),
    )?;
    attach_delivery_policy_cell_contract(&mut e2ee_delivery_policy)?;
    sign_federation_event(&mut e2ee_delivery_policy)?;
    let e2ee_bob_join = signed_federation_event(
        E2EE_BOB_JOIN_EVENT_ID,
        "ak.member.state",
        E2EE_REALM_ID,
        &alice_did,
        3,
        Some(&e2ee_delivery_policy.event_id),
        member_delivery_binding_payload(E2EE_REALM_ID, &bob_did, server_b.service_id()),
    )?;
    let e2ee_delivery_frontier = vec![e2ee_bob_join.event_id.clone()];
    let e2ee_bootstrap_body = peer_events_submit_body(
        E2EE_REALM_ID,
        vec![
            e2ee_realm_create,
            e2ee_founding_grant,
            e2ee_delivery_policy,
            e2ee_bob_join,
        ],
        Some("a-to-b-e2ee-bootstrap-01"),
    )?;
    let e2ee_url = server_b.url("/_arkret/peer/events");
    let pushed_e2ee_bootstrap = expect_json(
        with_federation_trust_headers(
            server_b.http().post(&e2ee_url).json(&e2ee_bootstrap_body),
            "POST",
            &e2ee_url,
            server_a,
            server_b,
            &e2ee_bootstrap_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_json_array_contains(
        &pushed_e2ee_bootstrap["accepted"],
        e2ee_realm_create_event_id.as_str(),
        &pushed_e2ee_bootstrap,
    );
    assert_json_array_contains(
        &pushed_e2ee_bootstrap["accepted"],
        E2EE_BOB_JOIN_EVENT_ID,
        &pushed_e2ee_bootstrap,
    );
    let peer_claim = claim_test_keypackage(
        server_a,
        server_b,
        &alice_did,
        &bob_did,
        &alice_device_key,
        &alice_signer_evidence,
    )
    .await?;
    let claimed_keypackage = peer_claim
        .claims
        .first()
        .context("peer KeyPackage claim returned no claim")?;

    let e2ee_genesis = signed_federation_event(
        E2EE_MLS_GENESIS_EVENT_ID,
        "ak.mls.genesis",
        E2EE_REALM_ID,
        &alice_did,
        4,
        Some(&e2ee_delivery_frontier[0]),
        mls_genesis_payload(E2EE_REALM_ID, &alice_did),
    )?;
    let mut e2ee_welcome = signed_federation_event(
        E2EE_MLS_WELCOME_EVENT_ID,
        "ak.mls.welcome",
        E2EE_REALM_ID,
        &alice_did,
        5,
        Some(&e2ee_genesis.event_id),
        mls_welcome_payload(
            E2EE_REALM_ID,
            &alice_did,
            &bob_did,
            &alice_device_key,
            ALICE_DEVICE_ID,
            claimed_keypackage,
            &peer_claim.claim_receipt,
        )?,
    )?;
    sign_federation_event_with_device(&mut e2ee_welcome, ALICE_DEVICE_ID, &alice_device_key)?;
    let e2ee_commit = signed_federation_event(
        E2EE_MLS_COMMIT_EVENT_ID,
        "ak.mls.commit",
        E2EE_REALM_ID,
        &alice_did,
        6,
        Some(&e2ee_welcome.event_id),
        mls_commit_payload(E2EE_REALM_ID),
    )?;
    let e2ee_message = signed_federation_event(
        E2EE_MESSAGE_EVENT_ID,
        "ak.message.create",
        E2EE_REALM_ID,
        &alice_did,
        7,
        Some(&e2ee_commit.event_id),
        encrypted_message_payload(E2EE_REALM_ID),
    )?;
    for (index, (accepted_id, event)) in [
        (E2EE_MLS_GENESIS_EVENT_ID, e2ee_genesis),
        (E2EE_MLS_WELCOME_EVENT_ID, e2ee_welcome),
        (E2EE_MLS_COMMIT_EVENT_ID, e2ee_commit),
        (E2EE_MESSAGE_EVENT_ID, e2ee_message),
    ]
    .into_iter()
    .enumerate()
    {
        let idempotency_key = format!("a-to-b-e2ee-{index:02}");
        let mut e2ee_body = peer_events_submit_body_with_delivery_frontier(
            E2EE_REALM_ID,
            vec![event],
            &e2ee_delivery_frontier,
            Some(&idempotency_key),
        )?;
        if accepted_id == E2EE_MLS_WELCOME_EVENT_ID {
            e2ee_body.signer_key_evidence = vec![alice_signer_evidence.clone()];
        }
        let pushed_e2ee = expect_json(
            with_federation_trust_headers(
                server_b.http().post(&e2ee_url).json(&e2ee_body),
                "POST",
                &e2ee_url,
                server_a,
                server_b,
                &e2ee_body,
            )?,
            StatusCode::OK,
        )
        .await?;
        assert_json_array_contains(&pushed_e2ee["accepted"], accepted_id, &pushed_e2ee);
    }

    let device_messages = expect_json(
        server_b
            .http()
            .get(server_b.url("/_arkret/self/device_messages"))
            .bearer_auth(&bob),
        StatusCode::OK,
    )
    .await?;
    let welcome_messages = device_messages["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|message| message["kind"] == "ak.mls.welcome")
        .collect::<Vec<_>>();
    assert_eq!(welcome_messages.len(), 1);
    assert_eq!(
        welcome_messages[0]["unsigned"]["mls_welcome_id"],
        "ak:blob:sha256:88888888888888888888888888888888888888888888888888888888888888e2"
    );
    assert_eq!(
        welcome_messages[0]["content"]["mls_group_id"],
        E2EE_MLS_GROUP_ID
    );

    let bob_e2ee_sync = expect_account_subscribe_delta(
        server_b
            .http()
            .get(server_b.url("/_arkret/self/account/subscribe?catchup=true"))
            .bearer_auth(&bob),
        StatusCode::OK,
    )
    .await?;
    let e2ee_event = sync_timeline_events(&bob_e2ee_sync, E2EE_REALM_ID)?
        .iter()
        .find(|event| event.get("event_id").and_then(Value::as_str) == Some(E2EE_MESSAGE_EVENT_ID))
        .with_context(|| format!("bob sync missing federated E2EE message: {bob_e2ee_sync}"))?;
    assert_eq!(
        event_encrypted_ciphertext(e2ee_event),
        Some(E2EE_MESSAGE_CIPHERTEXT)
    );
    assert!(
        !serde_json::to_string(&bob_e2ee_sync)?.contains(E2EE_MESSAGE_PLAINTEXT),
        "Bob sync leaked plaintext E2EE body: {bob_e2ee_sync}"
    );

    let bob_one_time_keys = json!({
        "signed_curve25519:bob-otk1": {
            "algorithm": "signed_curve25519",
            "key_id": "bob-otk1",
            "key": "bob-one-time"
        }
    });
    let bob_fallback_keys = json!({});
    let key_upload = expect_json(
        server_b
            .http()
            .post(server_b.url("/_arkret/self/keys/upload"))
            .bearer_auth(&bob)
            .json(&signed_keys_upload_body(
                &bob_did,
                BOB_DEVICE_ID,
                &bob_device_key,
                bob_one_time_keys,
                bob_fallback_keys,
            )?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(key_upload["one_time_key_counts"]["signed_curve25519"], 1);

    let device_message = expect_json(
        server_b
            .http()
            .post(server_b.url("/_arkret/self/device_messages"))
            .bearer_auth(&bob)
            .header("Idempotency-Key", "federation-to-bob-01")
            .json(&json!({
                "messages": {
                    bob_did.clone(): {
                        "ak:device:01904100-0000-7000-8000-0000000000bb": {
                            "message_id": "ak:device_message:01904100-0000-7000-8000-0000000000b1",
                            "kind": "ak.mls.welcome",
                            "content": encrypted_envelope("ak.mls.welcome", "opaque-cross-server-welcome"),
                            "expires_at": "2026-12-31T00:00:00.000Z"
                        }
                    }
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(device_message["ok"], true);

    let received = expect_json(
        server_b
            .http()
            .get(server_b.url("/_arkret/self/device_messages"))
            .bearer_auth(&bob),
        StatusCode::OK,
    )
    .await?;
    let received_device_message = received["messages"]
        .as_array()
        .and_then(|messages| {
            messages.iter().find(|message| {
                message["message_id"] == "ak:device_message:01904100-0000-7000-8000-0000000000b1"
            })
        })
        .with_context(|| {
            format!("Bob device-message response omitted the sent message: {received}")
        })?;
    assert_eq!(
        received_device_message["content"]["ciphertext"],
        "opaque-cross-server-welcome"
    );

    let blob = expect_json(
        server_a
            .http()
            .post(server_a.url("/_arkret/self/blob/upload"))
            .bearer_auth(&alice)
            .multipart(crate::scenarios::delivery_media::blob_upload_form(
                b"federated-media",
                "application/octet-stream",
            )?),
        StatusCode::OK,
    )
    .await?;
    let downloaded = expect_text(
        server_a
            .http()
            .get(server_a.url(&format!(
                "/_arkret/self/blob/get?blob_ref={}&purpose=federation.media",
                blob["blob_ref"].as_str().unwrap()
            )))
            .bearer_auth(&alice),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(downloaded, "federated-media");

    let push = expect_json(
        server_b
            .http()
            .post(server_b.url("/_arkret/edge/push/register-device"))
            .bearer_auth(&bob)
            .json(&json!({
                "device_id": BOB_DEVICE_ID,
                "push_gateway": "https://push.example",
                "push_key": "opaque",
                "platform": "desktop",
                "app_id": "inkson"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(push["ok"], true);

    let report = expect_json(
        server_b
            .http()
            .post(server_b.url("/_arkret/self/moderation/report"))
            .bearer_auth(&bob)
            .json(&json!({
                "realm_id": realm_id,
                "target_ref": ALICE_MESSAGE_EVENT_ID,
                "report_reason_code": "spam",
                "reporter": bob_did
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(report["status"], "submitted");

    Ok(())
}

async fn create_federated_realm(
    server: &ArkretServer,
    alice: &str,
    alice_did: &str,
    visible_services: &[String],
) -> Result<String> {
    let realm_id = "ak:realm:01904100-0000-7000-8000-fedc011ab001".to_owned();
    let events = realm_bootstrap_event_batch(
        alice_did,
        &realm_id,
        federated_realm_payload(&realm_id, alice_did, visible_services),
    )?;
    let created = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(alice)
            .json(&json!({"events": events})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(created["status"], "accepted");
    Ok(realm_id)
}

fn federated_realm_payload(realm_id: &str, alice_did: &str, visible_services: &[String]) -> Value {
    // soland gates plaintext (`encryption_profile: "none"`) message delivery on
    // each receiving service holding the `message_content` plaintext data class
    // for the realm (`RealmMetaRecord::allows_plaintext_data_class`). The realm
    // declaration MUST therefore carry structured `plaintext_visible_services`
    // entries (`{service_id, data_classes}`), not bare DIDs — bare strings
    // populate the legacy id list but never the typed data-class map.
    let plaintext_visible_services = visible_services
        .iter()
        .map(|service_id| {
            json!({
                "service_id": service_id,
                "service_kind": "principal_server",
                "data_classes": ["message_content"],
                "purposes": ["federated_plaintext_delivery"],
                "visibility": "private_plaintext"
            })
        })
        .collect::<Vec<_>>();
    json!({
        "object": {
            "id": realm_id,
            "schema": "ak.schema.realm.v1",
            "title": "Federated Collaboration Space",
            "summary": "cross server collaboration",
            "trust_domain": "ak:trust_domain:federation-collaboration.cotest.local",
            "created_by": alice_did,
            "schema_refs": ["ak.schema.realm.v1"],
            "default_discoverability": "invite_only",
            "default_join_rule": "invite",
            "history_visibility": "shared",
            "encryption_profile": "none",
            "security_class": "standard",
            "federation_policy": "open",
            "notary_profile": "single_did",
            "digest_algorithm": "sha256",
            "plaintext_visible_services": plaintext_visible_services,
            "notary": {
                "type": "single_did",
                "did": alice_did,
                "recovery_members": ["did:web:recovery-anchorer.cotest.local"],
                "controller_organization": "did:web:federation-collaboration.cotest.local",
                "recovery_controller_organizations": ["did:web:recovery-org.cotest.local"]
            },
            "created_at": "2026-05-02T00:00:00.000Z"
        }
    })
}

fn member_delivery_binding_payload(realm_id: &str, member_did: &str, service_id: &str) -> Value {
    member_join_payload_with_delivery_binding(
        realm_id,
        member_did,
        json!({
            "recipient_service_id": service_id,
            "recipient_service_kind": "principal_server",
            "binding_scope": "realm",
            "binding_source": "explicit",
            "delivery_modes": ["events", "sync", "to_device", "push", "key_packages"],
            "resolved_at": "2026-05-02T00:00:00.000Z",
            "service_acceptance_ref": "ak:event:01904100-0000-7000-8000-fedc00000005"
        }),
    )
    .expect("valid federation member delivery binding payload")
}

fn federated_e2ee_realm_payload(realm_id: &str, alice_did: &str) -> Value {
    json!({
        "object": {
            "id": realm_id,
            "schema": "ak.schema.realm.v1",
            "title": "Federated E2EE DM Realm",
            "summary": "cross personal server E2EE DM replication",
            "trust_domain": "ak:trust_domain:federation-collaboration.e2ee.cotest.local",
            "created_by": alice_did,
            "schema_refs": ["ak.schema.realm.v1"],
            "default_discoverability": "invite_only",
            "default_join_rule": "invite",
            "history_visibility": "shared",
            "encryption_profile": "mls_rfc9420",
            // realm.schema.json: pre-join history visibility (shared/invited/
            // world_readable) on an MLS-backed Realm requires the
            // history-capable content envelope scheme.
            "content_scheme": "mls_exporter_aead_v1",
            "security_class": "standard",
            "federation_policy": "open",
            "notary_profile": "single_did",
            "digest_algorithm": "sha256",
            "notary": {
                "type": "single_did",
                "did": alice_did,
                "recovery_members": ["did:web:recovery-anchorer.cotest.local"],
                "controller_organization": "did:web:federation-collaboration.cotest.local",
                "recovery_controller_organizations": ["did:web:recovery-org.cotest.local"]
            },
            "created_at": "2026-05-02T00:00:00.000Z"
        }
    })
}

fn mls_governance_binding(realm_id: &str, previous_epoch: u64, next_epoch: u64) -> Value {
    json!({
        "binding_version": 1,
        "encoding_profile": "cbor-deterministic-rfc8949-v1",
        "realm_id": realm_id,
        "effective_scope": {
            "kind": "realm",
            "realm_id": realm_id
        },
        "mls_group_id": E2EE_MLS_GROUP_ID,
        "previous_epoch": previous_epoch,
        "next_epoch": next_epoch,
        "membership_frontier": [E2EE_BOB_JOIN_EVENT_ID],
        "policy_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "capability_root": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "discussion_metadata_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "binding_profile": "ak.profile.mls_governance_binding.full.v1",
        "reducer_profile": "ak.reducer.v1"
    })
}

fn mls_genesis_payload(realm_id: &str, alice_did: &str) -> Value {
    json!({
        "mls_group_id": E2EE_MLS_GROUP_ID,
        "effective_scope": {
            "kind": "realm",
            "realm_id": realm_id
        },
        "epoch": 0,
        "creator_principal_id": alice_did,
        "creator_device_id": ALICE_DEVICE_ID,
        "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "group_info_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        "ratchet_tree_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
        "governance_binding": mls_governance_binding(realm_id, 0, 0),
        "created_at": "2026-05-25T00:00:01.000Z"
    })
}

fn mls_welcome_payload(
    realm_id: &str,
    alice_did: &str,
    bob_did: &str,
    requester_device_key: &SigningKey,
    requester_device_id: &str,
    claim: &KeyPackageClaimRecord,
    peer_claim_receipt: &arkret_models_crypto::PeerKeyPackageClaimReceipt,
) -> Result<Value> {
    let keypackage_ref = claim.keypackage_ref.as_str();
    let keypackage_digest = claim.keypackage_digest.as_str();
    // The welcome ciphertext is opaque base64-encoded MLS Welcome bytes: soland
    // base64-decodes `ciphertext` and binds `welcome_digest =
    // sha256(decoded bytes)` (reducer/mls.rs `validate_welcome_trust_binding`).
    // The digest MUST therefore be computed over the decoded plaintext, not the
    // base64 text.
    let welcome_plaintext = b"opaque-cross-server-mls-welcome";
    let welcome_bytes = URL_SAFE_NO_PAD.encode(welcome_plaintext);
    let welcome_digest = sha256_digest(welcome_plaintext);
    let claim_id = claim.claim_id.as_str();
    let nonce = peer_claim_receipt.request.claim_nonce.as_str();
    // §6.04 device path: the welcome `claim_envelope.signature` is a real
    // Ed25519 signature by the requester's device key over the SDK's
    // `MlsWelcomeClaimEnvelopeSigningInput` canonical bytes. soland deserialises
    // the envelope and recomputes the same canonical signing input, so we build
    // it field-for-field (device path → `requester_device_id`, no
    // `ssk_generation`) with the canonical timestamp form the SDK emits.
    let created_at_canonical = format_timestamp_canonical(peer_claim_receipt.claimed_at);
    let signing_input = json!({
        "keypackage_ref": keypackage_ref,
        "keypackage_digest": keypackage_digest,
        "intended_realm_id": realm_id,
        "claim_id": claim_id,
        "requester_did": alice_did,
        "requester_device_id": requester_device_id,
        "nonce": nonce,
        "welcome_digest": welcome_digest,
        "created_at": created_at_canonical,
    });
    let claim_signature = requester_device_key.sign(&canonical_json_bytes(&signing_input)?);
    let mut claim_ref = json!({
        "claim_id": claim_id,
        "keypackage_ref": keypackage_ref,
        "keypackage_digest": keypackage_digest,
        "capabilities_digest": claim.capabilities_digest,
    });
    if let Some(generation) = claim.ssk_generation {
        claim_ref["ssk_generation"] = json!(generation);
    }
    if let Some(event_id) = claim.device_authorize_event_id.as_deref() {
        claim_ref["device_authorize_event_id"] = json!(event_id);
    }
    Ok(json!({
        "mls_group_id": E2EE_MLS_GROUP_ID,
        "epoch": 1,
        "recipient_principal_id": bob_did,
        "recipient_device_id": BOB_DEVICE_ID,
        "keypackage_ref": keypackage_ref,
        "keypackage_digest": keypackage_digest,
        "claim_id": claim_id,
        "claim_ref": claim_ref,
        "claim_envelope": {
            "keypackage_ref": keypackage_ref,
            "keypackage_digest": keypackage_digest,
            "intended_realm_id": realm_id,
            "claim_id": claim_id,
            "requester_did": alice_did,
            "requester_device_id": requester_device_id,
            "nonce": nonce,
            "welcome_digest": welcome_digest,
            "created_at": created_at_canonical,
            "signature": {
                "kid": format!("{alice_did}#{requester_device_id}"),
                "alg": "EdDSA",
                "sig": URL_SAFE_NO_PAD.encode(claim_signature.to_bytes())
            }
        },
        "welcome_ref": "ak:blob:sha256:88888888888888888888888888888888888888888888888888888888888888e2",
        "ciphertext": welcome_bytes,
        "expires_at": peer_claim_receipt.expires_at,
        "commit_ref": E2EE_MLS_COMMIT_EVENT_ID,
        "governance_binding": mls_governance_binding(realm_id, 0, 1),
        "peer_claim_receipt": peer_claim_receipt
    }))
}

fn mls_commit_payload(realm_id: &str) -> Value {
    json!({
        "mls_group_id": E2EE_MLS_GROUP_ID,
        "base_epoch": 0,
        "base_epoch_ref": E2EE_MLS_GENESIS_EVENT_ID,
        "proposal_refs": [],
        "next_epoch": 1,
        "commit_digest": "sha256:7777777777777777777777777777777777777777777777777777777777777777",
        "governance_binding": mls_governance_binding(realm_id, 0, 1)
    })
}

fn encrypted_message_payload(realm_id: &str) -> Value {
    let strand_id = format!(
        "ak:strand:{}",
        realm_id.strip_prefix("ak:realm:").unwrap_or(realm_id)
    );
    json!({
        "strand_id": strand_id,
        "track_name": "discussion",
        "encrypted_content": {
            "scheme": "mls_rfc9420",
            "version": "1.0",
            "group_id": E2EE_MLS_GROUP_ID,
            "epoch": 1,
            "content_type": "application/vnd.arkret.message+json",
            "ciphertext": E2EE_MESSAGE_CIPHERTEXT,
            "aad_visibility_event_id": "hidden",
            "aad": {
                "realm_id": realm_id,
                "event_kind": "ak.message.create"
            },
            "key_ref": {
                "algorithm": "MLS",
                "group_state_ref": E2EE_MLS_COMMIT_EVENT_ID
            },
            "aad_digest": "sha256:9999999999999999999999999999999999999999999999999999999999999999",
            "payload_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    })
}

/// Typed model-A `ak.device.authorize` payload:
/// built on the SDK `DeviceAuthorizePayload` so a schema drift breaks the
/// build here instead of surfacing as a server-side `schema_violation`.
pub(crate) fn bootstrap_device_authorize_payload(
    principal_id: &str,
    device_id: &str,
    device_signing_key: &SigningKey,
) -> Result<Value> {
    let device_public_key =
        ed25519_pubkey_to_did_key_multibase(&device_signing_key.verifying_key().to_bytes());
    let principal = Did::new(principal_id.to_owned())
        .with_context(|| format!("invalid principal DID `{principal_id}`"))?;
    let device =
        arkret_identifiers::DeviceId::new(device_id.to_owned()).context("invalid device id")?;
    let algorithms = vec![
        arkret_wire::NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1").unwrap(),
        arkret_wire::NonEmptyString::new("ak.mls.v1").unwrap(),
    ];
    let trust_algorithms = algorithms
        .iter()
        .map(|algorithm| algorithm.as_str().to_owned())
        .collect::<Vec<_>>();
    let ssk_generation = std::num::NonZeroU64::new(1).unwrap();
    let ssk_signature =
        test_self_signing_key().sign(&arkret_crypto::DeviceTrustBinding::canonical_input(
            &principal,
            &device,
            &device_public_key,
            "z6LSCotestDeviceHpkeKey",
            &trust_algorithms,
            ssk_generation.get(),
        )?);
    let mut payload = arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload {
        principal_id: principal.clone(),
        device_id: device,
        device_public_key: arkret_wire::NonEmptyString::new(device_public_key)
            .map_err(anyhow::Error::msg)?,
        hpke_key: arkret_wire::NonEmptyString::new("z6LSCotestDeviceHpkeKey")
            .expect("static HPKE key is non-empty"),
        algorithms,
        device_key_algorithm: Some(arkret_wire::NonEmptyString::new("EdDSA").unwrap()),
        authorized_by: arkret_models_collaboration::events_payloads::device_identity::DeviceOrPrincipalRef::Did(principal),
        scopes: None,
        not_before: "2026-05-02T00:00:00.000Z"
            .parse()
            .expect("static timestamp parses"),
        expires_at: None,
        device_signature: None,
        proof: None,
        cross_signing_binding: Some(arkret_models_collaboration::events_payloads::device_identity::DeviceCrossSigningBinding {
            verification_method: arkret_wire::DidUrl::new(format!(
                "{principal_id}#ak_self_signing_v1"
            ))
            .map_err(anyhow::Error::msg)?,
            alg: arkret_wire::NonEmptyString::new("EdDSA").unwrap(),
            ssk_generation,
            signature: arkret_wire::Base64UrlString::new(
                URL_SAFE_NO_PAD.encode(ssk_signature.to_bytes()),
            )
            .unwrap(),
        }),
        enrollment_authority_binding: None,
        recovery_session_id: None,
    };
    let signature_input = payload
        .device_possession_signature_input()
        .context("build ak.device.authorize device possession signature input")?;
    let signature = device_signing_key.sign(&signature_input);
    let mut signature_material = BTreeMap::new();
    signature_material.insert("alg".to_owned(), json!("EdDSA"));
    signature_material.insert(
        "kid".to_owned(),
        json!(format!("{principal_id}#{device_id}")),
    );
    signature_material.insert(
        "sig".to_owned(),
        json!(URL_SAFE_NO_PAD.encode(signature.to_bytes())),
    );
    payload.device_signature = Some(
        arkret_models_collaboration::events_payloads::SignatureMaterial::Variant1(
            signature_material,
        ),
    );
    serde_json::to_value(&payload).context("serialize device.authorize payload")
}

fn test_self_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x52; 32])
}

fn test_principal_signing_key() -> SigningKey {
    SigningKey::from_bytes(&TEST_PRINCIPAL_SIGNING_KEY_SEED)
}

fn test_cross_signing_publish(actor: &str) -> Result<CrossSigningPublish> {
    let principal = Did::new(actor.to_owned()).context("invalid cross-signing principal")?;
    let psk = test_principal_signing_key();
    let ssk = test_self_signing_key();
    let usk = SigningKey::from_bytes(&[0x53; 32]);
    let psk_kid = format!("{actor}#cotest-principal-signing-key");
    let ssk_kid = format!("{actor}#ak_self_signing_v1");
    let usk_kid = format!("{actor}#ak_user_signing_v1");
    let key_record = |kid: String, key: &SigningKey| PublishedKey {
        kid: NonEmptyString::new(kid).expect("test key id is non-empty"),
        alg: NonEmptyString::new("EdDSA".to_owned()).unwrap(),
        public_key: NonEmptyString::new(ed25519_pubkey_to_did_key_multibase(
            &key.verifying_key().to_bytes(),
        ))
        .unwrap(),
        key_format: KeyFormat::Multibase,
    };
    let ssk_record = key_record(ssk_kid.clone(), &ssk);
    let usk_record = key_record(usk_kid, &usk);
    let pending_binding = |verification_method: String| SubordinateSignedKeyBinding {
        verification_method: NonEmptyString::new(verification_method).unwrap(),
        alg: NonEmptyString::new("EdDSA".to_owned()).unwrap(),
        signature: NonEmptyString::new("pending".to_owned()).unwrap(),
    };
    let mut publish = CrossSigningPublish {
        principal_id: principal,
        trust_domain: TypedTrustDomainId::new(
            "ak:trust_domain:0196419b-0000-7000-8000-000000000000".to_owned(),
        )?,
        principal_signing_key: key_record(psk_kid.clone(), &psk),
        self_signing_key: SubordinateSignedKey {
            kid: ssk_record.kid,
            alg: ssk_record.alg,
            public_key: ssk_record.public_key,
            key_format: ssk_record.key_format,
            binding: pending_binding(psk_kid.clone()),
        },
        user_signing_key: SubordinateSignedKey {
            kid: usk_record.kid,
            alg: usk_record.alg,
            public_key: usk_record.public_key,
            key_format: usk_record.key_format,
            binding: pending_binding(psk_kid),
        },
        expected_previous_generation: 0,
        generation: std::num::NonZeroU64::new(1).unwrap(),
        issued_at: "2026-05-02T00:00:00.000Z".parse().unwrap(),
    };
    publish.self_signing_key.binding.signature = NonEmptyString::new(
        URL_SAFE_NO_PAD.encode(psk.sign(&publish.self_signing_binding_input()?).to_bytes()),
    )
    .unwrap();
    publish.user_signing_key.binding.signature = NonEmptyString::new(
        URL_SAFE_NO_PAD.encode(psk.sign(&publish.user_signing_binding_input()?).to_bytes()),
    )
    .unwrap();
    Ok(publish)
}

async fn install_test_principal_control_document(server: &ArkretServer, actor: &str) -> Result<()> {
    let psk_kid = format!("{actor}#cotest-principal-signing-key");
    let (_, remainder) = actor
        .strip_prefix("did:webvh:")
        .and_then(|remainder| remainder.split_once(':'))
        .context("test principal is not a did:webvh DID")?;
    let (method_authority, local_id) = remainder
        .split_once(":webvh:")
        .context("test principal DID has no local id")?;
    let host = method_authority.replace("%3A", ":").replace("%3a", ":");
    let prepared = test_principal_inception(&host, local_id)?;
    anyhow::ensure!(
        prepared.did == actor,
        "deterministic native inception does not reproduce test principal DID"
    );
    let accepted = expect_json(
        server
            .http()
            .post(server.url("/_arkret/root/identity/submit-did-operation"))
            .json(&prepared.submit_body),
        StatusCode::OK,
    )
    .await?;
    anyhow::ensure!(
        matches!(accepted["status"].as_str(), Some("accepted" | "duplicate")),
        "principal inception was not accepted idempotently: {accepted}"
    );
    let resolved = expect_json(
        server
            .http()
            .post(server.url("/_arkret/root/identity/resolve"))
            .json(&json!({"did": actor})),
        StatusCode::OK,
    )
    .await?;
    anyhow::ensure!(
        resolved["did_document"]["verificationMethod"]
            .as_array()
            .is_some_and(|methods| methods.iter().any(|method| method["id"] == psk_kid)),
        "installed principal control key is absent from resolved DID document: {resolved}"
    );
    crate::harness::register_event_signing_identity(
        actor,
        TEST_PRINCIPAL_SIGNING_KEY_SEED,
        format!("{actor}#cotest-principal-signing-key"),
    );
    Ok(())
}

async fn publish_test_cross_signing(server: &ArkretServer, token: &str, actor: &str) -> Result<()> {
    install_test_principal_control_document(server, actor).await?;
    let principal = Did::new(actor.to_owned()).context("invalid cross-signing principal")?;
    let principal_realm = principal_control_realm_id(&principal);
    let accepted = crate::harness::submit_event_with_signing_seed_and_verification_method(
        server,
        token,
        actor,
        principal_realm.as_str(),
        "ak.cross_signing.publish",
        serde_json::to_value(test_cross_signing_publish(actor)?)?,
        StatusCode::OK,
        TEST_PRINCIPAL_SIGNING_KEY_SEED,
        &format!("{actor}#cotest-principal-signing-key"),
    )
    .await?;
    assert_eq!(accepted["status"], "accepted");
    Ok(())
}

pub async fn authorize_device_public_key(
    server: &ArkretServer,
    token: &str,
    actor: &str,
    device_id: &str,
    device_signing_key: &SigningKey,
) -> Result<()> {
    publish_test_cross_signing(server, token, actor).await?;
    authorize_additional_device_public_key(server, token, actor, device_id, device_signing_key)
        .await
}

pub(crate) async fn authorize_additional_device_public_key(
    server: &ArkretServer,
    token: &str,
    actor: &str,
    device_id: &str,
    device_signing_key: &SigningKey,
) -> Result<()> {
    let principal =
        Did::new(actor.to_owned()).with_context(|| format!("invalid principal DID `{actor}`"))?;
    let principal_realm = principal_control_realm_id(&principal);
    let accepted = crate::harness::submit_event_with_signing_seed_and_verification_method(
        server,
        token,
        actor,
        &principal_realm,
        "ak.device.authorize",
        bootstrap_device_authorize_payload(actor, device_id, device_signing_key)?,
        StatusCode::OK,
        TEST_PRINCIPAL_SIGNING_KEY_SEED,
        &format!("{actor}#cotest-principal-signing-key"),
    )
    .await?;
    assert_eq!(
        accepted["status"], "accepted",
        "device authorize response: {accepted}"
    );
    Ok(())
}

pub(crate) fn signed_keys_upload_body(
    actor: &str,
    device_id: &str,
    signing_key: &SigningKey,
    one_time_keys: Value,
    fallback_keys: Value,
) -> Result<KeysUploadRequestBody> {
    let one_time_keys = signed_algorithm_key_records(actor, one_time_keys, false)?;
    let fallback_keys = signed_algorithm_key_records(actor, fallback_keys, true)?;
    let signing_input = keys_upload_signing_input(device_id, &one_time_keys, &fallback_keys)?;
    let signature = signing_key.sign(&signing_input);
    let device_public_key =
        ed25519_pubkey_to_did_key_multibase(&signing_key.verifying_key().to_bytes());
    Ok(KeysUploadRequestBody {
        device_id: DeviceId::new(device_id.to_owned()).context("invalid keys/upload device id")?,
        one_time_keys,
        fallback_keys,
        device_signature: KeyOperationSignature {
            kid: NonEmptyString::new(format!("did:key:{device_public_key}#{device_public_key}"))
                .unwrap(),
            alg: Some(NonEmptyString::new("EdDSA").unwrap()),
            sig: Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes())).unwrap(),
        },
    })
}

fn signed_algorithm_key_records(
    actor: &str,
    records: Value,
    fallback: bool,
) -> Result<AlgorithmKeyRecords> {
    let Value::Object(records) = records else {
        anyhow::bail!("keys/upload key records must be an object");
    };
    let signing_key = test_self_signing_key();
    records
        .into_iter()
        .map(|(record_id, record)| {
            let Value::Object(mut record) = record else {
                anyhow::bail!("keys/upload record `{record_id}` must be an object");
            };
            let algorithm = record
                .get("algorithm")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .or_else(|| record_id.split_once(':').map(|(value, _)| value.to_owned()))
                .context("keys/upload record has no algorithm")?;
            let key_id = record
                .get("key_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .or_else(|| record_id.split_once(':').map(|(_, value)| value.to_owned()))
                .unwrap_or_else(|| record_id.clone());
            record
                .get("key")
                .and_then(Value::as_str)
                .context("keys/upload record has no key")?;
            record.insert("algorithm".to_owned(), json!(algorithm));
            record.insert("key_id".to_owned(), json!(key_id));
            if fallback {
                record.insert("fallback".to_owned(), json!(true));
            }
            let signed_fields = Value::Object(record.clone());
            let signature_input = canonical_json_bytes(&signed_fields)?;
            record.insert(
                "signature".to_owned(),
                json!({
                    "kid": format!("{actor}#ak_self_signing_v1"),
                    "alg": "EdDSA",
                    "sig": URL_SAFE_NO_PAD.encode(signing_key.sign(&signature_input).to_bytes()),
                }),
            );
            let record = serde_json::from_value(Value::Object(record))
                .with_context(|| format!("parse typed keys/upload record `{record_id}`"))?;
            let record_id = NonEmptyString::new(record_id).map_err(anyhow::Error::msg)?;
            Ok((record_id, record))
        })
        .collect()
}

pub(crate) fn keys_upload_signing_input(
    device_id: &str,
    one_time_keys: &impl Serialize,
    fallback_keys: &impl Serialize,
) -> Result<Vec<u8>> {
    let body = json!({
        "device_id": device_id,
        "one_time_keys": one_time_keys,
        "fallback_keys": fallback_keys,
    });
    let canonical = canonical_json_bytes(&body)?;
    let mut input = b"ak.keys-upload-v1\n".to_vec();
    input.extend_from_slice(&canonical);
    Ok(input)
}

fn signed_federation_event(
    event_id: &str,
    kind: &str,
    realm_id: &str,
    actor_id: &str,
    actor_seq: u64,
    prev_event_id: Option<&EventId>,
    payload: Value,
) -> Result<Event> {
    let mut event = Event::new(
        kind,
        RealmId::new(realm_id.to_owned())
            .with_context(|| format!("invalid federation realm_id `{realm_id}`"))?,
        Did::new(actor_id.to_owned())
            .with_context(|| format!("invalid federation actor_id `{actor_id}`"))?,
        actor_seq,
        Hlc::new(format!("01970e589d21-{actor_seq:04x}-a13f9c2e"))
            .context("invalid federation event HLC")?,
        payload,
    )?;
    event.created_at = chrono::DateTime::parse_from_rfc3339("2026-05-02T00:00:00.000Z")
        .context("invalid fixed federation event timestamp")?
        .with_timezone(&chrono::Utc);
    event.event_id = EventId::new(event_id.to_owned())
        .with_context(|| format!("invalid federation event_id `{event_id}`"))?;
    if let Some(prev_event_id) = prev_event_id {
        event.prev_refs.push(prev_event_id.clone());
    }
    sign_federation_event(&mut event)?;
    Ok(event)
}

fn sign_federation_event(event: &mut Event) -> Result<()> {
    let verification_method = format!("{}#cotest-principal-signing-key", event.actor_id);
    let signer = arkret_signatures::Ed25519MoveSigner::from_did_key_seed(
        test_principal_signing_key().to_bytes(),
        event.actor_id.clone(),
        verification_method.clone(),
    );
    let created_at = event.created_at;
    event.proofs.clear();
    arkret::signatures::sign_event(
        event,
        &signer,
        &verification_method,
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .context("sign federation Event with the provisioned principal key")
}

fn sign_federation_event_with_device(
    event: &mut Event,
    device_id: &str,
    device_signing_key: &SigningKey,
) -> Result<()> {
    let verification_method = format!("{}#{device_id}", event.actor_id);
    let signer = arkret_signatures::Ed25519MoveSigner::from_did_key_seed(
        device_signing_key.to_bytes(),
        event.actor_id.clone(),
        verification_method.clone(),
    );
    let created_at = event.created_at;
    event.proofs.clear();
    arkret::signatures::sign_event(
        event,
        &signer,
        &verification_method,
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .context("sign federation Event with the authorized device key")
}

async fn bootstrap_test_device_authorization(
    server: &ArkretServer,
    token: &str,
    actor: &str,
    device_id: &str,
    device_signing_key: &SigningKey,
) -> Result<arkret_wire::FederatedDeviceSigningKeyEvidence> {
    let (_, remainder) = actor
        .strip_prefix("did:webvh:")
        .and_then(|remainder| remainder.split_once(':'))
        .context("test principal is not a did:webvh DID")?;
    let (method_authority, local_id) = remainder
        .split_once(":webvh:")
        .context("test principal DID has no local id")?;
    let host = method_authority.replace("%3A", ":").replace("%3a", ":");
    let prepared = test_principal_inception(&host, local_id)?;
    let principal = Did::new(actor.to_owned()).context("invalid test principal DID")?;
    let realm_id = RealmId::new(principal_control_realm_id(&principal))?;
    let created_at = chrono::DateTime::parse_from_rfc3339("2026-05-02T00:00:00.000Z")?
        .with_timezone(&chrono::Utc);

    let mut create = build_self_principal_pcr_create(SelfPrincipalPcrCreateInput {
        principal_id: principal.clone(),
        realm_id: realm_id.clone(),
        trust_domain: server.trust_domain().clone(),
        did_inception_ref: EventRef::new(prepared.version_id.clone(), DID_INCEPTION_REF_ROLE),
        event_id: EventId::new(ALICE_PCR_CREATE_EVENT_ID.to_owned())?,
        created_at,
        hlc: Hlc::new("01970e589d21-0000-a13f9c2e")?,
    })?;
    let root_seed: [u8; 32] =
        Sha256::digest(format!("cotest:webvh:root:{host}:{local_id}").as_bytes()).into();
    let root_did = Did::new(format!("did:key:{}", prepared.root_public_key_multibase))?;
    let root_signer = arkret_signatures::Ed25519MoveSigner::from_did_key_seed(
        root_seed,
        root_did,
        prepared.root_verification_method.clone(),
    );
    arkret::signatures::sign_event(
        &mut create,
        &root_signer,
        &prepared.root_verification_method,
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )?;

    let enrollment_method = format!("{actor}#cotest-device-enrollment-authority");
    let device_public_key =
        ed25519_pubkey_to_did_key_multibase(&device_signing_key.verifying_key().to_bytes());
    let payload = arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload {
        principal_id: principal.clone(),
        device_id: DeviceId::new(device_id.to_owned())?,
        device_public_key: NonEmptyString::new(device_public_key.clone())
            .map_err(anyhow::Error::msg)?,
        hpke_key: NonEmptyString::new("z6LSCotestFederationHpkeKey").map_err(anyhow::Error::msg)?,
        algorithms: vec![
            NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1")
                .map_err(anyhow::Error::msg)?,
            NonEmptyString::new("ak.mls.v1").map_err(anyhow::Error::msg)?,
        ],
        device_key_algorithm: Some(NonEmptyString::new("EdDSA").map_err(anyhow::Error::msg)?),
        authorized_by: arkret_models_collaboration::events_payloads::device_identity::DeviceOrPrincipalRef::Did(principal.clone()),
        scopes: None,
        not_before: created_at,
        expires_at: None,
        device_signature: None,
        proof: None,
        cross_signing_binding: None,
        enrollment_authority_binding: Some(arkret_models_identity::artifacts_device_identity::DeviceEnrollmentAuthorityBinding {
            kind: arkret_models_identity::artifacts_device_identity::DeviceEnrollmentAuthorityBindingKind::ServiceAttested,
            authority_did: principal.clone(),
            authorization_ref: NonEmptyString::new(enrollment_method.clone())
                .map_err(anyhow::Error::msg)?,
        }),
        recovery_session_id: None,
    };
    let mut authorize = Event::new(
        arkret_wire::events::EventKind::DEVICE_AUTHORIZE,
        realm_id,
        principal.clone(),
        1,
        Hlc::new("01970e589d21-0001-a13f9c2e")?,
        serde_json::to_value(payload)?,
    )?;
    authorize.event_id = EventId::new(ALICE_DEVICE_AUTHORIZE_EVENT_ID.to_owned())?;
    authorize.created_at = created_at;
    authorize.prev_refs = vec![create.event_id.clone()];
    authorize.executed_by = Some(principal.clone());
    authorize.authorization_ref = Some(enrollment_method.clone());
    let enrollment_seed: [u8; 32] =
        Sha256::digest(format!("cotest:webvh:enrollment:{host}:{local_id}").as_bytes()).into();
    let enrollment_signer = arkret_signatures::Ed25519MoveSigner::from_did_key_seed(
        enrollment_seed,
        principal.clone(),
        enrollment_method.clone(),
    );
    arkret::signatures::sign_event(
        &mut authorize,
        &enrollment_signer,
        &enrollment_method,
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )?;

    let request = self_principal_bootstrap_submit_request(create, authorize.clone())?;
    let accepted = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(token)
            .json(&request),
        StatusCode::OK,
    )
    .await?;
    assert_json_array_contains(&accepted["accepted"], ALICE_PCR_CREATE_EVENT_ID, &accepted);
    assert_json_array_contains(
        &accepted["accepted"],
        ALICE_DEVICE_AUTHORIZE_EVENT_ID,
        &accepted,
    );

    Ok(arkret_wire::FederatedDeviceSigningKeyEvidence {
        actor_id: principal,
        device_id: DeviceId::new(device_id.to_owned())?,
        verification_method: format!("{actor}#{device_id}"),
        device_signing_key: arkret_wire::DidKey::new(format!("did:key:{device_public_key}"))
            .map_err(anyhow::Error::msg)?,
        authorization_accepted_at: chrono::Utc::now(),
        device_authorize_event: Box::new(authorize),
    })
}

async fn upload_test_keypackage(
    server: &ArkretServer,
    token: &str,
    principal_id: &str,
    device_id: &str,
    device_signing_key: &SigningKey,
) -> Result<()> {
    let key_package = b"cotest-cross-ps-bob-keypackage";
    let keypackage_digest = sha256_digest(key_package);
    let now = chrono::Utc::now();
    let unsigned: arkret_models_crypto::KeyPackagesUploadUnsignedRequest =
        serde_json::from_value(json!({
            "principal_id": principal_id,
            "device_id": device_id,
            "key_packages": [{
                "keypackage_id": "cotest-cross-ps-bob-keypackage-01",
                "keypackage_ref": keypackage_digest,
                "keypackage_digest": keypackage_digest,
                "key_package": URL_SAFE_NO_PAD.encode(key_package),
                "cipher_suites": ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
                "capabilities": ["mls"],
                "created_at": format_timestamp_canonical(now),
                "expires_at": format_timestamp_canonical(now + chrono::Duration::hours(1))
            }]
        }))?;
    let signature = arkret_signatures::keypackages::sign_keypackages_upload_request(
        &unsigned,
        &format!("{principal_id}#{device_id}"),
        &device_signing_key.to_bytes(),
    )?;
    let body = unsigned.into_signed(signature);
    let outcome = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/keys/keypackages/upload"))
            .bearer_auth(token)
            .json(&body),
        StatusCode::OK,
    )
    .await?;
    anyhow::ensure!(
        outcome["accepted"].as_u64() == Some(1),
        "Bob KeyPackage upload was not accepted: {outcome}"
    );
    Ok(())
}

async fn claim_test_keypackage(
    source: &ArkretServer,
    destination: &ArkretServer,
    requester: &str,
    target: &str,
    requester_device_key: &SigningKey,
    requester_evidence: &arkret_wire::FederatedDeviceSigningKeyEvidence,
) -> Result<PeerKeyPackagesClaimOutcome> {
    let claim_request_id =
        Base64UrlString::new("Y2xhaW0tY3Jvc3MtcHMtMDE").map_err(anyhow::Error::msg)?;
    let signed_at = chrono::Utc::now();
    let verification_method = format!("{requester}#{}", requester_evidence.device_id);
    let mut body = PeerKeyPackagesClaimRequestBody {
        claim_request_id: claim_request_id.clone(),
        target_principal_id: Did::new(target.to_owned())?,
        requester: Did::new(requester.to_owned())?,
        intended_realm_id: RealmId::new(E2EE_REALM_ID.to_owned())?,
        mls_group_id: NonEmptyString::new(E2EE_MLS_GROUP_ID).map_err(anyhow::Error::msg)?,
        claim_purpose: PeerKeyPackageClaimPurpose::RealmMembership,
        required_capabilities: vec![NonEmptyString::new("mls").map_err(anyhow::Error::msg)?],
        claim_nonce: Base64UrlString::new("Y2xhaW1fbm9uY2VfY3Jvc3NfcHNfMDE")
            .map_err(anyhow::Error::msg)?,
        expires_at: signed_at + chrono::Duration::minutes(5),
        target_device_ids: vec![DeviceId::new(BOB_DEVICE_ID.to_owned())?],
        minimal_metadata_allowed: Some(false),
        timeout_ms: Some(5_000),
        strand_id: None,
        pair_key: None,
        last_resort_allowed: Some(false),
        requester_authorization: PeerKeyPackageRequesterAuthorization {
            verification_method: NonEmptyString::new(verification_method.clone())
                .map_err(anyhow::Error::msg)?,
            requester_device_id: Some(requester_evidence.device_id.clone()),
            ssk_generation: None,
            device_authorize_event_id: Some(
                NonEmptyString::new(
                    requester_evidence
                        .device_authorize_event
                        .event_id
                        .to_string(),
                )
                .map_err(anyhow::Error::msg)?,
            ),
            signed_at,
            signature: KeyOperationSignature {
                kid: NonEmptyString::new(verification_method.clone())
                    .map_err(anyhow::Error::msg)?,
                alg: Some(NonEmptyString::new("EdDSA").map_err(anyhow::Error::msg)?),
                sig: Base64UrlString::new("AA").map_err(anyhow::Error::msg)?,
            },
        },
        requester_signing_key_evidence: Some(requester_evidence.clone()),
    };
    let draft = PeerKeyPackagesClaimAuthorizationDraft {
        request: body.unsigned_request(),
        transport_binding: PeerKeyPackagesClaimTransportBinding {
            source_service_id: Did::new(source.service_id().to_owned())?,
            destination_service_id: Did::new(destination.service_id().to_owned())?,
            source_trust_domain: source.trust_domain().clone(),
            destination_trust_domain: destination.trust_domain().clone(),
        },
    };
    let signing_bytes =
        peer_keypackage_claim_authorization_signing_bytes(&draft, &body.requester_authorization)?;
    body.requester_authorization.signature.sig = Base64UrlString::new(
        URL_SAFE_NO_PAD.encode(requester_device_key.sign(&signing_bytes).to_bytes()),
    )
    .map_err(anyhow::Error::msg)?;

    let url = destination.url("/_arkret/peer/keys/keypackages/claim");
    let outcome = expect_json(
        with_federation_trust_headers_and_idempotency(
            destination.http().post(&url).json(&body),
            "POST",
            &url,
            source,
            destination,
            &body,
            claim_request_id.as_str(),
        )?,
        StatusCode::OK,
    )
    .await?;
    serde_json::from_value(outcome).context("decode peer KeyPackage claim outcome")
}

fn attach_delivery_policy_cell_contract(event: &mut Event) -> Result<()> {
    let cell = arkret_identifiers::CellRef::new(format!(
        "ak:cell:ak.component.realm.delivery_binding_policy.v1:{}",
        event.realm_id
    ))?;
    event.preconditions = vec![arkret_wire::Precondition {
        cell: cell.clone(),
        predicate: arkret_wire::Predicate {
            op: arkret_wire::PredicateOp::HeadEq,
            value: Some(Value::Null),
            values: None,
            predicate_id: None,
        },
    }];
    event.effects = vec![arkret_wire::Effect {
        cell,
        op: arkret_wire::LatticeOp {
            op_type: arkret_wire::LatticeOpType::Set,
            tag: None,
            value: Some(serde_json::to_value(&event.payload)?),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        },
    }];
    Ok(())
}

fn with_federation_trust_headers(
    builder: reqwest::RequestBuilder,
    method: &str,
    target_url: &str,
    source: &ArkretServer,
    destination: &ArkretServer,
    body: &impl Serialize,
) -> Result<reqwest::RequestBuilder> {
    let body_bytes = canonical_json_bytes(body)?;
    let content_digest =
        ContentDigest::compute(&body_bytes, ContentDigestAlgorithm::Sha256).wire_value;
    let request_canonical_digest = canonical_sha256(body)?;
    let builder = with_federation_trust_headers_for_digest(
        builder,
        FederationDigestHeaders {
            method,
            target_url,
            source,
            destination,
            content_digest,
            request_canonical_digest,
            idempotency_key: None,
        },
    )?;
    Ok(builder.body(body_bytes))
}

fn with_federation_trust_headers_and_idempotency(
    builder: reqwest::RequestBuilder,
    method: &str,
    target_url: &str,
    source: &ArkretServer,
    destination: &ArkretServer,
    body: &impl Serialize,
    idempotency_key: &str,
) -> Result<reqwest::RequestBuilder> {
    let body_bytes = canonical_json_bytes(body)?;
    let content_digest =
        ContentDigest::compute(&body_bytes, ContentDigestAlgorithm::Sha256).wire_value;
    let request_canonical_digest = canonical_sha256(body)?;
    let builder = with_federation_trust_headers_for_digest(
        builder,
        FederationDigestHeaders {
            method,
            target_url,
            source,
            destination,
            content_digest,
            request_canonical_digest,
            idempotency_key: Some(idempotency_key),
        },
    )?;
    Ok(builder.body(body_bytes))
}

fn with_federation_trust_headers_empty(
    builder: reqwest::RequestBuilder,
    method: &str,
    target_url: &str,
    source: &ArkretServer,
    destination: &ArkretServer,
) -> Result<reqwest::RequestBuilder> {
    let source_service_id = source.service_id();
    let destination_service_id = destination.service_id();
    let source_trust_domain = source.trust_domain().as_str();
    let destination_trust_domain = destination.trust_domain().as_str();

    let parsed_url = Url::parse(target_url)?;
    let authority = parsed_url
        .port()
        .map(|port| format!("{}:{port}", parsed_url.host_str().unwrap_or("server")))
        .unwrap_or_else(|| parsed_url.host_str().unwrap_or("server").to_owned());
    let path_and_query = parsed_url
        .query()
        .map(|query| format!("{}?{query}", parsed_url.path()))
        .unwrap_or_else(|| parsed_url.path().to_owned());
    let target_uri = format!("{}://{}{}", parsed_url.scheme(), authority, path_and_query);

    let created = chrono::Utc::now().timestamp();
    let expires = created + 300;
    let keyid = format!("{source_service_id}#federation-fanout-key");
    let signature_params = format!(
        "(\"@method\" \"@target-uri\" \"@authority\" \"source-service-id\" \
         \"destination-service-id\" \"source-trust-domain\" \
         \"destination-trust-domain\");created={created};\
         expires={expires};keyid=\"{keyid}\";alg=\"ed25519\""
    );
    let signature_base = format!(
        "\"@method\": {}\n\
         \"@target-uri\": {target_uri}\n\
         \"@authority\": {authority}\n\
         \"source-service-id\": {source_service_id}\n\
         \"destination-service-id\": {destination_service_id}\n\
         \"source-trust-domain\": {source_trust_domain}\n\
         \"destination-trust-domain\": {destination_trust_domain}\n\
         \"@signature-params\": {signature_params}",
        method.to_ascii_uppercase()
    );
    let signing_key = signing_key_from_seed(source.notary_signing_key_seed());
    let signature = sign_message(signature_base.as_bytes(), &signing_key);

    Ok(builder
        .header("Source-Service-ID", source_service_id)
        .header("Destination-Service-ID", destination_service_id)
        .header("Source-Trust-Domain", source_trust_domain)
        .header("Destination-Trust-Domain", destination_trust_domain)
        .header("Signature-Input", format!("sig1={signature_params}"))
        .header("Signature", format!("sig1=:{signature}:")))
}

struct FederationDigestHeaders<'a> {
    method: &'a str,
    target_url: &'a str,
    source: &'a ArkretServer,
    destination: &'a ArkretServer,
    content_digest: String,
    request_canonical_digest: String,
    idempotency_key: Option<&'a str>,
}

fn with_federation_trust_headers_for_digest(
    builder: reqwest::RequestBuilder,
    headers: FederationDigestHeaders<'_>,
) -> Result<reqwest::RequestBuilder> {
    let FederationDigestHeaders {
        method,
        target_url,
        source,
        destination,
        content_digest,
        request_canonical_digest,
        idempotency_key,
    } = headers;
    let source_service_id = source.service_id();
    let destination_service_id = destination.service_id();
    let source_trust_domain = source.trust_domain().as_str();
    let destination_trust_domain = destination.trust_domain().as_str();

    let parsed_url = Url::parse(target_url)?;
    let authority = parsed_url
        .port()
        .map(|port| format!("{}:{port}", parsed_url.host_str().unwrap_or("server")))
        .unwrap_or_else(|| parsed_url.host_str().unwrap_or("server").to_owned());
    let path_and_query = parsed_url
        .query()
        .map(|query| format!("{}?{query}", parsed_url.path()))
        .unwrap_or_else(|| parsed_url.path().to_owned());
    let target_uri = format!("{}://{}{}", parsed_url.scheme(), authority, path_and_query);

    let created = chrono::Utc::now().timestamp();
    let expires = created + 300;
    let keyid = format!("{source_service_id}#federation-fanout-key");
    let idempotency_component = idempotency_key.map_or("", |_| " \"idempotency-key\"");
    let signature_params = format!(
        "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \
         \"source-service-id\" \"destination-service-id\" \"source-trust-domain\" \
         \"destination-trust-domain\" \"request-canonical-digest\"{idempotency_component});created={created};\
         expires={expires};keyid=\"{keyid}\";alg=\"ed25519\""
    );
    let idempotency_line = idempotency_key
        .map(|value| format!("\"idempotency-key\": {value}\n"))
        .unwrap_or_default();
    let signature_base = format!(
        "\"@method\": {}\n\
         \"@target-uri\": {target_uri}\n\
         \"@authority\": {authority}\n\
         \"content-digest\": {content_digest}\n\
         \"source-service-id\": {source_service_id}\n\
         \"destination-service-id\": {destination_service_id}\n\
         \"source-trust-domain\": {source_trust_domain}\n\
         \"destination-trust-domain\": {destination_trust_domain}\n\
         \"request-canonical-digest\": {request_canonical_digest}\n\
         {idempotency_line}\
         \"@signature-params\": {signature_params}",
        method.to_ascii_uppercase()
    );
    let signing_key = signing_key_from_seed(source.notary_signing_key_seed());
    let signature = sign_message(signature_base.as_bytes(), &signing_key);

    let mut builder = builder
        .header("Content-Digest", content_digest)
        .header("Source-Service-ID", source_service_id)
        .header("Destination-Service-ID", destination_service_id)
        .header("Source-Trust-Domain", source_trust_domain)
        .header("Destination-Trust-Domain", destination_trust_domain)
        .header("Request-Canonical-Digest", request_canonical_digest)
        .header("Signature-Input", format!("sig1={signature_params}"))
        .header("Signature", format!("sig1=:{signature}:"));
    if let Some(idempotency_key) = idempotency_key {
        builder = builder.header("Idempotency-Key", idempotency_key);
    }
    Ok(builder)
}

/// Mint a distinct, fully verifiable `did:webvh` principal for a test service.
/// When the harness service still uses `did:key`, its stable multibase value is
/// placed under the reserved `.cotest.local` suffix so the resulting method
/// authority is a DNS-shaped test host rather than a non-standard bare label.
pub fn actor_did_for_service(service_id: &str, actor: &str) -> Result<String> {
    Ok(prepare_actor_inception_for_service(service_id, actor)?.did)
}

/// Prepare the deterministic native WebVH inception used by live principal
/// scenarios without submitting it, so endpoint tests can inspect the exact
/// request and outcome themselves.
pub fn prepare_actor_inception_for_service(
    service_id: &str,
    actor: &str,
) -> Result<PreparedPrincipalInception> {
    let service_host = did_authority_from_service_id(service_id);
    let service_authority = did_web_host_to_url_authority(&service_host);
    let webvh_host = if service_authority.contains('.') {
        service_authority
    } else {
        format!("{service_authority}.cotest.local")
    };
    test_principal_inception(&webvh_host, actor).with_context(|| {
        format!("prepare test principal inception for local id {actor:?} at {webvh_host:?}")
    })
}

/// Convert the percent-encoded port separator required by `did:web` method
/// identifiers back into the HTTP authority form expected by `Url`.
///
/// Keep this conversion local to principal URL construction; federation trust
/// domains come directly from each service's typed describe response.
fn did_web_host_to_url_authority(host: &str) -> String {
    host.replace("%3A", ":").replace("%3a", ":")
}

fn test_principal_inception(host: &str, local_id: &str) -> Result<PreparedPrincipalInception> {
    let endpoint = Url::parse(&format!("https://{host}/"))
        .with_context(|| format!("invalid test principal WebVH host {host}"))?;
    let root_seed: [u8; 32] =
        Sha256::digest(format!("cotest:webvh:root:{host}:{local_id}").as_bytes()).into();
    let next_root_seed: [u8; 32] =
        Sha256::digest(format!("cotest:webvh:next-root:{host}:{local_id}").as_bytes()).into();
    let enrollment_seed: [u8; 32] =
        Sha256::digest(format!("cotest:webvh:enrollment:{host}:{local_id}").as_bytes()).into();
    let next_root = SigningKey::from_bytes(&next_root_seed);
    let enrollment = SigningKey::from_bytes(&enrollment_seed);
    let next_root_multibase =
        ed25519_pubkey_to_did_key_multibase(&next_root.verifying_key().to_bytes());
    let principal_signing_multibase = ed25519_pubkey_to_did_key_multibase(
        &test_principal_signing_key().verifying_key().to_bytes(),
    );
    let enrollment_multibase =
        ed25519_pubkey_to_did_key_multibase(&enrollment.verifying_key().to_bytes());
    prepare_principal_inception(&PrincipalInceptionInput {
        principal_endpoint: &endpoint,
        local_id,
        also_known_as: &[],
        version_time: chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00.000Z")?
            .with_timezone(&chrono::Utc),
        root_seed: &root_seed,
        next_root_public_key_multibase: &next_root_multibase,
        enrollment: PrincipalEnrollmentDelegation::SelfAuthority {
            principal_signing_public_key_multibase: &principal_signing_multibase,
            enrollment_public_key_multibase: &enrollment_multibase,
            principal_signing_fragment: Some("cotest-principal-signing-key"),
            enrollment_fragment: Some("cotest-device-enrollment-authority"),
        },
    })
    .with_context(|| {
        format!(
            "prepare deterministic native principal inception for local id {local_id:?} at {endpoint}"
        )
    })
}

/// Extract the DID method authority while retaining an encoded local port.
/// Principal inception needs the port to address the local WebVH endpoint.
fn did_authority_from_service_id(service_id: &str) -> String {
    if let Some(rest) = service_id.strip_prefix("did:webvh:") {
        let mut parts = rest.split(':');
        let scid = parts.next().unwrap_or_default();
        if let Some(host) = parts.next()
            && !scid.is_empty()
            && !host.is_empty()
        {
            return host.to_ascii_lowercase();
        }
    }
    if let Some(rest) = service_id.strip_prefix("did:web:")
        && let Some(host) = rest.split(':').next()
        && !host.is_empty()
    {
        return host.to_ascii_lowercase();
    }
    service_id
        .strip_prefix("did:key:")
        .unwrap_or(service_id)
        .to_ascii_lowercase()
        .replace(':', ".")
}

fn sync_timeline_events<'a>(delta: &'a Value, realm_id: &str) -> Result<&'a Vec<Value>> {
    delta
        .get("realms")
        .or_else(|| delta.get("spaces"))
        .and_then(|realms| realms.get(realm_id))
        .and_then(|realm| realm.get("timeline"))
        .and_then(|timeline| timeline.get("events"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            anyhow::anyhow!("sync delta missing timeline events for {realm_id}: {delta}")
        })
}

fn event_body(event: &Value) -> Option<&str> {
    event
        .pointer("/content/body")
        .or_else(|| event.pointer("/payload/content/body"))
        .or_else(|| event.pointer("/payload/body"))
        .and_then(Value::as_str)
}

fn event_encrypted_ciphertext(event: &Value) -> Option<&str> {
    event
        .pointer("/encrypted_content/ciphertext")
        .or_else(|| event.pointer("/payload/encrypted_content/ciphertext"))
        .or_else(|| event.pointer("/content/ciphertext"))
        .or_else(|| event.pointer("/content/encrypted_content/ciphertext"))
        .and_then(Value::as_str)
}

fn assert_json_array_contains(array: &Value, expected: &str, context: &Value) {
    assert!(
        array
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some(expected)),
        "expected {array} to contain {expected}; response: {context}"
    );
}
