use std::collections::BTreeMap;

use anyhow::{Context, Result};
use arkret::http_signature::{
    ContentDigest, ContentDigestAlgorithm, sign_message, signing_key_from_seed,
};
use arkret::identity::binding::multicodec_ed25519_public_key;
use arkret_core::canonical::{
    canonical_json_bytes, canonical_sha256, format_timestamp_canonical, sha256_digest,
};
use arkret_core::{
    AlgorithmKeyRecords, Base64UrlString, CrossSigningPublish, DeviceId, Did, Event, EventId, Hash,
    Hlc, KeyFormat, KeyOperationSignature, KeysUploadRequestBody, NonEmptyString, Proof,
    PublishedKey, RealmId, SubordinateSignedKey, SubordinateSignedKeyBinding, TypedTrustDomainId,
    principal_control_realm_id, proof_kind,
};
use arkret_signatures::webvh::{
    PreparedPrincipalInception, PrincipalEnrollmentDelegation, PrincipalInceptionInput,
    prepare_principal_inception,
};
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
    expect_json, expect_text, member_join_payload_value, member_join_payload_with_delivery_binding,
    message_create_text_payload, register_account, submit_event,
};
use crate::scenarios::_helpers::federation_binding::{
    peer_events_submit_body, peer_events_submit_body_with_delivery_frontier,
};

const ALICE_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-0000000000a1";
const BOB_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-0000000000bb";
const REALM_CREATE_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc011ab000";
const ALICE_MESSAGE_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000001";
const BOB_JOIN_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000002";
const BOB_MESSAGE_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000003";
const ALICE_DELIVERY_BINDING_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000004";
const E2EE_REALM_ID: &str = "ak:realm:01904100-0000-7000-8000-fedc011ab0e2";
const E2EE_REALM_CREATE_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000e01";
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
const ALICE_CROSS_SIGNING_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000a10";
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
    assert_eq!(describe_a["service_type"], "principal_server");
    assert_eq!(describe_b["service_type"], "principal_server");

    let bob_document = expect_json(
        server_a
            .http()
            .post(server_a.url("/_arkret/root/identity/resolve"))
            .json(&json!({"did": bob_did})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(bob_document["did_document"]["id"], bob_did);

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
            "allow_binding_sources": ["explicit"],
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
                "recipient_service_type": "principal_server",
                "binding_scope": "realm",
                "binding_source": "explicit",
                "delivery_modes": ["events", "sync"],
                "service_acceptance_ref": ALICE_DELIVERY_BINDING_EVENT_ID,
                "resolved_at": "2026-05-02T00:00:00Z"
            }),
        )?,
        StatusCode::OK,
    )
    .await?;
    let alice_local_binding_frontier = alice_local_binding["event_id"]
        .as_str()
        .context("alice server_a binding response missing event_id")?
        .to_owned();
    let realm_create = signed_federation_event(
        REALM_CREATE_EVENT_ID,
        "ak.realm.create",
        &realm_id,
        &alice_did,
        1,
        federated_realm_payload(&realm_id, &alice_did, &visible_services),
    )?;
    let alice_delivery_binding = signed_federation_event(
        ALICE_DELIVERY_BINDING_EVENT_ID,
        "ak.member.state",
        &realm_id,
        &alice_did,
        2,
        member_delivery_binding_payload(&realm_id, &alice_did, server_a.service_id()),
    )?;
    let alice_message = signed_federation_event(
        ALICE_MESSAGE_EVENT_ID,
        "ak.message.create",
        &realm_id,
        &alice_did,
        3,
        message_create_text_payload(&realm_id, "hello bob from server a")?,
    )?;
    let bob_join = signed_federation_event(
        BOB_JOIN_EVENT_ID,
        "ak.member.state",
        &realm_id,
        &alice_did,
        4,
        member_join_payload_value(&realm_id, &bob_did)?,
    )?;
    let a_to_b_body = peer_events_submit_body(
        &realm_id,
        vec![
            realm_create,
            alice_delivery_binding,
            alice_message,
            bob_join,
        ],
        Some("a-to-b-01"),
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
        REALM_CREATE_EVENT_ID,
        &pushed_to_b,
    );
    assert_json_array_contains(
        &pushed_to_b["accepted"],
        ALICE_DELIVERY_BINDING_EVENT_ID,
        &pushed_to_b,
    );
    assert_json_array_contains(
        &pushed_to_b["accepted"],
        ALICE_MESSAGE_EVENT_ID,
        &pushed_to_b,
    );
    assert_json_array_contains(&pushed_to_b["accepted"], BOB_JOIN_EVENT_ID, &pushed_to_b);

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
        1,
        message_create_text_payload(&realm_id, "hello alice from server b")?,
    )?;
    let b_to_a_delivery_frontier = vec![
        arkret_core::EventId::new(alice_local_binding_frontier)
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

    // Federate alice's device identity to server_b so the receiver can verify
    // the cross-server MLS Welcome's `claim_envelope.signature` against alice's
    // device key (crypto-media/encryption-and-audit.md §6.04 device path:
    // requester_device_id → the requester's current accepted, unrevoked device
    // projection). soland projects an accepted `ak.device.authorize` into a
    // `verification_state="verified"` device row (project_device_authorize), so
    // the welcome's device-bound claim signature can be checked on server_b.
    let alice_device_key = SigningKey::from_bytes(&ALICE_DEVICE_KEY_SEED);
    let alice_principal_realm =
        principal_control_realm_id(&Did::new(alice_did.clone()).context("invalid alice did")?);
    install_test_principal_control_document(server_b, &alice_did).await?;
    let alice_cross_signing = signed_federation_event(
        ALICE_CROSS_SIGNING_EVENT_ID,
        "ak.cross_signing.publish",
        &alice_principal_realm,
        &alice_did,
        4,
        serde_json::to_value(test_cross_signing_publish(&alice_did)?)?,
    )?;
    let mut alice_device_authorize = signed_federation_event(
        ALICE_DEVICE_AUTHORIZE_EVENT_ID,
        "ak.device.authorize",
        &alice_principal_realm,
        &alice_did,
        5,
        bootstrap_device_authorize_payload(&alice_did, ALICE_DEVICE_ID, &alice_device_key)?,
    )?;
    alice_device_authorize.prev_refs = vec![
        EventId::new(ALICE_CROSS_SIGNING_EVENT_ID.to_owned())
            .context("invalid alice cross-signing event id")?,
    ];
    let authorize_digest =
        Hash::new(alice_device_authorize.event_digest()?).context("invalid device event digest")?;
    alice_device_authorize.proofs[0].event_digest = authorize_digest;
    let alice_device_body = peer_events_submit_body(
        &alice_principal_realm,
        vec![alice_cross_signing, alice_device_authorize],
        Some("a-to-b-identity-bootstrap-01"),
    )?;
    let alice_device_url = server_b.url("/_arkret/peer/events");
    let alice_device_pushed = expect_json(
        with_federation_trust_headers(
            server_b
                .http()
                .post(&alice_device_url)
                .json(&alice_device_body),
            "POST",
            &alice_device_url,
            server_a,
            server_b,
            &alice_device_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_json_array_contains(
        &alice_device_pushed["accepted"],
        ALICE_CROSS_SIGNING_EVENT_ID,
        &alice_device_pushed,
    );
    assert_json_array_contains(
        &alice_device_pushed["accepted"],
        ALICE_DEVICE_AUTHORIZE_EVENT_ID,
        &alice_device_pushed,
    );

    let e2ee_realm_create = signed_federation_event(
        E2EE_REALM_CREATE_EVENT_ID,
        "ak.realm.create",
        E2EE_REALM_ID,
        &alice_did,
        6,
        federated_e2ee_realm_payload(E2EE_REALM_ID, &alice_did),
    )?;
    let e2ee_bob_join = signed_federation_event(
        E2EE_BOB_JOIN_EVENT_ID,
        "ak.member.state",
        E2EE_REALM_ID,
        &alice_did,
        7,
        member_delivery_binding_payload(E2EE_REALM_ID, &bob_did, server_b.service_id()),
    )?;
    let e2ee_genesis = signed_federation_event(
        E2EE_MLS_GENESIS_EVENT_ID,
        "ak.mls.genesis",
        E2EE_REALM_ID,
        &alice_did,
        8,
        mls_genesis_payload(E2EE_REALM_ID, &alice_did),
    )?;
    let e2ee_welcome = signed_federation_event(
        E2EE_MLS_WELCOME_EVENT_ID,
        "ak.mls.welcome",
        E2EE_REALM_ID,
        &alice_did,
        9,
        mls_welcome_payload(
            E2EE_REALM_ID,
            &alice_did,
            &bob_did,
            &alice_device_key,
            ALICE_DEVICE_ID,
            ALICE_DEVICE_AUTHORIZE_EVENT_ID,
        )?,
    )?;
    let e2ee_commit = signed_federation_event(
        E2EE_MLS_COMMIT_EVENT_ID,
        "ak.mls.commit",
        E2EE_REALM_ID,
        &alice_did,
        10,
        mls_commit_payload(E2EE_REALM_ID),
    )?;
    let e2ee_message = signed_federation_event(
        E2EE_MESSAGE_EVENT_ID,
        "ak.message.create",
        E2EE_REALM_ID,
        &alice_did,
        11,
        encrypted_message_payload(E2EE_REALM_ID),
    )?;
    let e2ee_body = peer_events_submit_body(
        E2EE_REALM_ID,
        vec![
            e2ee_realm_create,
            e2ee_bob_join,
            e2ee_genesis,
            e2ee_welcome,
            e2ee_commit,
            e2ee_message,
        ],
        Some("a-to-b-e2ee-01"),
    )?;
    let pushed_e2ee = expect_json(
        with_federation_trust_headers(
            server_b
                .http()
                .post(server_b.url("/_arkret/peer/events"))
                .json(&e2ee_body),
            "POST",
            &server_b.url("/_arkret/peer/events"),
            server_a,
            server_b,
            &e2ee_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    for accepted_id in [
        E2EE_REALM_CREATE_EVENT_ID,
        E2EE_BOB_JOIN_EVENT_ID,
        E2EE_MLS_GENESIS_EVENT_ID,
        E2EE_MLS_WELCOME_EVENT_ID,
        E2EE_MLS_COMMIT_EVENT_ID,
        E2EE_MESSAGE_EVENT_ID,
    ] {
        assert_json_array_contains(&pushed_e2ee["accepted"], accepted_id, &pushed_e2ee);
    }

    let pending_welcomes = expect_json(
        server_b
            .http()
            .get(server_b.url("/_soland/self/keys/keypackages/welcomes/pending"))
            .bearer_auth(&bob),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(pending_welcomes["welcomes"].as_array().unwrap().len(), 1);
    assert_eq!(
        pending_welcomes["welcomes"][0]["welcome_id"],
        "ak:blob:sha256:88888888888888888888888888888888888888888888888888888888888888e2"
    );
    assert_eq!(
        pending_welcomes["welcomes"][0]["mls_group_ref"],
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

    let bob_device_key = SigningKey::from_bytes(&BOB_DEVICE_KEY_SEED);
    authorize_device_public_key(server_b, &bob, &bob_did, BOB_DEVICE_ID, &bob_device_key).await?;
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
                            "kind": "ak.mls.welcome",
                            "content": encrypted_envelope("ak.mls.welcome", "opaque-cross-server-welcome"),
                            "expires_at": "2026-12-31T00:00:00Z"
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
    assert_eq!(
        received["messages"][0]["content"]["ciphertext"],
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
    let created = submit_event(
        server,
        alice,
        alice_did,
        &realm_id,
        "ak.realm.create",
        federated_realm_payload(&realm_id, alice_did, visible_services),
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
                "service_type": "principal_server",
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
            "created_at": "2026-05-02T00:00:00Z"
        }
    })
}

fn member_delivery_binding_payload(realm_id: &str, member_did: &str, service_id: &str) -> Value {
    member_join_payload_with_delivery_binding(
        realm_id,
        member_did,
        json!({
            "recipient_service_id": service_id,
            "recipient_service_type": "principal_server",
            "binding_scope": "realm",
            "binding_source": "explicit",
            "delivery_modes": ["events", "sync", "to_device", "push", "key_packages"],
            "resolved_at": "2026-05-02T00:00:00Z",
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
            "content_scheme": "mls-exporter-aead-v1",
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
            "created_at": "2026-05-02T00:00:00Z"
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
        "created_at": "2026-05-25T00:00:01Z"
    })
}

fn mls_welcome_payload(
    realm_id: &str,
    alice_did: &str,
    bob_did: &str,
    requester_device_key: &SigningKey,
    requester_device_id: &str,
    device_authorize_event_id: &str,
) -> Result<Value> {
    let keypackage_ref = "sha256:5555555555555555555555555555555555555555555555555555555555555555";
    // The welcome ciphertext is opaque base64-encoded MLS Welcome bytes: soland
    // base64-decodes `ciphertext` and binds `welcome_digest =
    // sha256(decoded bytes)` (reducer/mls.rs `validate_welcome_trust_binding`).
    // The digest MUST therefore be computed over the decoded plaintext, not the
    // base64 text.
    let welcome_plaintext = b"opaque-cross-server-mls-welcome";
    let welcome_bytes = URL_SAFE_NO_PAD.encode(welcome_plaintext);
    let welcome_digest = sha256_digest(welcome_plaintext);
    let claim_id = "claim-cross-ps-01";
    let nonce = "claim_cross_ps_01_nonce_128_bit_material";
    // §6.04 device path: the welcome `claim_envelope.signature` is a real
    // Ed25519 signature by the requester's device key over the SDK's
    // `MlsWelcomeClaimEnvelopeSigningInput` canonical bytes. soland deserialises
    // the envelope and recomputes the same canonical signing input, so we build
    // it field-for-field (device path → `requester_device_id`, no
    // `ssk_generation`) with the canonical timestamp form the SDK emits.
    let created_at_canonical = format_timestamp_canonical(
        chrono::DateTime::parse_from_rfc3339("2026-05-25T00:00:02Z")
            .context("welcome claim envelope timestamp")?
            .with_timezone(&chrono::Utc),
    );
    let signing_input = json!({
        "keypackage_ref": keypackage_ref,
        "keypackage_digest": keypackage_ref,
        "intended_realm_id": realm_id,
        "claim_id": claim_id,
        "requester_did": alice_did,
        "requester_device_id": requester_device_id,
        "nonce": nonce,
        "welcome_digest": welcome_digest,
        "created_at": created_at_canonical,
    });
    let claim_signature = requester_device_key.sign(&canonical_json_bytes(&signing_input)?);
    Ok(json!({
        "mls_group_id": E2EE_MLS_GROUP_ID,
        "epoch": 1,
        "recipient_principal_id": bob_did,
        "recipient_device_id": BOB_DEVICE_ID,
        "keypackage_ref": keypackage_ref,
        "keypackage_digest": keypackage_ref,
        "claim_id": claim_id,
        "claim_ref": {
            "claim_id": claim_id,
            "keypackage_ref": keypackage_ref,
            "keypackage_digest": keypackage_ref,
            "capabilities_digest": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
            "device_authorize_event_id": device_authorize_event_id
        },
        "claim_envelope": {
            "keypackage_ref": keypackage_ref,
            "keypackage_digest": keypackage_ref,
            "intended_realm_id": realm_id,
            "claim_id": claim_id,
            "requester_did": alice_did,
            "requester_device_id": requester_device_id,
            "nonce": nonce,
            "welcome_digest": welcome_digest,
            "created_at": created_at_canonical,
            "signature": {
                "kid": format!("{alice_did}#device"),
                "alg": "EdDSA",
                "sig": URL_SAFE_NO_PAD.encode(claim_signature.to_bytes())
            }
        },
        "welcome_ref": "ak:blob:sha256:88888888888888888888888888888888888888888888888888888888888888e2",
        "ciphertext": welcome_bytes,
        "expires_at": "2026-05-25T01:00:00Z",
        "commit_ref": E2EE_MLS_COMMIT_EVENT_ID,
        "governance_binding": mls_governance_binding(realm_id, 0, 0)
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
            "scheme": "mls-rfc9420",
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
    let device_public_key = multicodec_ed25519_public_key(&device_signing_key.verifying_key());
    let principal = Did::new(principal_id.to_owned())
        .with_context(|| format!("invalid principal DID `{principal_id}`"))?;
    let device = arkret_core::DeviceId::new(device_id.to_owned()).context("invalid device id")?;
    let algorithms = vec![
        arkret_core::NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1").unwrap(),
        arkret_core::NonEmptyString::new("ak.mls.v1").unwrap(),
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
    let mut payload = arkret_core::DeviceAuthorizePayload {
        principal_id: principal.clone(),
        device_id: device,
        device_public_key: arkret_core::NonEmptyString::new(device_public_key)
            .map_err(anyhow::Error::msg)?,
        hpke_key: arkret_core::NonEmptyString::new("z6LSCotestDeviceHpkeKey")
            .expect("static HPKE key is non-empty"),
        algorithms,
        device_key_algorithm: Some(arkret_core::NonEmptyString::new("EdDSA").unwrap()),
        authorized_by: arkret_core::DeviceOrPrincipalRef::Did(principal),
        scopes: None,
        not_before: "2026-05-02T00:00:00Z"
            .parse()
            .expect("static timestamp parses"),
        expires_at: None,
        device_signature: None,
        proof: None,
        cross_signing_binding: Some(arkret_core::DeviceCrossSigningBinding {
            verification_method: arkret_core::DidUrl::new(format!(
                "{principal_id}#ak_self_signing_v1"
            ))
            .map_err(anyhow::Error::msg)?,
            alg: arkret_core::NonEmptyString::new("EdDSA").unwrap(),
            ssk_generation,
            signature: arkret_core::Base64UrlString::new(
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
    payload.device_signature = Some(arkret_core::SignatureMaterial::Variant1(signature_material));
    serde_json::to_value(&payload).context("serialize device.authorize payload")
}

fn test_self_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x52; 32])
}

fn test_principal_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x51; 32])
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
        public_key: NonEmptyString::new(multicodec_ed25519_public_key(&key.verifying_key()))
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
        issued_at: "2026-05-02T00:00:00Z".parse().unwrap(),
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
    assert_eq!(accepted["status"], "accepted");
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
    Ok(())
}

async fn publish_test_cross_signing(server: &ArkretServer, token: &str, actor: &str) -> Result<()> {
    install_test_principal_control_document(server, actor).await?;
    let principal = Did::new(actor.to_owned()).context("invalid cross-signing principal")?;
    let principal_realm = principal_control_realm_id(&principal);
    let accepted = submit_event(
        server,
        token,
        actor,
        principal_realm.as_str(),
        "ak.cross_signing.publish",
        serde_json::to_value(test_cross_signing_publish(actor)?)?,
        StatusCode::OK,
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
    let accepted = submit_event(
        server,
        token,
        actor,
        &principal_realm,
        "ak.device.authorize",
        bootstrap_device_authorize_payload(actor, device_id, device_signing_key)?,
        StatusCode::OK,
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
    let device_public_key = multicodec_ed25519_public_key(&signing_key.verifying_key());
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
    event.created_at = chrono::DateTime::parse_from_rfc3339("2026-05-02T00:00:00Z")
        .context("invalid fixed federation event timestamp")?
        .with_timezone(&chrono::Utc);
    event.event_id = EventId::new(event_id.to_owned())
        .with_context(|| format!("invalid federation event_id `{event_id}`"))?;
    let event_digest =
        Hash::new(event.event_digest()?).context("invalid federation event digest")?;
    event.proofs.push(Proof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: format!("{actor_id}#01904100-0000-7000-8000-fedc00000011"),
        event_digest,
        created_at: event.created_at,
        domain: None,
        audience: None,
        jws: "dev-cotest-federation".to_owned(),
    });
    Ok(event)
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
    with_federation_trust_headers_for_digest(
        builder,
        method,
        target_url,
        source,
        destination,
        content_digest,
        request_canonical_digest,
    )
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
    let source_trust_domain = trust_domain_for(source_service_id);
    let destination_trust_domain = trust_domain_for(destination_service_id);

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

fn with_federation_trust_headers_for_digest(
    builder: reqwest::RequestBuilder,
    method: &str,
    target_url: &str,
    source: &ArkretServer,
    destination: &ArkretServer,
    content_digest: String,
    request_canonical_digest: String,
) -> Result<reqwest::RequestBuilder> {
    let source_service_id = source.service_id();
    let destination_service_id = destination.service_id();
    let source_trust_domain = trust_domain_for(source_service_id);
    let destination_trust_domain = trust_domain_for(destination_service_id);

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
        "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \
         \"source-service-id\" \"destination-service-id\" \"source-trust-domain\" \
         \"destination-trust-domain\" \"request-canonical-digest\");created={created};\
         expires={expires};keyid=\"{keyid}\";alg=\"ed25519\""
    );
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
         \"@signature-params\": {signature_params}",
        method.to_ascii_uppercase()
    );
    let signing_key = signing_key_from_seed(source.notary_signing_key_seed());
    let signature = sign_message(signature_base.as_bytes(), &signing_key);

    Ok(builder
        .header("Content-Digest", content_digest)
        .header("Source-Service-ID", source_service_id)
        .header("Destination-Service-ID", destination_service_id)
        .header("Source-Trust-Domain", source_trust_domain)
        .header("Destination-Trust-Domain", destination_trust_domain)
        .header("Request-Canonical-Digest", request_canonical_digest)
        .header("Signature-Input", format!("sig1={signature_params}"))
        .header("Signature", format!("sig1=:{signature}:")))
}

fn trust_domain_for(service_id: &str) -> String {
    format!("ak:trust_domain:{}", did_host_from_service_id(service_id))
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
    let service_host = did_host_from_service_id(service_id);
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
/// Keep this conversion local to principal URL construction: federation trust
/// domains continue to use the canonical DID host spelling returned by
/// `did_host_from_service_id`.
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
    let next_root_multibase = multicodec_ed25519_public_key(&next_root.verifying_key());
    let principal_signing_multibase =
        multicodec_ed25519_public_key(&test_principal_signing_key().verifying_key());
    let enrollment_multibase = multicodec_ed25519_public_key(&enrollment.verifying_key());
    prepare_principal_inception(&PrincipalInceptionInput {
        principal_endpoint: &endpoint,
        local_id,
        also_known_as: &[],
        version_time: chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")?
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

/// Extract the HTTP authority (host) a service DID's trust domain is scoped to,
/// mirroring soland's `trust_domain_from_service_id`.
///
/// For `did:webvh:<scid>:<host>[:...]` the host is the segment *after* the SCID,
/// so the SCID must not leak into the trust domain (soland test
/// `trust_domain_derives_webvh_host_not_scid`). `did:web:<host>[:...]` and the
/// `did:key:` fallback are kept for the negative/no-history fixtures that still
/// mint those forms.
fn did_host_from_service_id(service_id: &str) -> String {
    if let Some(rest) = service_id.strip_prefix("did:webvh:") {
        let mut parts = rest.split(':');
        let scid = parts.next().unwrap_or_default();
        if let Some(host) = parts.next() {
            if !scid.is_empty() && !host.is_empty() {
                return host.to_ascii_lowercase();
            }
        }
    }
    if let Some(rest) = service_id.strip_prefix("did:web:") {
        if let Some(host) = rest.split(':').next() {
            if !host.is_empty() {
                return host.to_ascii_lowercase();
            }
        }
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
