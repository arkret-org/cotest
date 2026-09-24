use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::harness::{ArkretServer, TestActorClient, expect_json, expect_status};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::bridge_contracts::session_grant::mock_session_grant_jwt;
use crate::scenarios::identity_test_support::{
    HARNESS_INTERNAL_AUTHORITY_SECRET, actor_did_for_service_did,
    spawn_with_harness_account_authority,
};

/// A Station behind the harness Coauth plus one founding-device author whose
/// standard DPoP session grant is bound at that Coauth.
struct SnapshotAuthor {
    _coauth: MockCoauthIntrospectionServer,
    server: ArkretServer,
    author: TestActorClient,
}

async fn snapshot_author(server_name: &str, actor: &str) -> Result<SnapshotAuthor> {
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let origin = coauth.origin();
    let introspection = coauth.url();
    let server = spawn_with_harness_account_authority(
        server_name,
        &[
            ("SOLAND_ACCOUNT_AUTHORITY_URL", origin.as_str()),
            ("SOLAND_DID_RESOLVER_ALLOW_METHODS", "web,webvh,key,uuid"),
            (
                "SOLAND_SESSION_GRANT_INTROSPECTION_URL",
                introspection.as_str(),
            ),
        ],
    )
    .await?;
    let actor_id = actor_did_for_service_did(server.service_did(), actor)?;
    let client = server
        .demo_client(&actor_id, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let principal = client.principal.as_ref().context("founding principal")?;
    let grant = mock_session_grant_jwt(
        principal.core_id.as_str(),
        principal.device_id.as_str(),
        server.service_id().as_str(),
    );
    coauth.bind_founding_device_grant(
        &grant,
        principal.core_id.as_str(),
        principal.device_id.as_str(),
        principal.founding_authorize_event_id.as_str(),
        &principal.device_signing_key.verifying_key(),
    )?;
    let author = server.client_with_founding_device_grant(principal, grant)?;
    Ok(SnapshotAuthor {
        _coauth: coauth,
        server,
        author,
    })
}

pub async fn narrow_snapshot_head_discloses_only_complete_creator_cut() -> Result<()> {
    let SnapshotAuthor {
        _coauth,
        server,
        author,
    } = snapshot_author("snapshot-head-disclosure", "snapshot-alice").await?;
    let bootstrap = author
        .create_realm_bootstrap_with(json!({
            "title": "Snapshot disclosure",
            "summary": "Snapshot disclosure",
            "public": false,
            "plaintext_visible_services": []
        }))
        .await?;
    let realm_id = bootstrap["realm_id"].as_str().context("realm_id")?;
    ensure!(
        bootstrap["event_response"]["commits"]
            .as_array()
            .is_some_and(|commits| commits.len() == 7),
        "baseline bootstrap must accept exactly seven Events: {bootstrap}"
    );
    let head_path = "/_arkret/self/realm-state-snapshot/head";
    let genesis_snapshot = expect_json(
        author.get(head_path).query(&[("realm_id", realm_id)]),
        StatusCode::OK,
    )
    .await?;
    let genesis_typed: arkret_wire::RealmStateSnapshot =
        serde_json::from_value(genesis_snapshot.clone())
            .context("seven-Commit head must be a signed wire snapshot")?;
    ensure!(
        genesis_typed.visible_stream_heads.len() == 1
            && genesis_typed.visible_stream_heads[0].stream_position == 6
            && genesis_typed.current_state_entries.len() == 8,
        "seven-Commit creator cut is incomplete: {genesis_snapshot}"
    );
    verify_test_notary_snapshot(&genesis_typed)?;
    // The head was issued at its cut: the exact original object is now
    // readable by reference, byte-for-byte, and never re-signed.
    let genesis_by_ref = read_by_ref(&author, &genesis_typed.snapshot_id, realm_id).await?;
    ensure_same_object(&genesis_typed, &genesis_by_ref)?;
    author.create_default_strand(realm_id).await?;
    let snapshot = expect_json(
        author.get(head_path).query(&[("realm_id", realm_id)]),
        StatusCode::OK,
    )
    .await?;
    let typed: arkret_wire::RealmStateSnapshot = serde_json::from_value(snapshot.clone())
        .context("head must be the complete signed wire snapshot")?;
    ensure!(
        typed.realm_id.as_str() == realm_id,
        "wrong Realm in snapshot: {snapshot}"
    );
    ensure!(
        typed.visible_stream_heads[0].stream_position == 8,
        "creator cut must include bootstrap, Strand create, and default-Strand Commit: {snapshot}"
    );
    ensure!(
        typed.current_state_entries.len() == 10,
        "creator cut must disclose all ten typed current results: {snapshot}"
    );
    ensure!(
        snapshot["visible_stream_heads"]
            .as_array()
            .is_some_and(|heads| heads.len() == 1),
        "single-stream creator cut omitted or added a stream head: {snapshot}"
    );
    ensure!(
        snapshot["retention_and_history_floor"]["stream_floors"]
            .as_array()
            .is_some_and(|floors| floors.len() == 1),
        "creator cut omitted its history floor: {snapshot}"
    );
    ensure!(
        snapshot["signature"].is_object(),
        "unsigned snapshot: {snapshot}"
    );
    verify_test_notary_snapshot(&typed)?;
    // A newer head does not replace the earlier exact reference: both stay
    // readable while the creator's join revision is unchanged.
    ensure!(
        typed.snapshot_id != genesis_typed.snapshot_id,
        "a later cut must be a distinct exact snapshot"
    );
    ensure_same_object(
        &genesis_typed,
        &read_by_ref(&author, &genesis_typed.snapshot_id, realm_id).await?,
    )?;
    ensure_same_object(
        &typed,
        &read_by_ref(&author, &typed.snapshot_id, realm_id).await?,
    )?;
    let never_issued = arkret_wire::RealmSnapshotId::from_digest([0x5a; 32]);
    expect_status(
        by_ref_request(&author, &never_issued, realm_id),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await?;
    let stranger = server
        .demo_client(
            &actor_did_for_service_did(server.service_did(), "snapshot-mallory")?,
            "ak:device:01904100-0000-7000-8000-0000000000a2",
        )
        .await?;
    expect_status(
        by_ref_request(&stranger, &genesis_typed.snapshot_id, realm_id),
        StatusCode::NOT_FOUND,
    )
    .await?;

    let with_plaintext = author
        .create_realm_with(json!({
            "title": "Extra current family",
            "summary": "Extra current family",
            "public": false,
            "plaintext_visible_services": [server.service_id()]
        }))
        .await?;
    let with_plaintext_id = with_plaintext["realm_id"]
        .as_str()
        .context("plaintext Realm id")?;
    ensure!(
        with_plaintext["event_response"]["commits"]
            .as_array()
            .is_some_and(|commits| commits.len() == 8),
        "facet bootstrap must accept eight Events before the Strand pair: {with_plaintext}"
    );
    expect_status(
        author
            .get(head_path)
            .query(&[("realm_id", with_plaintext_id)]),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await?;
    // An exact ref is bound to its Realm: naming it under another Realm the
    // caller can read is unavailable, never a substitute object.
    expect_status(
        by_ref_request(&author, &genesis_typed.snapshot_id, with_plaintext_id),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await?;
    Ok(())
}

/// A Snapshot issued at `/head` is read back through Garth's typed by-ref
/// client only because the live describe advertises the exact-read bundle,
/// byte-identical to the issued object even after the Realm moves on, and its
/// signature verifies under the Station key taken from the Station's complete
/// live did:webvh history at the Snapshot's signing time (no test constant,
/// no current document). Registered refusals surface as typed Garth refusals.
///
/// The fresh authority bundle and verified tail are not exercised here: the
/// live Station does not route `POST /_arkret/open/realm-authority/bundle` or
/// `POST /_arkret/self/streams/scan`, so the generation-bound
/// `install_verified_*` path stays covered by Garth and Inkson unit tests.
pub async fn exact_snapshot_by_ref_reads_through_garth_with_historical_station_key() -> Result<()> {
    let SnapshotAuthor {
        _coauth,
        server,
        author,
    } = snapshot_author("snapshot-by-ref-typed", "snapshot-carol").await?;
    let bootstrap = author
        .create_realm_bootstrap_with(json!({
            "title": "Snapshot by ref",
            "summary": "Snapshot by ref",
            "public": false,
            "plaintext_visible_services": []
        }))
        .await?;
    let realm = bootstrap["realm_id"].as_str().context("realm_id")?;
    let realm_id = arkret_wire::RealmId::new(realm.to_owned())?;
    let issued: arkret_wire::RealmStateSnapshot = serde_json::from_value(
        expect_json(
            author
                .get("/_arkret/self/realm-state-snapshot/head")
                .query(&[("realm_id", realm)]),
            StatusCode::OK,
        )
        .await?,
    )
    .context("issued head must be a closed signed snapshot")?;
    // The earlier exact reference stays readable after the Realm moves on.
    author.create_default_strand(realm).await?;

    let http = author.sdk();
    let describe = http
        .describe_for_role(arkret_wire::ServiceKind::Station)
        .await
        .context("live Station describe")?;
    ensure!(
        garth::exact_snapshot_read_advertised(&describe),
        "live Station must advertise the exact snapshot read bundle"
    );
    let authority = garth::AuthorityClient::new(http.clone());
    let snapshot = authority
        .exact_snapshot(&describe, &realm_id, &issued.snapshot_id)
        .await
        .context("typed by-ref read")?;
    ensure_same_object(&issued, &snapshot)?;

    let signer_did =
        arkret_identity::verification_method_did(snapshot.signature.verification_method.as_str())?;
    ensure!(
        signer_did.as_str().starts_with("did:webvh:"),
        "the Station must sign with a method-native historical DID: {signer_did}"
    );
    let signer_id = arkret_wire::project_did_to_core_id(&signer_did)?;
    ensure!(
        signer_id.as_str() == server.service_id().as_str(),
        "the Snapshot signer must be the governing Station"
    );
    let resolution = http
        .open_service_resolution(&signer_id)
        .await
        .context("live Station service resolution")?;
    let document = arkret_identity::authenticated_service_document_at(
        &resolution,
        &signer_id,
        snapshot.signature.created_at,
    )
    .context("Station history at the Snapshot signing time")?;
    arkret_identity::validate_verification_method_relationship(
        &document,
        &snapshot.signature.verification_method,
        &signer_did,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )?;
    let key = arkret_identity::resolve_verification_method_key_from_document(
        &document,
        snapshot.signature.verification_method.as_str(),
    )?
    .public_key;
    let unsigned = arkret_canonical::unsigned_value(&snapshot, &["signature"])?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &snapshot.signature,
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &key,
    )
    .context("Snapshot must verify under the historical Station key")?;
    let mut tampered = snapshot.clone();
    tampered.signature.signed_digest =
        arkret_wire::Hash::new(format!("sha256:{}", "f".repeat(64)))?;
    ensure!(
        arkret_signatures::detached_object::verify_detached_object_signature(
            &tampered.signature,
            &arkret_canonical::unsigned_value(&tampered, &["signature"])?,
            arkret_wire::DetachedSignatureContext::RealmSnapshot,
            &key,
        )
        .is_err(),
        "a tampered by-ref object must not verify"
    );
    ensure!(
        arkret_identity::authenticated_service_document_at(
            &resolution,
            &signer_id,
            snapshot.signature.created_at - chrono::Duration::days(3650),
        )
        .is_err(),
        "no Station key exists before the Station's inception"
    );

    let never_issued = arkret_wire::RealmSnapshotId::from_digest([0x5b; 32]);
    let unavailable = authority
        .exact_snapshot(&describe, &realm_id, &never_issued)
        .await
        .unwrap_err();
    ensure!(
        matches!(
            unavailable,
            garth::Error::ExactSnapshotRefused(garth::ExactSnapshotRefusal::Unavailable)
        ),
        "never-issued ref must be the registered unavailable refusal: {unavailable}"
    );
    let stranger = server
        .demo_client(
            &actor_did_for_service_did(server.service_did(), "snapshot-dave")?,
            "ak:device:01904100-0000-7000-8000-0000000000a3",
        )
        .await?;
    let hidden = garth::AuthorityClient::new(stranger.sdk())
        .exact_snapshot(&describe, &realm_id, &snapshot.snapshot_id)
        .await
        .unwrap_err();
    ensure!(
        matches!(
            hidden,
            garth::Error::ExactSnapshotRefused(garth::ExactSnapshotRefusal::NotVisible)
        ),
        "another Account must receive the registered not-visible refusal: {hidden}"
    );
    let mut unadvertised = describe.clone();
    unadvertised
        .supported_operation_bundles
        .retain(|bundle| bundle != "ak.operation_bundle.station.snapshot_exact_read.v1");
    let not_advertised = authority
        .exact_snapshot(&unadvertised, &realm_id, &snapshot.snapshot_id)
        .await
        .unwrap_err();
    ensure!(
        matches!(
            not_advertised,
            garth::Error::ExactSnapshotRefused(garth::ExactSnapshotRefusal::NotAdvertised)
        ),
        "without the advertised bundle the by-ref read must not be attempted"
    );
    Ok(())
}

fn by_ref_request(
    client: &crate::harness::TestActorClient,
    snapshot_id: &arkret_wire::RealmSnapshotId,
    realm_id: &str,
) -> reqwest::RequestBuilder {
    client
        .get(&format!(
            "/_arkret/self/realm-state-snapshot/{}",
            snapshot_id.as_str()
        ))
        .query(&[("realm_id", realm_id)])
}

async fn read_by_ref(
    client: &crate::harness::TestActorClient,
    snapshot_id: &arkret_wire::RealmSnapshotId,
    realm_id: &str,
) -> Result<arkret_wire::RealmStateSnapshot> {
    let body = expect_json(
        by_ref_request(client, snapshot_id, realm_id),
        StatusCode::OK,
    )
    .await?;
    let snapshot: arkret_wire::RealmStateSnapshot =
        serde_json::from_value(body).context("by-ref body must be a closed signed snapshot")?;
    ensure!(
        &snapshot.snapshot_id == snapshot_id && snapshot.realm_id.as_str() == realm_id,
        "by-ref response IDs differ from the request"
    );
    verify_test_notary_snapshot(&snapshot)?;
    Ok(snapshot)
}

fn ensure_same_object(
    issued: &arkret_wire::RealmStateSnapshot,
    read: &arkret_wire::RealmStateSnapshot,
) -> Result<()> {
    ensure!(
        arkret_canonical::canonical_json_bytes(issued)?
            == arkret_canonical::canonical_json_bytes(read)?,
        "by-ref must return the exact issued signed object"
    );
    Ok(())
}

fn verify_test_notary_snapshot(snapshot: &arkret_wire::RealmStateSnapshot) -> Result<()> {
    let seed: [u8; 32] = Sha256::digest(b"cotest:notary:snapshot-head-disclosure").into();
    let public_key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
            .to_vec(),
    };
    let unsigned = arkret_canonical::unsigned_value(snapshot, &["signature"])?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &snapshot.signature,
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &public_key,
    )
    .context("Snapshot detached signature does not verify against the test Station notary")?;
    let mut identity = serde_json::to_value(snapshot)?;
    let object = identity
        .as_object_mut()
        .context("Snapshot identity object")?;
    object.remove("signature");
    object.remove("snapshot_id");
    let derived = arkret_wire::RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(
        &arkret_canonical::canonical_json_bytes(&identity)?,
    ));
    ensure!(
        snapshot.snapshot_id == derived,
        "Snapshot ID does not address its canonical identity body"
    );
    Ok(())
}
