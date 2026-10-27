//! Recipient-produced Add proof must traverse the real cross-Station outbox.
use arkret::{ArkretMlsGroup, ArkretMlsIdentity, MlsCommitPayload, MlsGovernanceBindingPayload};
use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody;
use arkret_models_collaboration::events_payloads::MlsGenesisCreatorLeafAuthority;
use arkret_models_collaboration::mls_roster_authority::{
    MlsAttestAddRequestBody, MlsAttestAddResponseBody, MlsAttestAddStatus,
};
use arkret_models_crypto::KeyPackagesClaimResponseBody;
use arkret_wire::{EventKind, MlsCommitSubmission, MlsWelcomeRecipientEndpoint, ScopeRef};

use super::*;
use crate::harness::ArkretServer;
use crate::scenarios::mls_lifecycle_live::{self as mls, Member};

async fn original(
    station: &ArkretServer,
    table: &'static str,
    welcome: &str,
) -> Result<Option<Value>> {
    ensure!(
        matches!(
            table,
            "mls_add_authority_attestations" | "mls_add_authority_attestation_outbox"
        ),
        "unsupported native proof table"
    );
    let database = station
        .owned_database_url()
        .context("native Add proof database")?
        .to_owned();
    let welcome = welcome.to_owned();
    tokio::task::spawn_blocking(move || -> Result<Option<Value>> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        Ok(db
            .query_opt(
                &format!("SELECT to_jsonb(p) FROM {table} p WHERE welcome_id=$1"),
                &[&welcome],
            )?
            .map(|row| row.get(0)))
    })
    .await?
}

pub(super) async fn exercise(
    governor: &ArkretServer,
    recipient_station: &ArkretServer,
    alice: &Member,
    bob: &Member,
    identity: ArkretMlsIdentity,
    realm: &arkret_wire::RealmId,
    claim: &KeyPackagesClaimResponseBody,
) -> Result<Value> {
    ensure!(
        governor.service_id() != recipient_station.service_id(),
        "Add attestation requires two actual authorities"
    );
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let group_id = scope.canonical_mls_group_id()?;
    let genesis_binding = MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
    let mut group = alice
        .mls_identity()?
        .create_group_with_governance_binding(&scope, &genesis_binding)?;
    group.install_local_creator_binding(
        alice.actor.clone(),
        Some(alice.authorize_event_id.clone()),
    )?;
    let leaves = group.verified_leaf_bindings()?;
    let [creator] = leaves.as_slice() else {
        anyhow::bail!("native Add founding leaf is not unique")
    };
    let creator_authority = MlsGenesisCreatorLeafAuthority {
        leaf_signature_key_base64url: creator.signature_key.clone(),
        endpoint: MlsWelcomeRecipientEndpoint::Device {
            device_id: alice.device.clone(),
        },
        authorization_event_ref: alice.authorize_event_id.clone(),
    };
    let (info, tree) = group.public_group_state_bytes()?;
    let info_ref = mls::upload_public_blob(&alice.client, realm, &info).await?;
    let tree_ref = mls::upload_public_blob(&alice.client, realm, &tree).await?;
    let genesis = alice.client.author_event(realm.as_str(), EventKind::MlsGenesis.as_str(), mls::canonical(json!({
        "cipher_suite":mls::ACTIVE_SUITE,"group_info_ref":info_ref,"ratchet_tree_ref":tree_ref,
        "governance_binding":genesis_binding,"creator_leaf_authority":creator_authority,
        "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
    }))?).await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &alice.client,
        &alice.account,
        alice.device.as_str(),
        &genesis,
    )
    .await?;
    let accepted_genesis = mls::accepted_full_view(&alice.client, &genesis.event_id).await?;
    crate::scenarios::message_mls_cross_station_live::install_bindings(&mut group, &[alice])
        .await?;
    ensure!(
        claim.claims.len() == 1,
        "native Add requires the exact single actual claim"
    );
    let binding =
        MlsGovernanceBindingPayload::new(scope.clone(), Some(genesis.event_id.clone()), 0, 1, 0)?;
    let add = group.add_member_with_governance_binding(
        &mls::claimed_keypackage_record(&claim.claims[0], bob)?,
        &binding,
    )?;
    let payload = MlsCommitPayload::new(genesis.event_id.clone(), 0, &add.commit, binding)?;
    let event = alice
        .client
        .author_event(
            realm.as_str(),
            EventKind::MlsCommit.as_str(),
            mls::canonical(json!(payload))?,
        )
        .await?;
    let welcome = mls::signed_welcome(alice, &event, bob, &add.welcome)?;
    let submission = SelfAuthoritySubmitRequestBody::MlsCommit(MlsCommitSubmission {
        commit_event: event.clone(),
        welcomes: vec![welcome.clone()],
        idempotency_key: arkret_wire::UuidV7::new(mls::fresh_uuid_v7().parse()?)?,
    });
    let accepted = crate::harness::expect_json(
        alice.client.post("/_arkret/self/events").json(&submission),
        reqwest::StatusCode::OK,
    )
    .await?;
    let committed = mls::accepted_full_view(&alice.client, &event.event_id).await?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(90);
    let (queued, acknowledgement_token) = loop {
        let page = mls::recipient_welcomes(&bob.client).await?;
        if !page.0.is_empty() {
            break page;
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "the real recipient never received its accepted Add Welcome"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };
    ensure!(
        queued == vec![welcome.clone()] && !acknowledgement_token.is_empty(),
        "recipient substituted the actual admitted Welcome"
    );
    let mut joined =
        ArkretMlsGroup::join_from_verified_welcome_delivery(identity, &welcome, &committed)?;
    crate::scenarios::message_mls_cross_station_live::install_bindings(&mut joined, &[alice, bob])
        .await?;
    let state = joined.export_state_record()?;
    let bytes = serde_json::to_vec(&state)?;
    let mut saved = tempfile::NamedTempFile::new()?;
    use std::io::Write as _;
    saved.write_all(&bytes)?;
    saved.as_file().sync_all()?;
    let state = serde_json::from_slice(&std::fs::read(saved.path())?)?;
    let restored = ArkretMlsGroup::restore_from_state_record(&state)?;
    ensure!(
        restored.epoch() == 1,
        "recipient did not restore its actual durable Add state"
    );
    let (producer, installed) = loop {
        let producer = original(
            recipient_station,
            "mls_add_authority_attestation_outbox",
            welcome.welcome_id.as_str(),
        )
        .await?;
        let installed = original(
            governor,
            "mls_add_authority_attestations",
            welcome.welcome_id.as_str(),
        )
        .await?;
        if let (Some(producer), Some(installed)) = (producer, installed)
            && producer["acknowledged_at"].is_string()
        {
            break (producer, installed);
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "the real recipient Add producer/outbox has no completed governance installation"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };
    let request: MlsAttestAddRequestBody =
        serde_json::from_value(producer["request_json"].clone())?;
    request.validate_claim_binding()?;
    ensure!(
        json!(request.claim_outcome) == json!(claim)
            && request.attestation.mls_group_id == group_id
            && installed["request_json"] == producer["request_json"]
            && installed["attestation_digest"] == producer["attestation_digest"],
        "recipient and governor did not retain one actual original"
    );
    let replay = super::peer_keypackage_claims::peer(
        governor,
        recipient_station,
        "/_arkret/peer/mls/add-authority-attestations",
        &request,
        None,
    )
    .await?;
    let response: MlsAttestAddResponseBody = serde_json::from_value(replay.clone())?;
    ensure!(
        response.status == MlsAttestAddStatus::Duplicate
            && json!(response.attestation_digest) == producer["attestation_digest"],
        "exact Add proof replay did not retain its original installation"
    );
    let after = original(
        governor,
        "mls_add_authority_attestations",
        welcome.welcome_id.as_str(),
    )
    .await?
    .context("accepted original disappeared")?;
    ensure!(
        installed == after,
        "Add proof replay mutated its actual original"
    );
    Ok(
        json!({"genesis":accepted_genesis,"submission":submission,"accepted":accepted,"committed":committed,
        "welcome":welcome,"recipient_welcome":queued,"durable_state_digest":arkret_canonical::sha256_digest(&bytes),"restored_epoch":restored.epoch(),
        "request":request,"producer_original":producer,"governance_original":installed,"governance_after":after,"replay":replay}),
    )
}

pub(super) fn verify(observations: &NativeOperationObservations, evidence: &Value) -> Result<()> {
    let request: MlsAttestAddRequestBody = serde_json::from_value(evidence["request"].clone())?;
    let attestor = native_station_resolution(
        observations,
        &request.attestation.attestor_station_id,
        request.attestation.attested_at,
    )?;
    let issuer = native_station_resolution(
        observations,
        &request.claim_outcome.claim_receipt.destination_id,
        request.claim_outcome.claim_receipt.claimed_at,
    )?;
    arkret::verify_mls_attest_add_request(&request, &issuer, &attestor)?;
    verify_native_station_commits(
        observations,
        &[
            serde_json::from_value(evidence["genesis"].clone())?,
            serde_json::from_value(evidence["committed"].clone())?,
        ],
    )?;
    let exchange = original_exchange(observations, "ak.peer.mls.command.attest_add.v1")?;
    verify_native_station_http_request(observations, exchange, &[])?;
    ensure!(
        exchange.request_body == evidence["request"]
            && exchange.response_body == evidence["replay"]
            && exchange.explicit_request_headers["source-service-id"]
                == request.attestation.attestor_station_id.as_str()
            && exchange.explicit_request_headers["destination-service-id"]
                != request.attestation.attestor_station_id.as_str()
            && evidence["governance_original"] == evidence["governance_after"]
            && evidence["producer_original"]["request_json"] == evidence["request"]
            && evidence["producer_original"]["acknowledged_at"].is_string()
            && evidence["producer_original"]["attestation_digest"]
                == arkret_canonical::canonical_sha256(&request)?
            && evidence["welcome"]["welcome_id"] == json!(request.attestation.welcome_id)
            && evidence["committed"]["event"]["event_id"]
                == json!(request.attestation.commit_event_ref)
            && evidence["restored_epoch"] == 1,
        "native Add proof lost its original producer, actual peer or accepted durable cut"
    );
    Ok(())
}
