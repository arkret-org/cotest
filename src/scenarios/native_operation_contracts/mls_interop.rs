//! Native KeyPackage lifecycle with real issued members and a restored durable MLS snapshot.
use anyhow::Result;
use arkret::{ArkretMlsGroup, MlsCommitPayload, MlsGovernanceBindingPayload};
use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody;
use arkret_models_collaboration::device_messages::DeviceMessagesAcknowledgementRequestBody;
use arkret_models_collaboration::events_payloads::MlsGenesisCreatorLeafAuthority;
use arkret_models_crypto::*;
use arkret_wire::{
    ActorId, Base64UrlString, DeviceId, DidUrl, EventKind, MlsCommitSubmission,
    MlsWelcomeRecipientEndpoint, NonEmptyString, ScopeRef,
};

use super::*;
use crate::harness::{CanonicalClientRequest, TestActorClient, expect_json};
use crate::scenarios::mls_lifecycle_live::{self as mls, Member};

const SCOPE: [&str; 19] = [
    "ak.self.keys.keypackages.command.claim.v1",
    "ak.self.keys.keypackages.read.claim.v1",
    "ak.self.keys.keypackages.command.consume.v1",
    "ak.self.keys.keypackages.command.revoke.v1",
    "ak.open.mimi.command.update_room.v1",
    "ak.open.mimi.command.request_consent.v1",
    "ak.open.mimi.command.update_consent.v1",
    "ak.open.mimi.command.report_abuse.v1",
    "ak.open.mimi.read.identifiers.v1",
    "ak.open.mimi.exchange.request_key_material.v1",
    "ak.peer.realm_join.read.bootstrap.v1",
    "ak.peer.realm_join.read.preview.v1",
    "ak.peer.keys.read.lookup.v1",
    "ak.peer.signal.command.relay.v1",
    "ak.open.mimi.command.submit_message.v1",
    "ak.open.mimi.command.notify.v1",
    "ak.self.strand.watch.command.audit_read.v1",
    "ak.self.call.media.exchange.issue_token.v1",
    "ak.peer.invites.command.submit.v1",
];

pub(super) fn member(client: TestActorClient, station: &arkret_wire::DidCoreId) -> Result<Member> {
    let principal = client
        .principal
        .as_ref()
        .context("native member custody absent")?;
    let account = arkret_wire::AccountId::new(principal.core_id.clone(), station.clone());
    Ok(Member {
        actor: ActorId::account(account.clone()),
        account,
        device: principal.device_id.clone(),
        method: DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
            .map_err(anyhow::Error::msg)?,
        key: principal.device_signing_key.clone(),
        authorize_event_id: principal.founding_authorize_event_id.clone(),
        client,
    })
}

pub(super) async fn run() -> Result<()> {
    let (result,observations)=observe(crate::harness::heap_future(|| async {
        let deployment=crate::harness::heap_future(|| crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("native-keypackage-lifecycle")).await?;
        let device=DeviceId::new(arkret_identifiers::new_prefixed_uuid7("ak:device:"))?;
        let ca=deployment.station.tls_ca_path().context("owned Station CA absent")?;
        let bob_http=reqwest::Client::builder().tls_backend_rustls().tls_certs_only(reqwest::Certificate::from_pem_bundle(&std::fs::read(ca)?)?).cookie_store(true).redirect(reqwest::redirect::Policy::none()).timeout(std::time::Duration::from_secs(45)).build()?;
        let bob=crate::harness::heap_future(|| deployment.station.canonical_client(CanonicalClientRequest { http:&bob_http,endpoints:&deployment.endpoints,oidc_client_id:&deployment.oidc_client_id,handle:"bob",password:"1amTester!",device_id:device.as_str(),display_name:"MLS recipient" })).await?;
        let bob=member(bob,deployment.station.service_id())?;
        let alice=member(deployment.controller,deployment.station.service_id())?;
        let stations=[&deployment.station];
        let realm:arkret_wire::RealmId=crate::harness::heap_future(|| crate::scenarios::human_device_producer_live::create_realm_with_join_rule(&alice.client,"Native KeyPackage lifecycle","public",&stations)).await?.parse()?;
        let realm_genesis=mls::accepted_full_view(&alice.client,&arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256,realm.digest_bytes())).await?;
        let join=bob.client.author_event(realm.as_str(),EventKind::MemberState.as_str(),crate::scenarios::human_device_producer_live::membership_payload(realm.as_str(),bob.account.clone(),arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join,"native MLS recipient")?).await?;
        let joined=crate::scenarios::human_device_producer_live::submit_and_expect_commit(&bob.client,&bob.account,bob.device.as_str(),&join).await?;
        let bob_identity=bob.mls_identity()?;
        let first=bob_identity.key_package_record()?;
        let spare=bob_identity.key_package_record()?;
        let upload=bob_identity.signed_key_packages_upload_request(&[first.clone(),spare.clone()],bob.method.as_str())?;
        let uploaded:KeyPackagesUploadResponseBody=serde_json::from_value(expect_json(bob.client.post("/_arkret/self/keys/keypackages/upload").json(&upload),reqwest::StatusCode::OK).await?)?;
        ensure!(uploaded.accepted_count==2 && uploaded.rejections.is_empty(),"native KeyPackages were not accepted");
        let scope=ScopeRef::Realm { realm_id:realm.clone() };
        let group_id=scope.canonical_mls_group_id()?;
        let mut request_id=[0u8;16];getrandom::fill(&mut request_id).context("obtain claim OS entropy")?;
        let claim_request=mls::claim_request_between(&alice,&deployment.station,&deployment.station,&bob,&realm,group_id.as_str(),request_id,chrono::Duration::minutes(4))?;
        let send_claim=||alice.client.post("/_arkret/self/keys/keypackages/claim").header("Idempotency-Key",claim_request.claim_request_id.as_str()).json(&claim_request);
        let original=expect_json(send_claim(),reqwest::StatusCode::OK).await?;
        ensure!(expect_json(send_claim(),reqwest::StatusCode::OK).await?==original,"claim retry changed the original");
        let claimed:KeyPackagesClaimResponseBody=serde_json::from_value(original.clone())?;
        claimed.validate_shape().map_err(anyhow::Error::msg)?;
        ensure!(claimed.claims.len()==1,"native claim omitted the actual recipient package");
        let claim=&claimed.claims[0];
        ensure!(claim.actor_id==bob.actor && claim.device_id.as_ref()==Some(&bob.device) && claim.device_authorize_event_id.as_ref()==Some(&bob.authorize_event_id),"claim changed its accepted Device");
        let query=KeyPackagesClaimQueryRequestBody { claim_id:claim.claim_id.clone().parse()? };
        let queried=expect_json(bob.client.post("/_arkret/self/keys/keypackages/claims/query").json(&query),reqwest::StatusCode::OK).await?;
        ensure!(queried==original,"recipient claim lookup changed the original outcome");
        let genesis_binding=MlsGovernanceBindingPayload::new(scope.clone(),None,0,0,0)?;
        let mut alice_group=alice.mls_identity()?.create_group_with_governance_binding(&scope,&genesis_binding)?;
        alice_group.install_local_creator_binding(alice.actor.clone(),Some(alice.authorize_event_id.clone()))?;
        let leaves=alice_group.verified_leaf_bindings()?;
        let [creator]=leaves.as_slice() else {anyhow::bail!("MLS genesis must have the exact founding leaf")};
        let creator_authority=MlsGenesisCreatorLeafAuthority { leaf_signature_key_base64url:creator.signature_key.clone(),endpoint:MlsWelcomeRecipientEndpoint::Device { device_id:alice.device.clone() },authorization_event_ref:alice.authorize_event_id.clone() };
        let (info,tree)=alice_group.public_group_state_bytes()?;
        let info_ref=mls::upload_public_blob(&alice.client,&realm,&info).await?;
        let tree_ref=mls::upload_public_blob(&alice.client,&realm,&tree).await?;
        let genesis=alice.client.author_event(realm.as_str(),EventKind::MlsGenesis.as_str(),mls::canonical(json!({"cipher_suite":mls::ACTIVE_SUITE,"group_info_ref":info_ref,"ratchet_tree_ref":tree_ref,"governance_binding":genesis_binding,"creator_leaf_authority":creator_authority,"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}))?).await?;
        crate::scenarios::human_device_producer_live::submit_and_expect_commit(&alice.client,&alice.account,alice.device.as_str(),&genesis).await?;
        crate::scenarios::message_mls_cross_station_live::install_bindings(&mut alice_group,&[&alice]).await?;
        let add_binding=MlsGovernanceBindingPayload::new(scope.clone(),Some(genesis.event_id.clone()),0,1,0)?;
        let add=alice_group.add_member_with_governance_binding(&mls::claimed_keypackage_record(claim,&bob)?,&add_binding)?;
        let payload=MlsCommitPayload::new(genesis.event_id.clone(),0,&add.commit,add_binding)?;
        let commit_event=alice.client.author_event(realm.as_str(),EventKind::MlsCommit.as_str(),mls::canonical(serde_json::to_value(payload)?)?).await?;
        let welcome=mls::signed_welcome(&alice,&commit_event,&bob,&add.welcome)?;
        let submission=SelfAuthoritySubmitRequestBody::MlsCommit(MlsCommitSubmission { commit_event:commit_event.clone(),welcomes:vec![welcome.clone()],idempotency_key:arkret_wire::UuidV7::new(mls::fresh_uuid_v7().parse()?)? });
        let accepted_genesis=mls::accepted_full_view(&alice.client,&genesis.event_id).await?;
        let accepted=expect_json(alice.client.post("/_arkret/self/events").json(&submission),reqwest::StatusCode::OK).await?;
        let committed=mls::accepted_full_view(&alice.client,&commit_event.event_id).await?;
        let base=arkret_wire::MlsGroupValue { effective_scope:scope.clone(),genesis_event_ref:genesis.event_id.clone(),cipher_suite:NonEmptyString::new(mls::ACTIVE_SUITE).map_err(anyhow::Error::msg)?,current_mls_commit_event_ref:genesis.event_id.clone(),epoch:0,current_key_access_revision:0,covered_key_access_revision:0,public_tree_ref:tree_ref.parse()? };
        ensure!(alice_group.install_accepted_commit(&committed,&base)?==1,"sender did not install its accepted Add");
        crate::scenarios::message_mls_cross_station_live::install_bindings(&mut alice_group,&[&alice,&bob]).await?;
        let (queued,ack)=mls::recipient_welcomes(&bob.client).await?;
        ensure!(queued==vec![welcome.clone()],"recipient did not receive the exact admitted Welcome");
        let mut bob_group=ArkretMlsGroup::join_from_verified_welcome_delivery(bob_identity,&welcome,&committed)?;
        crate::scenarios::message_mls_cross_station_live::install_bindings(&mut bob_group,&[&alice,&bob]).await?;
        let record=bob_group.export_state_record()?;
        let bytes=serde_json::to_vec(&record)?;
        let mut durable=tempfile::NamedTempFile::new()?;
        use std::io::Write as _;
        durable.write_all(&bytes)?;durable.as_file().sync_all()?;
        let restored_record:MlsGroupStateRecord=serde_json::from_slice(&std::fs::read(durable.path())?)?;
        let mut restored=ArkretMlsGroup::restore_from_state_record(&restored_record)?;
        crate::scenarios::message_mls_cross_station_live::install_bindings(&mut restored,&[&alice,&bob]).await?;
        ensure!(restored.epoch()==1 && restored.group_id()==group_id,"recipient durable snapshot did not restore the accepted group");
        bob.client.post("/_arkret/self/device_messages/ack").json(&DeviceMessagesAcknowledgementRequestBody { acknowledgement_token:ack }).send().await?.error_for_status()?;
        let receipt=RecipientMlsDurableReceipt { domain:NonEmptyString::new(arkret_wire::DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1).map_err(anyhow::Error::msg)?,claim_request_id:claim_request.claim_request_id.clone(),keypackage_ref:NonEmptyString::new(claim.keypackage_ref.clone()).map_err(anyhow::Error::msg)?,recipient:RecipientMlsDurableSigner::Device { recipient_account_id:bob.account.clone(),recipient_device_id:bob.device.clone(),device_verification_method:bob.method.clone() },recipient_id:deployment.station.service_id().clone(),realm_id:realm.clone(),mls_group_id:group_id.clone(),mls_epoch:restored.epoch(),welcome_ref:welcome.welcome_id.clone(),welcome_digest:welcome.durable_receipt_digest()?,durable_at:arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),signature:KeyOperationSignature { kid:NonEmptyString::new(bob.method.to_string()).map_err(anyhow::Error::msg)?,signature_algorithm:None,signature:Base64UrlString::new("AA").map_err(anyhow::Error::msg)? } };
        let signer=bob.mls_identity()?;
        let consume=signer.signed_key_packages_consume_request(claim.claim_id.clone().parse()?,signer.sign_recipient_mls_durable_receipt(receipt)?)?;
        let consumed=expect_json(bob.client.post("/_arkret/self/keys/keypackages/consume").json(&consume),reqwest::StatusCode::OK).await?;
        ensure!(expect_json(bob.client.post("/_arkret/self/keys/keypackages/consume").json(&consume),reqwest::StatusCode::OK).await?==consumed,"consume retry changed the accepted durable receipt");
        let unused=if claim.keypackage_ref==first.keypackage_ref.to_string() {spare.keypackage_ref.to_string()} else {first.keypackage_ref.to_string()};
        let fields=KeyPackagesRevokeFields { keypackage_refs:vec![unused.clone()],device_id:bob.device.clone(),reason:None };
        let signature=arkret_signatures::keypackages::sign_keypackages_revoke_request(&fields,bob.method.as_str(),&bob.key.to_bytes())?;
        let revoke=fields.into_signed(signature);
        let revoked=expect_json(bob.client.post("/_arkret/self/keys/keypackages/revoke").json(&revoke),reqwest::StatusCode::OK).await?;
        ensure!(revoked["revoked"]==json!([unused]),"native revoke did not remove the unused accepted package");
        let membership=mls::accepted_full_view(&bob.client,&join.event_id).await?;
        let mimi_control=crate::harness::heap_future(|| super::mimi_control::exercise(&deployment.station,&alice,&bob,&realm,&group_id,&membership)).await?;
        let peer_reads=crate::harness::heap_future(|| super::peer_membership_reads::exercise(&deployment.station,&alice,&bob,&realm,&membership)).await?;
        let signal=crate::harness::heap_future(|| super::peer_signal::exercise(&deployment.station,&alice,&bob,&realm,&commit_event.event_id,&mut alice_group,&mut restored)).await?;
        let binding:arkret_wire::CommittedEventFullView=serde_json::from_value(mimi_control["binding_commit"].clone())?;
        let mimi_message=crate::harness::heap_future(|| super::mimi_message::exercise(&deployment.station,&alice,&bob,&mut alice_group,&mut restored,&realm,&commit_event.event_id,&binding)).await?;
        let mimi_notify=crate::harness::heap_future(|| super::mimi_notify::exercise(&deployment.station,&bob,&realm,&binding,&mimi_message)).await?;
        let watch_audit=crate::harness::heap_future(|| super::watch_audit::exercise(&deployment.station,&alice,&bob,&realm)).await?;
        let media_token=crate::harness::heap_future(|| super::media_token::exercise(&deployment.station,&alice,&realm)).await?;
        let peer_invite=crate::harness::heap_future(|| super::peer_invite::exercise(&deployment.station,&alice,&bob)).await?;
        let database=deployment.station.configured_database_url().context("native database absent")?.to_owned();
        let claim_id=claim.claim_id.clone();
        let originals=tokio::task::spawn_blocking(move || -> Result<Value> {
            let mut db=postgres::Client::connect(&database,postgres::NoTls)?;
            let binding:Value=db.query_one("SELECT to_jsonb(b) FROM keypackage_claim_welcome_bindings b WHERE claim_id=$1",&[&claim_id])?.get(0);
            let ledger:Value=db.query_one("SELECT to_jsonb(c) FROM peer_keypackage_claims c WHERE source_id=$1 AND claim_request_id=$2",&[&binding["source_id"].as_str().context("claim source absent")?,&binding["claim_request_id"].as_str().context("claim request absent")?])?.get(0);
            let revoked:Value=db.query_one("SELECT to_jsonb(k) FROM mls_key_packages k WHERE keypackage_ref=$1",&[&unused])?.get(0);
            Ok(json!({"welcome_binding":binding,"claim":ledger,"revoked_package":revoked}))
        }).await??;
        retain_diagnostic("mls-lifecycle",&json!({"originals":originals,"claim":original,"consumed":consumed,"revoked":revoked}))?;
        ensure!(originals["claim"]["state"]=="consumed" && originals["claim"]["outcome"]==original && originals["revoked_package"]["claimed_by_mls_group_id"]=="revoked" && originals["revoked_package"]["claim_expires_at_unix_ms"].is_null(),"native KeyPackage ledger lost its accepted lifecycle");
        Ok::<_,anyhow::Error>(json!({"mimi_notify":mimi_notify,"mimi_message":mimi_message,"watch_audit":watch_audit,"media_token":media_token,"peer_invite":peer_invite,"peer_reads":peer_reads,"signal":signal,"mimi_control":mimi_control,"claim_request":claim_request,"claim":claimed,"query":queried,"upload":upload,"uploaded":uploaded,"member_join":join,"member_join_commit":joined,"genesis":genesis,"accepted_genesis":accepted_genesis,"realm_genesis":realm_genesis,"submission":submission,"accepted":accepted,"committed":committed,"welcome":welcome,"consume_request":consume,"consumed":consumed,"revoke_request":revoke,"revoked":revoked,"durable_snapshot_digest":arkret_canonical::sha256_digest(&bytes),"restored_epoch":restored.epoch(),"authority_originals":originals,"processes":[deployment.coauth.server.native_process_identity()?,deployment.station.native_process_identity()?]}))
    })).await;
    retain_attempt("mls-interop", &observations)?;
    let mut artifact = result?;
    validate_exchange_schemas(&observations, &SCOPE)?;
    let claimed: KeyPackagesClaimResponseBody = serde_json::from_value(artifact["claim"].clone())?;
    let original_request: KeyPackagesClaimRequestBody =
        serde_json::from_value(artifact["claim_request"].clone())?;
    ensure!(
        serde_json::to_value(&claimed.claim_receipt.request)?
            == serde_json::to_value(original_request.unsigned_request())?,
        "native claim receipt changed the actual request selectors"
    );
    verify_native_station_keypackage_signature(
        &observations,
        &claimed.claim_receipt.signature,
        claimed.claim_receipt.claimed_at,
        &peer_keypackage_claim_receipt_signing_bytes(&claimed.claim_receipt)?,
    )?;
    let consumed: KeyPackagesConsumeResponseBody =
        serde_json::from_value(artifact["consumed"].clone())?;
    let request: KeyPackagesConsumeRequestBody =
        serde_json::from_value(artifact["consume_request"].clone())?;
    consumed
        .consume_receipt
        .validate_shape()
        .map_err(anyhow::Error::msg)?;
    ensure!(
        consumed.consume_receipt.claim_id == request.claim_id
            && serde_json::to_value(&consumed.consume_receipt.recipient_durable_receipt)?
                == serde_json::to_value(&request.recipient_durable_receipt)?
            && consumed.consume_receipt.request_digest.as_str()
                == keypackages_consume_request_digest(&request)?,
        "native consume receipt changed its exact request"
    );
    verify_native_station_keypackage_signature(
        &observations,
        &consumed.consume_receipt.signature,
        consumed.consume_receipt.consumed_at,
        &consumed.consume_receipt.canonical_signing_bytes()?,
    )?;
    let views = ["realm_genesis", "accepted_genesis", "committed"]
        .map(|member| serde_json::from_value(artifact[member].clone()))
        .into_iter()
        .collect::<std::result::Result<Vec<arkret_wire::CommittedEventFullView>, _>>()?;
    verify_native_station_commits(&observations, &views)?;
    for view in &views {
        ensure!(
            view.commit.governance_generation == 0
                && view.commit.authority_ref
                    == arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                        views[0].event.event_id.clone()
                    ),
            "MLS commit changed its accepted Realm governor"
        );
    }
    super::mimi_control::verify(&observations, &artifact["mimi_control"])?;
    let binding: arkret_wire::CommittedEventFullView =
        serde_json::from_value(artifact["mimi_control"]["binding_commit"].clone())?;
    let binding_payload = serde_json::to_value(&binding.event.payload)?;
    let expected = json!({
        "selector":{"kind":"mimi_room_binding", "mimi_room_uri":binding_payload["mimi_room_uri"]},
        "source_stream_ref":binding.commit.stream_ref,
        "revision":{"commit_id":binding.commit.commit_id, "stream_position":binding.commit.stream_position},
        "value":binding.event.payload
    });
    ensure!(
        artifact["peer_reads"]["bootstrap"]["snapshot"]["current_state_entries"]
            .as_array()
            .context("actual bootstrap current absent")?
            .contains(&expected),
        "peer bootstrap omitted or changed its accepted MIMI binding Current"
    );
    super::mimi_message::verify(&observations, &artifact["mimi_message"])?;
    super::mimi_notify::verify(
        &observations,
        &artifact["mimi_notify"],
        &artifact["mimi_message"],
    )?;
    super::watch_audit::verify(&observations, &artifact["watch_audit"])?;
    super::media_token::verify(&observations, &artifact["media_token"])?;
    super::peer_invite::verify(&observations, &artifact["peer_invite"])?;
    super::peer_membership_reads::verify(&observations, &artifact["peer_reads"])?;
    super::peer_signal::verify(&observations, &artifact["signal"])?;
    artifact["case"] = json!("mls_interop");
    artifact["format_version"] = json!(1);
    artifact["scope"] = json!(SCOPE);
    artifact["observations"] = serde_json::to_value(observations)?;
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("mls-interop.json"),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    for operation in SCOPE {
        println!("native operation contract passed: {operation}");
    }
    Ok(())
}
