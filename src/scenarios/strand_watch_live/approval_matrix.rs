//! Detached grant approvals bind the complete original registered unit.
use arkret_models_collaboration::authority_commit::{
    AuditPairedEventAcceptanceOutcome, AuditPairedEventUnitKind, AuditPairedEventUnitSubmission,
};
use arkret_wire::{
    AccountId, ApprovalContext, ApprovalSignature, ApprovalSignatureInput, ApprovalSignatureProof,
    ApprovalSignatureProofKind, ApprovalTarget, CapabilityActionId, Did, EventAdmissionSubmission,
    GrantId, Hash, SemanticRef,
};
use serde_json::json;

use super::*;
use crate::harness::{ArkretServer, CanonicalJsonBody};
use crate::scenarios::identity_test_support::test_principal_root_signing_authority;

#[expect(
    clippy::too_many_arguments,
    reason = "Approval matrix keeps independent principals and the accepted governor context explicit"
)]
pub(super) async fn run(
    alice: &TestActorClient,
    alice_account: &AccountId,
    bob: &TestActorClient,
    bob_account: &AccountId,
    owner: &TestActorClient,
    governor: &ArkretServer,
    governor_database: &str,
    realm: &str,
    strand: &StrandId,
) -> Result<()> {
    let actions = [
        "ak.strand.watch.set.others",
        "ak.audit.accessed",
        "ak.realm.notification.audit",
    ];
    grant_realm_actions(owner, governor, realm, bob_account, &actions).await?;
    let owner_actor = ActorId::account(AccountId::new(
        owner.principal.as_ref().context("owner")?.core_id.clone(),
        governor.service_id().clone(),
    ));
    let writer = ActorId::account(alice_account.clone());
    let target = ActorId::account(bob_account.clone());
    let typed_realm: RealmId = realm.parse()?;
    let grant = owner.author_event(realm, EventKind::CapabilityGrant.as_str(), json!({"grant":{
        "schema":"ak.schema.capability.v1","realm_id":realm,"issuer_id":owner_actor,"subject":writer,
        "actions":actions,"resources":[{"kind":"realm","realm_id":realm,"match_scope":"realm_wide"}],
        "constraints":[{"constraint_kind":"claim_based","constraint_subkind":"approval","effect":"require_review",
            "approval_required":true,"approval_mode":"before_commit","approval_actor_ids":[bob_account.principal_id],
            "approval_threshold":"unanimous","timeout":"PT60S"}],
        "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":typed_realm.event_id(),"authority_generation":"0"}],
        "issued_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}})).await?;
    let grant_id = GrantId::from_event_id(&grant.event_id);
    let grant_commit = submit_and_expect_commit(
        owner,
        owner_actor.as_account_id().context("owner")?,
        &owner.device_id,
        &grant,
    )
    .await?;
    let business = event(
        alice,
        realm,
        &StrandWatchSetPayload::set(
            strand.clone(),
            target.clone(),
            StrandWatchLevel::Participating,
            None,
        )
        .with_expected_value(StrandWatchValue::Cleared(())),
    )
    .await?;
    let mut audit = alice.author_event(realm, EventKind::AuditAccessed.as_str(),json!({"access_kind":"watch_set_others",
        "writer_actor_id":writer,"target_actor_id":target,"target_ref":strand,"paired_event_id":business.event_id,
        "purpose":"Complete unit approval","accessed_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())})).await?;
    audit.semantic_refs.push(SemanticRef::new(
        business.event_id.to_string(),
        "audit_pair",
    ));
    crate::harness::refresh_typed_event_proof(&mut audit)?;
    let mut bare = AuditPairedEventUnitSubmission {
        unit_kind: AuditPairedEventUnitKind::AuditPairedEvent,
        events: [business, audit].map(EventAdmissionSubmission::new),
    };
    bare.validate()?;
    let selector = StrandWatchCurrentRequestBody {
        realm_id: typed_realm.clone(),
        strand_id: strand.clone(),
        watcher_actor_id: target,
    };
    let before = read(bob, &selector).await?;
    let response = alice
        .post("/_arkret/self/events")
        .canonical_json(&bare)?
        .send()
        .await?;
    let status = response.status();
    let problem: serde_json::Value = response.json().await?;
    ensure!(
        status.is_client_error() && problem["reason_code"] == "approval_required",
        "missing unit approval: {status} {problem}"
    );
    ensure!(
        read(bob, &selector).await? == before,
        "missing approval changed Watch current"
    );
    ensure!(
        unit_effect_counts(governor_database, &bare).await? == [0, 0, 0, 0],
        "missing approval left committed originals, private nonce or unit fence"
    );
    renew_unit(&mut bare, 1)?;
    let digest = Hash::new(arkret_canonical::canonical_sha256(&bare)?)?;
    let (method, seed) = test_principal_root_signing_authority(&bob.actor)?;
    let signer = arkret_signatures::Ed25519DetachedJwsSigner::from_seed(seed, method.as_str());
    let make_vote = |index: usize, action: CapabilityActionId| -> Result<ApprovalSignature> {
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(anyhow::Error::msg)?;
        let mut vote = ApprovalSignature {
            input: ApprovalSignatureInput {
                approval_context: ApprovalContext::Grant {
                    grant_id: grant_id.clone(),
                },
                approval_target: ApprovalTarget::Operation,
                request_canonical_digest: digest.clone(),
                operation: "ak.self.events.command.submit.v1".to_owned(),
                action,
                realm_id: typed_realm.clone(),
                initiating_actor_id: writer.clone(),
                approver_did: Did::new(&bob.actor)?,
                approved_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
                nonce: format!(
                    "registered-watch-full-unit-nonce-{index}-{}",
                    arkret_canonical::base64url_encode(nonce)
                ),
            },
            proof: ApprovalSignatureProof {
                kind: ApprovalSignatureProofKind::DetachedJws,
                verification_method: method.clone(),
                jws: String::new(),
            },
        };
        vote.proof.jws = signer.sign_detached_jws(
            &arkret_signatures::approval_signature::approval_signature_signing_bytes(&vote)?,
        );
        Ok(vote)
    };
    let mut approved = bare.clone();
    approved.events[0].approval_signatures = Some(vec![make_vote(
        0,
        CapabilityActionId::StrandWatchSetOthers,
    )?]);
    approved.events[1].approval_signatures =
        Some(vec![make_vote(1, CapabilityActionId::AuditAccessed)?]);
    let mut wrong = approved.clone();
    renew_unit(&mut wrong, 1)?;
    let wrong_digest = Hash::new(arkret_canonical::canonical_sha256(
        &AuditPairedEventUnitSubmission {
            unit_kind: wrong.unit_kind,
            events: wrong.events.clone().map(|mut slot| {
                slot.approval_signatures = None;
                slot
            }),
        },
    )?)?;
    for slot in &mut wrong.events {
        for vote in slot.approval_signatures.as_mut().unwrap() {
            vote.input.approval_target = ApprovalTarget::Operation;
            vote.input.request_canonical_digest = wrong_digest.clone();
            vote.proof.jws = signer.sign_detached_jws(
                &arkret_signatures::approval_signature::approval_signature_signing_bytes(vote)?,
            );
        }
    }
    wrong.events[0].approval_signatures.as_mut().unwrap()[0]
        .input
        .request_canonical_digest =
        Hash::new(arkret_canonical::canonical_sha256(&wrong.events[0].event)?)?;
    let vote = &mut wrong.events[0].approval_signatures.as_mut().unwrap()[0];
    vote.proof.jws = signer.sign_detached_jws(
        &arkret_signatures::approval_signature::approval_signature_signing_bytes(vote)?,
    );
    let response = alice
        .post("/_arkret/self/events")
        .canonical_json(&wrong)?
        .send()
        .await?;
    ensure!(
        response.status().is_client_error(),
        "slot-only approval was accepted"
    );
    ensure!(
        read(bob, &selector).await? == before,
        "invalid whole-unit binding changed Watch current"
    );
    ensure!(
        unit_effect_counts(governor_database, &wrong).await? == [0, 0, 0, 0],
        "wrong unit digest left committed originals, private nonce or unit fence"
    );
    let mut extra = approved.clone();
    renew_unit(&mut extra, 2)?;
    let extra_digest = Hash::new(arkret_canonical::canonical_sha256(
        &AuditPairedEventUnitSubmission {
            unit_kind: extra.unit_kind,
            events: extra.events.clone().map(|mut slot| {
                slot.approval_signatures = None;
                slot
            }),
        },
    )?)?;
    for slot in &mut extra.events {
        for vote in slot.approval_signatures.as_mut().unwrap() {
            vote.input.request_canonical_digest = extra_digest.clone();
            vote.input.nonce.push_str("-unused-evidence-case");
            vote.proof.jws = signer.sign_detached_jws(
                &arkret_signatures::approval_signature::approval_signature_signing_bytes(vote)?,
            );
        }
    }
    let mut unused = extra.events[0].approval_signatures.as_ref().unwrap()[0].clone();
    unused.input.nonce.push_str("-extra");
    // Keep valid required evidence, but add one invalid, unnecessary proof.
    extra.events[0]
        .approval_signatures
        .as_mut()
        .unwrap()
        .push(unused);
    let response = alice
        .post("/_arkret/self/events")
        .canonical_json(&extra)?
        .send()
        .await?;
    ensure!(
        response.status().is_client_error(),
        "unused invalid approval proof bypassed admission"
    );
    ensure!(
        unit_effect_counts(governor_database, &extra).await? == [0, 0, 0, 0]
            && read(bob, &selector).await? == before,
        "unused invalid proof consumed a nonce or changed accepted state"
    );
    let outcome: AuditPairedEventAcceptanceOutcome = serde_json::from_value(
        expect_json(
            alice
                .post("/_arkret/self/events")
                .canonical_json(&approved)?,
            StatusCode::OK,
        )
        .await?,
    )?;
    outcome.validate_for_request(&approved)?;
    let accepted_counts = unit_effect_counts(governor_database, &approved).await?;
    ensure!(
        accepted_counts == [2, 2, 2, 1],
        "approval unit lacks two exact private approval and source rows: {accepted_counts:?}"
    );
    let replay: AuditPairedEventAcceptanceOutcome = serde_json::from_value(
        expect_json(
            alice
                .post("/_arkret/self/events")
                .canonical_json(&approved)?,
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        replay == outcome,
        "approved replay produced new source Commits"
    );
    ensure!(
        unit_effect_counts(governor_database, &approved).await? == accepted_counts,
        "exact approval replay consumed another nonce or installed another unit"
    );
    println!(
        "[registered-watch-approvals] real_two_stations=1 missing_refused=1 slot_digest_refused=1 unused_invalid_proof_zero_effects=1 whole_unit_signed=1 exact_private_nonces=2 exact_replay=1"
    );
    // Remove the global review requirement before independent Circle cases.
    let revoke = owner
        .author_event(
            realm,
            EventKind::CapabilityRevoke.as_str(),
            json!({"grant_id":grant_id,"expected_revision":{"commit_id":grant_commit.commit_id,"stream_position":grant_commit.stream_position}}),
        )
        .await?;
    submit_and_expect_commit(
        owner,
        owner_actor.as_account_id().context("owner")?,
        &owner.device_id,
        &revoke,
    )
    .await?;
    Ok(())
}

async fn unit_effect_counts(
    database: &str,
    unit: &AuditPairedEventUnitSubmission,
) -> Result<[i64; 4]> {
    let database = database.to_owned();
    let events = unit
        .events
        .iter()
        .map(|slot| slot.event.event_id.to_string())
        .collect::<Vec<_>>();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut connection = postgres::Client::connect(&database, postgres::NoTls)?;
        let row = connection.query_one("SELECT (SELECT count(*) FROM canonical_events WHERE state='committed' AND envelope->>'event_id'=ANY($1)), (SELECT count(*) FROM realm_commits WHERE commit_json->>'event_ref'=ANY($1)), (SELECT count(*) FROM event_approval_private_audit WHERE event_id=ANY($1)), (SELECT count(*) FROM registered_audit_units WHERE business_event_id=ANY($1))", &[&events])?;
        Ok([row.get(0),row.get(1),row.get(2),row.get(3)])
    }).await?
}

fn renew_unit(unit: &mut AuditPairedEventUnitSubmission, millis: i64) -> Result<()> {
    unit.events[0].event.created_at += chrono::Duration::milliseconds(millis);
    crate::harness::refresh_typed_event_proof(&mut unit.events[0].event)?;
    let business_id = unit.events[0].event.event_id.clone();
    let audit = &mut unit.events[1].event;
    audit.created_at += chrono::Duration::milliseconds(millis);
    audit.payload.insert(
        "paired_event_id".to_owned(),
        serde_json::to_value(&business_id)?,
    );
    audit.semantic_refs = vec![SemanticRef::new(business_id.to_string(), "audit_pair")];
    crate::harness::refresh_typed_event_proof(audit)?;
    unit.validate()?;
    Ok(())
}
