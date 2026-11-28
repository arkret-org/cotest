//! Agent PCR root admission through independent Station and issuer processes.
use arkret_crypto::content_history::{ContentRootBackupAuthor, ContentRootBackupDraft};
use arkret_models_crypto::{
    ContentRootBackupEntry, ContentRootContext, ContentRootItemKind, KeyBackup,
    KeyBackupDomainSeparation,
};
use arkret_wire::{BackupSeriesId, ErrorCode};

use super::*;
use crate::harness::{CanonicalJsonBody as _, heap_future};
use crate::scenarios::mls_lifecycle_live::{ACTIVE_SUITE, Member};

pub async fn run_agent_pcr_backup() -> Result<()> {
    let deployment = coauth_session_evidence::actual_agent_deployment("agent-pcr-backup").await?;
    heap_future(move || exercise(deployment)).await
}

pub(super) struct Subject {
    pub(super) agent_account: AccountId,
    pub(super) controller_account: AccountId,
    pub(super) agent_pcr: RealmId,
    pub(super) delegation: DidUrl,
    pub(super) custody_authorization: EventId,
    pub(super) history_custody: arkret_models_crypto::AgentHistoryCustody,
    pub(super) history_recipient_public: [u8; 32],
}

impl From<&AgentRuntimeSession> for Subject {
    fn from(agent: &AgentRuntimeSession) -> Self {
        Self {
            agent_account: agent.agent_account.clone(),
            controller_account: agent.controller_account.clone(),
            agent_pcr: agent.agent_pcr.clone(),
            delegation: agent.delegation.clone(),
            custody_authorization: agent.custody_authorization.clone(),
            history_custody: agent.history_custody.clone(),
            history_recipient_public: agent.history_recipient_public,
        }
    }
}

pub(super) struct InitialBackup {
    series: BackupSeriesId,
    root: ContentRootBackupEntry,
    packet: KeyBackup,
}

async fn provision_runtime(
    deployment: &ActualAgentDeployment,
    name: &str,
) -> Result<(AgentRuntimeSession, InitialBackup)> {
    let issuer = AgentSessionIssuer::Coauth {
        base: deployment.coauth.base_url(),
        database_url: &deployment.coauth.pg.connect_url,
    };
    let mut initial = None;
    let scope = requested_scope(&[ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_REPLACE_V1])?;
    let paired = heap_future(|| {
        AgentRuntimeSession::establish_with_bootstrap(
            &deployment.station,
            &issuer,
            &deployment.controller,
            &deployment.account,
            name,
            scope,
            None,
            Some(&mut initial),
        )
    })
    .await?;
    let runtime =
        heap_future(|| AgentRuntimeSession::issue_paired(&deployment.station, issuer, paired))
            .await?;
    Ok((runtime, initial.context("missing pre-pairing root backup")?))
}

// Supply a genuine controller-generated MLS root as private client input. The
// backup endpoint receives only the public index and the HPKE-encrypted packet.
async fn controller_root(
    station: &ArkretServer,
    controller: &Member,
    agent: &Subject,
) -> Result<ContentRootBackupEntry> {
    let scope = ScopeRef::Realm {
        realm_id: agent.agent_pcr.clone(),
    };
    let binding = arkret::MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
    let mut group = controller
        .mls_identity()?
        .create_group_with_governance_binding(&scope, &binding)?;
    let leaf = crate::scenarios::cross_station_mls_welcome::genesis_creator_leaf_authority(
        &mut group, controller,
    )?;
    let (info, tree) = group.public_group_state_bytes()?;
    let info = heap_future(|| super::direct_mls_evidence::blob(&controller.client, &info)).await?;
    let tree = heap_future(|| super::direct_mls_evidence::blob(&controller.client, &tree)).await?;
    let at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let mut raw = arkret_wire::test_support::raw_event_for_actor_at(
        "ak.mls.genesis",
        scope.clone(),
        ActorId::account(agent.agent_account.clone()),
        json!({"cipher_suite":ACTIVE_SUITE, "group_info_ref":info,
            "ratchet_tree_ref":tree, "governance_binding":binding,
            "creator_leaf_authority":leaf, "created_at":arkret_canonical::format_timestamp_canonical(at)}),
        at,
    )?;
    raw.executed_by = Some(controller.actor.clone());
    raw.authorization_ref = Some(
        arkret_wire::AuthorizationRef::new(agent.delegation.as_str())
            .map_err(anyhow::Error::msg)?,
    );
    let genesis = sign(
        arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            raw,
            arkret_canonical::DigestSuite::Sha256,
        )?,
        &controller.method,
        controller.key.to_bytes(),
    )?;
    let result: AuthoritySubmitResponseBody = serde_json::from_value(
        expect_json(
            controller
                .client
                .post("/_arkret/self/events")
                .canonical_json(&arkret_wire::EventAdmissionSubmission::new(genesis.clone()))?,
            StatusCode::OK,
        )
        .await
        .context("commit controller-signed MLS Genesis in the Agent PCR")?,
    )?;
    let AuthoritySubmitResponseBody::Accepted {
        status: AuthorityCommitStatus::Committed,
        commit,
        ..
    } = result
    else {
        bail!("Station did not commit the controller's PCR MLS Genesis")
    };
    ensure!(commit.event_ref == genesis.event_id && commit.realm_id == agent.agent_pcr);
    crate::scenarios::human_device_producer_live::ensure_commit_signed_by(&commit, station)?;
    let context = ContentRootContext {
        effective_scope: scope,
        genesis_event_ref: genesis.event_id.clone(),
        epoch: group.epoch(),
        group_state_ref: genesis.event_id,
        cipher_suite: ACTIVE_SUITE.into(),
        encryption_backup_strategy: arkret_wire::EncryptionBackupStrategy::EpochContentRoots,
        backup_strategy_ref: agent.agent_pcr.event_id(),
    };
    let secret = group.export_content_root(&context)?;
    let root_ref = arkret_crypto::content_history::content_root_ref(&secret, &context)?;
    Ok(ContentRootBackupEntry {
        item_kind: ContentRootItemKind::ContentEpochRoot,
        secret_id: format!("root_{}", root_ref.as_str().trim_start_matches("sha256:")),
        root_ref,
        root_context: context,
        root_base64url: secret,
    })
}

fn packet(
    agent: &AgentRuntimeSession,
    series: &BackupSeriesId,
    predecessor: Option<&KeyBackup>,
    roots: Vec<ContentRootBackupEntry>,
    key: &SigningKey,
) -> Result<KeyBackup> {
    let author = ContentRootBackupAuthor::Agent {
        verification_method: agent.verification_method.clone(),
        authorization_event_ref: agent.key_authorization.clone(),
    };
    seal(
        &Subject::from(agent),
        series,
        predecessor,
        roots,
        key,
        author,
    )
}

fn seal(
    agent: &Subject,
    series: &BackupSeriesId,
    predecessor: Option<&KeyBackup>,
    roots: Vec<ContentRootBackupEntry>,
    key: &SigningKey,
    author: ContentRootBackupAuthor,
) -> Result<KeyBackup> {
    let supersedes = predecessor
        .map(|prior| -> Result<_> {
            Ok((
                prior.backup_id.clone(),
                arkret_wire::Hash::new(arkret_canonical::sha256_digest(
                    prior.signing_payload_bytes()?,
                ))
                .map_err(anyhow::Error::msg)?,
            ))
        })
        .transpose()?;
    Ok(ContentRootBackupDraft {
        backup_id: arkret_wire::BackupId::new(arkret::new_prefixed_uuid7("ak:backup:"))
            .map_err(anyhow::Error::msg)?,
        actor_id: ActorId::account(agent.agent_account.clone()),
        created_at: arkret_canonical::normalize_timestamp_canonical(Utc::now()),
        expires_at: None,
        author,
        recipient_key_ref: agent.history_custody.recipient_key_ref.to_string(),
        recovery_policy_ref: agent.history_custody.recovery_policy_ref.clone(),
        domain_separation: KeyBackupDomainSeparation {
            subdomain: "content_epoch_root".into(),
            aead_aad_extensions: Default::default(),
        },
        series_id: series.clone(),
        series_sequence: predecessor.map_or(0, |p| p.series_sequence + 1),
        supersedes,
        custody: Some((
            ActorId::account(agent.controller_account.clone()),
            agent.custody_authorization.clone(),
        )),
    }
    .seal(roots, &agent.history_recipient_public, |bytes| {
        Ok(key.sign(bytes).to_bytes().to_vec())
    })?)
}

async fn backup_rows(db: &str) -> Result<serde_json::Value> {
    let db = db.to_owned();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut conn = postgres::Client::connect(&db, postgres::NoTls)?;
        let row = conn.query_one(
            "SELECT jsonb_build_object(
                'identities', (SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY id), '[]'::jsonb)
                               FROM key_backup_identities i),
                'backups', (SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY id), '[]'::jsonb)
                            FROM key_backups b))",
            &[],
        )?;
        Ok(row.get(0))
    })
    .await?
}

pub(super) async fn initial_backup(
    station: &ArkretServer,
    client: &TestActorClient,
    agent: &Subject,
) -> Result<InitialBackup> {
    let owner = Member::from_client(client.clone(), agent.controller_account.clone())?;
    let series =
        heap_future(|| super::content_sidecar_evidence::select_agent_backup_series(&owner, agent))
            .await?;
    let root = heap_future(|| controller_root(station, &owner, agent)).await?;
    let owner_sdk = owner.client.sdk();
    let provision =
        heap_future(|| owner_sdk.committed_event_get(&agent.custody_authorization)).await?;
    let initial = seal(
        agent,
        &series,
        None,
        vec![root.clone()],
        &owner.key,
        ContentRootBackupAuthor::Device {
            binding: arkret_crypto::backup::KeyBackupAuthorizationBinding {
                device_id: owner.device.clone(),
                verification_method: owner.method.clone(),
                signature_algorithm: arkret_models_crypto::KeyBackupSignatureAlgorithm::Ed25519,
                device_authorize_event_id: owner.authorize_event_id.clone(),
            },
            source: arkret_models_crypto::KeyBackupSourceCommitRef {
                realm_commit_id: provision.commit().commit_id.clone(),
                device_generation_ref: 1,
            },
        },
    )?;
    let token = format!("arkret-key-backup-{}", initial.backup_id);
    let first = heap_future(|| owner_sdk.put_key_backup(&initial.backup_id, &initial, &token))
        .await
        .context("controller publishes the initial recoverable PCR root")?;
    ensure!(
        first.backup_id == initial.backup_id
            && first.ciphertext_digest == initial.ciphertext_digest
    );
    println!("[agent-pcr-backup] controller published the initial MLS root before runtime pairing");
    Ok(InitialBackup {
        series,
        root,
        packet: initial,
    })
}

async fn exercise(deployment: ActualAgentDeployment) -> Result<()> {
    let (
        agent,
        InitialBackup {
            series,
            root,
            packet: initial,
        },
    ) = heap_future(|| provision_runtime(&deployment, "pcr-backup-writer")).await?;
    let (other, other_backup) =
        heap_future(|| provision_runtime(&deployment, "pcr-backup-sibling")).await?;
    ensure!(
        agent.agent_pcr != other.agent_pcr && agent.controller_account == other.controller_account
    );
    let foreign = other_backup.root;
    let own = agent
        .runtime
        .sdk()
        .own_station_result_client()?
        .context("issued Agent binding")?;
    let db = deployment
        .station
        .owned_database_url()
        .context("owned Station database")?;
    let before = backup_rows(db).await?;
    let accepted = packet(
        &agent,
        &series,
        Some(&initial),
        vec![root.clone()],
        &agent.runtime_key,
    )?;
    let ack = heap_future(|| own.put_own_key_backup(&accepted)).await?;
    ensure!(
        ack.value()?.backup_id == accepted.backup_id
            && ack.value()?.ciphertext_digest == accepted.ciphertext_digest
    );
    let stored = backup_rows(db).await?;
    for table in ["identities", "backups"] {
        ensure!(
            stored[table].as_array().context("stored rows")?.len()
                == before[table].as_array().context("baseline rows")?.len() + 1
        );
    }
    let identity = stored["identities"]
        .as_array()
        .context("identity rows")?
        .iter()
        .find(|row| {
            row["series_id"].as_str() == Some(series.as_str()) && row["series_sequence"] == 1
        })
        .context("new backup identity")?;
    let original = stored["backups"]
        .as_array()
        .context("packet rows")?
        .iter()
        .find(|row| row["id"] == identity["id"])
        .context("stored signed packet")?;
    let original: KeyBackup = serde_json::from_value(original["payload"].clone())?;
    ensure!(
        original == accepted,
        "Station did not retain the signed original"
    );
    let proof = &identity["writer_admission"];
    let public = agent.runtime_key.verifying_key().to_bytes();
    ensure!(
        proof["signer_actor"]
            == serde_json::to_value(ActorId::account(agent.agent_account.clone()))?
            && proof["authorization_event_ref"] == agent.key_authorization.as_str()
            && proof["agent_method"] == agent.verification_method.as_str()
            && proof["public_key_did"]
                == format!(
                    "did:key:{}",
                    arkret_canonical::ed25519_pubkey_to_did_key_multibase(&public)
                )
            && proof.get("signer_device").is_none()
            && proof.get("generation").is_none()
    );
    ensure!(arkret_signatures::verify_detached_ed25519_signature(
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: public.to_vec()
        },
        &accepted.signing_payload_bytes()?,
        accepted.signature_proof.signature.as_str()
    ));
    println!(
        "[agent-pcr-backup] own root accepted; backups {} -> {}, identities {} -> {}; persisted writer matched issued authorization, method and Ed25519 public key",
        before["backups"].as_array().unwrap().len(),
        stored["backups"].as_array().unwrap().len(),
        before["identities"].as_array().unwrap().len(),
        stored["identities"].as_array().unwrap().len()
    );

    for (label, roots, key, code) in [
        (
            "foreign PCR",
            vec![foreign.clone()],
            &agent.runtime_key,
            ErrorCode::CapabilityDenied,
        ),
        (
            "mixed PCRs",
            vec![root.clone(), foreign],
            &agent.runtime_key,
            ErrorCode::CapabilityDenied,
        ),
        (
            "different signing key",
            vec![root.clone()],
            &other.runtime_key,
            ErrorCode::SignatureInvalid,
        ),
    ] {
        let bad = packet(&agent, &series, Some(&accepted), roots, key)?;
        let error = heap_future(|| own.put_own_key_backup(&bad))
            .await
            .err()
            .context("unexpected backup acceptance")?;
        ensure!(
            matches!(&error,arkret_http_client::Error::Api {status,error} if (400..500).contains(status) && error.error_code()==Some(code)),
            "{label}: {error}"
        );
        ensure!(
            backup_rows(db).await? == stored,
            "{label}: backup storage changed"
        );
        println!("[agent-pcr-backup] {label} refused: {error}; backup rows unchanged");
    }
    let successor = packet(
        &agent,
        &series,
        Some(&accepted),
        vec![root],
        &agent.runtime_key,
    )?;
    heap_future(|| revoke_runtime_key(&deployment.controller, &agent)).await?;
    let error = heap_future(|| own.put_own_key_backup(&successor))
        .await
        .err()
        .context("revoked upload accepted")?;
    ensure!(
        matches!(
            &error,
            arkret_http_client::Error::Api {
                status: 401 | 403,
                ..
            }
        ),
        "revoked session: {error}"
    );
    ensure!(
        backup_rows(db).await? == stored,
        "revocation refusal changed backup storage"
    );
    println!(
        "[agent-pcr-backup] same issued session after committed key revocation: {error}; backup rows unchanged"
    );
    Ok(())
}
