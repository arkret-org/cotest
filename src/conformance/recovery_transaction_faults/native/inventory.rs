//! A real registered Human, accepted PCR MLS Genesis and sealed root.
use arkret_crypto::content_history::{ContentRootBackupAuthor, ContentRootBackupDraft};
use arkret_models_crypto::*;
use arkret_wire::{ActorId, EventKind, ScopeRef};

mod rekey;
pub(super) use rekey::run as rekey;

use super::*;
use crate::scenarios::mls_lifecycle_live::{ACTIVE_SUITE, Member, accepted_full_view};

pub(super) struct Material {
    event: arkret_wire::Event,
    profile: arkret_wire::Event,
    header: EventContentPreEncryptionHeader,
    empty_group: arkret_wire::Event,
    leaf: arkret_models_collaboration::events_payloads::MlsGenesisCreatorLeafAuthority,
    root: ContentRootBackupEntry,
    packet: KeyBackup,
    owner: Member,
    recipient: [u8; 32],
    recipient_public: [u8; 32],
}

async fn upload(client: &TestActorClient, bytes: &[u8]) -> Result<Value> {
    let form =
        crate::scenarios::delivery_media::blob_upload_form(bytes, "application/octet-stream")?;
    Ok(expect_json(
        client.post("/_arkret/self/blob/upload").multipart(form),
        reqwest::StatusCode::OK,
    )
    .await?["blob_ref"]
        .clone())
}

fn private_event(
    owner: &Member,
    realm: &arkret_wire::RealmId,
    kind: EventKind,
    payload: Value,
) -> arkret_wire::Event {
    // The Human's own PCR admits its actual current Device, without a Realm owner's delegation.
    crate::harness::event_envelope_with_signing_identity(
        &owner.client.actor,
        realm.as_str(),
        kind.as_str(),
        payload,
        owner.key.to_bytes(),
        &owner.method,
        Some(&owner.account.station_id),
    )
}

async fn activate(
    owner: &Member,
    realm: &arkret_wire::RealmId,
) -> Result<(
    arkret::ArkretMlsGroup,
    arkret_wire::Event,
    arkret_models_collaboration::events_payloads::MlsGenesisCreatorLeafAuthority,
    arkret_wire::CommittedEventFullView,
)> {
    let client = &owner.client;
    let account = &owner.account;
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let binding = arkret::MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
    let mut group = owner
        .mls_identity()?
        .create_group_with_governance_binding(&scope, &binding)?;
    let leaf = crate::scenarios::cross_station_mls_welcome::genesis_creator_leaf_authority(
        &mut group, owner,
    )?;
    let (info, tree) = group.public_group_state_bytes()?;
    let payload = json!({
        "cipher_suite":ACTIVE_SUITE, "group_info_ref":upload(client,&info).await?,
        "ratchet_tree_ref":upload(client,&tree).await?, "governance_binding":binding,
        "creator_leaf_authority":leaf,"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
    });
    let event = if &client
        .principal
        .as_ref()
        .context("registered Human")?
        .pcr_realm_id
        == realm
    {
        private_event(owner, realm, EventKind::MlsGenesis, payload)
    } else {
        client
            .author_event(realm.as_str(), EventKind::MlsGenesis.as_str(), payload)
            .await?
    };
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        client,
        account,
        owner.device.as_str(),
        &event,
    )
    .await?;
    let accepted = accepted_full_view(client, &event.event_id).await?;
    ensure!(accepted.event == event);
    Ok((group, event, leaf, accepted))
}

const PROFILE_FIELDS: &[u8] = br#"{"profile_fields":{"biography":"PCR recovery inventory"}}"#;

async fn publish_profile(
    owner: &Member,
    leaf: &arkret_models_collaboration::events_payloads::MlsGenesisCreatorLeafAuthority,
    root: &ContentRootBackupEntry,
    packet: &KeyBackup,
) -> Result<(arkret_wire::Event, EventContentPreEncryptionHeader)> {
    use arkret_crypto::content_history as crypto;
    let basis = &root.root_context;
    let realm = basis
        .effective_scope
        .realm_id_opt()
        .context("profile PCR")?;
    let mut object = json!({"principal_id":owner.account.principal_id,"actor_kind":"user","display_name":"Inventory recovery"});
    let mut event = private_event(
        owner,
        realm,
        EventKind::ProfileCreate,
        json!({"object":object}),
    );
    let producer = ContentEndpoint {
        actor_id: owner.actor.clone(),
        endpoint: leaf.endpoint.clone(),
        authorization_event_ref: leaf.authorization_event_ref.clone(),
        signature_key_base64url: leaf.leaf_signature_key_base64url.to_string(),
    };
    let context = ContentContext {
        root_context: basis.clone(),
        root_ref: root.root_ref.clone(),
        purpose: ContentPurpose::EventBody,
        encryption_scheme: arkret_wire::EncryptedPayloadScheme::EpochContentAead,
        encryption_algorithm: ContentEncryptionAlgorithm::Aes128Gcm,
        producer,
        content_key_salt: crypto::fresh_content_key_salt()?,
    };
    let key = crypto::derive_content_key(&root.root_base64url, &context)?;
    let commitment = crypto::content_key_commitment(&context, &key)?;
    let protection = ContentProtection {
        root_refs: vec![root.root_ref.clone()],
        backup_refs: vec![packet.backup_id.clone()],
        blob_refs: vec![],
    };
    let mut outer = serde_json::to_value(&event)?;
    for key in ["event_id", "payload", "producer_proof", "unsigned"] {
        outer
            .as_object_mut()
            .context("original envelope")?
            .remove(key);
    }
    let header = EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/json",
        context.encryption_scheme.clone(),
        basis.effective_scope.clone(),
        event.kind.as_str(),
        basis.epoch,
        basis.group_state_ref.clone(),
        arkret_canonical::canonical_json_string(&owner.actor)?,
        EventContentRoutingContext::None,
        EventContentMaterial {
            content_context: context.clone(),
            outer_event: outer,
            protection: protection.clone(),
            key_commitment: commitment.clone(),
        },
    )?;
    object["encrypted_private_fields"] = serde_json::to_value(EncryptedEnvelope {
        version: "1.0".into(),
        content_type: "application/json".into(),
        encryption_scheme: context.encryption_scheme,
        encryption_context: EncryptedEnvelopeEncryptionContext::EpochContent {
            epoch: basis.epoch,
            group_state_ref: basis.group_state_ref.clone(),
            content_key_salt: context.content_key_salt,
            root_ref: root.root_ref.clone(),
            key_commitment: commitment,
            protection,
            routing_context: None,
        },
        ciphertext: crypto::seal_content(&root.root_base64url, &header, PROFILE_FIELDS)?,
    })?;
    event.payload.insert("object".into(), object);
    crate::harness::refresh_typed_event_proof_with_signing_seed(&mut event, owner.key.to_bytes())?;
    let submission = arkret_wire::EventAdmissionSubmission::new(event.clone());
    let accepted = expect_json(
        owner
            .client
            .post("/_arkret/self/account/profile")
            .canonical_json(&json!({"profile_event":submission}))?,
        reqwest::StatusCode::OK,
    )
    .await?;
    let commit: arkret_wire::RealmCommit = serde_json::from_value(accepted["commit"].clone())?;
    commit.validate_content_address()?;
    ensure!(
        commit.event_ref == event.event_id,
        "account profile committed a different original"
    );
    Ok((event, header))
}

pub(super) async fn provision(
    fixture: &CanonicalApiFixture,
    authority: &recovery::RecoveryAuthority,
) -> Result<Material> {
    let client = &fixture.client;
    let principal = client.principal.as_ref().context("founding identity")?;
    let account = authority
        .policy_event
        .actor_id
        .as_account_id()
        .context("Human recovery policy")?;
    let owner = Member::from_client(client.clone(), account.clone())?;
    let realm = &principal.pcr_realm_id;
    let (group, event, leaf, accepted) =
        crate::harness::heap_future(|| activate(&owner, realm)).await?;
    let empty_realm = crate::scenarios::human_device_producer_live::create_realm_with_join_rule(
        client,
        "Recovery inventory empty MLS Realm",
        "public",
        &[&fixture.server],
    )
    .await?;
    let empty_realm = arkret_wire::RealmId::new(empty_realm)?;
    let (_, empty_group, ..) =
        crate::harness::heap_future(|| activate(&owner, &empty_realm)).await?;
    let scope = event.scope_ref.clone();
    let context = ContentRootContext {
        effective_scope: scope,
        genesis_event_ref: event.event_id.clone(),
        epoch: group.epoch(),
        group_state_ref: event.event_id.clone(),
        cipher_suite: ACTIVE_SUITE.into(),
        encryption_backup_strategy: arkret_wire::EncryptionBackupStrategy::EpochContentRoots,
        backup_strategy_ref: realm.event_id(),
    };
    let secret = group.export_content_root(&context)?;
    let root = ContentRootBackupEntry {
        item_kind: ContentRootItemKind::ContentEpochRoot,
        secret_id: "recovery_inventory_pcr".into(),
        root_ref: arkret_crypto::content_history::content_root_ref(&secret, &context)?,
        root_context: context,
        root_base64url: secret,
    };
    let policy: RecoveryPolicy =
        serde_json::from_value(authority.policy_event.payload["value"].clone())?;
    let material =
        arkret_crypto::identity_root::derive_identity_recovery_key_material(&authority.seed, 0)?;
    let agreement = policy
        .methods
        .iter()
        .filter_map(|method| match method {
            RecoveryMethod::RecoveryUnlock { keys } => Some(keys),
            _ => None,
        })
        .flatten()
        .map(|key| &key.backup_hpke)
        .find(|entry| entry.public_key_multibase == material.backup_hpke_public_key_multikey)
        .context("the signed policy must contain the derived backup recipient")?;
    let packet = ContentRootBackupDraft {
        backup_id: arkret_identifiers::new_prefixed_uuid7("ak:backup:").parse()?,
        actor_id: ActorId::account(account.clone()),
        created_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        expires_at: None,
        author: ContentRootBackupAuthor::Device {
            binding: arkret_crypto::backup::KeyBackupAuthorizationBinding {
                device_id: owner.device.clone(),
                verification_method: owner.method.clone(),
                signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
                device_authorize_event_id: owner.authorize_event_id.clone(),
            },
            source: KeyBackupSourceCommitRef {
                realm_commit_id: accepted.commit.commit_id,
                device_generation_ref: 1,
            },
        },
        recipient_key_ref: agreement.key_agreement_ref.to_string(),
        recovery_policy_ref: RecoveryPolicyRef {
            policy_id: policy.policy_id,
            policy_version: policy.version,
        },
        domain_separation: KeyBackupDomainSeparation {
            subdomain: "content_epoch_root".into(),
            aead_aad_extensions: Default::default(),
        },
        series_id: arkret_identifiers::new_prefixed_uuid7("ak:backup_series:").parse()?,
        series_sequence: 0,
        supersedes: None,
        custody: None,
    }
    .seal(
        vec![root.clone()],
        &material.backup_hpke_public_key,
        |bytes| Ok(owner.key.sign(bytes).to_bytes().to_vec()),
    )?;
    let stored = client
        .sdk()
        .put_key_backup(
            &packet.backup_id,
            &packet,
            &format!("arkret-key-backup-{}", packet.backup_id),
        )
        .await
        .context("upload actual Human PCR root")?;
    ensure!(stored.ciphertext_digest == packet.ciphertext_digest);
    let (profile, header) =
        crate::harness::heap_future(|| publish_profile(&owner, &leaf, &root, &packet)).await?;
    Ok(Material {
        profile,
        header,
        empty_group,
        event,
        leaf,
        root,
        packet,
        owner,
        recipient: material.backup_hpke_serialized_private_key,
        recipient_public: material.backup_hpke_public_key,
    })
}

fn verify_original(view: &arkret_wire::CommittedEventFullView, owner: &Member) -> Result<()> {
    view.validate_shape()?;
    view.commit.validate_content_address()?;
    let event = &view.event;
    event.verify_event_id_matches_content_with_digest_suite(
        event.realm_id.digest_suite_code().digest_suite(),
    )?;
    let proof = event
        .producer_proof
        .as_ref()
        .context("original producer proof")?;
    ensure!(proof.verification_method == owner.method && event.actual_signer() == &owner.actor);
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &arkret_signatures::EventProofBuilder::new().envelope_bytes(event)?,
        &owner.actor,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: owner.key.verifying_key().to_bytes().to_vec(),
        },
        event.realm_id.digest_suite_code().digest_suite(),
    )?;
    Ok(())
}

/// Observe native writes even if the worker wins before the first HTTP poll.
pub(super) async fn observe_transitions(database: &str) -> Result<()> {
    query(database, |db| {
        db.batch_execute(
            "CREATE TABLE cotest_inventory_transitions (
                seq bigserial PRIMARY KEY, authorization_ref text NOT NULL, state text NOT NULL, blob text
             );
             CREATE FUNCTION cotest_observe_inventory() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN
                INSERT INTO cotest_inventory_transitions(authorization_ref,state,blob)
                VALUES (NEW.authorization_event_ref,NEW.state,NEW.inventory_blob_ref);
                RETURN NEW;
             END $$;
             CREATE TRIGGER cotest_inventory_transition AFTER INSERT OR UPDATE OF state
             ON content_recovery_episodes FOR EACH ROW EXECUTE FUNCTION cotest_observe_inventory();",
        )?;
        Ok(())
    }).await
}

pub(super) async fn verify(
    client: &TestActorClient,
    completion: &RecoveryTransactionCompletion,
    material: &Material,
    database: &str,
    station: &crate::harness::ArkretServer,
) -> Result<Value> {
    let cut = &completion
        .completion_attestation
        .device_authorization_event_ref;
    let path = format!("/_arkret/self/mls/content-recoveries/{}", cut.event_id);
    let preparation = tokio::time::timeout(std::time::Duration::from_secs(75), async {
        loop {
            let value: ContentRecoveryPreparation = serde_json::from_value(
                expect_json(client.get(&path), reqwest::StatusCode::OK).await?,
            )?;
            value.validate_for_authorization(&cut.event_id)?;
            ensure!(&value.pcr_cut == cut);
            if value.state == ContentRecoveryPreparationState::Prepared {
                return Ok::<_, anyhow::Error>(value);
            }
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        }
    })
    .await
    .context("native inventory worker did not publish prepared")??;
    let reference = preparation
        .inventory_blob_ref
        .as_ref()
        .context("prepared inventory address")?;
    let authorization = cut.event_id.to_string();
    let transitions = query(database, move |db| {
        db.query("SELECT state,blob FROM cotest_inventory_transitions WHERE authorization_ref=$1 ORDER BY seq", &[&authorization])?
            .into_iter().map(|row| Ok((row.try_get::<_,String>(0)?, row.try_get::<_,Option<String>>(1)?))).collect::<Result<Vec<_>>>()
    }).await?;
    ensure!(
        transitions
            == [
                ("pending".to_owned(), None),
                ("prepared".to_owned(), Some(reference.to_string()))
            ],
        "native transaction did not publish exactly one inventory after its pending cut"
    );
    let path = "/_arkret/self/blob/get";
    let params = [("blob_ref", reference.as_str())];
    let body = client
        .get(path)
        .query(&params)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    ensure!(
        reference.as_str() == format!("ak:blob:sha256:{}", arkret_canonical::sha256_hex(&body))
    );
    let inventory: ContentRecoveryInventory = serde_json::from_slice(&body)?;
    let digest = arkret_crypto::content_history::recovery_inventory_digest(&inventory)?;
    ensure!(
        body.as_ref() == arkret_canonical::canonical_json_bytes(&inventory)?
            && inventory.replacement == preparation.replacement
            && &inventory.pcr_cut == cut
    );
    let ranged = client
        .get(path)
        .query(&params)
        .header("Range", "bytes=0-15")
        .send()
        .await?;
    ensure!(
        ranged.status() == reqwest::StatusCode::PARTIAL_CONTENT
            && ranged.bytes().await?.as_ref() == &body[..16]
    );
    let upload = crate::scenarios::delivery_media::blob_upload_form(&body, "application/json")?;
    let collision = client
        .post("/_arkret/self/blob/upload")
        .multipart(upload)
        .send()
        .await?;
    ensure!(
        collision.status() == reqwest::StatusCode::CONFLICT,
        "ordinary upload reclassified inventory"
    );
    let denied = material
        .owner
        .client
        .get(path)
        .query(&params)
        .send()
        .await?;
    ensure!(denied.status().is_client_error());
    ensure!(
        inventory.entries.len() == 2,
        "expected exactly an empty Realm and the backed-up PCR"
    );
    let empty = inventory
        .entries
        .iter()
        .find(|entry| entry.genesis_event_ref == material.empty_group.event_id)
        .context("group without content or backup omitted")?;
    ensure!(
        empty.effective_scope == material.empty_group.scope_ref
            && empty.base_group_state_ref == material.empty_group.event_id
            && empty.epoch == 0
            && empty.old_leaves.len() == 1
    );
    let head = client
        .authorize(station.http().head(station.url(path)).query(&params))
        .send()
        .await?;
    ensure!(
        head.status() == reqwest::StatusCode::OK
            && head
                .headers()
                .get(reqwest::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<usize>().ok())
                == Some(body.len()),
        "inventory HEAD returned {} with Content-Length {:?}, expected {}",
        head.status(),
        head.headers().get(reqwest::header::CONTENT_LENGTH),
        body.len()
    );
    let expected_digest = format!("sha-256={}", arkret_canonical::sha256_hex(&body));
    ensure!(
        head.headers().get("digest").and_then(|h| h.to_str().ok())
            == Some(expected_digest.as_str()),
        "inventory HEAD digest differs from the complete private Blob"
    );
    let anonymous = station
        .http()
        .get(station.url(path))
        .query(&params)
        .send()
        .await?;
    ensure!(anonymous.status().is_client_error());
    let entry = inventory
        .entries
        .iter()
        .find(|entry| entry.genesis_event_ref == material.event.event_id)
        .context("missing original PCR")?;
    ensure!(
        entry.effective_scope == material.event.scope_ref
            && entry.base_group_state_ref == material.event.event_id
            && entry.epoch == 0
    );
    let [old] = entry.old_leaves.as_slice() else {
        anyhow::bail!("expected original device leaf")
    };
    ensure!(
        old.leaf_index == 0
            && old.endpoint.actor_id == material.owner.actor
            && old.endpoint.authorization_event_ref == material.leaf.authorization_event_ref
            && old.endpoint.signature_key_base64url
                == material.leaf.leaf_signature_key_base64url.as_str()
    );
    let original = accepted_full_view(client, &material.event.event_id).await?;
    ensure!(original.event == material.event);
    verify_original(&original, &material.owner)?;
    let profile = accepted_full_view(client, &material.profile.event_id).await?;
    ensure!(profile.event == material.profile);
    verify_original(&profile, &material.owner)?;
    let replacement = client
        .principal
        .as_ref()
        .context("replacement Device custody")?;
    let challenge = client
        .sdk()
        .issue_key_backup_unlock_challenge(
            &material.packet.backup_id,
            &KeysBackupsIssueUnlockChallengeRequestBody {
                request_id: arkret_wire::Base64UrlString::new(
                    arkret_crypto::content_history::fresh_content_key_salt()?,
                )
                .map_err(anyhow::Error::msg)?,
                subject_actor_id: None,
                custody_authorization_ref: None,
                content_history: Some(ContentHistoryBackupAccess {
                    source: arkret_wire::CommittedEventRef {
                        event_id: profile.event.event_id.clone(),
                        commit_id: profile.commit.commit_id.clone(),
                        stream_ref: profile.commit.stream_ref.clone(),
                        stream_position: profile.commit.stream_position,
                    },
                    root_refs: vec![material.root.root_ref.clone()],
                }),
            },
        )
        .await
        .context("replacement requests the root of the accepted original")?;
    let method = arkret_wire::DidUrl::new(format!("{}#{}", replacement.did, replacement.device_id))
        .map_err(anyhow::Error::msg)?;
    let proof = challenge.sign_unlock_proof_at(method, chrono::Utc::now(), |bytes| {
        Ok(replacement
            .device_signing_key
            .sign(bytes)
            .to_bytes()
            .to_vec())
    })?;
    let packet = client
        .sdk()
        .unlock_key_backup(
            &material.packet.backup_id,
            &KeysBackupsUnlockRequestBody { proof },
        )
        .await
        .context("replacement unlocks the original root package")?;
    let id = material.packet.backup_id.to_string();
    let persisted: Value = query(database, move |db| {
        Ok(db
            .query_one(
                "SELECT payload FROM key_backups WHERE payload->>'backup_id'=$1",
                &[&id],
            )?
            .get(0))
    })
    .await?;
    let persisted: KeyBackup = serde_json::from_value(persisted)?;
    ensure!(
        persisted == packet,
        "Station HTTP returned a different envelope from PostgreSQL"
    );
    ensure!(
        packet == material.packet
            && packet.contents.iter().any(|item| item.root_ref.as_ref()
                == Some(&material.root.root_ref)
                && item.root_context.as_ref() == Some(&material.root.root_context))
    );
    let bag = arkret_crypto::content_history::open_content_root_backup(
        &packet,
        &material.recipient,
        |bytes, proof| {
            let sig = ed25519_dalek::Signature::from_slice(
                &arkret_canonical::base64url_decode(proof.signature.as_str())
                    .map_err(|e| arkret_crypto::Error::Protocol(e.to_string()))?,
            )
            .map_err(|e| arkret_crypto::Error::Protocol(e.to_string()))?;
            material
                .owner
                .key
                .verifying_key()
                .verify_strict(bytes, &sig)
                .map_err(|e| arkret_crypto::Error::Protocol(e.to_string()))?;
            Ok(())
        },
    )?;
    ensure!(
        matches!(bag.items.as_slice(),[SecretStorageEntry::ContentRoot(root)] if root==&material.root)
    );
    let envelope: EncryptedEnvelope = serde_json::from_value(
        profile.event.payload["object"]["encrypted_private_fields"].clone(),
    )?;
    let SecretStorageEntry::ContentRoot(restored) = &bag.items[0] else {
        anyhow::bail!("missing recovered root")
    };
    ensure!(
        arkret_crypto::content_history::open_content(
            &restored.root_base64url,
            &material.header,
            &envelope.ciphertext
        )? == PROFILE_FIELDS
    );
    let profile_id = profile.event.event_id.to_string();
    let authorization = cut.event_id.to_string();
    let (covered,stored_digest,stored_bytes,stored_ref):(Value,String,Vec<u8>,String)=query(database,move|db|{
        let row=db.query_one("SELECT o.coverage,i.inventory_digest,i.canonical_bytes,e.inventory_blob_ref FROM content_originals o JOIN content_recovery_episodes e ON e.authorization_event_ref=$2 JOIN content_recovery_inventory_blobs i USING(authorization_event_ref) WHERE o.event_id=$1 AND o.retain_full_history AND e.state='prepared' AND i.blob_ref=e.inventory_blob_ref",&[&profile_id,&authorization])?;
        Ok((row.get(0),row.get(1),row.get(2),row.get(3)))
    }).await?;
    let coverage: ContentCoverageEntry = serde_json::from_value(covered)?;
    ensure!(
        coverage.source.event_id == profile.event.event_id
            && coverage.source.commit_id == profile.commit.commit_id
            && coverage.source.stream_ref == profile.commit.stream_ref
            && coverage.source.stream_position == profile.commit.stream_position
            && coverage.root_refs.as_slice() == std::slice::from_ref(&restored.root_ref)
            && coverage.blob_refs.is_empty()
    );
    ensure!(
        stored_bytes == body.as_ref()
            && stored_digest == digest.as_str()
            && stored_ref == reference.as_str()
    );
    Ok(
        json!({"transitions":transitions,"preparation":preparation,"inventory_digest":digest,"entry":entry,"empty_realm_entry":empty,"genesis_commit":original.commit.commit_id,"profile_event":profile.event.event_id,"profile_commit":profile.commit.commit_id,"coverage":coverage,"backup_id":packet.backup_id,"root_ref":material.root.root_ref,"range":206,"old_device_status":denied.status().as_u16()}),
    )
}

pub(super) async fn freeze_old_message(
    material: &Material,
    station: &crate::harness::ArkretServer,
) -> Result<arkret_wire::Event> {
    let owner = &material.owner;
    let realm = &material.empty_group.realm_id;
    crate::scenarios::human_device_producer_live::grant_message_create(
        &owner.client,
        station,
        realm.as_str(),
        &owner.account,
    )
    .await?;
    let strand = owner.client.default_strand_id(realm.as_str())?;
    owner.client.author_event(realm.as_str(),EventKind::MessageCreate.as_str(),json!({"strand_id":strand,"track_name":"discussion","content":arkret::ContentBlock::text("queued on the old device")})).await
}
