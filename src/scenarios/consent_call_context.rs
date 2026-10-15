//! Actual accepted-device, membership and MLS source for Consent call acceptance.
use anyhow::{Context, Result, ensure};
use arkret::{ArkretMlsGroup, MlsGovernanceBindingPayload};
use arkret_wire::{
    AuthoritySubmitOutcome, EventId, EventKind, MlsCommitSubmission, RealmId, ScopeRef,
};

use super::_helpers::bridge::MockCoauthIntrospectionServer;
use super::_helpers::coauth_bootstrap::EphemeralPg;
use super::cross_station_mls_welcome::{
    claim_for, genesis_creator_leaf_authority, join_through_invite, publish_one, wait_for_welcome,
};
use super::human_device_producer_live::{
    create_realm_with_join_rule, database, grant_realm_actions, station_env,
    submit_and_expect_commit,
};
use super::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
use super::mls_lifecycle_live::{
    ACTIVE_SUITE, Member, accepted_full_view, canonical, claimed_keypackage_record, fresh_uuid_v7,
    post_json, signed_welcome, upload_public_blob,
};
use crate::harness::TestServerGroup;

pub struct ConsentCallContext {
    pub stations: TestServerGroup,
    pub issuer: MockCoauthIntrospectionServer,
    pub databases: Vec<EphemeralPg>,
    pub caller: Member,
    pub holder: Member,
    pub denied_holder: Member,
    pub realm: RealmId,
    pub accepted_group: EventId,
    pub caller_group: ArkretMlsGroup,
    pub holder_group: ArkretMlsGroup,
    pub denied_group: ArkretMlsGroup,
}

impl ConsentCallContext {
    pub async fn create(namespace: &str, holder_env: &[(String, String)]) -> Result<Self> {
        Self::create_with_node_envs(namespace, &[Vec::new(), holder_env.to_vec(), Vec::new()]).await
    }

    pub async fn create_with_node_envs(
        namespace: &str,
        node_envs: &[Vec<(String, String)>; 3],
    ) -> Result<Self> {
        let mut databases = Vec::new();
        for _ in 0..3 {
            databases
                .push(database(namespace)?.context("Consent suite requires actual PostgreSQL")?);
        }
        let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
            HARNESS_INTERNAL_AUTHORITY_SECRET,
        )
        .await?;
        let mut environments: Vec<_> = databases
            .iter()
            .map(|db| station_env(&db.connect_url, &issuer))
            .collect();
        for (environment, extra) in environments.iter_mut().zip(node_envs) {
            environment.extend_from_slice(extra);
        }
        let stations = crate::harness::heap_future(|| {
            TestServerGroup::try_multi_external_with_node_envs(namespace, &environments)
        })
        .await?
        .context("Consent suite requires the frozen production Coland binary")?;
        eprintln!("[2141-live] actual three Station processes ready");
        let a = stations.server(0);
        let b = stations.server(1);
        let caller = Member::provision(
            a,
            &issuer,
            "consent-call-caller",
            "ak:device:01904100-0000-7000-8000-000000002d01",
        )
        .await?;
        let holder = Member::provision(
            b,
            &issuer,
            "consent-call-holder",
            "ak:device:01904100-0000-7000-8000-000000002d02",
        )
        .await?;
        let denied_holder = Member::provision(
            b,
            &issuer,
            "consent-call-denied",
            "ak:device:01904100-0000-7000-8000-000000002d03",
        )
        .await?;
        let realm = RealmId::new(
            create_realm_with_join_rule(&caller.client, "Consent call current", "invite", &[a, b])
                .await?,
        )?;
        for (member, request, seed) in [
            (
                &holder,
                "ak:request:019b0000-0000-7000-8000-000000002d04",
                'e',
            ),
            (
                &denied_holder,
                "ak:request:019b0000-0000-7000-8000-000000002d05",
                'f',
            ),
        ] {
            join_through_invite(&caller, a, member, realm.as_str(), request, seed).await?;
            grant_realm_actions(
                &caller.client,
                a,
                realm.as_str(),
                &member.account,
                &[arkret_wire::CapabilityActionId::CALL_JOIN],
            )
            .await?;
        }
        grant_realm_actions(
            &caller.client,
            a,
            realm.as_str(),
            &caller.account,
            &[
                arkret_wire::CapabilityActionId::CALL_JOIN,
                arkret_wire::CapabilityActionId::CALL_SIGNAL_SEND,
            ],
        )
        .await?;
        let scope = ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        let mut caller_group = caller
            .mls_identity()?
            .create_group_with_governance_binding(
                &scope,
                &MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?,
            )?;
        let creator_leaf_authority = genesis_creator_leaf_authority(&mut caller_group, &caller)?;
        let (info, tree) = caller_group.public_group_state_bytes()?;
        let tree_ref =
            arkret_wire::BlobRef::new(upload_public_blob(&caller.client, &realm, &tree).await?)?;
        let genesis = caller
            .client
            .author_event(
                realm.as_str(),
                EventKind::MlsGenesis.as_str(),
                canonical(serde_json::to_value(arkret::MlsGenesisPayload {
                    cipher_suite: arkret::NonEmptyString::new(ACTIVE_SUITE.to_owned())
                        .map_err(anyhow::Error::msg)?,
                    group_info_ref: arkret_wire::BlobRef::new(
                        upload_public_blob(&caller.client, &realm, &info).await?,
                    )?,
                    ratchet_tree_ref: tree_ref.clone(),
                    creator_leaf_authority,
                    governance_binding: MlsGovernanceBindingPayload::new(
                        scope.clone(),
                        None,
                        0,
                        0,
                        0,
                    )?,
                    created_at: chrono::Utc::now(),
                })?)?,
            )
            .await?;
        submit_and_expect_commit(
            &caller.client,
            &caller.account,
            caller.device.as_str(),
            &genesis,
        )
        .await?;
        let mut base = arkret_wire::MlsGroupCurrent {
            effective_scope: scope.clone(),
            genesis_event_ref: genesis.event_id.clone(),
            cipher_suite: arkret_wire::NonEmptyString::new(ACTIVE_SUITE)
                .map_err(anyhow::Error::msg)?,
            current_mls_commit_event_ref: genesis.event_id.clone(),
            epoch: 0,
            current_key_access_revision: 0,
            covered_key_access_revision: 0,
            public_tree_ref: tree_ref,
        };
        let mut joined = Vec::new();
        for (index, member) in [&holder, &denied_holder].into_iter().enumerate() {
            let identity = publish_one(member).await?;
            let (claim, ..) = claim_for(
                &caller,
                a,
                b,
                member,
                &realm,
                &scope.canonical_mls_group_id()?,
                0x91 + index as u8,
            )
            .await?;
            ensure!(claim.claims.len() == 1 && claim.claims[0].actor_id == member.actor);
            let binding = MlsGovernanceBindingPayload::new(
                scope.clone(),
                Some(base.current_mls_commit_event_ref.clone()),
                base.epoch,
                base.epoch + 1,
                0,
            )?;
            let add = caller_group.add_member_with_governance_binding(
                &claimed_keypackage_record(&claim.claims[0], member)?,
                &binding,
            )?;
            let event = caller
                .client
                .author_event(
                    realm.as_str(),
                    EventKind::MlsCommit.as_str(),
                    canonical(serde_json::to_value(arkret::MlsCommitPayload::new(
                        base.current_mls_commit_event_ref.clone(),
                        base.current_key_access_revision,
                        &add.commit,
                        binding,
                    )?)?)?,
                )
                .await?;
            let welcome = signed_welcome(&caller, &event, member, &add.welcome)?;
            let request=arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::MlsCommit(MlsCommitSubmission {commit_event:event.clone(),welcomes:vec![welcome.clone()],idempotency_key:arkret_wire::UuidV7::new(fresh_uuid_v7().parse()?)?});
            let (status, outcome) = post_json(&caller.client, &request).await?;
            ensure!(
                status == reqwest::StatusCode::OK,
                "actual MLS add {index} failed: {status} {outcome}"
            );
            ensure!(matches!(
                serde_json::from_value::<AuthoritySubmitOutcome>(outcome)?,
                AuthoritySubmitOutcome::Accepted { .. }
            ));
            let accepted = accepted_full_view(&caller.client, &event.event_id).await?;
            caller_group.install_accepted_commit(&accepted, &base)?;
            for group in &mut joined {
                ArkretMlsGroup::install_accepted_commit(group, &accepted, &base)?;
            }
            wait_for_welcome(member, &welcome).await?;
            let remote = accepted_full_view(&member.client, &event.event_id).await?;
            ensure!(
                accepted == remote,
                "member Station changed the accepting Commit"
            );
            joined.push(ArkretMlsGroup::join_from_verified_welcome_delivery(
                identity, &welcome, &remote,
            )?);
            base.current_mls_commit_event_ref = event.event_id;
            base.epoch += 1;
        }
        let mut holder_group = joined.remove(0);
        let mut denied_group = joined.remove(0);
        for group in [&mut caller_group, &mut holder_group, &mut denied_group] {
            super::message_mls_cross_station_live::install_bindings(
                group,
                &[&caller, &holder, &denied_holder],
            )
            .await?;
        }
        Ok(Self {
            stations,
            issuer,
            databases,
            caller,
            holder,
            denied_holder,
            realm,
            accepted_group: base.current_mls_commit_event_ref,
            caller_group,
            holder_group,
            denied_group,
        })
    }
}
