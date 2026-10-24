//! Additional real MLS holder for the independent Call admission matrix.
use super::*;
use crate::harness::ArkretServer;

pub(super) async fn provision_other(
    sender: &Member,
    governance: &ArkretServer,
    hosting: &ArkretServer,
    coauth: &MockCoauthIntrospectionServer,
    realm: &RealmId,
) -> Result<Member> {
    let member = Member::provision(
        hosting,
        coauth,
        "consent-other-holder",
        "ak:device:01904100-0000-7000-8000-000000002806",
    )
    .await?;
    join_through_invite(
        sender,
        governance,
        &member,
        realm.as_str(),
        "ak:request:019b0000-0000-7000-8000-000000002807",
        'd',
    )
    .await?;
    crate::scenarios::human_device_producer_live::grant_realm_actions(
        &sender.client,
        governance,
        realm.as_str(),
        &member.account,
        &[arkret_wire::CapabilityActionId::CALL_JOIN],
    )
    .await?;
    Ok(member)
}

#[expect(
    clippy::too_many_arguments,
    reason = "Actual accepted MLS and service fixture"
)]
pub(super) async fn add_other(
    sender: &Member,
    holder: &Member,
    other: &Member,
    governance: &ArkretServer,
    hosting: &ArkretServer,
    realm: &RealmId,
    database_url: &str,
    sender_group: &mut ArkretMlsGroup,
    holder_group: &mut ArkretMlsGroup,
) -> Result<(ArkretMlsGroup, EventId)> {
    ensure!(
        holder.account != other.account
            && holder.device != other.device
            && holder.key.verifying_key() != other.key.verifying_key()
    );
    let identity = publish_one(other).await?;
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let (claim, ..) = claim_for(
        sender,
        governance,
        hosting,
        other,
        realm,
        &scope.canonical_mls_group_id()?,
        0x82,
    )
    .await?;
    ensure!(claim.claims.len() == 1 && claim.claims[0].actor_id == other.actor);
    let url = database_url.to_owned();
    let realm_text = realm.to_string();
    let scope_value = serde_json::to_value(&scope)?;
    let base: arkret_wire::MlsGroupValue = tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
        let rows = db.query("SELECT value FROM mls_group_current_states WHERE realm_id=$1 AND value->'effective_scope'=$2", &[&realm_text, &scope_value])?;
        ensure!(rows.len() == 1, "actual governing MLS current must be unique");
        Ok(serde_json::from_value(rows[0].get(0))?)
    }).await??;
    ensure!(
        base.epoch == 1 && base.current_key_access_revision == base.covered_key_access_revision,
        "both holders joined before the original MLS activation"
    );
    let binding = MlsGovernanceBindingPayload::new(
        scope,
        Some(base.current_mls_commit_event_ref.clone()),
        1,
        2,
        base.current_key_access_revision,
    )?;
    let add = sender_group.add_member_with_governance_binding(
        &claimed_keypackage_record(&claim.claims[0], other)?,
        &binding,
    )?;
    let payload = MlsCommitPayload::new(
        base.current_mls_commit_event_ref.clone(),
        base.current_key_access_revision,
        &add.commit,
        binding,
    )?;
    let event = sender
        .client
        .author_event(
            realm.as_str(),
            EventKind::MlsCommit.as_str(),
            canonical(serde_json::to_value(payload)?)?,
        )
        .await?;
    let welcome = signed_welcome(sender, &event, other, &add.welcome)?;
    let submission = SelfAuthoritySubmitRequestBody::MlsCommit(MlsCommitSubmission {
        commit_event: event.clone(),
        welcomes: vec![welcome.clone()],
        idempotency_key: arkret_wire::UuidV7::new(fresh_uuid_v7().parse()?)?,
    });
    let (status, outcome) = post_json(&sender.client, &submission).await?;
    ensure!(
        status == StatusCode::OK,
        "actual second holder Add: {status} {outcome}"
    );
    let accepted = accepted_full_view(&sender.client, &event.event_id).await?;
    ensure!(sender_group.install_accepted_commit(&accepted, &base)? == 2);
    wait_for_committed(&holder.client, &event.event_id).await?;
    ensure!(accepted_full_view(&holder.client, &event.event_id).await? == accepted);
    ensure!(holder_group.install_accepted_commit(&accepted, &base)? == 2);
    wait_for_welcome(other, &welcome).await?;
    let remote = accepted_full_view(&other.client, &event.event_id).await?;
    ensure!(remote == accepted);
    let mut other_group =
        ArkretMlsGroup::join_from_verified_welcome_delivery(identity, &welcome, &remote)?;
    for group in [&mut *sender_group, &mut *holder_group, &mut other_group] {
        install_bindings(group, &[sender, holder, other]).await?;
        ensure!(group.active_author_leaves().len() == 3 && group.epoch() == 2);
    }
    Ok((other_group, event.event_id))
}
