//! Actual revoke accepted after token preparation and before its final cut.

use super::*;

pub(super) async fn run(
    sender: &Member,
    holder: &Member,
    producer: &inkson::sync_engine::NativeAccountHost,
    realm: &arkret_wire::RealmId,
    material: &inkson::signal::SignalKeyMaterial,
    original: &inkson::signal::SignalPayload,
    signal_probe: &std::path::Path,
) -> Result<()> {
    let grant = grant(holder, &sender.actor, ConsentScope::VideoCall).await?;
    let path = signal_probe.with_file_name("media-token-release.pause");
    for (sequence, deny) in [(401, false), (402, true)] {
        let mut payload = original.clone();
        let inkson::signal::SignalPayload::CallSignal { seq, call_id, .. } = &mut payload else {
            anyhow::bail!("real Invite payload")
        };
        *seq = sequence;
        let call = call_id.clone();
        let prepared = producer
            .prepare_call_invitation(
                holder.account.clone(),
                ScopeRef::Realm {
                    realm_id: realm.clone(),
                },
                material,
                &payload,
            )
            .await?;
        let expiry = prepared.invitation.expires_at;
        let request =
            arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody {
                realm_id: realm.clone(),
                call_id: call,
                actor_id: holder.actor.clone(),
                device_id: holder.device.clone(),
                focus_id: "consent-native".into(),
                capability_refs: None,
                desired_media: Some(
                    arkret_models_collaboration::objects::media::CallMediaDesiredMedia {
                        audio: Some(true),
                        video: Some(true),
                        screen: Some(false),
                    },
                ),
                join_context: CallJoinContext::Invitation(CallInvitationJoinRequestBody {
                    kind: CallInvitationJoinKind::Invitation,
                    invitation: prepared.invitation,
                    envelope: prepared.envelope,
                }),
            };
        let reached = path.with_extension("reached");
        if reached.exists() {
            std::fs::remove_file(&reached)?;
        }
        let digest: arkret_wire::Hash = arkret_canonical::canonical_sha256(&request)?.parse()?;
        std::fs::write(&path, serde_json::to_vec(&digest)?)?;
        let token = cotest::harness::expect_json(
            holder.client.post("/_arkret/self/rtc/token").json(&request),
            if deny {
                reqwest::StatusCode::FORBIDDEN
            } else {
                reqwest::StatusCode::OK
            },
        );
        let race = async {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while !reached.exists() {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await
            .context("real token preparation did not reach its final cut")?;
            if deny {
                revoke(holder, &grant).await?;
            }
            ensure!(
                chrono::Utc::now() + chrono::Duration::seconds(3) < expiry,
                "race must precede original Invitation expiry"
            );
            std::fs::remove_file(&path)?;
            Ok::<(), anyhow::Error>(())
        };
        let (response, raced) = tokio::join!(token, race);
        raced?;
        let response = response?;
        if deny {
            ensure!(
                response["type"] == "https://arkret.org/problems/capability_denied",
                "token race hit another rejection"
            );
        } else {
            let outcome: arkret_models_collaboration::objects::media::CallMediaTokenExchangeOutcome = serde_json::from_value(response)?;
            outcome
                .subject_binding
                .validate_outcome(&request, &outcome)?;
        }
        std::fs::remove_file(reached)?;
    }
    eprintln!(
        "[consent-call] token_final_cut_positive=1 prepared_before_revoke_release_denied=1 original_invitation_live=1"
    );
    Ok(())
}
