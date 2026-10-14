//! Deferred mute payloads cannot partially advance an ordinary live Call.
use serde_json::json;

use super::*;
use crate::harness::CanonicalJsonBody;

pub(super) async fn run(
    client: &TestActorClient,
    account: &arkret_wire::AccountId,
    realm: &str,
    database: &str,
) -> Result<()> {
    let create = client
        .author_event(
            realm,
            EventKind::CallCreate.as_str(),
            json!({"initial_state":"connecting"}),
        )
        .await?;
    submit_and_expect_commit(client, account, &client.device_id, &create).await?;
    let call = arkret_wire::CallId::from_event_id(&create.event_id);
    let before =
        crate::scenarios::_helpers::acceptance_footprint::acceptance_rows(database).await?;
    let base = json!({"actor_id":ActorId::account(account.clone()),"device_id":client.device_id,
        "changed_by":account.principal_id,"changed_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())});
    for (status, audio, video) in [
        ("active", Some(true), Some(false)),
        ("active", Some(false), Some(true)),
        ("cleared", None, None),
    ] {
        let mut value = base.clone();
        value["status"] = json!(status);
        if let Some(audio) = audio {
            value["audio_muted"] = json!(audio);
        }
        if let Some(video) = video {
            value["video_muted"] = json!(video);
        }
        let event = client
            .author_event(
                realm,
                EventKind::CallState.as_str(),
                json!({"call_id":call,
            "state_transition":{"from":"connecting","to":"active"},"mute_override":value}),
            )
            .await?;
        let response = client
            .post("/_arkret/self/events")
            .canonical_json(&arkret_wire::EventAdmissionSubmission::new(event))?
            .send()
            .await?;
        let status = response.status();
        let problem: arkret_wire::Problem = response.json().await?;
        ensure!(
            !status.is_success() && problem.detail.contains("mute"),
            "deferred payload reached another decision: {status} {problem:?}"
        );
        ensure!(
            crate::scenarios::_helpers::acceptance_footprint::acceptance_rows(database).await?
                == before,
            "refused mute payload changed accepting effects"
        );
    }
    println!(
        "[call-mute] actual_native_call=1 active_audio_video_and_cleared_refused=1 full_acceptance_footprint_unchanged=1 ordinary_call_genesis_retained=1"
    );
    Ok(())
}
