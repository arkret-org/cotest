//! Read actual scoped originals; this module never inserts a fixture row.
use arkret_wire::{BlobRef, DidCoreId, RealmId};

use super::*;

pub(super) async fn snapshot(database: &str, realm: &RealmId, refs: &[BlobRef]) -> Result<Value> {
    let database = database.to_owned();
    let realm = realm.to_string();
    let refs = refs.iter().map(ToString::to_string).collect::<Vec<_>>();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database,postgres::NoTls)?;
        let row = db.query_one("SELECT jsonb_build_object('blobs',(SELECT COALESCE(jsonb_agg(to_jsonb(b) ORDER BY b.id),'[]'::jsonb) FROM blobs b WHERE b.id=ANY($2)), 'committed',(SELECT COALESCE(jsonb_agg(jsonb_build_object('event',e.envelope,'commit',c.commit_json) ORDER BY c.stream_ref::text,c.stream_position),'[]'::jsonb) FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.realm_id=$1 AND e.state='committed'), 'binding',(SELECT COALESCE(jsonb_agg(to_jsonb(b) ORDER BY b.mimi_room_uri),'[]'::jsonb) FROM mimi_room_binding_current_states b WHERE b.realm_id=$1), 'policy',(SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY p.state_family),'[]'::jsonb) FROM realm_bootstrap_current_states p WHERE p.realm_id=$1 AND p.state_family='realm_asset_privacy_policy'), 'download_audits',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',a.id,'action',a.action,'actor_id',a.actor_id,'outcome',a.outcome) ORDER BY a.created_at,a.id),'[]'::jsonb) FROM audit_logs a WHERE a.action='mimi.public_asset_download' AND a.actor_id=current_device_inventory_station()))",&[&realm,&refs])?;
        Ok(row.get(0))
    }).await?
}

pub(super) fn verify_issuance(before: &Value, after: &Value, station: &DidCoreId) -> Result<()> {
    for field in ["blobs", "committed", "binding", "policy"] {
        ensure!(
            before[field] == after[field],
            "download issuance rewrote its {field} authority originals"
        );
    }
    let old = before["download_audits"]
        .as_array()
        .context("original asset audits")?;
    let new = after["download_audits"]
        .as_array()
        .context("accepted asset audits")?;
    ensure!(
        new.len() == old.len() + 1 && new.starts_with(old),
        "native download lacks exactly one new real outer diagnostic"
    );
    let diagnostic = new.last().context("actual outer diagnostic row")?;
    ensure!(
        diagnostic["action"] == "mimi.public_asset_download"
            && diagnostic["actor_id"] == json!(station)
            && diagnostic["outcome"] == "accepted"
            && diagnostic["id"].as_str().is_some_and(|id| !id.is_empty())
            && diagnostic.as_object().is_some_and(|row| row.len() == 4),
        "download diagnostic lost its real outer identity or revived private body"
    );
    Ok(())
}
