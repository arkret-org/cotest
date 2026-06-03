use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::{
    load_fixture_value, looks_like_sha256_digest, required_field, validate_profile, value_array,
    value_field_str,
};

pub fn run_sync_fixture_suite() -> Result<()> {
    let value = load_fixture_value("sync-fixture.json")?;
    validate_profile(&value, "cx.profile.sync_vectors.v1")?;
    validate_collection_projection(&value)?;
    validate_flow_discussion_timeline(&value)?;
    validate_snapshot_frontier_recovery(&value)?;
    validate_e2ee_pending(&value)?;
    Ok(())
}

fn validate_collection_projection(value: &Value) -> Result<()> {
    let projection = required_field(value, "collection_projection")?;
    if value_field_str(projection, "projection")? != "collection"
        || value_field_str(projection, "renderer")? != "board"
    {
        bail!("sync artifact collection projection discriminator drifted");
    }
    let state_digest = projection
        .pointer("/frontier/state_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("sync artifact collection projection missing state_digest"))?;
    if !looks_like_sha256_digest(state_digest) {
        bail!("sync artifact collection projection state_digest was invalid");
    }
    let groups = value_array(
        required_field(projection, "groups")?,
        "collection_projection.groups",
    )?;
    if groups.is_empty() {
        bail!("sync artifact collection projection has no groups");
    }
    for group in groups {
        let items = value_array(required_field(group, "items")?, "group.items")?;
        for item in items {
            let object = required_field(item, "object")?;
            if !value_field_str(object, "id")?.starts_with("ck:flow:") {
                bail!("sync artifact collection item object id was not a flow");
            }
            let position = required_field(item, "position")?;
            let model = value_field_str(position, "model")?;
            if model != "relation" && model != "relation_container" {
                bail!("sync artifact collection item position model was invalid");
            }
            if !value_field_str(position, "relation_id")?.starts_with("ck:relation:") {
                bail!("sync artifact collection item relation id was invalid");
            }
        }
    }
    Ok(())
}

fn validate_flow_discussion_timeline(value: &Value) -> Result<()> {
    let timeline = required_field(value, "flow_discussion_timeline")?;
    if !value_field_str(timeline, "flow_id")?.starts_with("ck:flow:") {
        bail!("sync artifact flow discussion timeline flow id was invalid");
    }
    if !value_field_str(timeline, "next_cursor")?.starts_with("ck:cursor:") {
        bail!("sync artifact flow discussion timeline cursor was invalid");
    }
    for entry in value_array(
        required_field(timeline, "entries")?,
        "flow_discussion_timeline.entries",
    )? {
        if !value_field_str(entry, "event_id")?.starts_with("ck:event:") {
            bail!("sync artifact flow discussion timeline event id was invalid");
        }
        if !value_field_str(entry, "message_id")?.starts_with("ck:message:") {
            bail!("sync artifact flow discussion timeline message id was invalid");
        }
    }
    Ok(())
}

fn validate_snapshot_frontier_recovery(value: &Value) -> Result<()> {
    let snapshot = required_field(value, "snapshot_frontier_recovery")?;
    let state_digest = value_field_str(snapshot, "state_digest")?;
    if !looks_like_sha256_digest(state_digest) {
        bail!("sync artifact snapshot state_digest was invalid");
    }
    let root = snapshot
        .pointer("/event_set_commitment/root")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("sync artifact snapshot commitment missing digest root"))?;
    if !looks_like_sha256_digest(root) {
        bail!("sync artifact snapshot commitment root was invalid");
    }
    Ok(())
}

fn validate_e2ee_pending(value: &Value) -> Result<()> {
    let pending = required_field(value, "e2ee_decryption_pending")?;
    if pending
        .get("must_not_drop_timeline_entry")
        .and_then(Value::as_bool)
        != Some(true)
    {
        bail!("sync artifact no longer requires keeping pending E2EE entries");
    }
    Ok(())
}
