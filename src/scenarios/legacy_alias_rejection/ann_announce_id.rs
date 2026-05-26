//! Legacy `ann_*` directory announce id rejection.
//!
//! The canonical form is `cx:announce:<uuidv7>`. The legacy short form
//! `ann_<arbitrary>` MUST be fail-closed by the directory ingest
//! validator (teabay) and by the SDK's `AnnounceId` validator.

use anyhow::{Result, anyhow};

use contrix_core::AnnounceId;

pub async fn ann_announce_id_run() -> Result<()> {
    // Canonical form is accepted.
    let ok = AnnounceId::new("cx:announce:01999999-0000-7000-8000-00000000ann1".to_owned())
        .map_err(|e| anyhow!("canonical AnnounceId construction: {e}"))?;
    if !ok.as_str().starts_with("cx:announce:") {
        return Err(anyhow!(
            "canonical AnnounceId lost prefix: {ok}"
        ));
    }
    // Legacy form is rejected.
    for legacy in ["ann_x", "ann_alice", "ann_01999999"] {
        let bad = AnnounceId::new(legacy.to_owned());
        if bad.is_ok() {
            return Err(anyhow!(
                "AnnounceId accepted legacy short form `{legacy}` — fail-closed missing"
            ));
        }
    }
    // TODO(P4-impl): live teabay POST /api/v1/directory/announce with
    // an `ann_alice` id → expect 422 schema_violation.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn legacy_ann_form_rejected() {
        ann_announce_id_run().await.unwrap();
    }
}
