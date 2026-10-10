//! Fresh-process readback of an already admitted native current and stream cut.

use anyhow::{Context, Result, ensure};

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let state_path = args.next().context("missing state path")?;
    let evidence_path = args.next().context("missing expected cut path")?;
    ensure!(args.next().is_none(), "unexpected readback argument");
    let evidence: serde_json::Value = serde_json::from_slice(&std::fs::read(&evidence_path)?)?;
    if evidence.is_object() {
        let account = serde_json::from_value(evidence["account"].clone())?;
        let realm = serde_json::from_value(evidence["realm"].clone())?;
        let store = inkson::LocalStateStore::with_path(std::path::PathBuf::from(state_path));
        ensure!(
            store.sync_cursor().as_deref() == evidence["cursor"].as_str(),
            "fresh process lost the ordering checkpoint"
        );
        let runtime = tokio::runtime::Runtime::new()?;
        let cut = runtime.block_on(inkson::conformance::retained_realm_current(
            &store, &account, &realm,
        ))?;
        ensure!(
            cut == evidence["cut"],
            "fresh process changed the ordered Realm current cut"
        );
        if let Some(key) = evidence["stream_key"].as_str() {
            let state = serde_json::to_value(store.load())?;
            ensure!(
                state["verified_commit_stream_cursors"][key] == evidence["head"]
                    && state["verified_commit_stream_anchors"][key] == evidence["anchor"],
                "fresh process lost the exact verified Realm stream checkpoint or signed anchor"
            );
        }
        return Ok(());
    }
    let (scope, snapshot, history, cursor): (
        arkret_wire::ScopeRef,
        arkret_wire::RealmStateSnapshot,
        Vec<arkret_wire::CommittedEventFullView>,
        String,
    ) = serde_json::from_slice(&std::fs::read(evidence_path)?)?;
    let store = inkson::LocalStateStore::with_path(std::path::PathBuf::from(state_path));
    ensure!(
        store.sync_cursor().as_deref() == Some(cursor.as_str()),
        "the fresh process lost the Account checkpoint"
    );
    ensure!(
        inkson::conformance::retained_sidecar_cut(&store, &scope)? == (snapshot, history),
        "the fresh process recovered a different private cut"
    );
    Ok(())
}
