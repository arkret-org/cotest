//! Fresh-process readback of an already admitted native private cut.

use anyhow::{Context, Result, ensure};

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let state_path = args.next().context("missing state path")?;
    let evidence_path = args.next().context("missing expected cut path")?;
    ensure!(args.next().is_none(), "unexpected readback argument");
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
