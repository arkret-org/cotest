//! Fresh native readback under the creating executable's OS custody identity.
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, ensure};

const REQUEST_ENV: &str = "COTEST_CHECKPOINT_READBACK_REQUEST";
const VERIFIED: &str = "[checkpoint-readback] durable_cut_verified=1";
static TARGET: Mutex<Option<&'static str>> = Mutex::new(None);

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    test_name: String,
    state_path: PathBuf,
    evidence_path: PathBuf,
}

pub struct CheckpointReadbackScope(&'static str);
impl Drop for CheckpointReadbackScope {
    fn drop(&mut self) {
        if let Ok(mut target) = TARGET.lock() {
            if *target == Some(self.0) {
                *target = None;
            }
        }
    }
}

/// Register the real parent test, or perform its explicitly selected child readback.
pub fn checkpoint_readback_test(
    test_name: &'static str,
) -> Result<Option<CheckpointReadbackScope>> {
    if let Some(request) = std::env::var_os(REQUEST_ENV) {
        let request = request
            .into_string()
            .map_err(|_| anyhow!("non-UTF8 readback request"))?;
        let request: Request = serde_json::from_str(&request)?;
        ensure!(
            request.test_name == test_name,
            "readback selected the wrong test entry"
        );
        ensure!(
            request.state_path.is_absolute() && request.evidence_path.is_absolute(),
            "readback paths must be absolute"
        );
        readback(&request.state_path, &request.evidence_path)?;
        println!("{VERIFIED}");
        return Ok(None);
    }
    let mut target = TARGET
        .lock()
        .map_err(|_| anyhow!("readback target lock poisoned"))?;
    ensure!(target.is_none(), "another native readback test is active");
    *target = Some(test_name);
    Ok(Some(CheckpointReadbackScope(test_name)))
}

pub(super) fn executable() -> Result<PathBuf> {
    ensure!(
        TARGET
            .lock()
            .map_err(|_| anyhow!("readback target lock poisoned"))?
            .is_some(),
        "native readback test entry is not registered"
    );
    Ok(std::env::current_exe()?)
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

pub(super) fn output(reader: &Path, state_path: &Path, evidence_path: &Path) -> Result<Output> {
    ensure!(
        std::fs::canonicalize(reader)? == std::fs::canonicalize(std::env::current_exe()?)?,
        "readback requires the creating executable's custody identity"
    );
    let test_name = TARGET
        .lock()
        .map_err(|_| anyhow!("readback target lock poisoned"))?
        .context("native readback test entry is not registered")?;
    let request = Request {
        test_name: test_name.to_owned(),
        state_path: state_path.to_owned(),
        evidence_path: evidence_path.to_owned(),
    };
    let mut child = OwnedChild(
        Command::new(reader)
            .args([
                "--exact",
                test_name,
                "--nocapture",
                "--test-threads=1",
                "--color=never",
            ])
            .env(REQUEST_ENV, serde_json::to_string(&request)?)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let mut stdout = child.0.stdout.take().context("missing readback stdout")?;
    let mut stderr = child.0.stderr.take().context("missing readback stderr")?;
    let stdout = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut data = Vec::new();
        stdout.read_to_end(&mut data)?;
        Ok(data)
    });
    let stderr = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut data = Vec::new();
        stderr.read_to_end(&mut data)?;
        Ok(data)
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        ensure!(
            Instant::now() < deadline,
            "native checkpoint readback exceeded its 60 second deadline"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = Output {
        status,
        stdout: stdout
            .join()
            .map_err(|_| anyhow!("readback stdout reader panicked"))??,
        stderr: stderr
            .join()
            .map_err(|_| anyhow!("readback stderr reader panicked"))??,
    };
    if output.status.success() {
        verified_execution(std::str::from_utf8(&output.stdout)?)?;
        eprintln!("[checkpoint-readback] verified_child_completed=1");
    }
    Ok(output)
}

fn readback(state_path: &Path, evidence_path: &Path) -> Result<()> {
    let evidence: serde_json::Value = serde_json::from_slice(&std::fs::read(&evidence_path)?)?;
    if evidence.is_object() {
        let account = serde_json::from_value(evidence["account"].clone())?;
        let realm = serde_json::from_value(evidence["realm"].clone())?;
        let mut store = inkson::LocalStateStore::with_path(std::path::PathBuf::from(state_path));
        if evidence.get("sidecar_exchange_projections").is_some() {
            inkson::conformance::hydrate_native_private_cache(&mut store)?;
        }
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
        if evidence.get("stream_heads").is_some() {
            let state = serde_json::to_value(store.load())?;
            ensure!(
                state["verified_commit_stream_cursors"] == evidence["stream_heads"]
                    && state["verified_commit_stream_anchors"] == evidence["stream_anchors"],
                "fresh process changed the independent stream checkpoints or original anchors"
            );
        }
        if let Some(private) = evidence
            .get("private_state")
            .filter(|value| !value.is_null())
        {
            let state = serde_json::to_value(store.load())?;
            for (key, expected) in private
                .as_object()
                .context("private readback is not an object")?
            {
                ensure!(
                    state[key] == *expected,
                    "fresh process changed private state {key}"
                );
            }
        }
        if let Some(scope) = evidence
            .get("private_sidecar_scope")
            .filter(|value| !value.is_null())
        {
            let scope: arkret_wire::ScopeRef = serde_json::from_value(scope.clone())?;
            ensure!(
                serde_json::to_value(inkson::conformance::retained_sidecar_cut(&store, &scope)?)?
                    == evidence["private_sidecar_cut"],
                "fresh process changed the original private signed Sidecar cut"
            );
        }
        if let Some(projections) = evidence.get("sidecar_exchange_projections") {
            ensure!(
                serde_json::to_value(inkson::sidecar::cached_sidecar_exchange_projections(
                    &store,
                    &account,
                    realm.as_str()
                )?)? == *projections,
                "fresh process changed the authenticated private discussion projection"
            );
            let scope = serde_json::from_value(evidence["private_sidecar_scope"].clone())?;
            let event = serde_json::from_value(evidence["response_event_id"].clone())?;
            let plaintext = inkson::conformance::private_sidecar_response_plaintext(
                &store, &account, &scope, &event,
            )?;
            ensure!(
                arkret_canonical::canonical_sha256(&serde_json::from_slice::<serde_json::Value>(
                    &plaintext
                )?)? == evidence["response_plaintext_digest"]
                    .as_str()
                    .context("response digest")?,
                "fresh process lost the actual private Agent response plaintext"
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

fn verified_execution(stdout: &str) -> Result<()> {
    ensure!(
        stdout.matches(VERIFIED).count() == 1
            && stdout
                .lines()
                .any(|line| line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;")),
        "readback returned success without exactly one verified child execution"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_zero_case_child_has_no_readback_credit() {
        assert!(verified_execution("test result: ok. 0 passed; 0 failed; 0 ignored;").is_err());
    }
    #[test]
    fn an_unverified_or_duplicate_receipt_has_no_readback_credit() {
        let footer = "test result: ok. 1 passed; 0 failed; 0 ignored;";
        assert!(verified_execution(footer).is_err());
        assert!(verified_execution(&format!("{VERIFIED}\n{VERIFIED}\n{footer}")).is_err());
    }
    #[test]
    fn one_verified_executed_child_has_readback_credit() {
        verified_execution(&format!("test parent_entry ... {VERIFIED}\nok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 2 filtered out;")).unwrap();
    }
}
