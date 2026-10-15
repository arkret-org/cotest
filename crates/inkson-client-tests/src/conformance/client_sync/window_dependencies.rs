//! Real Station window dependencies and the native Account durability barrier.

use super::*;

struct DependencyReadFaultRail {
    http: arkret_http_client::Client,
    stream: arkret_wire::CommitStreamRef,
    control: cotest::harness::ScanGapControl,
    withheld: bool,
    injected: Mutex<Option<(arkret_wire::CommittedEventRef, usize)>>,
}

fn dependency_path(reference: &arkret_wire::CommittedEventRef) -> String {
    format!("/_arkret/self/committed-events/{}", reference.event_id)
}

impl AccountSubscribeTransport for DependencyReadFaultRail {
    async fn subscribe(
        &self,
        request: &SyncRequestBody,
    ) -> garth::Result<AccountSubscribeSnapshotResult> {
        let batch = self.http.account_subscribe_batch(request).await?;
        let dependency = batch
            .frames
            .iter()
            .flat_map(|frame| frame.realms.iter())
            .flat_map(|realms| realms.entries.values())
            .find_map(|entry| {
                let window = entry
                    .streams
                    .iter()
                    .flatten()
                    .find(|window| window.stream_ref == self.stream)?;
                let nonempty = entry
                    .committed_events
                    .iter()
                    .flatten()
                    .any(|row| row.commit().stream_ref == self.stream);
                nonempty
                    .then_some(window.window_start_basis.as_ref()?)?
                    .accepted_dependency_refs
                    .as_ref()?
                    .first()
                    .cloned()
            })
            .ok_or_else(|| {
                garth::Error::Protocol(
                    "Station did not issue nonempty dependencies with a real tail".into(),
                )
            })?;
        let mut injected = self.injected.lock().unwrap();
        if injected.is_some() {
            return Err(garth::Error::Protocol(
                "dependency refusal unexpectedly retried the Account frame".into(),
            ));
        }
        // Fault only the exact GET. Parent scans and the Station-issued frame
        // stay byte-exact, so an earlier changed parent row cannot mask the gate.
        let previous = if self.withheld {
            let previous = self.control.withheld_event_get_count(&dependency.event_id);
            self.control
                .set_event_get_withheld(&dependency.event_id, true);
            previous
        } else {
            let path = dependency_path(&dependency);
            let previous = self.control.unavailable_request_count(&path);
            self.control.set_path_unavailable(&path, true);
            previous
        };
        *injected = Some((dependency, previous));
        Ok(AccountSubscribeSnapshotResult::Batch(batch))
    }
}

pub(super) async fn assert_dependency_reads_keep_checkpoint(
    host: &NativeAccountHost,
    http: arkret_http_client::Client,
    stream: &arkret_wire::CommitStreamRef,
    control: cotest::harness::ScanGapControl,
) -> Result<()> {
    let before = state(host)?;
    let committed =
        serde_json::to_value(host.state_store().conformance_committed_account_state()?)?;
    let token = host.state_store().conformance_account_checkpoint_token()?;
    for withheld in [true, false] {
        let rail = DependencyReadFaultRail {
            http: http.clone(),
            stream: stream.clone(),
            control: control.clone(),
            withheld,
            injected: Default::default(),
        };
        let refused = host.catch_up_with_conformance_transport(&rail).await;
        let (injected, previous) = rail
            .injected
            .lock()
            .unwrap()
            .take()
            .context("missing real Station dependency injection")?;
        let path = dependency_path(&injected);
        control.set_event_get_withheld(&injected.event_id, false);
        control.set_path_unavailable(&path, false);
        let reads = if withheld {
            control.withheld_event_get_count(&injected.event_id)
        } else {
            control.unavailable_request_count(&path)
        };
        ensure!(
            reads > previous,
            "the actual dependency GET never reached its fault boundary"
        );
        ensure!(
            refused.is_err(),
            "an unreadable dependency advanced the Account frame"
        );
        if withheld {
            ensure!(
                matches!(&refused,Err(garth::Error::Protocol(message))
                if message == "ordinary exact Event differs from requested original"),
                "withheld dependency did not fail at its actual original read: {refused:?}"
            );
        }
        ensure!(
            host.state_store().conformance_account_checkpoint_token()? == token
                && serde_json::to_value(host.state_store().conformance_committed_account_state()?)?
                    == committed
                && state(host)? == before,
            "unreadable dependency changed the account root, installed cut or Account cursor"
        );
    }
    Ok(())
}

pub(super) fn assert_issued_dependencies(
    batches: &[AccountSubscribeBatch],
    stream: &arkret_wire::CommitStreamRef,
) -> Result<()> {
    let windows = batches
        .iter()
        .flat_map(|batch| &batch.frames)
        .flat_map(|frame| frame.realms.iter())
        .flat_map(|realms| realms.entries.values())
        .flat_map(|entry| entry.streams.iter().flatten())
        .filter(|window| &window.stream_ref == stream && window.window_start_basis.is_some())
        .collect::<Vec<_>>();
    ensure!(
        !windows.is_empty()
            && windows.iter().all(|window| window
                .window_start_basis
                .as_ref()
                .and_then(|basis| basis.accepted_dependency_refs.as_ref())
                .is_some_and(|refs| !refs.is_empty()
                    && refs.iter().all(|reference| &reference.stream_ref != stream
                        && reference.stream_ref.realm_id() == stream.realm_id()))),
        "actual Station did not issue exact cross-stream authorization dependencies"
    );
    Ok(())
}

pub(super) fn assert_only_tail_and_dependency_scans(
    scans: &[arkret_wire::StreamScanRequest],
    stream: &arkret_wire::CommitStreamRef,
    dependencies: &[arkret_wire::CommittedEventRef],
) -> Result<()> {
    ensure!(
        scans.iter().any(|scan| &scan.stream_ref == stream)
            && scans.iter().all(|scan| &scan.stream_ref == stream
                || dependencies
                    .iter()
                    .any(|reference| is_exact_dependency_scan(scan, reference)))
            && dependencies.iter().all(|reference| scans
                .iter()
                .any(|scan| is_exact_dependency_scan(scan, reference))),
        "stream recovery read beyond its tail and exact issued dependencies: {scans:?}"
    );
    Ok(())
}

pub(super) fn is_exact_dependency_scan(
    scan: &arkret_wire::StreamScanRequest,
    reference: &arkret_wire::CommittedEventRef,
) -> bool {
    scan.realm_id == *reference.stream_ref.realm_id()
        && scan.stream_ref == reference.stream_ref
        && scan.limit == 1
        && reference
            .stream_position
            .checked_add(1)
            .is_some_and(|before| {
                scan.direction == arkret_wire::StreamScanDirection::Before(Some(before))
            })
}
