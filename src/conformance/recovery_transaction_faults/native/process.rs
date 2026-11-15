use std::io::Read as _;
use std::net::{Shutdown, TcpListener};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use serde_json::{Value, json};

pub(super) fn process_evidence(mut identity: Value) -> Result<Value> {
    let pid = identity["pid"]
        .as_u64()
        .context("owned process PID absent")?;
    #[cfg(windows)]
    {
        let output = Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", &format!("Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}' | Select-Object ProcessId,CreationDate,CommandLine | ConvertTo-Json -Compress")]).output()?;
        ensure!(
            output.status.success(),
            "cannot capture owned process birth and command line"
        );
        let observed: Value = serde_json::from_slice(&output.stdout)?;
        ensure!(
            observed["ProcessId"].as_u64() == Some(pid)
                && !observed["CreationDate"].is_null()
                && observed["CommandLine"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty()),
            "owned PID observation is incomplete"
        );
        identity["os_process"] = observed;
    }
    #[cfg(not(windows))]
    {
        let output = Command::new("ps")
            .args([
                "-p",
                &pid.to_string(),
                "-o",
                "pid=",
                "-o",
                "lstart=",
                "-o",
                "args=",
            ])
            .output()?;
        ensure!(
            output.status.success(),
            "cannot capture owned process birth and command line"
        );
        let observed = String::from_utf8(output.stdout)?;
        ensure!(
            observed.trim_start().starts_with(&pid.to_string()),
            "owned PID disappeared during OS observation"
        );
        identity["os_process"] = json!({"pid_start_time_command":observed});
    }
    identity["observed_at"] = json!(chrono::Utc::now());
    Ok(identity)
}

/// Real TCP downstream whose response bytes are held by the test relay. The
/// upstream is the original TLS Station URL and exact authorized request. This
/// is a transport response-loss boundary, not a claimed server instruction hook.
pub(super) struct HeldResponse {
    release: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<Result<()>>>,
    downstream: Option<tokio::task::JoinHandle<Result<reqwest::Response, reqwest::Error>>>,
}
impl HeldResponse {
    pub(super) async fn forward(
        http: &reqwest::Client,
        request: reqwest::Request,
    ) -> Result<(Self, reqwest::StatusCode, Vec<u8>)> {
        let expected = request
            .body()
            .and_then(reqwest::Body::as_bytes)
            .context("exact canonical request bytes absent")?
            .to_vec();
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let (release, commands) = mpsc::channel();
        let (ready, readiness) = tokio::sync::oneshot::channel();
        let relay_expected = expected.clone();
        let worker = thread::spawn(move || -> Result<()> {
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        ensure!(
                            std::time::Instant::now() < deadline,
                            "downstream did not connect to response relay"
                        );
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            socket.set_nonblocking(false)?;
            socket.set_read_timeout(Some(Duration::from_secs(10)))?;
            let mut incoming = Vec::new();
            let body_at = loop {
                let mut chunk = [0u8; 4096];
                let read = socket.read(&mut chunk)?;
                ensure!(read > 0, "downstream closed before frozen request");
                incoming.extend_from_slice(&chunk[..read]);
                ensure!(
                    incoming.len() <= relay_expected.len() + 65536,
                    "unexpected relay request size"
                );
                if let Some(index) = incoming.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let headers = std::str::from_utf8(&incoming[..body_at])?;
            let content_length = headers.lines().find_map(|line| {
                line.split_once(':')
                    .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            });
            ensure!(
                content_length == Some(relay_expected.len()),
                "downstream request length changed"
            );
            while incoming.len() - body_at < relay_expected.len() {
                let mut chunk = [0u8; 4096];
                let read = socket.read(&mut chunk)?;
                ensure!(read > 0, "downstream closed before full request");
                incoming.extend_from_slice(&chunk[..read]);
            }
            ensure!(
                incoming[body_at..] == relay_expected,
                "relay did not receive exact frozen R"
            );
            ready
                .send(())
                .map_err(|_| anyhow::anyhow!("relay caller disappeared"))?;
            // Intentionally write zero response bytes until the owner has killed
            // the actual Station. A dropped sender also closes this socket.
            let _ = commands.recv();
            socket.shutdown(Shutdown::Both)?;
            Ok(())
        });
        let downstream = tokio::spawn(async move {
            reqwest::Client::builder()
                .no_proxy()
                .build()
                .expect("local relay HTTP client")
                .post(format!("http://{address}/held-recovery-response"))
                .timeout(Duration::from_secs(60))
                .body(expected)
                .send()
                .await
        });
        let relay = Self {
            release,
            worker: Some(worker),
            downstream: Some(downstream),
        };
        tokio::time::timeout(Duration::from_secs(30), readiness).await??;
        let response = http.execute(request).await?;
        let status = response.status();
        let body = response.bytes().await?.to_vec();
        Ok((relay, status, body))
    }
    pub(super) async fn lose_after_kill(mut self) -> Result<Value> {
        self.release.send(())?;
        self.worker
            .take()
            .context("response relay worker absent")?
            .join()
            .map_err(|_| anyhow::anyhow!("response relay panicked"))??;
        let response = self
            .downstream
            .take()
            .context("response relay client absent")?
            .await?;
        ensure!(
            response.is_err(),
            "withheld downstream unexpectedly received a response"
        );
        Ok(
            json!({"upstream":"real TLS Station POST accepted", "downstream":"real TCP response withheld; zero response bytes; disconnected after owned-process kill", "network_error":response.err().map(|e|e.to_string())}),
        )
    }
}
impl Drop for HeldResponse {
    fn drop(&mut self) {
        let _ = self.release.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        if let Some(task) = self.downstream.take() {
            task.abort();
        }
    }
}
