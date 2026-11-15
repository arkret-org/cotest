//! Owned native client processes at a real durable Account page boundary.
use std::io::{BufRead as _, Write as _};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, ensure};
use serde_json::{Value, json};

use super::{CHILD_ENV, Launch, MARKER};

pub(super) struct OwnedClient {
    child: Child,
    input: ChildStdin,
    events: tokio::sync::mpsc::UnboundedReceiver<std::result::Result<Value, String>>,
    stdout: Option<std::thread::JoinHandle<()>>,
    stderr: Option<std::thread::JoinHandle<Vec<u8>>>,
}

impl Drop for OwnedClient {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.stdout.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.stderr.take() {
            let _ = reader.join();
        }
    }
}

impl OwnedClient {
    pub(super) fn spawn(test_name: &str, launch: Launch) -> Result<Self> {
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&launch)?);
        let executable = std::fs::canonicalize(std::env::current_exe()?)?;
        let mut child = Command::new(&executable)
            .args([
                "--exact",
                test_name,
                "--nocapture",
                "--test-threads=1",
                "--color=never",
            ])
            .env(CHILD_ENV, test_name)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let (Some(input), Some(stdout), Some(mut stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("owned native client did not retain all three process pipes");
        };
        let (send, events) = tokio::sync::mpsc::unbounded_channel();
        let stdout = std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let line = match line {
                    Ok(line) => line,
                    Err(error) => {
                        let _ = send.send(Err(error.to_string()));
                        return;
                    }
                };
                if let Some((_, value)) = line.split_once(MARKER) {
                    let event = serde_json::from_str(value).map_err(|error| error.to_string());
                    if send.send(event).is_err() {
                        return;
                    }
                }
            }
        });
        let stderr = std::thread::spawn(move || {
            use std::io::Read as _;
            let mut bytes = Vec::new();
            let _ = stderr.read_to_end(&mut bytes);
            bytes
        });
        let mut owned = Self {
            child,
            input,
            events,
            stdout: Some(stdout),
            stderr: Some(stderr),
        };
        owned.input.write_all(&bytes)?;
        owned.input.write_all(b"\n")?;
        owned.input.flush()?;
        Ok(owned)
    }

    pub(super) async fn event(&mut self) -> Result<Value> {
        let event = match tokio::time::timeout(Duration::from_secs(90), self.events.recv()).await {
            Ok(Some(event)) => event.map_err(anyhow::Error::msg)?,
            outcome => {
                if !matches!(self.child.try_wait(), Ok(Some(_))) {
                    let _ = self.child.kill();
                }
                let status = self.child.wait()?;
                let stderr = self
                    .stderr
                    .take()
                    .context("native stderr already consumed")?
                    .join()
                    .map_err(|_| anyhow::anyhow!("native stderr reader panicked"))?;
                anyhow::bail!(
                    "owned native client missed its required boundary ({outcome:?}; {status}): {}",
                    String::from_utf8_lossy(&stderr)
                );
            }
        };
        ensure!(
            event["pid"].as_u64() == Some(u64::from(self.child.id())),
            "boundary came from another process"
        );
        Ok(event)
    }

    pub(super) fn command(&mut self, command: &Value) -> Result<()> {
        serde_json::to_writer(&mut self.input, command)?;
        self.input.write_all(b"\n")?;
        self.input.flush()?;
        Ok(())
    }

    pub(super) fn identity(&mut self) -> Result<Value> {
        ensure!(
            self.child.try_wait()?.is_none(),
            "native client exited before its kill boundary"
        );
        let pid = self.child.id();
        let executable = std::fs::canonicalize(std::env::current_exe()?)?;
        let digest = arkret_canonical::sha256_hex(std::fs::read(&executable)?);
        #[cfg(windows)]
        let identity = {
            let output = Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", &format!("Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}' | Select-Object ProcessId,CreationDate,CommandLine | ConvertTo-Json -Compress")]).output()?;
            ensure!(
                output.status.success(),
                "owned native client OS observation failed"
            );
            let identity: Value = serde_json::from_slice(&output.stdout)?;
            ensure!(
                identity["ProcessId"].as_u64() == Some(u64::from(pid))
                    && !identity["CreationDate"].is_null()
                    && identity["CommandLine"]
                        .as_str()
                        .is_some_and(|value| !value.is_empty()),
                "owned native client OS identity is incomplete"
            );
            identity
        };
        #[cfg(not(windows))]
        let identity = {
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
                "owned native client OS observation failed"
            );
            let identity = String::from_utf8(output.stdout)?;
            ensure!(
                identity.trim_start().starts_with(&pid.to_string()),
                "owned native client PID disappeared"
            );
            json!({"pid_start_time_command":identity})
        };
        Ok(
            json!({"pid":pid,"executable":executable,"executable_sha256":digest,"os_process":identity}),
        )
    }

    pub(super) fn kill_and_wait(&mut self) -> Result<Value> {
        let before = self.identity()?;
        self.child.kill()?;
        let status = self.child.wait()?;
        ensure!(
            !status.success(),
            "kill unexpectedly became a successful client exit"
        );
        Ok(json!({"before":before,"waited":true,"exit_status":status.to_string()}))
    }

    pub(super) fn finish(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = self.child.try_wait()? {
                if !status.success() {
                    let stderr = self
                        .stderr
                        .take()
                        .context("native stderr already consumed")?
                        .join()
                        .map_err(|_| anyhow::anyhow!("native stderr reader panicked"))?;
                    anyhow::bail!(
                        "native client exited {status}: {}",
                        String::from_utf8_lossy(&stderr)
                    );
                }
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "native client did not exit after its completed checkpoint"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
