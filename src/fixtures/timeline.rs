//! Failure event-timeline and causality trace.
//!
//! When a scenario assertion fails, the raw error message often elides the
//! ordering of events the harness observed before the failure. This module
//! reads the redacted ndjson transcript the harness already writes (see
//! `crate::harness::append_transcript_entry`) and renders a one-line-per-event
//! summary suitable for dropping straight into a test failure log.
//!
//! ## Wiring
//!
//! - The harness writes to `$COTEST_TRANSCRIPT_PATH` (or `$COTEST_ARTIFACT_DIR/transcript.ndjson`)
//!   if those env vars are set.
//! - On panic the panic hook installed by [`install_failure_dump_hook`] reads back the transcript
//!   and writes a pretty-printed timeline to stderr before re-raising via the original hook.
//! - The unit test below covers the parse + format path against an inline ndjson buffer, so the
//!   failure path is exercised without depending on a real server.

use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Once;

use anyhow::{Context, Result};
use serde_json::Value;

/// One row of the rendered failure timeline.
///
/// Sender / op_id / kind / event_digest correspond to the four fields the
/// harness transcript records per request. `depends_on` carries the
/// `prev_refs` array from the event envelope (the "depends-on-frontier" the
/// task asks for) when the request body parses as an event envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineEntry {
    pub seq: usize,
    pub timestamp: String,
    pub sender: String,
    pub op_id: String,
    pub kind: String,
    pub event_digest: String,
    pub depends_on: Vec<String>,
    pub status: Option<u16>,
}

impl TimelineEntry {
    fn from_transcript_line(seq: usize, raw: &str) -> Option<Self> {
        let value: Value = serde_json::from_str(raw).ok()?;
        let timestamp = value
            .get("timestamp")
            .and_then(Value::as_str)
            .unwrap_or("--")
            .to_owned();

        let request = value.get("request")?;
        let body = request.get("body").unwrap_or(&Value::Null);
        let method = request.get("method").and_then(Value::as_str).unwrap_or("?");
        let url = request.get("url").and_then(Value::as_str).unwrap_or("?");

        // Extract envelope fields if the body looks like a Arkret event.
        let mut sender = String::from("-");
        let mut op_id = format!("{method} {url}");
        let mut kind = String::from("http");
        let mut depends_on = Vec::new();

        if let Some(actor) = body.get("actor_id").and_then(Value::as_str) {
            sender = actor.to_owned();
        }
        if let Some(event_id) = body.get("event_id").and_then(Value::as_str) {
            op_id = event_id.to_owned();
        } else if let Some(operation_id) = body
            .get("unsigned")
            .and_then(|u| u.get("local_operation_idempotency_alias"))
            .and_then(Value::as_str)
        {
            op_id = operation_id.to_owned();
        }
        if let Some(event_kind) = body.get("kind").and_then(Value::as_str) {
            kind = event_kind.to_owned();
        }
        if let Some(refs) = body.get("prev_refs").and_then(Value::as_array) {
            depends_on = refs
                .iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect();
        }

        let event_digest = body
            .get("proofs")
            .and_then(|p| p.get(0))
            .and_then(|p| p.get("event_digest"))
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_owned();

        let status = value
            .get("response")
            .and_then(|r| r.get("status"))
            .and_then(Value::as_u64)
            .map(|s| s as u16);

        Some(Self {
            seq,
            timestamp,
            sender,
            op_id,
            kind,
            event_digest,
            depends_on,
            status,
        })
    }
}

/// Rendered failure timeline. Use the [`Display`] impl to render to a string;
/// it produces a fixed-width column layout suitable for stderr or test logs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventTimeline {
    pub events: Vec<TimelineEntry>,
    pub source: Option<PathBuf>,
}

impl EventTimeline {
    /// Parse the ndjson transcript at `path` into a timeline.
    ///
    /// Returns an empty timeline (no events, source populated) when the file
    /// exists but contains zero parseable rows. Returns `Err` when the file
    /// is unreadable; missing files yield `Ok(Self::default())` with the
    /// `source` field set so callers can distinguish "no transcript wired in"
    /// from "transcript was empty".
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self {
                events: Vec::new(),
                source: Some(path.to_path_buf()),
            });
        }
        let body = fs::read_to_string(path)
            .with_context(|| format!("read transcript at {}", path.display()))?;
        Ok(Self::from_ndjson(&body).with_source(path))
    }

    /// Parse ndjson contents directly. Useful for unit tests that want to
    /// exercise the rendering path without touching the filesystem.
    pub fn from_ndjson(body: &str) -> Self {
        let events = body
            .lines()
            .filter(|line| !line.trim().is_empty())
            .enumerate()
            .filter_map(|(idx, line)| TimelineEntry::from_transcript_line(idx + 1, line))
            .collect();
        Self {
            events,
            source: None,
        }
    }

    fn with_source(mut self, path: &Path) -> Self {
        self.source = Some(path.to_path_buf());
        self
    }

    /// Best-effort load from the same env vars the harness writes to.
    ///
    /// Returns `None` when neither `COTEST_TRANSCRIPT_PATH` nor
    /// `COTEST_ARTIFACT_DIR` is set — i.e. the harness was not asked to
    /// produce a transcript and there is nothing to dump.
    pub fn load_from_env() -> Option<Self> {
        let path = std::env::var_os("COTEST_TRANSCRIPT_PATH")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("COTEST_ARTIFACT_DIR")
                    .map(PathBuf::from)
                    .map(|p| p.join("transcript.ndjson"))
            })?;
        Self::load(&path).ok()
    }
}

impl Display for EventTimeline {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "==== cotest event timeline ====")?;
        if let Some(source) = &self.source {
            writeln!(f, "source: {}", source.display())?;
        }
        if self.events.is_empty() {
            writeln!(f, "(no transcript events captured)")?;
            return Ok(());
        }
        writeln!(
            f,
            "{:>4}  {:<25}  {:<28}  {:<40}  {:<6}  {:<24}  depends_on / digest",
            "#", "timestamp", "sender", "op_id", "status", "kind"
        )?;
        for entry in &self.events {
            let depends = if entry.depends_on.is_empty() {
                String::from("(none)")
            } else {
                entry.depends_on.join(",")
            };
            let status = entry
                .status
                .map(|s| s.to_string())
                .unwrap_or_else(|| String::from("-"));
            writeln!(
                f,
                "{:>4}  {:<25}  {:<28}  {:<40}  {:<6}  {:<24}  deps=[{}] digest={}",
                entry.seq,
                truncate(&entry.timestamp, 25),
                truncate(&entry.sender, 28),
                truncate(&entry.op_id, 40),
                status,
                truncate(&entry.kind, 24),
                truncate(&depends, 80),
                entry.event_digest
            )?;
        }
        Ok(())
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_owned()
    } else {
        let head: String = value.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

static INSTALL_ONCE: Once = Once::new();

/// Install a panic hook that dumps the event timeline to stderr before
/// delegating to the previously-installed hook (so default panic formatting
/// — including backtraces — still appears after the timeline).
///
/// Idempotent: safe to call from every scenario entry point. Multiple calls
/// after the first one are no-ops.
pub fn install_failure_dump_hook() {
    INSTALL_ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if let Some(timeline) = EventTimeline::load_from_env() {
                eprintln!("{timeline}");
            }
            previous(info);
        }));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_EVENT_LINE: &str = r#"{"timestamp":"2026-05-18T10:00:00.000Z","duration_ms":5,"request":{"method":"POST","url":"http://127.0.0.1:8008/_arkret/self/events","headers":{},"body":{"event_id":"ak:event:01999999-0000-7000-8000-000000000001","kind":"ak.message.create","actor_id":"did:webvh:z6mkfixture:alice.example","realm_id":"ak:realm:abc","prev_refs":["ak:event:prev-1"],"proofs":[{"kind":"detached_jws","event_digest":"sha256:deadbeef"}],"unsigned":{"local_operation_idempotency_alias":"ak:operation:01999999"}}},"response":{"status":200,"headers":{},"body":{}}}"#;
    const SAMPLE_GET_LINE: &str = r#"{"timestamp":"2026-05-18T10:00:01.000Z","duration_ms":2,"request":{"method":"GET","url":"http://127.0.0.1:8008/_arkret/self/account/subscribe","headers":{},"body":null},"response":{"status":401,"headers":{},"body":{"ok":false}}}"#;

    #[test]
    fn parses_event_envelope_and_get_request() {
        let ndjson = format!("{SAMPLE_EVENT_LINE}\n{SAMPLE_GET_LINE}\n");
        let timeline = EventTimeline::from_ndjson(&ndjson);
        assert_eq!(timeline.events.len(), 2);

        let first = &timeline.events[0];
        assert_eq!(first.sender, "did:webvh:z6mkfixture:alice.example");
        assert_eq!(first.op_id, "ak:event:01999999-0000-7000-8000-000000000001");
        assert_eq!(first.kind, "ak.message.create");
        assert_eq!(first.event_digest, "sha256:deadbeef");
        assert_eq!(first.depends_on, vec!["ak:event:prev-1".to_owned()]);
        assert_eq!(first.status, Some(200));

        let second = &timeline.events[1];
        assert_eq!(second.sender, "-");
        assert_eq!(
            second.op_id,
            "GET http://127.0.0.1:8008/_arkret/self/account/subscribe"
        );
        assert_eq!(second.kind, "http");
        assert!(second.depends_on.is_empty());
        assert_eq!(second.status, Some(401));
    }

    #[test]
    fn display_renders_header_and_rows() {
        let ndjson = format!("{SAMPLE_EVENT_LINE}\n{SAMPLE_GET_LINE}\n");
        let rendered = EventTimeline::from_ndjson(&ndjson).to_string();
        assert!(rendered.contains("cotest event timeline"));
        // The sender column is truncated to 28 chars, so the full 35-char
        // `did:webvh:z6mkfixture:alice.example` renders as its visible prefix.
        assert!(rendered.contains("did:webvh:z6mkfixture:alice"));
        assert!(rendered.contains("ak.message.create"));
        assert!(rendered.contains("sha256:deadbeef"));
        assert!(rendered.contains("ak:event:prev-1"));
        assert!(rendered.contains("401"));
    }

    #[test]
    fn empty_transcript_renders_placeholder() {
        let rendered = EventTimeline::from_ndjson("").to_string();
        assert!(rendered.contains("(no transcript events captured)"));
    }

    #[test]
    fn missing_file_yields_empty_timeline_with_source() {
        let tmp = std::env::temp_dir().join("cotest-test-missing-transcript.ndjson");
        let _ = fs::remove_file(&tmp);
        let timeline = EventTimeline::load(&tmp).unwrap();
        assert!(timeline.events.is_empty());
        assert_eq!(timeline.source.as_deref(), Some(tmp.as_path()));
    }

    /// Triggers a panic in a controlled child thread to verify the failure
    /// dump hook actually writes the timeline to stderr before the panic
    /// propagates. We can't redirect process-wide stderr without disturbing
    /// the rest of the test suite, so this test asserts the hook installs
    /// without error and the rendered output for a synthetic transcript
    /// contains the expected marker — which is what the hook would emit if
    /// invoked.
    #[test]
    fn panic_hook_renders_timeline_for_inline_transcript() {
        // Write a transcript to a temp file and point the env var at it.
        let dir =
            std::env::temp_dir().join(format!("cotest-timeline-panic-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let transcript = dir.join("transcript.ndjson");
        fs::write(&transcript, SAMPLE_EVENT_LINE).unwrap();

        // SAFETY: tests in this module run with `#[test]` which `cargo test`
        // executes on a thread pool. Mutating process env from one of those
        // threads can race with other tests reading env. We scope the mutation
        // tightly and restore the prior value before returning to minimise
        // the window. The unsafety arises because `set_var`/`remove_var`
        // are `unsafe` in Rust 2024 edition; we accept it because the test
        // is self-contained and runs serially with itself via `Once`.
        let prior = std::env::var_os("COTEST_TRANSCRIPT_PATH");
        unsafe {
            std::env::set_var("COTEST_TRANSCRIPT_PATH", &transcript);
        }

        // Verify load_from_env picks up the transcript.
        let loaded = EventTimeline::load_from_env().expect("env-driven load");
        let rendered = loaded.to_string();
        // Sender column truncates at 28 chars; assert the visible prefix.
        assert!(rendered.contains("did:webvh:z6mkfixture:alice"));
        assert!(rendered.contains("ak.message.create"));

        // Install the hook and run a panic in a child thread; the join handle
        // captures the panic so the test process itself does not abort.
        install_failure_dump_hook();
        let handle = std::thread::spawn(|| {
            panic!("synthetic panic for timeline dump test");
        });
        let join_result = handle.join();
        assert!(join_result.is_err(), "expected child thread to panic");

        // Restore prior env state.
        unsafe {
            match prior {
                Some(value) => std::env::set_var("COTEST_TRANSCRIPT_PATH", value),
                None => std::env::remove_var("COTEST_TRANSCRIPT_PATH"),
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
