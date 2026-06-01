//! Structured tracing transcripts for cotest conformance vectors.
//!
//! C34.5 (Q3) — every conformance call site that runs a normative vector emits
//! a structured `tracing::info!` event via [`record_vector_event`]. Events are
//! routed through a process-wide [`MakeWriter`] that appends one JSONL line
//! per event to `target/conformance-transcripts/<scenario>.jsonl`, where
//! `<scenario>` is the name passed to [`init_transcript_writer`] for the
//! currently-running thread. External tooling (release gates, CI dashboards,
//! cross-impl diff tools) can consume the JSONL stream directly without having
//! to re-parse Rust test output.
//!
//! ## Wiring
//!
//! - Call [`init_transcript_writer`] once per scenario; the returned [`TranscriptGuard`] flushes +
//!   closes the per-scenario file on drop.
//! - The first call also initialises the global tracing subscriber with the JSON formatter +
//!   `RUST_LOG`-honouring env filter (default `info`).
//! - Subsequent calls reuse the global subscriber and just register a new per-scenario file + bind
//!   the active scenario for the calling thread.
//! - Inside instrumented call sites, use [`record_vector_event`] to emit `kind` / `payload` /
//!   `expected` / `actual` as JSON-encoded fields.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde_json::Value;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::format::FmtSpan;

const DEFAULT_TARGET_SUBDIR: &str = "target/conformance-transcripts";
const ENV_FILTER_FALLBACK: &str = "info";

thread_local! {
    /// The transcript scenario currently bound to this thread. `record_vector_event`
    /// uses this to decide which per-scenario JSONL file to append to. Updated by
    /// [`init_transcript_writer`] on entry and restored to its previous value when
    /// the returned [`TranscriptGuard`] is dropped.
    static ACTIVE_SCENARIO: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Per-scenario JSONL writers, keyed by scenario name. A single registry is
/// shared across all instrumented call sites because tracing's global subscriber
/// can only be installed once per process.
static REGISTRY: OnceLock<Mutex<HashMap<String, BufWriter<File>>>> = OnceLock::new();

/// Tracks whether the global tracing subscriber has been installed.
static SUBSCRIBER_INITIALISED: OnceLock<()> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<String, BufWriter<File>>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// `MakeWriter` impl that routes each tracing event to the JSONL file for the
/// scenario currently bound to the emitting thread. Events emitted from threads
/// without a bound scenario are dropped on the floor (no-op writer).
#[derive(Clone, Copy, Default)]
struct TranscriptMakeWriter;

impl<'a> MakeWriter<'a> for TranscriptMakeWriter {
    type Writer = TranscriptWriter;

    fn make_writer(&'a self) -> Self::Writer {
        TranscriptWriter {
            scenario: ACTIVE_SCENARIO.with(|cell| cell.borrow().clone()),
        }
    }
}

struct TranscriptWriter {
    scenario: Option<String>,
}

impl Write for TranscriptWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Some(scenario) = self.scenario.as_deref() else {
            return Ok(buf.len());
        };
        let mut guard = registry()
            .lock()
            .map_err(|err| io::Error::other(format!("transcript registry poisoned: {err}")))?;
        if let Some(file) = guard.get_mut(scenario) {
            file.write_all(buf)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let Some(scenario) = self.scenario.as_deref() else {
            return Ok(());
        };
        let mut guard = registry()
            .lock()
            .map_err(|err| io::Error::other(format!("transcript registry poisoned: {err}")))?;
        if let Some(file) = guard.get_mut(scenario) {
            file.flush()?;
        }
        Ok(())
    }
}

/// Guard returned by [`init_transcript_writer`]. Drops flush the per-scenario
/// JSONL file and unbind the scenario from the calling thread.
pub struct TranscriptGuard {
    scenario: String,
    previous: Option<String>,
}

impl Drop for TranscriptGuard {
    fn drop(&mut self) {
        // Flush + close the per-scenario writer. We deliberately drop the
        // BufWriter so any lingering buffered bytes hit disk before the test
        // process exits (cargo test's default panic-handler skips Drop on the
        // global subscriber, which would otherwise lose the tail of the log).
        if let Ok(mut guard) = registry().lock() {
            if let Some(mut file) = guard.remove(&self.scenario) {
                let _ = file.flush();
            }
        }
        let previous = self.previous.take();
        ACTIVE_SCENARIO.with(|cell| {
            *cell.borrow_mut() = previous;
        });
    }
}

/// Bind `scenario_name` to the calling thread, creating
/// `<target_dir>/<scenario_name>.jsonl` (truncating any prior content) and
/// installing the global tracing subscriber on the first call.
///
/// `target_dir` defaults to `target/conformance-transcripts/` when `None`.
/// Returns a [`TranscriptGuard`] that flushes + unbinds on drop.
pub fn init_transcript_writer(
    scenario_name: &str,
    target_dir: Option<&Path>,
) -> io::Result<TranscriptGuard> {
    let target_dir = target_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(default_target_dir);
    fs::create_dir_all(&target_dir)?;

    let path = target_dir.join(format!("{scenario_name}.jsonl"));
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)?;
    {
        let mut guard = registry()
            .lock()
            .map_err(|err| io::Error::other(format!("transcript registry poisoned: {err}")))?;
        guard.insert(scenario_name.to_owned(), BufWriter::new(file));
    }

    SUBSCRIBER_INITIALISED.get_or_init(|| {
        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(ENV_FILTER_FALLBACK));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_current_span(false)
            .with_span_list(false)
            .with_target(false)
            .with_span_events(FmtSpan::NONE)
            .with_writer(TranscriptMakeWriter)
            .with_env_filter(env_filter)
            .finish();
        // try_init: another harness in the same process may have already
        // installed a subscriber (e.g. when several scenarios run back-to-back
        // in one cargo test invocation). The MakeWriter is global anyway, so
        // a previously-installed subscriber will route to our registry too.
        let _ = tracing::subscriber::set_global_default(subscriber);
    });

    let previous = ACTIVE_SCENARIO.with(|cell| cell.borrow().clone());
    ACTIVE_SCENARIO.with(|cell| {
        *cell.borrow_mut() = Some(scenario_name.to_owned());
    });

    Ok(TranscriptGuard {
        scenario: scenario_name.to_owned(),
        previous,
    })
}

/// Emit one structured transcript event for a conformance vector.
///
/// `kind` is a short stable identifier (e.g. `"redaction.preserved_fields"`)
/// that downstream consumers can group on. `payload`, `expected`, `actual` are
/// JSON-encoded as string fields to keep the on-disk JSONL format flat — the
/// tracing-subscriber `json` formatter already produces structured output, so
/// nested JSON-as-string survives a single `serde_json::from_str` round-trip
/// at the consumer side.
///
/// No-op when called from a thread that has not been bound via
/// [`init_transcript_writer`] — instrumented call sites stay safe to invoke
/// from non-transcript code paths (e.g. ad-hoc scenarios, ordinary tests).
pub fn record_vector_event(kind: &str, payload: &Value, expected: &Value, actual: &Value) {
    if !is_active() {
        return;
    }
    let scenario = ACTIVE_SCENARIO
        .with(|cell| cell.borrow().clone())
        .unwrap_or_default();
    let entry = serde_json::json!({
        "level": "INFO",
        "fields": {
            "message": "vector",
            "scenario": scenario,
            "kind": kind,
            "payload": payload.to_string(),
            "expected": expected.to_string(),
            "actual": actual.to_string(),
        }
    });
    if let Ok(mut guard) = registry().lock()
        && let Some(file) = guard.get_mut(&scenario)
    {
        let _ = serde_json::to_writer(&mut *file, &entry);
        let _ = file.write_all(b"\n");
    }
}

/// Returns true when the calling thread has an active transcript writer bound.
/// Useful for skipping expensive payload synthesis when no one is listening.
pub fn is_active() -> bool {
    ACTIVE_SCENARIO.with(|cell| cell.borrow().is_some())
}

/// Default target directory for transcript JSONL files: `target/conformance-transcripts/`
/// resolved relative to `CARGO_MANIFEST_DIR`.
pub fn default_target_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_TARGET_SUBDIR)
}
