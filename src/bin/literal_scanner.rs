//! `literal_scanner` — repo-level drift scanner CLI.
//!
//! Usage:
//!
//! ```text
//! literal_scanner --root <path> [--format text|json] [--fail-on-violation]
//!                 [--registry-dir <path>]
//! ```
//!
//! Loads the six drift-detection artifacts from
//! `cokret-spec/spec/v1/artifacts/registry/` (or `--registry-dir`, or the
//! `COKRET_SPEC_DIR` env var), walks `--root`, and emits findings.
//!
//! Exit codes:
//! * `0` — scan completed; no unallowed violations (or `--fail-on-violation` was not supplied).
//! * `1` — scan completed but unallowed violations were found and `--fail-on-violation` was
//!   supplied.
//! * `2` — scanner itself failed (bad path, malformed registry, etc.).

use std::path::PathBuf;
use std::process::ExitCode;

use cotest::literal_scanner::{
    self, ScanReport, load_all_rules_from, resolve_registry_dir, scan_tree,
};

#[derive(Debug)]
struct CliArgs {
    root: PathBuf,
    format: OutputFormat,
    fail_on_violation: bool,
    registry_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
enum OutputFormat {
    Text,
    Json,
}

fn print_usage() {
    eprintln!(
        "usage: literal_scanner --root <path> [--format text|json] \
         [--fail-on-violation] [--registry-dir <path>]"
    );
}

fn parse_args() -> Result<CliArgs, String> {
    let mut iter = std::env::args().skip(1);
    let mut root: Option<PathBuf> = None;
    let mut format = OutputFormat::Text;
    let mut fail_on_violation = false;
    let mut registry_dir: Option<PathBuf> = None;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                root = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| "--root requires a value".to_string())?,
                ));
            }
            "--format" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--format requires a value".to_string())?;
                format = match v.as_str() {
                    "text" => OutputFormat::Text,
                    "json" => OutputFormat::Json,
                    other => return Err(format!("unknown --format value: {other}")),
                };
            }
            "--fail-on-violation" => fail_on_violation = true,
            "--registry-dir" => {
                registry_dir =
                    Some(PathBuf::from(iter.next().ok_or_else(|| {
                        "--registry-dir requires a value".to_string()
                    })?));
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let root = root.ok_or_else(|| "--root is required".to_string())?;
    Ok(CliArgs {
        root,
        format,
        fail_on_violation,
        registry_dir,
    })
}

fn run() -> anyhow::Result<ScanReport> {
    let args = parse_args().map_err(|e| {
        print_usage();
        anyhow::anyhow!(e)
    })?;
    let registry_dir = args.registry_dir.unwrap_or_else(resolve_registry_dir);
    let rules = load_all_rules_from(&registry_dir)?;
    let findings = scan_tree(&args.root, &rules)?;
    let report = ScanReport {
        root: args.root,
        registry_dir,
        rules_loaded: rules.len(),
        findings,
    };
    match args.format {
        OutputFormat::Text => print!("{}", report.render_text()),
        OutputFormat::Json => println!("{}", report.render_json()?),
    }
    if args.fail_on_violation && report.has_violations() {
        // Caller-visible signal that violations were found.
        return Err(anyhow::anyhow!(
            "literal_scanner: {} violation(s) found",
            report.violations().count()
        ));
    }
    Ok(report)
}

fn main() -> ExitCode {
    // Touch the module so unused-import lints don't fire on bare runs.
    let _ = literal_scanner::ArtifactSource::all();
    match run() {
        Ok(_) => ExitCode::from(0),
        Err(err) => {
            eprintln!("literal_scanner: error: {err:#}");
            // Distinguish "had violations" (1) from "scanner crashed" (2).
            // The fail-on-violation branch returns an anyhow error containing
            // the substring "violation(s) found"; match it loosely.
            let msg = format!("{err:#}");
            if msg.contains("violation(s) found") {
                ExitCode::from(1)
            } else {
                ExitCode::from(2)
            }
        }
    }
}
