//! Explicit first-store provisioning through the owning Service CLI.

use anyhow::{Context as _, Result, ensure};

use super::{Command, Path, append_service_log, fs};

/// Only a newly owned store may create this Service secret. Restart, migration
/// and shared frontend startup retain the original key and never call this.
pub(super) fn provision_first_owned_store(
    server: &Command,
    server_binary: &Path,
    log_path: Option<&Path>,
) -> Result<()> {
    let cli = server_binary.with_file_name(format!(
        "coland-keystore-snapshot{}",
        std::env::consts::EXE_SUFFIX
    ));
    ensure!(
        cli.is_file(),
        "owned initial custody provisioning requires the newly built sibling CLI at {}; build both --bin coland and --bin coland-keystore-snapshot from the same reviewed source",
        cli.display()
    );
    let mut provision = Command::new(&cli);
    provision.arg("--generate-custody-key");
    // Preserve the exact configured KeyStore boundary and env removals. Keys
    // remain environment values; no secret enters command arguments or logs.
    for (name, value) in server.get_envs() {
        if let Some(value) = value {
            provision.env(name, value);
        } else {
            provision.env_remove(name);
        }
    }
    let output = provision.output().with_context(|| {
        format!(
            "execute explicit custody provisioning CLI {}",
            cli.display()
        )
    })?;
    ensure!(
        output.status.success(),
        "explicit initial custody provisioning failed with {}; no Coland process started (stdout {} bytes, stderr {} bytes)",
        output.status,
        output.stdout.len(),
        output.stderr.len()
    );
    ensure!(
        output.stdout.is_empty(),
        "custody provisioning CLI unexpectedly produced stdout"
    );
    // A local evidence record binds this explicit action to both real binaries;
    // the validation pipeline separately binds their hashes to source inputs.
    append_service_log(
        log_path,
        &serde_json::json!({
            "event":"explicit_initial_service_custody_provision",
            "mode":"generate_custody_key",
            "server_executable_sha256":arkret_canonical::sha256_digest(fs::read(server_binary)?),
            "custody_cli_executable_sha256":arkret_canonical::sha256_digest(fs::read(&cli)?),
        })
        .to_string(),
    )?;
    Ok(())
}
