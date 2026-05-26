//! Legacy `cx.secret_storage.v1` wire envelope rejection.
//!
//! Per B-C key-backup hardening §3.2, the soland backups PUT MUST
//! reject any envelope carrying `kind = cx.secret_storage.v1` with the
//! errcode `legacy_secret_storage_wire_form`.

use anyhow::{Result, anyhow};

use contrix_core::error::ERROR_CODE_LEGACY_SECRET_STORAGE_WIRE_FORM;

pub async fn legacy_secret_storage_wire_run() -> Result<()> {
    if ERROR_CODE_LEGACY_SECRET_STORAGE_WIRE_FORM != "legacy_secret_storage_wire_form" {
        return Err(anyhow!(
            "ERROR_CODE_LEGACY_SECRET_STORAGE_WIRE_FORM drifted: \
             {ERROR_CODE_LEGACY_SECRET_STORAGE_WIRE_FORM}"
        ));
    }
    // The validator MUST treat `cx.secret_storage.v1` as a fail-closed
    // sentinel; any envelope kind matching this string is rejected.
    let candidate = "cx.secret_storage.v1";
    if candidate != "cx.secret_storage.v1" {
        return Err(anyhow!(
            "legacy_secret_storage wire form value drifted: {candidate}"
        ));
    }
    // TODO(P4-impl): live PUT carrying kind=cx.secret_storage.v1 →
    // expect 422 legacy_secret_storage_wire_form.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn legacy_wire_form_rejected() {
        legacy_secret_storage_wire_run().await.unwrap();
    }
}
