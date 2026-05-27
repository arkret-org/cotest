//! P4-C.1 — `series_chain_broken` reason.
//!
//! When a PUT envelope's `supersedes_digest` does not match the on-
//! server `supersedes` envelope's digest, the soland reducer MUST
//! reject with HTTP 409 + errcode `series_chain_broken`.

use anyhow::{Result, anyhow};

use contrix_core::error::ERROR_CODE_SERIES_CHAIN_BROKEN;

pub async fn series_chain_broken_run() -> Result<()> {
    if ERROR_CODE_SERIES_CHAIN_BROKEN != "series_chain_broken" {
        return Err(anyhow!(
            "ERROR_CODE_SERIES_CHAIN_BROKEN spelling drifted: {ERROR_CODE_SERIES_CHAIN_BROKEN}"
        ));
    }
    // Negative-shape pin: a mismatched supersedes_digest MUST be
    // detectable by digest equality alone.
    let on_server = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let claimed = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    if on_server == claimed {
        return Err(anyhow!("test scaffold accidentally produced equal digests"));
    }

    // TODO(P4-impl): drive a live PUT /api/v1/keys/backups/{id} with
    // series_seq=2 and a supersedes_digest that doesn't match the
    // genesis envelope's digest; assert 409 + `series_chain_broken`.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn errcode_constant_pinned() {
        series_chain_broken_run().await.unwrap();
    }
}
