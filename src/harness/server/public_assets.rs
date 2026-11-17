//! Reconfigure the existing deployment-public asset list on an owned process.
use super::*;

impl ArkretServer {
    pub(crate) async fn restart_with_public_blob_refs(
        &mut self,
        references: &[arkret_wire::BlobRef],
    ) -> Result<()> {
        let config = self
            .external_restart
            .as_mut()
            .context("owned Station restart configuration")?;
        config
            .extra_env
            .retain(|(name, _)| name != "COLAND_PUBLIC_BLOB_REFS");
        if !references.is_empty() {
            config.extra_env.push((
                "COLAND_PUBLIC_BLOB_REFS".into(),
                serde_json::to_string(references)?,
            ));
        }
        self.restart_external_process().await
    }
}
