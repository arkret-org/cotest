use anyhow::{Result, ensure};
use serde_json::Value;

/// Capture accepting effects and the independent general signer-query cache.
pub(crate) async fn acceptance_rows(url: &str) -> Result<Value> {
    acceptance_rows_with_agent_stores(url, false).await
}

/// Include operation-local Agent state in the same repeatable-read snapshot.
pub(crate) async fn acceptance_rows_with_agent_stores(
    url: &str,
    include_agents: bool,
) -> Result<Value> {
    let url = url.to_owned();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut connection = postgres::Client::connect(&url, postgres::NoTls)?;
        let mut transaction = connection.build_transaction().isolation_level(postgres::IsolationLevel::RepeatableRead).start()?;
        let tables = transaction.query("SELECT tablename::text FROM pg_tables WHERE schemaname='public' AND (tablename LIKE '%current_states' OR ($1 AND (tablename LIKE 'agent_%' OR tablename IN ('notifications','accounts','invite_new_source_hmac_keys'))) OR tablename IN ('canonical_events','realm_commits','realm_authorities','federation_outbox','event_federation_outbox','replica_stream_anchors','replica_authorization_rows','replica_authorization_cuts','account_summary_current','account_summary_versions','account_summary_clock','current_state_heads','current_state_versions','direct_conversation_founding_slots','agent_producer_signer_keys','account_device_signer_evidence','account_device_committed_evidence','forwarded_producer_device_evidence','forwarded_producer_agent_evidence','governance_unscoped_signer_evidence','registered_audit_units','watch_audit_read_results','registered_audit_forward_units','registered_audit_replica_units','event_approval_private_audit','actor_private_events')) ORDER BY tablename", &[&include_agents])?;
        let mut snapshot = serde_json::Map::new();
        for table in tables {
            let name: String = table.get(0);
            ensure!(name.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_'));
            let statement = format!("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM public.{name} r");
            snapshot.insert(name, transaction.query_one(&statement, &[])?.get(0));
        }
        for name in ["canonical_events", "realm_commits", "realm_authorities", "federation_outbox", "event_federation_outbox", "replica_stream_anchors", "replica_authorization_cuts", "member_state_current_states", "account_summary_current"] {
            ensure!(snapshot.contains_key(name), "acceptance footprint lacks {name}");
        }
        transaction.commit()?;
        Ok(Value::Object(snapshot))
    }).await?
}
