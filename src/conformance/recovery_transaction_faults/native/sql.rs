use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use serde_json::{Value, json};

pub(super) async fn query<T: Send + 'static>(
    database: &str,
    read: impl FnOnce(&mut postgres::Client) -> Result<T> + Send + 'static,
) -> Result<T> {
    let database = database.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut client = postgres::Client::connect(&database, postgres::NoTls)?;
        read(&mut client)
    })
    .await?
}

pub(super) async fn database_identity(database: &str) -> Result<Value> {
    query(database, |db| {
        let row = db.query_one("SELECT current_database(),inet_server_addr()::text,inet_server_port()", &[])?;
        Ok(json!({"database":row.get::<_,String>(0),"server_address":row.get::<_,Option<String>>(1),"server_port":row.get::<_,Option<i32>>(2)}))
    }).await
}

pub(super) async fn station_footprint(database: &str) -> Result<Value> {
    query(database, |client| {
        let mut result = serde_json::Map::new();
        for table in [
            "canonical_events", "realm_commits", "security_transactions", "recovery_sessions",
            "pcr_device_generation_current_states", "pcr_device_authorization_current_states",
        ] {
            let rows: Value = client.query_one(
                &format!("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM {table} t"), &[],
            )?.get(0);
            result.insert(table.to_owned(), rows);
        }
        // Worker progress is independent of security completion. Compare its
        // immutable admission facts, without mistaking background preparation
        // for a second Recovery acceptance.
        let episodes: Value = client.query_one("SELECT coalesce(jsonb_agg(jsonb_build_object('authorization_event_ref',authorization_event_ref,'transaction_id',transaction_id,'actor_id',actor_id,'replacement',replacement,'pcr_cut',pcr_cut) ORDER BY authorization_event_ref),'[]'::jsonb) FROM content_recovery_episodes", &[])?.get(0);
        result.insert("content_recovery_admission".into(), episodes);
        Ok(Value::Object(result))
    }).await
}

pub(super) async fn issuer_footprint(database: &str) -> Result<Value> {
    query(database, |client| {
        let mut result = serde_json::Map::new();
        for table in ["oauth_session_grant_operations", "oauth_session_grants", "recovery_completion_grant_issuances", "dpop_jti_replay"] {
            result.insert(table.into(), client.query_one(
                &format!("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM {table} t"), &[],
            )?.get::<_, Value>(0));
        }
        Ok(Value::Object(result))
    }).await
}

pub(super) async fn accepted_completion(
    database: &str,
    transaction: &str,
) -> Result<Option<Value>> {
    let transaction = transaction
        .strip_prefix("ak:transaction:")
        .context("typed transaction id")?
        .to_owned();
    query(database, move |client| {
        Ok(client
            .query_opt(
                "SELECT recovery_completion FROM security_transactions WHERE id::text=$1",
                &[&transaction],
            )?
            .map(|row| row.get(0)))
    })
    .await
}

/// A test-only trigger in this scenario's owned database. The dedicated
/// connection owns its advisory lock; dropping this guard releases it and
/// removes exactly the trigger/function installed here, including on failure.
pub(super) struct Instrumentation {
    command: mpsc::Sender<bool>,
    worker: Option<thread::JoinHandle<Result<()>>>,
    pub(super) backend_pid: i32,
}

impl Instrumentation {
    pub(super) fn station_before_insert(database: &str) -> Result<Self> {
        Self::install(database, "security_transactions", true)
    }
    pub(super) fn issuer_fail_insert(database: &str) -> Result<Self> {
        Self::install(database, "recovery_completion_grant_issuances", false)
    }
    fn install(database: &str, table: &'static str, pause: bool) -> Result<Self> {
        let database = database.to_owned();
        let (command, commands) = mpsc::channel();
        let (ready, readiness) = mpsc::channel();
        let worker = thread::spawn(move || -> Result<()> {
            let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
            db.batch_execute("SET lock_timeout='5s'; SET statement_timeout='15s'")?;
            let exists: bool = db.query_one("SELECT EXISTS(SELECT 1 FROM pg_proc WHERE proname='cotest_0191_recovery_fault')", &[])?.get(0);
            ensure!(
                !exists,
                "test instrumentation already exists in this database"
            );
            let action = if pause {
                "PERFORM pg_advisory_xact_lock(204301915);"
            } else {
                "RAISE EXCEPTION 'cotest_0191_completion_issuer_rollback' USING ERRCODE='P0001';"
            };
            db.batch_execute(&format!("BEGIN; CREATE SEQUENCE cotest_0191_recovery_fault_hits; CREATE FUNCTION cotest_0191_recovery_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('cotest_0191_recovery_fault_hits'); {action} RETURN NEW; END $$; CREATE TRIGGER cotest_0191_recovery_fault BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION cotest_0191_recovery_fault(); COMMIT;"))?;
            let run = (|| -> Result<()> {
                let pid: i32 = db.query_one("SELECT pg_backend_pid()", &[])?.get(0);
                if pause {
                    db.query_one("SELECT pg_advisory_lock(204301915)", &[])?;
                }
                ready
                    .send(pid)
                    .map_err(|_| anyhow::anyhow!("instrumentation owner disappeared"))?;
                while let Ok(cleanup) = commands.recv() {
                    if pause {
                        db.query_one("SELECT pg_advisory_unlock(204301915)", &[])?;
                    }
                    if cleanup {
                        break;
                    }
                }
                Ok(())
            })();
            // Also clean up when readiness delivery or lock acquisition fails.
            // Release a possibly-held session lock before waiting on DDL.
            if pause {
                let _ = db.query_one("SELECT pg_advisory_unlock(204301915)", &[]);
            }
            let cleanup = db.batch_execute(&format!("DROP TRIGGER cotest_0191_recovery_fault ON {table}; DROP FUNCTION cotest_0191_recovery_fault(); DROP SEQUENCE cotest_0191_recovery_fault_hits;")).map_err(anyhow::Error::from);
            run.and(cleanup)
        });
        let backend_pid = match readiness.recv_timeout(Duration::from_secs(20)) {
            Ok(pid) => pid,
            Err(error) => {
                drop(command);
                let result = worker
                    .join()
                    .map_err(|_| anyhow::anyhow!("instrumentation thread panicked"))?;
                result?;
                return Err(error.into());
            }
        };
        Ok(Self {
            command,
            worker: Some(worker),
            backend_pid,
        })
    }
    pub(super) fn release(&self) -> Result<()> {
        self.command
            .send(false)
            .context("release actual SQL barrier")
    }
    pub(super) fn cleanup(mut self) -> Result<()> {
        self.command
            .send(true)
            .context("remove SQL instrumentation")?;
        self.worker
            .take()
            .context("instrumentation worker missing")?
            .join()
            .map_err(|_| anyhow::anyhow!("instrumentation cleanup panicked"))?
    }
}
impl Drop for Instrumentation {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = self.command.send(true);
            if let Ok(Err(error)) = worker.join() {
                eprintln!("owned recovery fault cleanup: {error:#}");
            }
        }
    }
}

/// Sequence advancement is intentionally nontransactional instrumentation:
/// it proves the real failing INSERT reached the trigger even after rollback.
/// It is not included in the business-ledger zero-write assertion.
pub(super) async fn fault_hits(database: &str) -> Result<i64> {
    query(database, |db| {
        Ok(db.query_one("SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM cotest_0191_recovery_fault_hits", &[])?.get(0))
    }).await
}

pub(super) async fn wait_for_waiters(database: &str, barrier: i32, count: usize) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let waiters = query(database, move |db| {
            let rows = db.query("WITH RECURSIVE waiting(pid) AS (SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) UNION SELECT a.pid FROM pg_stat_activity a JOIN waiting w ON w.pid=ANY(pg_blocking_pids(a.pid))) SELECT a.pid,a.query,a.wait_event_type,a.wait_event,pg_blocking_pids(a.pid) FROM pg_stat_activity a JOIN waiting w USING(pid) ORDER BY a.pid", &[&barrier])?;
            Ok(rows.into_iter().map(|row| json!({"pid":row.get::<_,i32>(0),"query":row.get::<_,String>(1),"wait_event_type":row.get::<_,Option<String>>(2),"wait_event":row.get::<_,Option<String>>(3),"blocking_pids":row.get::<_,Vec<i32>>(4)})).collect::<Vec<_>>())
        }).await?;
        if waiters.len() >= count {
            ensure!(
                waiters.iter().all(|row| row["wait_event_type"] == "Lock"),
                "waiters did not hold real PostgreSQL lock waits"
            );
            return Ok(json!({"barrier_pid":barrier,"waiters":waiters}));
        }
        if Instant::now() >= deadline {
            bail!(
                "only {} of {count} actual Recovery connections reached SQL barrier",
                waiters.len()
            );
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}
