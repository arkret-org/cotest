//! One public TLS origin for two private workers of the same Station.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result, ensure};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use url::Url;

pub(super) struct WorkerEndpoint {
    pub base: Url,
    workers: Arc<OnceLock<[SocketAddr; 2]>>,
    selected: Arc<AtomicUsize>,
    forwarded: Arc<[AtomicUsize; 2]>,
    task: JoinHandle<()>,
}

impl WorkerEndpoint {
    pub async fn bind() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let base = Url::parse(&format!("https://{}/", listener.local_addr()?))?;
        let workers = Arc::new(OnceLock::<[SocketAddr; 2]>::new());
        let selected = Arc::new(AtomicUsize::new(0));
        let forwarded = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
        let task_workers = workers.clone();
        let task_selected = selected.clone();
        let task_forwarded = forwarded.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((mut inbound, _)) = accepted else { break };
                        let Some(workers) = task_workers.get() else { continue };
                        let index = task_selected.load(Ordering::SeqCst);
                        let target = workers[index];
                        let counts = task_forwarded.clone();
                        connections.spawn(async move {
                            if let Ok(mut outbound) = TcpStream::connect(target).await {
                                counts[index].fetch_add(1, Ordering::SeqCst);
                                // Forward TLS bytes unchanged. The client and worker
                                // keep the public origin, signatures and hostname checks.
                                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                            }
                        });
                    }
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Ok(Self {
            base,
            workers,
            selected,
            forwarded,
            task,
        })
    }

    pub fn configure(&self, bases: [Url; 2]) -> Result<()> {
        let workers = bases.map(|base| -> Result<SocketAddr> {
            ensure!(
                base.host_str() == Some("127.0.0.1"),
                "private loopback worker required"
            );
            Ok(SocketAddr::from((
                [127, 0, 0, 1],
                base.port().context("worker port")?,
            )))
        });
        let [first, second] = workers;
        self.workers
            .set([first?, second?])
            .map_err(|_| anyhow::anyhow!("workers already configured"))
    }

    pub fn select(&self, index: usize) {
        assert!(index < 2);
        self.selected.store(index, Ordering::SeqCst);
    }

    pub fn assert_both_workers_used(&self) -> Result<()> {
        ensure!(
            self.forwarded
                .iter()
                .all(|count| count.load(Ordering::SeqCst) > 0),
            "the public endpoint did not reach both actual workers"
        );
        Ok(())
    }
}

impl Drop for WorkerEndpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}
