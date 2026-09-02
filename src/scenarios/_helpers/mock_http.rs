//! Shared in-process salvo mock-server primitive.
//!
//! Each scenario builds its own [`salvo::Router`] — their handlers differ
//! (auth checks, capture, response shapes) — and hands it to [`spawn_mock`],
//! which binds an ephemeral loopback port and serves the router on the current
//! tokio runtime. The returned [`MockServer`] stops the server (by aborting its
//! serve task, which drops the listener) when it goes out of scope.
//!
//! Salvo is deliberately the same HTTP framework the production servers run on,
//! so request framing and status-line handling here match what a scenario would
//! see against a real server instead of a bespoke parser's approximation.

use std::net::SocketAddr;

use anyhow::Result;
use salvo::Router;
use salvo::conn::{Listener, TcpListener};
use salvo::prelude::Server;
use tokio::task::JoinHandle;

use crate::harness::ReservedPort;

/// A running in-process salvo mock server bound to an ephemeral loopback port.
///
/// Dropping it aborts the serve task, releasing the port.
pub struct MockServer {
    addr: SocketAddr,
    task: JoinHandle<()>,
    _port_reservation: ReservedPort,
}

impl MockServer {
    /// The bound `127.0.0.1:<port>` address the mock is listening on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Bind `router` on an ephemeral loopback port and serve it on the current
/// tokio runtime. Must be called from within a tokio runtime.
pub async fn spawn_mock(router: Router) -> Result<MockServer> {
    // `reserve_port` holds a guard listener on the chosen port; it MUST be
    // released before salvo binds the same address or the bind races other
    // test processes and panics with AddrInUse (salvo's `bind()` panics on
    // error — use `try_bind` so a lost race surfaces as a retryable Err).
    let mut last_error = None;
    let mut bound = None;
    for _ in 0..8 {
        let mut port = crate::harness::reserve_port()?;
        let addr = SocketAddr::from(([127, 0, 0, 1], port.port()));
        port.release();
        match TcpListener::new(addr).try_bind().await {
            Ok(acceptor) => {
                bound = Some((acceptor, addr, port));
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let Some((acceptor, addr, port)) = bound else {
        return Err(anyhow::anyhow!(
            "mock server could not bind an ephemeral loopback port after 8 attempts: {last_error:?}"
        ));
    };
    let task = tokio::spawn(async move {
        Server::new(acceptor).serve(router).await;
    });
    Ok(MockServer {
        addr,
        task,
        _port_reservation: port,
    })
}
