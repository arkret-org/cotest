//! Shared in-process salvo mock-server primitive.
//!
//! Replaces the former hand-written `TcpStream` HTTP/1.1 parser (round-28 dedup
//! pass). Each scenario builds its own [`salvo::Router`] — their handlers differ
//! (auth checks, capture, response shapes) — and hands it to [`spawn_mock`],
//! which binds an ephemeral loopback port and serves the router on the current
//! tokio runtime. The returned [`MockServer`] stops the server (by aborting its
//! serve task, which drops the listener) when it goes out of scope.
//!
//! Using salvo — the same HTTP framework the production servers run on — removes
//! the bespoke request framing / status-line code (and the old "every non-200
//! reason is `Unauthorized`" wart) in favour of the framework's correct HTTP
//! semantics.

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
    let port = crate::harness::reserve_port()?;
    let addr = SocketAddr::from(([127, 0, 0, 1], port.port()));
    let acceptor = TcpListener::new(addr).bind().await;
    let task = tokio::spawn(async move {
        Server::new(acceptor).serve(router).await;
    });
    Ok(MockServer {
        addr,
        task,
        _port_reservation: port,
    })
}
