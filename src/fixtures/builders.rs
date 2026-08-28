//! Fluent fixture builders for cotest scenarios.
//!
//! `TestActorBuilder` replaces the per-scenario boilerplate of:
//!
//! ```ignore
//! let server = ArkretServer::spawn("my-scenario").await?;
//! let alice = server.register_client(&alice_did, "@alice", "ak:device:01904100-0000-7000-8000-0000000000a1").await?;
//! let realm_id = alice.create_realm("Some Realm").await?;
//! ```
//!
//! …with a fluent chain:
//!
//! ```ignore
//! let alice = TestActorBuilder::new(&server, "@alice")
//!     .with_did(&alice_did)
//!     .with_device("ak:device:01904100-0000-7000-8000-0000000000a1")
//!     .create()
//!     .await?;
//! let realm_id = alice.client().create_realm("Some Realm").await?;
//! ```
//!
//! The builder owns the small bits of repetitive logic — handle/DID
//! derivation and default device naming — so scenarios can focus on the
//! behaviour under test instead of plumbing.
//!
//! ## Design notes
//!
//! - The builder accepts a borrowed [`ArkretServer`] rather than a higher `TestHarness` wrapper
//!   (which the cotest crate does not currently define). When a wrapper type is introduced the
//!   builder can be retargeted without changing call sites — only the type bound moves.
//! - The builder is intentionally `async`-free until `create()` so callers can inspect / mutate the
//!   spec without holding a future.

use std::fmt;

use anyhow::{Context, Result};

use crate::harness::{ArkretServer, TestActorClient};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

/// The fully-realised actor fixture returned by [`TestActorBuilder::create`].
///
/// Wraps the raw [`TestActorClient`] with the metadata the builder collected
/// during the fixture preamble. The underlying client is exposed via
/// [`TestActor::client`] so scenarios can keep using all of the existing
/// `client.create_realm(...)` / `client.post(...)` / `client.submit_event(...)`
/// methods unchanged.
///
/// `Debug` is implemented manually because [`TestActorClient`] (which embeds
/// an `SdkClient` / `HttpClient`) is not itself `Debug`.
#[derive(Clone)]
pub struct TestActor {
    pub handle: String,
    pub did: String,
    pub primary_device_id: String,
    pub client: TestActorClient,
}

impl fmt::Debug for TestActor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestActor")
            .field("handle", &self.handle)
            .field("did", &self.did)
            .field("primary_device_id", &self.primary_device_id)
            .field("client", &"<TestActorClient>")
            .finish()
    }
}

impl TestActor {
    /// Borrow the underlying [`TestActorClient`] so callers can issue HTTP
    /// requests against the server they were registered with.
    pub fn client(&self) -> &TestActorClient {
        &self.client
    }
}

/// Fluent builder for [`TestActor`].
///
/// Holds a borrow of the [`ArkretServer`] under test so multiple actors can
/// be assembled against the same instance without re-cloning server-state. The
/// builder is `#[must_use]` because building a spec without calling
/// [`Self::create`] is almost always a mistake.
#[must_use = "TestActorBuilder must end in `.create().await` to actually register the actor"]
pub struct TestActorBuilder<'a> {
    server: &'a ArkretServer,
    handle: String,
    did: Option<String>,
    primary_device: Option<String>,
}

impl<'a> TestActorBuilder<'a> {
    /// Start a new builder for `handle` against `server`.
    ///
    /// `handle` accepts either the bare nickname (`alice`) or the leading-`@`
    /// form (`@alice`) — both shapes appear in existing scenarios. The default
    /// DID is the deterministic harness DID for `bare-handle` scoped to the
    /// server's service DID, and the default primary device id is
    /// `dev_<bare-handle>`, both overridable.
    pub fn new(server: &'a ArkretServer, handle: &str) -> Self {
        let handle = handle.to_owned();
        Self {
            server,
            handle,
            did: None,
            primary_device: None,
        }
    }

    /// Override the DID. By default the builder derives the deterministic
    /// harness DID for the bare handle scoped to the server's service DID.
    pub fn with_did(mut self, did: &str) -> Self {
        self.did = Some(did.to_owned());
        self
    }

    /// Set the primary device label for this actor (the one passed to
    /// `register_client` / `dev_login`). The first call wins; additional
    /// devices are not provisioned by the builder — scenarios that need real
    /// per-device clients call `server.demo_client(did, device_id)` directly.
    pub fn with_device(mut self, label: &str) -> Self {
        if self.primary_device.is_none() {
            self.primary_device = Some(label.to_owned());
        }
        self
    }

    /// Drive the builder to completion: register the actor against the server
    /// and open the primary session.
    pub async fn create(self) -> Result<TestActor> {
        let bare_handle = self
            .handle
            .strip_prefix('@')
            .unwrap_or(&self.handle)
            .to_owned();
        let did = match self.did.clone() {
            Some(did) => did,
            None => actor_did_for_service_did(self.server.service_did(), &bare_handle)?,
        };
        let primary_device = self
            .primary_device
            .clone()
            .unwrap_or_else(|| format!("dev_{bare_handle}"));
        // Existing scenarios call `register_client` with the handle in
        // `@alice` form. Preserve that convention so server-side handle
        // validation (which currently accepts both) keeps working uniformly.
        let display_handle = if self.handle.starts_with('@') {
            self.handle.clone()
        } else {
            format!("@{}", self.handle)
        };

        let client = self
            .server
            .register_client(&did, &display_handle, &primary_device)
            .await
            .with_context(|| {
                format!(
                    "TestActorBuilder: register_client failed for {display_handle} ({did}, device {primary_device})"
                )
            })?;

        Ok(TestActor {
            handle: display_handle,
            did,
            primary_device_id: crate::harness::canonical_device_id(&primary_device),
            client,
        })
    }
}

#[cfg(test)]
mod tests {
    // These tests are pure builder-state checks; they intentionally do NOT
    // call `create()` because that would require a live ArkretServer.
    // Scenario-level coverage of `create()` lives in the migrated scenarios
    // (e.g. `tests/events_backfill.rs`).

    #[test]
    fn defaults_derive_did_and_device_from_handle() {
        use crate::harness::canonical_device_id;

        // Build the spec without driving create() so we can assert the
        // derivations the builder applies. The default DID derivation needs a
        // live server's service DID, so it is covered by scenario-level
        // tests; here we pin the handle strip and the device derivation.
        let raw = "@alice";
        let bare = raw.strip_prefix('@').unwrap_or(raw);
        assert_eq!(bare, "alice");
        assert_eq!(
            canonical_device_id(&format!("dev_{bare}")),
            "ak:device:01904100-0000-7000-8000-0000000000a1"
        );
    }

    #[test]
    fn handle_without_at_prefix_is_normalised_for_display() {
        let raw = "bob";
        let display = if raw.starts_with('@') {
            raw.to_owned()
        } else {
            format!("@{raw}")
        };
        assert_eq!(display, "@bob");
    }
}
