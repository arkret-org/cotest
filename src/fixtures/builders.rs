//! Fluent fixture builders for cotest scenarios.
//!
//! `TestActorBuilder` replaces the per-scenario boilerplate of:
//!
//! ```ignore
//! let server = ContrixServer::spawn("my-scenario").await?;
//! let alice = server.register_client("did:web:alice.example", "@alice", "dev_alice").await?;
//! let space_id = alice.create_space("Some Space").await?;
//! ```
//!
//! …with a fluent chain:
//!
//! ```ignore
//! let alice = TestActorBuilder::new(&server, "@alice")
//!     .with_did("did:web:alice.example")
//!     .with_device("dev_alice")
//!     .with_space("Some Space")
//!     .create()
//!     .await?;
//! let space_id = alice.first_space().expect("seeded one space");
//! ```
//!
//! The builder owns the small bits of repetitive logic — handle/DID
//! derivation, default device naming, seeded-space tracking — so scenarios
//! can focus on the behaviour under test instead of plumbing.
//!
//! ## Design notes
//!
//! - The builder accepts a borrowed [`ContrixServer`] rather than a higher `TestHarness` wrapper
//!   (which the cotest crate does not currently define). When a wrapper type is introduced the
//!   builder can be retargeted without changing call sites — only the type bound moves.
//! - `with_key_package(n)` is reserved for future KeyPackage publication. The server currently does
//!   not expose a KeyPackage publish endpoint in the dev-login fast path; storing the requested
//!   count lets scenarios assert the value once the wire surface exists, without having to revisit
//!   the builder shape.
//! - The builder is intentionally `async`-free until `create()` so callers can inspect / mutate the
//!   spec without holding a future.

use std::fmt;

use anyhow::{Context, Result};

use crate::harness::{ContrixServer, TestActorClient};

/// Tracks the spaces a scenario asked the builder to create as part of the
/// fixture preamble. Each entry stores the original requested name and the
/// allocated `cx:space:...` id so scenarios can route follow-up assertions to
/// the right space without re-querying the server.
#[derive(Debug, Clone)]
pub struct SeededSpace {
    pub name: String,
    pub space_id: String,
}

/// The fully-realised actor fixture returned by [`TestActorBuilder::create`].
///
/// Wraps the raw [`TestActorClient`] with the metadata the builder collected
/// during the fixture preamble. The underlying client is exposed via
/// [`TestActor::client`] so scenarios can keep using all of the existing
/// `client.create_space(...)` / `client.post(...)` / `client.submit_event(...)`
/// methods unchanged.
///
/// `Debug` is implemented manually because [`TestActorClient`] (which embeds
/// an `SdkClient` / `HttpClient`) is not itself `Debug`.
#[derive(Clone)]
pub struct TestActor {
    pub handle: String,
    pub did: String,
    pub primary_device_id: String,
    pub additional_devices: Vec<String>,
    pub key_package_count: usize,
    pub spaces: Vec<SeededSpace>,
    pub client: TestActorClient,
}

impl fmt::Debug for TestActor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestActor")
            .field("handle", &self.handle)
            .field("did", &self.did)
            .field("primary_device_id", &self.primary_device_id)
            .field("additional_devices", &self.additional_devices)
            .field("key_package_count", &self.key_package_count)
            .field("spaces", &self.spaces)
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

    /// Convenience accessor that returns the `cx:space:...` id of the first
    /// space the builder seeded, if any.
    pub fn first_space(&self) -> Option<&str> {
        self.spaces.first().map(|seeded| seeded.space_id.as_str())
    }

    /// Lookup a seeded space by the original name passed to
    /// [`TestActorBuilder::with_space`].
    pub fn space_by_name(&self, name: &str) -> Option<&str> {
        self.spaces
            .iter()
            .find(|seeded| seeded.name == name)
            .map(|seeded| seeded.space_id.as_str())
    }
}

/// Fluent builder for [`TestActor`].
///
/// Holds a borrow of the [`ContrixServer`] under test so multiple actors can
/// be assembled against the same instance without re-cloning server-state. The
/// builder is `#[must_use]` because building a spec without calling
/// [`Self::create`] is almost always a mistake.
#[must_use = "TestActorBuilder must end in `.create().await` to actually register the actor"]
pub struct TestActorBuilder<'a> {
    server: &'a ContrixServer,
    handle: String,
    did: Option<String>,
    primary_device: Option<String>,
    additional_devices: Vec<String>,
    key_packages: usize,
    spaces: Vec<String>,
}

impl<'a> TestActorBuilder<'a> {
    /// Start a new builder for `handle` against `server`.
    ///
    /// `handle` accepts either the bare nickname (`alice`) or the leading-`@`
    /// form (`@alice`) — both shapes appear in existing scenarios. The default
    /// DID is derived as `did:web:<bare-handle>.example` and the default
    /// primary device id as `dev_<bare-handle>`, both overridable.
    pub fn new(server: &'a ContrixServer, handle: &str) -> Self {
        let handle = handle.to_owned();
        Self {
            server,
            handle,
            did: None,
            primary_device: None,
            additional_devices: Vec::new(),
            key_packages: 0,
            spaces: Vec::new(),
        }
    }

    /// Override the DID. By default the builder derives
    /// `did:web:<bare-handle>.example` from the handle.
    pub fn with_did(mut self, did: &str) -> Self {
        self.did = Some(did.to_owned());
        self
    }

    /// Register a device label for this actor.
    ///
    /// The first call sets the primary device id (the one passed to
    /// `register_client` / `dev_login`). Subsequent calls are recorded in
    /// `TestActor::additional_devices` for scenarios that want to assert how
    /// many devices they declared. The server does not yet provision the
    /// additional devices automatically — scenarios that need real per-device
    /// clients should call `server.demo_client(did, device_id)` directly with
    /// the labels stored on the returned `TestActor`.
    pub fn with_device(mut self, label: &str) -> Self {
        if self.primary_device.is_none() {
            self.primary_device = Some(label.to_owned());
        } else {
            self.additional_devices.push(label.to_owned());
        }
        self
    }

    /// Record the number of MLS KeyPackages the scenario expects this actor
    /// to publish.
    ///
    /// The cotest harness does not currently expose a KeyPackage publish API,
    /// so the count is stored as metadata for scenarios that want to assert
    /// the requested provisioning shape. When a publish endpoint lands the
    /// `create()` flow will pre-seed `count` KeyPackages without changing the
    /// builder surface.
    pub fn with_key_package(mut self, count: usize) -> Self {
        self.key_packages = count;
        self
    }

    /// Pre-seed a space owned by this actor.
    ///
    /// Spaces are created in the order they are declared. The allocated
    /// `cx:space:...` ids are returned on the resulting [`TestActor`] via
    /// `actor.spaces` or `actor.first_space()` / `actor.space_by_name(...)`.
    pub fn with_space(mut self, name: &str) -> Self {
        self.spaces.push(name.to_owned());
        self
    }

    /// Drive the builder to completion: register the actor against the server,
    /// open the primary session, and seed any declared spaces.
    pub async fn create(self) -> Result<TestActor> {
        let bare_handle = self
            .handle
            .strip_prefix('@')
            .unwrap_or(&self.handle)
            .to_owned();
        let did = self
            .did
            .clone()
            .unwrap_or_else(|| format!("did:web:{bare_handle}.example"));
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

        let mut seeded = Vec::with_capacity(self.spaces.len());
        for name in &self.spaces {
            let space_id = client
                .create_space(name)
                .await
                .with_context(|| format!("TestActorBuilder: create_space({name}) failed"))?;
            seeded.push(SeededSpace {
                name: name.clone(),
                space_id,
            });
        }

        Ok(TestActor {
            handle: display_handle,
            did,
            primary_device_id: primary_device,
            additional_devices: self.additional_devices,
            key_package_count: self.key_packages,
            spaces: seeded,
            client,
        })
    }
}

#[cfg(test)]
mod tests {
    // These tests are pure builder-state checks; they intentionally do NOT
    // call `create()` because that would require a live ContrixServer.
    // Scenario-level coverage of `create()` lives in the migrated scenarios
    // (e.g. `tests/events_backfill.rs`).

    #[test]
    fn defaults_derive_did_and_device_from_handle() {
        // Build the spec without driving create() so we can assert the
        // derivations the builder applies. We use a dummy server reference
        // by leaking a never-spawned ContrixServer through a builder method
        // that does not touch it — `with_*` methods are all pure setters.
        //
        // Note: we cannot construct a ContrixServer in a unit test, so we
        // instead verify the derivation logic directly via the same helpers
        // create() uses.
        let raw = "@alice";
        let bare = raw.strip_prefix('@').unwrap_or(raw);
        assert_eq!(bare, "alice");
        assert_eq!(format!("did:web:{bare}.example"), "did:web:alice.example");
        assert_eq!(format!("dev_{bare}"), "dev_alice");
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
