//! Typed record of a fully provisioned self-sovereign test principal.
//!
//! `device-lifecycle.md` section 5.1 closes principal bootstrap over a
//! two-Event PCR genesis unit (`ak.realm.create` with
//! `purpose=principal_control` plus the `registration_anchor`
//! `ak.device.authorize`). Harness entry points that register an actor route
//! through this provisioning so every durable-write gate sees an accepted
//! founding-device authorization; scenarios that need an unauthorized device
//! opt out through explicitly named builders instead of relying on a missing
//! bootstrap step.

use arkret_identifiers::{DeviceId, DidCoreId, DidFullId, EventId, RealmId};
use ed25519_dalek::SigningKey;

/// Typed handles produced by the canonical actor bootstrap: the deterministic
/// `did:webvh` identity, the registration-time control key, the founding
/// device key, and the accepted PCR genesis coordinates.
#[derive(Clone)]
pub struct ProvisionedTestPrincipal {
    /// Full `did:webvh` principal id (carries the method history reference).
    pub full_id: DidFullId,
    /// Projected `ak:did_core:` business identity.
    pub core_id: DidCoreId,
    /// Founding device id authorized by the genesis unit.
    pub device_id: DeviceId,
    /// Founding device signing key (deterministic per principal and device).
    pub device_signing_key: SigningKey,
    /// Registration-time WebVH root (control) key seed.
    pub root_key_seed: [u8; 32],
    /// Event-derived Principal Control Realm id.
    pub pcr_realm_id: RealmId,
    /// Accepted founding `ak.device.authorize` Event id.
    pub founding_authorize_event_id: EventId,
}
