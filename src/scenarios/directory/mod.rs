//! Directory / anti-enumeration conformance scenarios (P2F.4).
//!
//! teabay is the v1 directory service. AKP-0007 hardens the boundary
//! between teabay's public surface and the per-Circle private state on
//! soland: Circle membership MUST NOT leak through directory queries,
//! and the public surface MUST still defend against enumeration on
//! Realm-level signals (member-count bucketing, response-latency jitter,
//! takedown audit trail).
//!
//! These scenarios live in `cotest` so the harness can exercise the
//! contract independently of a live teabay binary. They drive pure-Rust
//! helpers that model the spec's normative output (bucketing function,
//! jitter floor/ceiling, takedown reason set). Live-server variants will
//! be added by P5 once `teabay` exposes the corresponding endpoints.

pub mod anti_enumeration_buckets;
pub mod circle_not_indexed;
pub mod latency_jitter;
pub mod takedown_audit_log;
