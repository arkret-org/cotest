//! CXP-0007 Circle conformance scenarios (P2F.3).
//!
//! Each module exposes one async `..._run()` function that returns
//! `Result<()>`. The scenarios deliberately drive the SDK types directly
//! (no live server) so the suite can run inside `cargo test --workspace`
//! without bootstrapping soland / coauth / floria. Cross-project joint
//! exercises live under [`crate::scenarios::full_stack_e2e`] and
//! [`crate::scenarios::four_service_smoke`] and will pick up the Circle
//! flows in phase P5.
//!
//! Scenarios (per `_cotest_todos.md` P2F.3.1):
//!
//! 1. [`create_circle`] — happy-path Circle round-trip (JSON canonicalisation,
//!    state defaults, strict-subset accepts the empty case).
//! 2. [`member_strict_subset`] — accepts `Circle ⊆ Realm`, rejects any
//!    Circle member outside the parent Realm.
//! 3. [`flow_scope_visibility`] — a `Flow.scope_circle_id` binding stamps
//!    `EffectiveScope::Circle` on the envelope; envelopes whose payload
//!    declares a different Circle than the envelope are rejected by
//!    [`flow_scope_visibility::flow_scope_visibility_run`].
//! 4. [`effective_scope_mismatch`] — envelope-vs-payload `scope_circle_id`
//!    disagreement is rejected (`circle_realm_mismatch` /
//!    `scope_rebind_forbidden` family).
//! 5. [`confidential_discussion_relation`] — `Relation::ConfidentialDiscussionOf`
//!    accepts a two-Flow round-trip and rejects non-flow endpoints.
//! 6. [`cap_action_grant`] — every CXP-0007 capability-action constant is
//!    spelled identically to the spec registry and is well-formed.
//! 7. [`error_code_paths`] — every CXP-0007 reason code is registered with
//!    the SDK and accepted by `is_known_error_code` / round-trippable.

pub mod cap_action_grant;
pub mod confidential_discussion_relation;
pub mod create_circle;
pub mod effective_scope_mismatch;
pub mod error_code_paths;
pub mod flow_scope_visibility;
pub mod member_strict_subset;
