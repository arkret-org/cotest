//! CKP-0007 Circle conformance scenarios (P2F.3).
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
//! 1. [`create_circle`] â€” happy-path Circle round-trip (JSON canonicalisation, state defaults,
//!    strict-subset accepts the empty case).
//! 2. [`member_strict_subset`] â€” accepts `Circle âŠ† Realm`, rejects any Circle member outside
//!    the parent Realm.
//! 3. [`flow_scope_visibility`] â€” a `Flow.scope_circle_id` binding stamps
//!    `EffectiveScope::Circle` on the envelope; envelopes whose payload declares a different Circle
//!    than the envelope are rejected by [`flow_scope_visibility::flow_scope_visibility_run`].
//! 4. [`effective_scope_mismatch`] â€” envelope-vs-payload `scope_circle_id` disagreement is
//!    rejected (`circle_realm_mismatch` / `scope_rebind_forbidden` family).
//! 5. [`confidential_discussion_relation`] â€” `Relation::ConfidentialDiscussionOf` accepts a
//!    two-Flow round-trip and rejects non-flow endpoints.
//! 7. [`error_code_paths`] â€” every CKP-0007 reason code is registered with the SDK and accepted
//!    by `is_known_error_code` / round-trippable.
//!
//! Phase A invariant scenarios (P2F.3.2):
//!
//!  8. [`member_state_machine`] â€” Circle member state transition table from CKP-0007 Â§3.6 (legal
//!     `invited / active / left / banned` edges + illegal `banned â†’ active`, regression,
//!     self-loop guards).
//!  9. [`scope_circle_id_immutability`] â€” `scope_circle_id` rebind across sequential states of
//!     the same Flow/Space/Morph MUST be rejected with `scope_rebind_forbidden`.
//! 10. [`history_visibility_floor`] â€” effective Circle history visibility is `max(strictness)` of
//!     (parent Realm floor, Circle setting); Circle MAY only tighten.
//! 11. [`metadata_encryption_floor`] â€” Circle `metadata_encryption_floor` MAY only tighten the
//!     parent Realm floor; loosening MUST fail with `metadata_encryption_floor_violation`.
//! 12. [`child_scope_policy`] â€” Space `child_scope_policy` enforcement for each of the four
//!     variants (`allow_any` / `require_e2ee` / `require_same_scope` / `require_scope_circle_id`).

pub mod child_scope_policy;
pub mod confidential_discussion_relation;
pub mod create_circle;
pub mod effective_scope_mismatch;
pub mod error_code_paths;
pub mod flow_scope_visibility;
pub mod history_visibility_floor;
pub mod member_state_machine;
pub mod member_strict_subset;
pub mod metadata_encryption_floor;
pub mod scope_circle_id_immutability;
