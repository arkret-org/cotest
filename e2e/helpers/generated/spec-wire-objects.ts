// GENERATED FILE — DO NOT EDIT BY HAND.
//
// Source: arkret-spec/spec/v1/artifacts/schemas/*.json
// Producer: e2e/scripts/generate-wire-types.mjs
//
// Regenerate with `npm run gen:wire-types`; `npm run check:wire-types` fails
// when this file no longer matches the spec artifacts. Annotate hand-built wire
// literals with these types so an unregistered member is a `tsc` error rather
// than a live-server rejection.

/** `realm-join-intake.schema.json#/$defs/self_prepare_request_body` — closed object schema. */
export type RealmJoinPrepareRequestBody = {
  "request_id": string;
  "account_id": {
    "principal_id": string;
    "station_id": string;
  };
  "realm_id": string;
  "intent": {
    "intent": "invite_accept";
    "invite_id": string;
    "invite_token": string;
  } | {
    "intent": "member_join";
    "gate_proofs"?: Array<{
      "gate_id": string;
      "kind": "challenge_response" | "claim_required";
      "realm_id": string;
      "applicant_actor_id": {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "policy_digest": string;
      "created_at": string;
      "challenge_kind"?: "captcha" | "pow" | "attested_human" | "idp_oidc";
      "challenge_id"?: string;
      "issuer_id"?: string;
      "claims"?: string[];
      "proofs": Array<{
        "kind": "detached_jws";
        "verification_method": string;
        "payload_digest": string;
        "created_at": string;
        "domain"?: string;
        "audience"?: string | string[];
        "proof_purpose"?: "issuer_attestation" | "holder_acceptance" | "status_attestation" | "revocation_authorization" | "governance_authorization";
        "jws": string;
      }>;
    }>;
  } | {
    "intent": "knock";
  };
  "created_at": string;
  "hlc"?: string;
};

/** `message-authoring.schema.json#/$defs/message_prepare_request_body` — closed object schema. */
export type MessagePrepareRequestBody = {
  "request_id": string;
  "account_id": {
    "principal_id": string;
    "station_id": string;
  };
  "realm_id": string;
  "intent": {
    "strand_id": string;
    "track_name": "discussion";
    "content": {
      "kind": "plaintext";
      "content": {
        "kind": string;
        "body": string;
        "format"?: "plain" | "markdown" | "prosemirror_json";
        "formatted_body"?: string | Record<string, unknown>;
        "parts"?: Array<{
          "kind": string;
          "body": string;
          "format"?: "plain" | "markdown" | "prosemirror_json";
          "formatted_body"?: string | Record<string, unknown>;
          "parts"?: Array<{
            "kind": string;
            "body": string;
            "format"?: "plain" | "markdown" | "prosemirror_json";
            "formatted_body"?: string | Record<string, unknown>;
            "parts"?: Array<{
              "kind": string;
              "body": string;
              "format"?: "plain" | "markdown" | "prosemirror_json";
              "formatted_body"?: string | Record<string, unknown>;
              "parts"?: Array<{
                "kind": string;
                "body": string;
                "format"?: "plain" | "markdown" | "prosemirror_json";
                "formatted_body"?: string | Record<string, unknown>;
                "parts"?: Array<{
                  "kind": string;
                  "body": string;
                  "format"?: "plain" | "markdown" | "prosemirror_json";
                  "formatted_body"?: string | Record<string, unknown>;
                  "parts"?: Array<{
                    "kind": string;
                    "body": string;
                    "format"?: "plain" | "markdown" | "prosemirror_json";
                    "formatted_body"?: string | Record<string, unknown>;
                    "parts"?: Array<{
                      "kind": string;
                      "body": string;
                      "format"?: "plain" | "markdown" | "prosemirror_json";
                      "formatted_body"?: string | Record<string, unknown>;
                      "parts"?: Array<{
                        "kind": unknown;
                        "body": string;
                        "format"?: "plain" | "markdown" | "prosemirror_json";
                        "formatted_body"?: unknown;
                        "parts"?: unknown[];
                        "mentions"?: unknown[];
                        "audience_mentions"?: unknown[];
                        "attachments"?: unknown[];
                        "reply_context"?: {
                          "message_ref"?: unknown;
                          "sender_actor_id"?: unknown;
                          "excerpt"?: unknown;
                          [key: string]: unknown;
                        };
                        [key: string]: unknown;
                      }>;
                      "mentions"?: Array<{
                        "kind": "mention";
                        "subject_account_id": unknown;
                        "display_name_at_time"?: string;
                        "handle_at_time"?: unknown;
                        "controller_subject_account_id"?: unknown;
                        "controller_handle_at_time"?: unknown;
                        "agent_slug_at_time"?: unknown;
                        "mention_text_original"?: string;
                        "resolved_at"?: unknown;
                      }>;
                      "audience_mentions"?: Array<{
                        "kind": "audience_mention";
                        "audience": "effective_scope_members" | "strand_participants" | "strand_watchers" | "strand_engaged" | "assigned_actors";
                        "mention_text_original"?: string;
                        "resolved_at"?: unknown;
                      }>;
                      "attachments"?: Array<Record<string, unknown>>;
                      "reply_context"?: {
                        "message_ref"?: string;
                        "sender_actor_id"?: {
                          "kind": unknown;
                          "account_id": unknown;
                        } | {
                          "kind": unknown;
                          "service_id": unknown;
                        };
                        "excerpt"?: string;
                        [key: string]: unknown;
                      };
                      [key: string]: unknown;
                    }>;
                    "mentions"?: Array<{
                      "kind": "mention";
                      "subject_account_id": {
                        "principal_id": string;
                        "station_id": string;
                      };
                      "display_name_at_time"?: string;
                      "handle_at_time"?: string;
                      "controller_subject_account_id"?: {
                        "principal_id": string;
                        "station_id": string;
                      };
                      "controller_handle_at_time"?: string;
                      "agent_slug_at_time"?: string;
                      "mention_text_original"?: string;
                      "resolved_at"?: string;
                    }>;
                    "audience_mentions"?: Array<{
                      "kind": "audience_mention";
                      "audience": "effective_scope_members" | "strand_participants" | "strand_watchers" | "strand_engaged" | "assigned_actors";
                      "mention_text_original"?: string;
                      "resolved_at"?: string;
                    }>;
                    "attachments"?: Array<Record<string, unknown>>;
                    "reply_context"?: {
                      "message_ref"?: string;
                      "sender_actor_id"?: {
                        "kind": "account";
                        "account_id": {
                          "principal_id": unknown;
                          "station_id": unknown;
                        };
                      } | {
                        "kind": "service";
                        "service_id": string;
                      };
                      "excerpt"?: string;
                      [key: string]: unknown;
                    };
                    [key: string]: unknown;
                  }>;
                  "mentions"?: Array<{
                    "kind": "mention";
                    "subject_account_id": {
                      "principal_id": string;
                      "station_id": string;
                    };
                    "display_name_at_time"?: string;
                    "handle_at_time"?: string;
                    "controller_subject_account_id"?: {
                      "principal_id": string;
                      "station_id": string;
                    };
                    "controller_handle_at_time"?: string;
                    "agent_slug_at_time"?: string;
                    "mention_text_original"?: string;
                    "resolved_at"?: string;
                  }>;
                  "audience_mentions"?: Array<{
                    "kind": "audience_mention";
                    "audience": "effective_scope_members" | "strand_participants" | "strand_watchers" | "strand_engaged" | "assigned_actors";
                    "mention_text_original"?: string;
                    "resolved_at"?: string;
                  }>;
                  "attachments"?: Array<Record<string, unknown>>;
                  "reply_context"?: {
                    "message_ref"?: string;
                    "sender_actor_id"?: {
                      "kind": "account";
                      "account_id": {
                        "principal_id": string;
                        "station_id": string;
                      };
                    } | {
                      "kind": "service";
                      "service_id": string;
                    };
                    "excerpt"?: string;
                    [key: string]: unknown;
                  };
                  [key: string]: unknown;
                }>;
                "mentions"?: Array<{
                  "kind": "mention";
                  "subject_account_id": {
                    "principal_id": string;
                    "station_id": string;
                  };
                  "display_name_at_time"?: string;
                  "handle_at_time"?: string;
                  "controller_subject_account_id"?: {
                    "principal_id": string;
                    "station_id": string;
                  };
                  "controller_handle_at_time"?: string;
                  "agent_slug_at_time"?: string;
                  "mention_text_original"?: string;
                  "resolved_at"?: string;
                }>;
                "audience_mentions"?: Array<{
                  "kind": "audience_mention";
                  "audience": "effective_scope_members" | "strand_participants" | "strand_watchers" | "strand_engaged" | "assigned_actors";
                  "mention_text_original"?: string;
                  "resolved_at"?: string;
                }>;
                "attachments"?: Array<Record<string, unknown>>;
                "reply_context"?: {
                  "message_ref"?: string;
                  "sender_actor_id"?: {
                    "kind": "account";
                    "account_id": {
                      "principal_id": string;
                      "station_id": string;
                    };
                  } | {
                    "kind": "service";
                    "service_id": string;
                  };
                  "excerpt"?: string;
                  [key: string]: unknown;
                };
                [key: string]: unknown;
              }>;
              "mentions"?: Array<{
                "kind": "mention";
                "subject_account_id": {
                  "principal_id": string;
                  "station_id": string;
                };
                "display_name_at_time"?: string;
                "handle_at_time"?: string;
                "controller_subject_account_id"?: {
                  "principal_id": string;
                  "station_id": string;
                };
                "controller_handle_at_time"?: string;
                "agent_slug_at_time"?: string;
                "mention_text_original"?: string;
                "resolved_at"?: string;
              }>;
              "audience_mentions"?: Array<{
                "kind": "audience_mention";
                "audience": "effective_scope_members" | "strand_participants" | "strand_watchers" | "strand_engaged" | "assigned_actors";
                "mention_text_original"?: string;
                "resolved_at"?: string;
              }>;
              "attachments"?: Array<Record<string, unknown>>;
              "reply_context"?: {
                "message_ref"?: string;
                "sender_actor_id"?: {
                  "kind": "account";
                  "account_id": {
                    "principal_id": string;
                    "station_id": string;
                  };
                } | {
                  "kind": "service";
                  "service_id": string;
                };
                "excerpt"?: string;
                [key: string]: unknown;
              };
              [key: string]: unknown;
            }>;
            "mentions"?: Array<{
              "kind": "mention";
              "subject_account_id": {
                "principal_id": string;
                "station_id": string;
              };
              "display_name_at_time"?: string;
              "handle_at_time"?: string;
              "controller_subject_account_id"?: {
                "principal_id": string;
                "station_id": string;
              };
              "controller_handle_at_time"?: string;
              "agent_slug_at_time"?: string;
              "mention_text_original"?: string;
              "resolved_at"?: string;
            }>;
            "audience_mentions"?: Array<{
              "kind": "audience_mention";
              "audience": "effective_scope_members" | "strand_participants" | "strand_watchers" | "strand_engaged" | "assigned_actors";
              "mention_text_original"?: string;
              "resolved_at"?: string;
            }>;
            "attachments"?: Array<Record<string, unknown>>;
            "reply_context"?: {
              "message_ref"?: string;
              "sender_actor_id"?: {
                "kind": "account";
                "account_id": {
                  "principal_id": string;
                  "station_id": string;
                };
              } | {
                "kind": "service";
                "service_id": string;
              };
              "excerpt"?: string;
              [key: string]: unknown;
            };
            [key: string]: unknown;
          }>;
          "mentions"?: Array<{
            "kind": "mention";
            "subject_account_id": {
              "principal_id": string;
              "station_id": string;
            };
            "display_name_at_time"?: string;
            "handle_at_time"?: string;
            "controller_subject_account_id"?: {
              "principal_id": string;
              "station_id": string;
            };
            "controller_handle_at_time"?: string;
            "agent_slug_at_time"?: string;
            "mention_text_original"?: string;
            "resolved_at"?: string;
          }>;
          "audience_mentions"?: Array<{
            "kind": "audience_mention";
            "audience": "effective_scope_members" | "strand_participants" | "strand_watchers" | "strand_engaged" | "assigned_actors";
            "mention_text_original"?: string;
            "resolved_at"?: string;
          }>;
          "attachments"?: Array<Record<string, unknown>>;
          "reply_context"?: {
            "message_ref"?: string;
            "sender_actor_id"?: {
              "kind": "account";
              "account_id": {
                "principal_id": string;
                "station_id": string;
              };
            } | {
              "kind": "service";
              "service_id": string;
            };
            "excerpt"?: string;
            [key: string]: unknown;
          };
          [key: string]: unknown;
        }>;
        "mentions"?: Array<{
          "kind": "mention";
          "subject_account_id": {
            "principal_id": string;
            "station_id": string;
          };
          "display_name_at_time"?: string;
          "handle_at_time"?: string;
          "controller_subject_account_id"?: {
            "principal_id": string;
            "station_id": string;
          };
          "controller_handle_at_time"?: string;
          "agent_slug_at_time"?: string;
          "mention_text_original"?: string;
          "resolved_at"?: string;
        }>;
        "audience_mentions"?: Array<{
          "kind": "audience_mention";
          "audience": "effective_scope_members" | "strand_participants" | "strand_watchers" | "strand_engaged" | "assigned_actors";
          "mention_text_original"?: string;
          "resolved_at"?: string;
        }>;
        "attachments"?: Array<Record<string, unknown>>;
        "reply_context"?: {
          "message_ref"?: string;
          "sender_actor_id"?: {
            "kind": "account";
            "account_id": {
              "principal_id": string;
              "station_id": string;
            };
          } | {
            "kind": "service";
            "service_id": string;
          };
          "excerpt"?: string;
          [key: string]: unknown;
        };
        [key: string]: unknown;
      };
      "metadata"?: {
        "fields"?: Record<string, unknown>;
        [key: string]: unknown;
      };
    } | {
      "kind": "mls";
      "encrypted_content": {
        "version": "1.0";
        "content_type": string;
        "encryption_context": {
          "epoch": number;
          "group_state_ref": string;
          "routing_context"?: {
            "target_ref": string;
            "routing_tag": string;
          };
        } | {
          "epoch": number;
          "group_state_ref": string;
          "counter": number;
          "routing_context"?: {
            "target_ref": string;
            "routing_tag": string;
          };
        };
        "ciphertext": string;
      };
      "encrypted_metadata"?: {
        "version": "1.0";
        "content_type": string;
        "encryption_context": {
          "epoch": number;
          "group_state_ref": string;
          "routing_context"?: {
            "target_ref": string;
            "routing_tag": string;
          };
        } | {
          "epoch": number;
          "group_state_ref": string;
          "counter": number;
          "routing_context"?: {
            "target_ref": string;
            "routing_tag": string;
          };
        };
        "ciphertext": string;
      };
      "encryption_context": {
        "scheme": "mls_rfc9420" | "mls_exporter_aead_v1";
        "effective_scope": {
          "kind": "realm";
          "realm_id": string;
        } | {
          "kind": "circle";
          "realm_id": string;
          "circle_id": string;
        } | {
          "kind": "sidecar";
          "realm_id": string;
          "sidecar_id": string;
        } | {
          "kind": "realm_genesis";
        };
        "sender_domain": string;
      };
    };
    "blob_refs"?: string[];
    "reply_to_id"?: string;
  };
  "created_at": string;
  "hlc"?: string;
};

/** `identity-resolution.schema.json#/$defs/public_principal_resolution` — closed object schema. */
export type PublicPrincipalResolution = {
  "account_id": {
    "principal_id": string;
    "station_id": string;
  };
  "resolution_projection": {
    "did": string;
    "method_history_head": string;
    "version_id": string;
    "resolution_event_ref": string;
    "updated_at": string;
  };
  "method_history_evidence": {
    "evidence_kind": "webvh_log";
    "boundary": {
      "from_method_history_head": string;
      "from_version_id": string;
      "to_method_history_head": string;
      "to_version_id": string;
    };
    "evidence": {
      "kind": "ak.did.binding_evidence.v1";
      "method": string;
      "document_digest": string;
      "method_proofs": Array<{
        "kind": "webvh_log";
        "history_head": string;
        "witnesses": Array<{
          "witness_did": string;
          "controlling_organization_did": string;
        }>;
        "witness_proofs_digest": string;
      }>;
    };
    "log_entries": Array<Record<string, unknown>>;
    "witness_records": Array<Record<string, unknown>>;
  } | {
    "evidence_kind": "did_web_document";
    "boundary": {
      "from_method_history_head": string;
      "from_version_id": string;
      "to_method_history_head": string;
      "to_version_id": string;
    };
    "evidence": {
      "kind": "ak.did.binding_evidence.v1";
      "method": string;
      "document_digest": string;
      "method_proofs": Array<{
        "kind": "webvh_log";
        "history_head": string;
        "witnesses": Array<{
          "witness_did": string;
          "controlling_organization_did": string;
        }>;
        "witness_proofs_digest": string;
      }>;
    };
  } | {
    "evidence_kind": "did_key_expansion";
    "boundary": {
      "from_method_history_head": string;
      "from_version_id": string;
      "to_method_history_head": string;
      "to_version_id": string;
    };
    "evidence": {
      "kind": "ak.did.binding_evidence.v1";
      "method": string;
      "document_digest": string;
      "method_proofs": Array<{
        "kind": "webvh_log";
        "history_head": string;
        "witnesses": Array<{
          "witness_did": string;
          "controlling_organization_did": string;
        }>;
        "witness_proofs_digest": string;
      }>;
    };
  };
  "projection_attestation": {
    "attestation": {
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
      "resolution_projection": {
        "did": string;
        "method_history_head": string;
        "version_id": string;
        "resolution_event_ref": string;
        "updated_at": string;
      };
      "method_history_evidence_digest": string;
      "issued_at": string;
      "expires_at": string;
    };
    "proof": {
      "verification_method": string;
      "created_at": string;
      "jws": string;
    };
  };
};

/** `circle-operations.schema.json#/$defs/circle_view` — closed object schema. */
export type CircleView = {
  "circle_id": string;
  "realm_id": string;
  "profile_ref"?: string;
  "title": string;
  "summary"?: string;
  "display": {
    "short_name": string;
    "color_token": "slate" | "red" | "orange" | "amber" | "yellow" | "lime" | "green" | "emerald" | "teal" | "cyan" | "sky" | "blue" | "indigo" | "violet" | "fuchsia" | "pink" | "gray_high_contrast";
    "symbol": unknown;
  };
  "directory_visibility": "member_ids" | "realm_members";
  "join_rule": "invite" | "knock" | "public";
  "history_access": "since_join" | "all_history_for_current_members";
  "content_encryption_floor"?: "allow_plaintext" | "e2ee_required";
  "metadata_encryption_floor"?: "allow_plaintext" | "e2ee_required";
  "encryption_profile": "none" | "mls_rfc9420";
  "content_scheme"?: "mls_rfc9420" | "mls_exporter_aead_v1";
  "mls_group_id"?: string;
  "durability_policy"?: "none" | "organization_recovery_key";
  "state": "active" | "archived" | "tombstoned";
  "viewer_membership"?: "join" | "knock" | "leave" | "ban";
  "member_ids": Array<{
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  }>;
  "created_by": {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "created_at": string;
  "updated_by"?: {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "updated_at"?: string;
};

/** `circle-operations.schema.json#/$defs/circle_membership_outcome` — closed object schema. */
export type CircleMembershipOutcome = {
  "circle_id": string;
  "member_id": {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "membership": "join" | "knock" | "leave" | "ban";
};

/** `contact-operations.schema.json#/$defs/contact_peer` — closed object schema. */
export type ContactPeer = {
  "kind": "human";
  "account_id": {
    "principal_id": string;
    "station_id": string;
  };
} | {
  "kind": "agent";
  "actor_id": {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "controller_account_id": {
    "principal_id": string;
    "station_id": string;
  };
};

/** `common-ids.schema.json#/$defs/actor_id` — closed object schema. */
export type ActorId = {
  "kind": "account";
  "account_id": {
    "principal_id": string;
    "station_id": string;
  };
} | {
  "kind": "service";
  "service_id": string;
};

/** `common-ids.schema.json#/$defs/account_id` — closed object schema. */
export type AccountId = {
  "principal_id": string;
  "station_id": string;
};

/** `invite.schema.json` — closed object schema. */
export type InviteObject = {
  "id": string;
  "schema": "ak.schema.invite.v1";
  "realm_id": string;
  "inviter_account_id": {
    "principal_id": string;
    "station_id": string;
  };
  "invitee_account_id"?: {
    "principal_id": string;
    "station_id": string;
  };
  "introduction_evidence_digest"?: string;
  "third_party_invite"?: {
    "display_name_hint"?: string;
    "token_commitment": string;
    "token_salt_id"?: string;
    "lookup_table_ref"?: string;
    "pepper_id"?: string;
    "oob_code_kind": "offline_token" | "lookup";
    "token_entropy_bits"?: number;
    "verification_id": string;
    "verification_public_key": string;
    "max_claims"?: number;
  };
  "capability_grant_refs"?: string[];
  "state": "pending" | "accepted" | "rejected" | "revoked" | "expired" | "claimed" | "send_failed" | "revoked_by_capability_loss" | "revoked_by_inviter_left" | "invalidated_by_rate_limit";
  "expires_at": string;
  "created_at": string;
  "updated_by"?: {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "updated_at"?: string;
};

/** `event-payload.schema.json#/$defs/membership_payload` — closed object schema. */
export type MembershipPayload = {
  "strand_id"?: string;
  "realm_id"?: string;
  "member_id": {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "membership": "join" | "knock" | "leave" | "ban";
  "gate_proofs"?: Array<{
    "gate_id": string;
    "kind": "challenge_response" | "claim_required";
    "realm_id": string;
    "applicant_actor_id": {
      "kind": "account";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
    } | {
      "kind": "service";
      "service_id": string;
    };
    "policy_digest": string;
    "created_at": string;
    "challenge_kind"?: "captcha" | "pow" | "attested_human" | "idp_oidc";
    "challenge_id"?: string;
    "issuer_id"?: string;
    "claims"?: string[];
    "proofs": Array<{
      "kind": "detached_jws";
      "verification_method": string;
      "payload_digest": string;
      "created_at": string;
      "domain"?: string;
      "audience"?: string | string[];
      "proof_purpose"?: "issuer_attestation" | "holder_acceptance" | "status_attestation" | "revocation_authorization" | "governance_authorization";
      "jws": string;
    }>;
  }>;
  "reason"?: string;
  "membership_cause"?: "controller_membership_ended";
  "agent_controller_binding"?: {
    "controller_account_id": {
      "principal_id": string;
      "station_id": string;
    };
    "controller_membership_generation_ref": string;
    "controller_terminal_event_ref"?: string;
  };
  "invite_ref"?: string;
};

/** `realm.schema.json` — closed object schema. */
export type RealmObject = {
  "id"?: string;
  "schema": "ak.schema.realm.v1";
  "title": string;
  "summary"?: string;
  "security_class"?: "standard" | "high_assurance";
  "trust_domain": string;
  "owning_organization_ids"?: string[];
  "schema_refs": Array<string | "ak.profile.principal_control_realm.v1" | "ak.profile.direct_conversation_realm.v1" | "ak.profile.mls.minimal_metadata_realm.v1">;
  "fields"?: {
    "purpose"?: "principal_control" | "agent_control" | "applet_managed_control";
    "collaboration_role"?: "direct_conversation";
    [key: string]: unknown;
  };
  "policy_id"?: string;
  "preview_policy_id"?: string;
  "default_strand_id"?: string | null;
  "default_discoverability": "public" | "listed" | "restricted" | "unlisted" | "invite_only" | "secret";
  "default_join_rule": "public" | "invite" | "knock" | "restricted" | "knock_restricted" | "closed";
  "history_access": "since_join" | "all_history_for_current_members";
  "reducer_profile": string;
  "encryption_profile": "none" | "mls_rfc9420" | "external";
  "content_scheme"?: "mls_rfc9420" | "mls_exporter_aead_v1";
  "content_encryption_floor"?: "allow_plaintext" | "e2ee_required";
  "metadata_encryption_floor"?: "allow_plaintext" | "e2ee_required";
  "agent_participation"?: {
    "agent": {
      "reply_message": boolean;
      "reaction_add": boolean;
      "reaction_remove": boolean;
      "accept_third_party_mention": boolean;
      "act_on_behalf": boolean;
    };
  };
  "durability_policy"?: "none" | "organization_recovery_key";
  "federation_policy"?: "open" | "restricted" | "closed" | "quarantine";
  "availability_policy"?: {
    "min_holders": number;
    "applies_to": Array<"seal_include" | "snapshot" | "backfill">;
    "minimum_retention_ms"?: number;
  };
  "audit_policy"?: {
    "seal_transparency_auditor_ids": string[];
    "seal_transparency_min_attestations": number;
    "seal_transparency_auditor_independence": "distinct_did" | "distinct_controlling_organization";
  };
  "digest_algorithm"?: "sha256" | "blake3";
  "notary": {
    "signer": {
      "actor_id": {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "verification_method": string;
      "key_kind": "ed25519_raw32";
      "jose_algorithm": "Ed25519";
      "frozen_public_key_b64u": string;
    } | {
      "actor_id": {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "verification_method": string;
      "key_kind": "p256_sec1_compressed33";
      "jose_algorithm": "ES256";
      "frozen_public_key_b64u": string;
    };
    "max_clock_error_ms": number;
  };
  "proposal_intake_sla_ms"?: number;
  "proposal_decision_window_ms"?: number;
  "proposal_absolute_deadline_ms"?: number;
  "max_proposal_defers"?: number;
  "seal_compaction_max_interval_ms"?: number;
  "max_authority_lifetime_ms"?: number;
  "bottom_escalation_after_ms"?: number;
  "retention_policy_id"?: string;
  "avatar_blob_ref"?: string;
  "created_by": {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "created_at": string;
  "updated_by"?: {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "updated_at"?: string;
};

/** `space.schema.json` — closed object schema. */
export type SpaceObject = {
  "id"?: string;
  "schema": "ak.schema.space.v1";
  "realm_id": string;
  "scope_circle_id"?: string;
  "child_scope_policy"?: {
    "kind": "allow_any" | "require_e2ee" | "require_same_scope" | "require_scope_circle_id";
    "scope_circle_id"?: string;
  };
  "parent_space_id"?: string;
  "kind": string;
  "rank"?: string;
  "schema_refs"?: string[];
  "title": string;
  "summary"?: string;
  "labels"?: string[];
  "fields"?: {
    "wip_limit"?: number;
    "wip_limit_enforcement"?: "warn" | "reject" | "require_review";
    [key: string]: unknown;
  };
  "avatar_blob_ref"?: string;
  "state"?: "active" | "archived" | "tombstoned";
  "state_changed_at"?: string;
  "created_by": {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "created_at": string;
  "updated_by"?: {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "updated_at"?: string;
};

/** `capability-grant.schema.json` — closed object schema. */
export type CapabilityGrantObject = {
  "id": string;
  "schema": "ak.schema.capability.v1";
  "realm_id"?: string;
  "issuer_id": {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "subject": {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  } | {
    "kind": "condition";
    "required_claims": unknown[];
    [key: string]: unknown;
  };
  "actions": string[];
  "resources": Array<{
    "kind": "realm" | "space" | "circle" | "strand" | "message" | "morph" | "object" | "relation" | "view" | "event" | "actor" | "schema" | "policy" | "invite" | "notification" | "read_cursor" | "blob" | "*";
    "realm_id"?: string;
    "space_id"?: string;
    "circle_id"?: string;
    "object_kind"?: string;
    "object_ref"?: string;
    "strand_id"?: string;
    "message_id"?: string;
    "morph_id"?: string;
    "morph_kind"?: string;
    "relation_kind"?: string;
    "relation_id"?: string;
    "view_id"?: string;
    "event_id"?: string;
    "actor_id"?: {
      "kind": "account";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
    } | {
      "kind": "service";
      "service_id": string;
    };
    "schema_ref"?: string;
    "policy_id"?: string;
    "invite_id"?: string;
    "blob_ref"?: string;
    "match_scope"?: "exact" | "realm_wide";
  }>;
  "constraints"?: Array<{
    "constraint_id"?: string;
    "constraint_kind": "temporal" | "field_access" | "kind_restriction" | "scope_limitation" | "authority_control" | "quota" | "claim_based" | "confidentiality";
    "effect": "allow" | "deny" | "quarantine" | "require_review";
    "evaluation_class"?: "stateless" | "grant_local" | "realm_state" | "external";
    "constraint_subkind"?: "claim" | "approval" | "accountability" | "rate" | "resource" | "encryption" | "visibility" | "window" | "edit_window" | "redact_window" | "session" | "applet_authority";
    "applies_to_actions"?: string[];
    "not_before"?: string;
    "expires_at"?: string;
    "recurrence"?: {
      "frequency"?: "daily" | "weekly" | "monthly" | "custom";
      "days"?: Array<"mon" | "tue" | "wed" | "thu" | "fri" | "sat" | "sun">;
      "window_start"?: string;
      "window_end"?: string;
      "timezone"?: string;
      [key: string]: unknown;
    };
    "max_duration"?: string;
    "max_session_duration"?: string;
    "inactivity_timeout"?: string;
    "expires_after"?: string;
    "message_edit_window"?: string;
    "message_redact_window"?: string;
    "redact_after_window_allowed"?: boolean;
    "condition"?: {
      "kind": "object_is_owned_by_actor" | "actor_is_assignee" | "actor_is_responsible" | "actor_is_guardian" | "actor_is_controller" | "object_in_actor_container" | "object_is_unencrypted" | "object_is_encrypted" | "always" | "never";
      [key: string]: unknown;
    };
    "allowed_write_fields"?: string[];
    "denied_write_fields"?: string[];
    "allowed_read_fields"?: string[];
    "denied_read_fields"?: string[];
    "sensitive_fields"?: string[];
    "sensitive_handling"?: "redact" | "hash" | "omit";
    "allowed_object_kinds"?: string[];
    "denied_object_kinds"?: string[];
    "allowed_morph_kinds"?: string[];
    "denied_morph_kinds"?: string[];
    "allowed_space_kinds"?: string[];
    "denied_space_kinds"?: string[];
    "allowed_facets"?: Array<"container" | "replyable" | "schedulable" | "assignable" | "stateful" | "rankable" | "reviewable" | "notifiable" | "documentable" | "renderable">;
    "denied_facets"?: Array<"container" | "replyable" | "schedulable" | "assignable" | "stateful" | "rankable" | "reviewable" | "notifiable" | "documentable" | "renderable">;
    "allowed_view_ids"?: string[];
    "allowed_strand_ids"?: string[];
    "denied_strand_ids"?: string[];
    "allowed_space_ids"?: string[];
    "denied_space_ids"?: string[];
    "allowed_circle_ids"?: string[];
    "allowed_session_ids"?: string[];
    "allowed_view_kinds"?: string[];
    "allowed_view_renderers"?: string[];
    "denied_view_kinds"?: string[];
    "denied_view_renderers"?: string[];
    "allowed_relation_kinds"?: string[];
    "allowed_from_container_refs"?: string[];
    "allowed_to_container_refs"?: string[];
    "wip_limit_override"?: boolean;
    "allowed_tracks"?: string[];
    "denied_tracks"?: string[];
    "blob_presign_scope"?: {
      "allowed_purposes": Array<"media_inline" | "thumbnail" | "download">;
      "blob_ref_pattern"?: string;
      "realm_ids"?: string[];
    };
    "allowed_data_labels"?: string[];
    "allowed_endpoints"?: string[];
    "max_authority_depth"?: number;
    "authority_path_ids"?: string[];
    "authority_regrant_allowed"?: boolean;
    "authority_scope"?: "narrowing_only" | "same_scope" | "custom";
    "applet_id"?: string;
    "executed_by"?: {
      "kind": "account";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
    } | {
      "kind": "service";
      "service_id": string;
    };
    "registration_epoch"?: string;
    "blob_max_bytes"?: number;
    "blob_presign_max_ttl_seconds"?: number;
    "max_total_blob_bytes"?: number;
    "max_artifact_bytes"?: number;
    "max_operations"?: number;
    "period"?: string;
    "burst"?: number;
    "constraint_scope"?: "per_actor" | "per_space" | "per_realm" | "global";
    "max_resources"?: number;
    "resource_kind"?: string;
    "approval_required"?: boolean;
    "approval_mode"?: "before_commit" | "proposal_then_approve";
    "approval_actor_ids"?: string[];
    "approval_relation"?: "responsible" | "controller" | "guardian" | "realm_admin" | "custom";
    "timeout"?: string;
    "auto_reject_on_timeout"?: boolean;
    "proposal_morph_kind"?: string;
    "approval_threshold"?: "majority" | "unanimous" | "quorum" | "custom";
    "approver_ids"?: string[];
    "accountability_required"?: boolean;
    "guardian_approval_required"?: boolean;
    "controller_approval_required"?: boolean;
    "required_claims"?: unknown[];
    "trusted_claim_issuer_ids"?: string[];
    "claim_refresh_required"?: boolean;
    "claim_max_age"?: string;
    "allowed_history_access_values"?: Array<"since_join" | "all_history_for_current_members">;
    "redacted_history_allowed"?: boolean;
    "encryption_required"?: boolean;
    "min_encryption_level"?: "none" | "mls_rfc9420" | "external";
    "plaintext_fallback_allowed"?: boolean;
    "audit_trail_required"?: boolean;
    "key_rotation_period"?: string;
    "max_key_age"?: string;
    "key_backup_required"?: boolean;
    "approved_key_issuer_ids"?: string[];
    "depends_on_moderation_state"?: boolean;
  }>;
  "issued_at": string;
  "updated_by"?: {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "updated_at"?: string;
  "revoked_by"?: {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "revoked_at"?: string;
  "issuer_authority_refs": Array<{
    "kind": "grant";
    "grant_id": string;
  } | {
    "kind": "realm_root";
    "realm_id": string;
    "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null";
    "controller_epoch_at_issuance": number;
    "authority_generation": number;
  }>;
  "authority_depth"?: number;
  "authority_root_refs"?: Array<{
    "kind": "realm_root";
    "realm_id": string;
    "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null";
    "authority_generation": number;
  }>;
};

/** `invite-delivery-request.schema.json` — closed object schema. */
export type InviteDeliveryRequestBody = {
  "schema": "ak.schema.invite_delivery_request.v1";
  "invite_event": {
    "event_id": string;
    "kind": string;
    "realm_id"?: string;
    "scope_ref": {
      "kind": "realm";
      "realm_id": string;
    } | {
      "kind": "circle";
      "realm_id": string;
      "circle_id": string;
    } | {
      "kind": "sidecar";
      "realm_id": string;
      "sidecar_id": string;
    } | {
      "kind": "realm_genesis";
    };
    "actor_id": {
      "kind": "account";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
    } | {
      "kind": "service";
      "service_id": string;
    };
    "executed_by"?: {
      "kind": "account";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
    } | {
      "kind": "service";
      "service_id": string;
    };
    "authorization_ref"?: string | "ak:cell:ak.component.realm.authority_root.v1:null" | "ak.authority.direct_conversation_participant.v1" | "ak.authority.direct_conversation_bootstrap_participant.v1";
    "applet_id"?: string;
    "external_ref"?: {
      "schema"?: string;
      "protocol"?: string;
      "network_id"?: string;
      "instance_id"?: string;
      "user_id"?: string;
      "location_id"?: string;
      "event_id"?: string;
      "external_id"?: string;
      "uri"?: string;
      [key: string]: unknown;
    };
    "actor_seq": number;
    "created_at": string;
    "hlc"?: string;
    "prev_refs": string[];
    "refs"?: Array<{
      "id": string;
      "role": "state_witness" | "inclusion_proof";
      "critical": true;
      "proof": {
        "kind": "rfc6962_merkle";
        "root_field": "state_root" | "control_event_set_root";
        "root_digest": string;
        "leaf_canonical_preimage_b64u": string;
        "leaf_digest": string;
        "audit_path": string[];
        "leaf_index": number;
        "leaf_count": number;
      };
    } | {
      "id": string;
      "role": "authorized_by" | "attestation" | "parent_event" | "after" | "audit_pair" | "recovery_capability" | "did_inception" | "accountability" | "bootstrap_genesis" | "authorization_closure" | "disclosure_authorization" | "capture_stop";
      "critical": boolean;
    }>;
    "causal_refs"?: string[];
    "preconditions"?: Array<{
      "cell_id": string;
      "predicate": {
        "op": "head_eq" | "head_in" | "satisfies" | "contains";
        "value"?: unknown;
        "values"?: unknown[];
        "predicate_id"?: string;
      };
    }>;
    "auth_context"?: {
      "authority_refs": string[];
    };
    "data_basis"?: string;
    "seal_basis"?: {
      "leaves": string[];
    };
    "payload": Record<string, unknown>;
    "unsigned"?: Record<string, unknown>;
    "proofs": Array<{
      "kind": "detached_jws";
      "verification_method": string;
      "event_digest": string;
      "created_at": string;
      "signer_resolution_evidence_ref"?: string;
      "domain"?: string;
      "audience"?: string | string[];
      "proof_purpose"?: "issuer_attestation" | "holder_acceptance";
      "jws": string;
    }>;
    "requirements"?: {
      "schema"?: string[];
      "features"?: string[];
      "critical_extensions"?: Array<{
        "id": string;
        "extension_scope": "event" | "payload" | "proof" | "authz" | "reducer" | "projection" | "encryption";
        "schema_ref"?: string;
        "profile_ref"?: string;
        "parameters"?: Record<string, unknown>;
        "material_digest"?: string;
        "evidence_ref"?: string;
        "fail_closed": true;
      }>;
    };
  };
  "invite_address": {
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
    "service_resolution": {
      "inline": {
        "service_id": string;
        "service_kind": string;
        "method_history_evidence": {
          "evidence_kind": "webvh_log";
          "boundary": {
            "from_method_history_head": string;
            "from_version_id": string;
            "to_method_history_head": string;
            "to_version_id": string;
          };
          "evidence": {
            "kind": "ak.did.binding_evidence.v1";
            "method": string;
            "document_digest": string;
            "method_proofs": Array<{
              "kind": "webvh_log";
              "history_head": string;
              "witnesses": Array<{
                "witness_did": string;
                "controlling_organization_did": string;
              }>;
              "witness_proofs_digest": string;
            }>;
          };
          "log_entries": Array<Record<string, unknown>>;
          "witness_records": Array<Record<string, unknown>>;
        } | {
          "evidence_kind": "did_web_document";
          "boundary": {
            "from_method_history_head": string;
            "from_version_id": string;
            "to_method_history_head": string;
            "to_version_id": string;
          };
          "evidence": {
            "kind": "ak.did.binding_evidence.v1";
            "method": string;
            "document_digest": string;
            "method_proofs": Array<{
              "kind": "webvh_log";
              "history_head": string;
              "witnesses": Array<{
                "witness_did": string;
                "controlling_organization_did": string;
              }>;
              "witness_proofs_digest": string;
            }>;
          };
        } | {
          "evidence_kind": "did_key_expansion";
          "boundary": {
            "from_method_history_head": string;
            "from_version_id": string;
            "to_method_history_head": string;
            "to_version_id": string;
          };
          "evidence": {
            "kind": "ak.did.binding_evidence.v1";
            "method": string;
            "document_digest": string;
            "method_proofs": Array<{
              "kind": "webvh_log";
              "history_head": string;
              "witnesses": Array<{
                "witness_did": string;
                "controlling_organization_did": string;
              }>;
              "witness_proofs_digest": string;
            }>;
          };
        };
        "normalized_did_document": {
          "did": string;
          "contexts": Array<string | Record<string, unknown>>;
          "controller_dids": string[];
          "also_known_as": string[];
          "verification_methods": Array<{
            "verification_method": string;
            "controller_did": string;
            "verification_method_suite": string;
            "public_key_material": Record<string, unknown>;
            "extensions": Array<{
              "name": string;
              "value": unknown;
            }>;
          }>;
          "authentication": Array<{
            "verification_method": string;
          }>;
          "assertion_methods": Array<{
            "verification_method": string;
          }>;
          "key_agreements": Array<{
            "verification_method": string;
          }>;
          "capability_invocations": Array<{
            "verification_method": string;
          }>;
          "capability_delegations": Array<{
            "verification_method": string;
          }>;
          "services": Array<{
            "uri": string;
            "protocol_names": string[];
            "endpoint": unknown;
            "extensions": Array<{
              "name": string;
              "value": unknown;
            }>;
          }>;
          "metadata": {
            "primary_handle"?: string;
          };
          "extensions": Array<{
            "name": string;
            "value": unknown;
          }>;
        };
      };
    } | {
      "resolution_url": string;
    };
    "route_assistance"?: {
      "mirror_hints": Array<{
        "mirror_id": string;
        "service_resolution": {
          "inline": {
            "service_id": string;
            "service_kind": string;
            "method_history_evidence": {
              "evidence_kind": "webvh_log";
              "boundary": {
                "from_method_history_head": string;
                "from_version_id": string;
                "to_method_history_head": string;
                "to_version_id": string;
              };
              "evidence": {
                "kind": "ak.did.binding_evidence.v1";
                "method": string;
                "document_digest": string;
                "method_proofs": Array<{
                  "kind": "webvh_log";
                  "history_head": string;
                  "witnesses": Array<{
                    "witness_did": string;
                    "controlling_organization_did": string;
                  }>;
                  "witness_proofs_digest": string;
                }>;
              };
              "log_entries": Array<Record<string, unknown>>;
              "witness_records": Array<Record<string, unknown>>;
            } | {
              "evidence_kind": "did_web_document";
              "boundary": {
                "from_method_history_head": string;
                "from_version_id": string;
                "to_method_history_head": string;
                "to_version_id": string;
              };
              "evidence": {
                "kind": "ak.did.binding_evidence.v1";
                "method": string;
                "document_digest": string;
                "method_proofs": Array<{
                  "kind": "webvh_log";
                  "history_head": string;
                  "witnesses": Array<{
                    "witness_did": string;
                    "controlling_organization_did": string;
                  }>;
                  "witness_proofs_digest": string;
                }>;
              };
            } | {
              "evidence_kind": "did_key_expansion";
              "boundary": {
                "from_method_history_head": string;
                "from_version_id": string;
                "to_method_history_head": string;
                "to_version_id": string;
              };
              "evidence": {
                "kind": "ak.did.binding_evidence.v1";
                "method": string;
                "document_digest": string;
                "method_proofs": Array<{
                  "kind": "webvh_log";
                  "history_head": string;
                  "witnesses": Array<{
                    "witness_did": string;
                    "controlling_organization_did": string;
                  }>;
                  "witness_proofs_digest": string;
                }>;
              };
            };
            "normalized_did_document": {
              "did": string;
              "contexts": Array<string | Record<string, unknown>>;
              "controller_dids": string[];
              "also_known_as": string[];
              "verification_methods": Array<{
                "verification_method": string;
                "controller_did": string;
                "verification_method_suite": string;
                "public_key_material": Record<string, unknown>;
                "extensions": Array<{
                  "name": string;
                  "value": unknown;
                }>;
              }>;
              "authentication": Array<{
                "verification_method": string;
              }>;
              "assertion_methods": Array<{
                "verification_method": string;
              }>;
              "key_agreements": Array<{
                "verification_method": string;
              }>;
              "capability_invocations": Array<{
                "verification_method": string;
              }>;
              "capability_delegations": Array<{
                "verification_method": string;
              }>;
              "services": Array<{
                "uri": string;
                "protocol_names": string[];
                "endpoint": unknown;
                "extensions": Array<{
                  "name": string;
                  "value": unknown;
                }>;
              }>;
              "metadata": {
                "primary_handle"?: string;
              };
              "extensions": Array<{
                "name": string;
                "value": unknown;
              }>;
            };
          };
        } | {
          "resolution_url": string;
        };
      }>;
    };
  };
  "introduction_evidence": {
    "kind": "locator_ref";
    "principal_locator": {
      "schema": "ak.schema.principal_locator.v1";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
      "service_resolution": {
        "inline": {
          "service_id": string;
          "service_kind": string;
          "method_history_evidence": {
            "evidence_kind": "webvh_log";
            "boundary": {
              "from_method_history_head": string;
              "from_version_id": string;
              "to_method_history_head": string;
              "to_version_id": string;
            };
            "evidence": {
              "kind": "ak.did.binding_evidence.v1";
              "method": string;
              "document_digest": string;
              "method_proofs": Array<{
                "kind": "webvh_log";
                "history_head": string;
                "witnesses": Array<{
                  "witness_did": string;
                  "controlling_organization_did": string;
                }>;
                "witness_proofs_digest": string;
              }>;
            };
            "log_entries": Array<Record<string, unknown>>;
            "witness_records": Array<Record<string, unknown>>;
          } | {
            "evidence_kind": "did_web_document";
            "boundary": {
              "from_method_history_head": string;
              "from_version_id": string;
              "to_method_history_head": string;
              "to_version_id": string;
            };
            "evidence": {
              "kind": "ak.did.binding_evidence.v1";
              "method": string;
              "document_digest": string;
              "method_proofs": Array<{
                "kind": "webvh_log";
                "history_head": string;
                "witnesses": Array<{
                  "witness_did": string;
                  "controlling_organization_did": string;
                }>;
                "witness_proofs_digest": string;
              }>;
            };
          } | {
            "evidence_kind": "did_key_expansion";
            "boundary": {
              "from_method_history_head": string;
              "from_version_id": string;
              "to_method_history_head": string;
              "to_version_id": string;
            };
            "evidence": {
              "kind": "ak.did.binding_evidence.v1";
              "method": string;
              "document_digest": string;
              "method_proofs": Array<{
                "kind": "webvh_log";
                "history_head": string;
                "witnesses": Array<{
                  "witness_did": string;
                  "controlling_organization_did": string;
                }>;
                "witness_proofs_digest": string;
              }>;
            };
          };
          "normalized_did_document": {
            "did": string;
            "contexts": Array<string | Record<string, unknown>>;
            "controller_dids": string[];
            "also_known_as": string[];
            "verification_methods": Array<{
              "verification_method": string;
              "controller_did": string;
              "verification_method_suite": string;
              "public_key_material": Record<string, unknown>;
              "extensions": Array<{
                "name": string;
                "value": unknown;
              }>;
            }>;
            "authentication": Array<{
              "verification_method": string;
            }>;
            "assertion_methods": Array<{
              "verification_method": string;
            }>;
            "key_agreements": Array<{
              "verification_method": string;
            }>;
            "capability_invocations": Array<{
              "verification_method": string;
            }>;
            "capability_delegations": Array<{
              "verification_method": string;
            }>;
            "services": Array<{
              "uri": string;
              "protocol_names": string[];
              "endpoint": unknown;
              "extensions": Array<{
                "name": string;
                "value": unknown;
              }>;
            }>;
            "metadata": {
              "primary_handle"?: string;
            };
            "extensions": Array<{
              "name": string;
              "value": unknown;
            }>;
          };
        };
      } | {
        "resolution_url": string;
      };
      "route_assistance"?: {
        "mirror_hints": Array<{
          "mirror_id": string;
          "service_resolution": {
            "inline": {
              "service_id": string;
              "service_kind": string;
              "method_history_evidence": {
                "evidence_kind": "webvh_log";
                "boundary": {
                  "from_method_history_head": string;
                  "from_version_id": string;
                  "to_method_history_head": string;
                  "to_version_id": string;
                };
                "evidence": {
                  "kind": "ak.did.binding_evidence.v1";
                  "method": string;
                  "document_digest": string;
                  "method_proofs": Array<{
                    "kind": "webvh_log";
                    "history_head": string;
                    "witnesses": Array<{
                      "witness_did": string;
                      "controlling_organization_did": string;
                    }>;
                    "witness_proofs_digest": string;
                  }>;
                };
                "log_entries": Array<Record<string, unknown>>;
                "witness_records": Array<Record<string, unknown>>;
              } | {
                "evidence_kind": "did_web_document";
                "boundary": {
                  "from_method_history_head": string;
                  "from_version_id": string;
                  "to_method_history_head": string;
                  "to_version_id": string;
                };
                "evidence": {
                  "kind": "ak.did.binding_evidence.v1";
                  "method": string;
                  "document_digest": string;
                  "method_proofs": Array<{
                    "kind": "webvh_log";
                    "history_head": string;
                    "witnesses": Array<{
                      "witness_did": string;
                      "controlling_organization_did": string;
                    }>;
                    "witness_proofs_digest": string;
                  }>;
                };
              } | {
                "evidence_kind": "did_key_expansion";
                "boundary": {
                  "from_method_history_head": string;
                  "from_version_id": string;
                  "to_method_history_head": string;
                  "to_version_id": string;
                };
                "evidence": {
                  "kind": "ak.did.binding_evidence.v1";
                  "method": string;
                  "document_digest": string;
                  "method_proofs": Array<{
                    "kind": "webvh_log";
                    "history_head": string;
                    "witnesses": Array<{
                      "witness_did": string;
                      "controlling_organization_did": string;
                    }>;
                    "witness_proofs_digest": string;
                  }>;
                };
              };
              "normalized_did_document": {
                "did": string;
                "contexts": Array<string | Record<string, unknown>>;
                "controller_dids": string[];
                "also_known_as": string[];
                "verification_methods": Array<{
                  "verification_method": string;
                  "controller_did": string;
                  "verification_method_suite": string;
                  "public_key_material": Record<string, unknown>;
                  "extensions": Array<{
                    "name": string;
                    "value": unknown;
                  }>;
                }>;
                "authentication": Array<{
                  "verification_method": string;
                }>;
                "assertion_methods": Array<{
                  "verification_method": string;
                }>;
                "key_agreements": Array<{
                  "verification_method": string;
                }>;
                "capability_invocations": Array<{
                  "verification_method": string;
                }>;
                "capability_delegations": Array<{
                  "verification_method": string;
                }>;
                "services": Array<{
                  "uri": string;
                  "protocol_names": string[];
                  "endpoint": unknown;
                  "extensions": Array<{
                    "name": string;
                    "value": unknown;
                  }>;
                }>;
                "metadata": {
                  "primary_handle"?: string;
                };
                "extensions": Array<{
                  "name": string;
                  "value": unknown;
                }>;
              };
            };
          } | {
            "resolution_url": string;
          };
        }>;
      };
      "issued_at": string;
      "expires_at": string;
      "locator_ref_digest": string;
      "display_hint"?: {
        "display_name_hint"?: string;
        "avatar_blob_ref"?: string;
      };
      "proofs": Array<{
        "proof_purpose": "subject_locator_authorization" | "recipient_service_acceptance";
        "proof": {
          "kind": "detached_jws";
          "verification_method": string;
          "payload_digest": string;
          "created_at": string;
          "domain"?: string;
          "audience"?: string | string[];
          "proof_purpose"?: "issuer_attestation" | "holder_acceptance" | "status_attestation" | "revocation_authorization" | "governance_authorization";
          "jws": string;
        };
      }>;
    };
  } | {
    "kind": "consent_grant";
    "consent_grant_ref": string;
    "consent_id"?: string;
  } | {
    "kind": "shared_realm";
    "realm_id": string;
    "inviter_member_ref": string;
    "invitee_member_ref": string;
  } | {
    "kind": "handle_claim";
    "handle": string;
    "handle_claim": {
      "schema": "ak.schema.handle_claim.v1";
      "claim": {
        "schema": "ak.schema.handle_claim_core.v1";
        "handle": string;
        "handle_aliases": string[];
        "subject_account_id": {
          "principal_id": string;
          "station_id": string;
        };
        "issuer_id": string;
        "claim": {
          "kind": "handle_binding";
        } | {
          "kind": "organization_handle";
          "organization_id": string;
        };
        "visibility": "public" | "restricted" | "private";
        "audience": string | null;
        "issued_at": string;
        "expires_at": string | null;
        "source_refs": string[];
        "proofs": unknown[];
      };
      "status": "pending" | "verified" | "revoked";
      "as_of": string;
      "verifier_id": string;
      "verified_at": string | null;
      "revocation": {
        "schema": "ak.schema.handle_claim_revocation.v1";
        "claim_digest": string;
        "revoked_at": string;
        "revoker": {
          "role": "issuer";
          "issuer_id": string;
        } | {
          "role": "holder";
          "subject_account_id": {
            "principal_id": string;
            "station_id": string;
          };
        };
        "proof": {
          "kind": "detached_jws";
          "verification_method": string;
          "payload_digest": string;
          "created_at": string;
          "domain"?: string;
          "audience"?: string | string[];
          "proof_purpose"?: "issuer_attestation" | "holder_acceptance" | "status_attestation" | "revocation_authorization" | "governance_authorization";
          "jws": string;
        } & {
          "domain": "ak.handle_claim_revocation.v1";
          "proof_purpose": "revocation_authorization";
          [key: string]: unknown;
        };
      } | null;
      "fresh_until": string;
      "status_proof": {
        "kind": "detached_jws";
        "verification_method": string;
        "payload_digest": string;
        "created_at": string;
        "domain"?: string;
        "audience"?: string | string[];
        "proof_purpose"?: "issuer_attestation" | "holder_acceptance" | "status_attestation" | "revocation_authorization" | "governance_authorization";
        "jws": string;
      } & {
        "domain": "ak.handle_claim_status.v1";
        "proof_purpose": "status_attestation";
        [key: string]: unknown;
      };
    };
    "resolved_by"?: string;
    "resolved_at"?: string;
  } | {
    "kind": "explicit_address";
  };
  "idempotency_key": string;
};

/** `invite-delivery-request.schema.json#/$defs/self_invite_dispatch_request_body` — closed object schema. */
export type SelfInviteDispatchRequestBody = {
  "schema": "ak.schema.invite_delivery_request.v1";
  "invite_event_id": string;
  "invite_address": {
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
    "service_resolution": {
      "inline": {
        "service_id": string;
        "service_kind": string;
        "method_history_evidence": {
          "evidence_kind": "webvh_log";
          "boundary": {
            "from_method_history_head": string;
            "from_version_id": string;
            "to_method_history_head": string;
            "to_version_id": string;
          };
          "evidence": {
            "kind": "ak.did.binding_evidence.v1";
            "method": string;
            "document_digest": string;
            "method_proofs": Array<{
              "kind": "webvh_log";
              "history_head": string;
              "witnesses": Array<{
                "witness_did": string;
                "controlling_organization_did": string;
              }>;
              "witness_proofs_digest": string;
            }>;
          };
          "log_entries": Array<Record<string, unknown>>;
          "witness_records": Array<Record<string, unknown>>;
        } | {
          "evidence_kind": "did_web_document";
          "boundary": {
            "from_method_history_head": string;
            "from_version_id": string;
            "to_method_history_head": string;
            "to_version_id": string;
          };
          "evidence": {
            "kind": "ak.did.binding_evidence.v1";
            "method": string;
            "document_digest": string;
            "method_proofs": Array<{
              "kind": "webvh_log";
              "history_head": string;
              "witnesses": Array<{
                "witness_did": string;
                "controlling_organization_did": string;
              }>;
              "witness_proofs_digest": string;
            }>;
          };
        } | {
          "evidence_kind": "did_key_expansion";
          "boundary": {
            "from_method_history_head": string;
            "from_version_id": string;
            "to_method_history_head": string;
            "to_version_id": string;
          };
          "evidence": {
            "kind": "ak.did.binding_evidence.v1";
            "method": string;
            "document_digest": string;
            "method_proofs": Array<{
              "kind": "webvh_log";
              "history_head": string;
              "witnesses": Array<{
                "witness_did": string;
                "controlling_organization_did": string;
              }>;
              "witness_proofs_digest": string;
            }>;
          };
        };
        "normalized_did_document": {
          "did": string;
          "contexts": Array<string | Record<string, unknown>>;
          "controller_dids": string[];
          "also_known_as": string[];
          "verification_methods": Array<{
            "verification_method": string;
            "controller_did": string;
            "verification_method_suite": string;
            "public_key_material": Record<string, unknown>;
            "extensions": Array<{
              "name": string;
              "value": unknown;
            }>;
          }>;
          "authentication": Array<{
            "verification_method": string;
          }>;
          "assertion_methods": Array<{
            "verification_method": string;
          }>;
          "key_agreements": Array<{
            "verification_method": string;
          }>;
          "capability_invocations": Array<{
            "verification_method": string;
          }>;
          "capability_delegations": Array<{
            "verification_method": string;
          }>;
          "services": Array<{
            "uri": string;
            "protocol_names": string[];
            "endpoint": unknown;
            "extensions": Array<{
              "name": string;
              "value": unknown;
            }>;
          }>;
          "metadata": {
            "primary_handle"?: string;
          };
          "extensions": Array<{
            "name": string;
            "value": unknown;
          }>;
        };
      };
    } | {
      "resolution_url": string;
    };
    "route_assistance"?: {
      "mirror_hints": Array<{
        "mirror_id": string;
        "service_resolution": {
          "inline": {
            "service_id": string;
            "service_kind": string;
            "method_history_evidence": {
              "evidence_kind": "webvh_log";
              "boundary": {
                "from_method_history_head": string;
                "from_version_id": string;
                "to_method_history_head": string;
                "to_version_id": string;
              };
              "evidence": {
                "kind": "ak.did.binding_evidence.v1";
                "method": string;
                "document_digest": string;
                "method_proofs": Array<{
                  "kind": "webvh_log";
                  "history_head": string;
                  "witnesses": Array<{
                    "witness_did": string;
                    "controlling_organization_did": string;
                  }>;
                  "witness_proofs_digest": string;
                }>;
              };
              "log_entries": Array<Record<string, unknown>>;
              "witness_records": Array<Record<string, unknown>>;
            } | {
              "evidence_kind": "did_web_document";
              "boundary": {
                "from_method_history_head": string;
                "from_version_id": string;
                "to_method_history_head": string;
                "to_version_id": string;
              };
              "evidence": {
                "kind": "ak.did.binding_evidence.v1";
                "method": string;
                "document_digest": string;
                "method_proofs": Array<{
                  "kind": "webvh_log";
                  "history_head": string;
                  "witnesses": Array<{
                    "witness_did": string;
                    "controlling_organization_did": string;
                  }>;
                  "witness_proofs_digest": string;
                }>;
              };
            } | {
              "evidence_kind": "did_key_expansion";
              "boundary": {
                "from_method_history_head": string;
                "from_version_id": string;
                "to_method_history_head": string;
                "to_version_id": string;
              };
              "evidence": {
                "kind": "ak.did.binding_evidence.v1";
                "method": string;
                "document_digest": string;
                "method_proofs": Array<{
                  "kind": "webvh_log";
                  "history_head": string;
                  "witnesses": Array<{
                    "witness_did": string;
                    "controlling_organization_did": string;
                  }>;
                  "witness_proofs_digest": string;
                }>;
              };
            };
            "normalized_did_document": {
              "did": string;
              "contexts": Array<string | Record<string, unknown>>;
              "controller_dids": string[];
              "also_known_as": string[];
              "verification_methods": Array<{
                "verification_method": string;
                "controller_did": string;
                "verification_method_suite": string;
                "public_key_material": Record<string, unknown>;
                "extensions": Array<{
                  "name": string;
                  "value": unknown;
                }>;
              }>;
              "authentication": Array<{
                "verification_method": string;
              }>;
              "assertion_methods": Array<{
                "verification_method": string;
              }>;
              "key_agreements": Array<{
                "verification_method": string;
              }>;
              "capability_invocations": Array<{
                "verification_method": string;
              }>;
              "capability_delegations": Array<{
                "verification_method": string;
              }>;
              "services": Array<{
                "uri": string;
                "protocol_names": string[];
                "endpoint": unknown;
                "extensions": Array<{
                  "name": string;
                  "value": unknown;
                }>;
              }>;
              "metadata": {
                "primary_handle"?: string;
              };
              "extensions": Array<{
                "name": string;
                "value": unknown;
              }>;
            };
          };
        } | {
          "resolution_url": string;
        };
      }>;
    };
  };
  "introduction_evidence": {
    "kind": "locator_ref";
    "principal_locator": {
      "schema": "ak.schema.principal_locator.v1";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
      "service_resolution": {
        "inline": {
          "service_id": string;
          "service_kind": string;
          "method_history_evidence": {
            "evidence_kind": "webvh_log";
            "boundary": {
              "from_method_history_head": string;
              "from_version_id": string;
              "to_method_history_head": string;
              "to_version_id": string;
            };
            "evidence": {
              "kind": "ak.did.binding_evidence.v1";
              "method": string;
              "document_digest": string;
              "method_proofs": Array<{
                "kind": "webvh_log";
                "history_head": string;
                "witnesses": Array<{
                  "witness_did": string;
                  "controlling_organization_did": string;
                }>;
                "witness_proofs_digest": string;
              }>;
            };
            "log_entries": Array<Record<string, unknown>>;
            "witness_records": Array<Record<string, unknown>>;
          } | {
            "evidence_kind": "did_web_document";
            "boundary": {
              "from_method_history_head": string;
              "from_version_id": string;
              "to_method_history_head": string;
              "to_version_id": string;
            };
            "evidence": {
              "kind": "ak.did.binding_evidence.v1";
              "method": string;
              "document_digest": string;
              "method_proofs": Array<{
                "kind": "webvh_log";
                "history_head": string;
                "witnesses": Array<{
                  "witness_did": string;
                  "controlling_organization_did": string;
                }>;
                "witness_proofs_digest": string;
              }>;
            };
          } | {
            "evidence_kind": "did_key_expansion";
            "boundary": {
              "from_method_history_head": string;
              "from_version_id": string;
              "to_method_history_head": string;
              "to_version_id": string;
            };
            "evidence": {
              "kind": "ak.did.binding_evidence.v1";
              "method": string;
              "document_digest": string;
              "method_proofs": Array<{
                "kind": "webvh_log";
                "history_head": string;
                "witnesses": Array<{
                  "witness_did": string;
                  "controlling_organization_did": string;
                }>;
                "witness_proofs_digest": string;
              }>;
            };
          };
          "normalized_did_document": {
            "did": string;
            "contexts": Array<string | Record<string, unknown>>;
            "controller_dids": string[];
            "also_known_as": string[];
            "verification_methods": Array<{
              "verification_method": string;
              "controller_did": string;
              "verification_method_suite": string;
              "public_key_material": Record<string, unknown>;
              "extensions": Array<{
                "name": string;
                "value": unknown;
              }>;
            }>;
            "authentication": Array<{
              "verification_method": string;
            }>;
            "assertion_methods": Array<{
              "verification_method": string;
            }>;
            "key_agreements": Array<{
              "verification_method": string;
            }>;
            "capability_invocations": Array<{
              "verification_method": string;
            }>;
            "capability_delegations": Array<{
              "verification_method": string;
            }>;
            "services": Array<{
              "uri": string;
              "protocol_names": string[];
              "endpoint": unknown;
              "extensions": Array<{
                "name": string;
                "value": unknown;
              }>;
            }>;
            "metadata": {
              "primary_handle"?: string;
            };
            "extensions": Array<{
              "name": string;
              "value": unknown;
            }>;
          };
        };
      } | {
        "resolution_url": string;
      };
      "route_assistance"?: {
        "mirror_hints": Array<{
          "mirror_id": string;
          "service_resolution": {
            "inline": {
              "service_id": string;
              "service_kind": string;
              "method_history_evidence": {
                "evidence_kind": "webvh_log";
                "boundary": {
                  "from_method_history_head": string;
                  "from_version_id": string;
                  "to_method_history_head": string;
                  "to_version_id": string;
                };
                "evidence": {
                  "kind": "ak.did.binding_evidence.v1";
                  "method": string;
                  "document_digest": string;
                  "method_proofs": Array<{
                    "kind": "webvh_log";
                    "history_head": string;
                    "witnesses": Array<{
                      "witness_did": string;
                      "controlling_organization_did": string;
                    }>;
                    "witness_proofs_digest": string;
                  }>;
                };
                "log_entries": Array<Record<string, unknown>>;
                "witness_records": Array<Record<string, unknown>>;
              } | {
                "evidence_kind": "did_web_document";
                "boundary": {
                  "from_method_history_head": string;
                  "from_version_id": string;
                  "to_method_history_head": string;
                  "to_version_id": string;
                };
                "evidence": {
                  "kind": "ak.did.binding_evidence.v1";
                  "method": string;
                  "document_digest": string;
                  "method_proofs": Array<{
                    "kind": "webvh_log";
                    "history_head": string;
                    "witnesses": Array<{
                      "witness_did": string;
                      "controlling_organization_did": string;
                    }>;
                    "witness_proofs_digest": string;
                  }>;
                };
              } | {
                "evidence_kind": "did_key_expansion";
                "boundary": {
                  "from_method_history_head": string;
                  "from_version_id": string;
                  "to_method_history_head": string;
                  "to_version_id": string;
                };
                "evidence": {
                  "kind": "ak.did.binding_evidence.v1";
                  "method": string;
                  "document_digest": string;
                  "method_proofs": Array<{
                    "kind": "webvh_log";
                    "history_head": string;
                    "witnesses": Array<{
                      "witness_did": string;
                      "controlling_organization_did": string;
                    }>;
                    "witness_proofs_digest": string;
                  }>;
                };
              };
              "normalized_did_document": {
                "did": string;
                "contexts": Array<string | Record<string, unknown>>;
                "controller_dids": string[];
                "also_known_as": string[];
                "verification_methods": Array<{
                  "verification_method": string;
                  "controller_did": string;
                  "verification_method_suite": string;
                  "public_key_material": Record<string, unknown>;
                  "extensions": Array<{
                    "name": string;
                    "value": unknown;
                  }>;
                }>;
                "authentication": Array<{
                  "verification_method": string;
                }>;
                "assertion_methods": Array<{
                  "verification_method": string;
                }>;
                "key_agreements": Array<{
                  "verification_method": string;
                }>;
                "capability_invocations": Array<{
                  "verification_method": string;
                }>;
                "capability_delegations": Array<{
                  "verification_method": string;
                }>;
                "services": Array<{
                  "uri": string;
                  "protocol_names": string[];
                  "endpoint": unknown;
                  "extensions": Array<{
                    "name": string;
                    "value": unknown;
                  }>;
                }>;
                "metadata": {
                  "primary_handle"?: string;
                };
                "extensions": Array<{
                  "name": string;
                  "value": unknown;
                }>;
              };
            };
          } | {
            "resolution_url": string;
          };
        }>;
      };
      "issued_at": string;
      "expires_at": string;
      "locator_ref_digest": string;
      "display_hint"?: {
        "display_name_hint"?: string;
        "avatar_blob_ref"?: string;
      };
      "proofs": Array<{
        "proof_purpose": "subject_locator_authorization" | "recipient_service_acceptance";
        "proof": {
          "kind": "detached_jws";
          "verification_method": string;
          "payload_digest": string;
          "created_at": string;
          "domain"?: string;
          "audience"?: string | string[];
          "proof_purpose"?: "issuer_attestation" | "holder_acceptance" | "status_attestation" | "revocation_authorization" | "governance_authorization";
          "jws": string;
        };
      }>;
    };
  } | {
    "kind": "consent_grant";
    "consent_grant_ref": string;
    "consent_id"?: string;
  } | {
    "kind": "shared_realm";
    "realm_id": string;
    "inviter_member_ref": string;
    "invitee_member_ref": string;
  } | {
    "kind": "handle_claim";
    "handle": string;
    "handle_claim": {
      "schema": "ak.schema.handle_claim.v1";
      "claim": {
        "schema": "ak.schema.handle_claim_core.v1";
        "handle": string;
        "handle_aliases": string[];
        "subject_account_id": {
          "principal_id": string;
          "station_id": string;
        };
        "issuer_id": string;
        "claim": {
          "kind": "handle_binding";
        } | {
          "kind": "organization_handle";
          "organization_id": string;
        };
        "visibility": "public" | "restricted" | "private";
        "audience": string | null;
        "issued_at": string;
        "expires_at": string | null;
        "source_refs": string[];
        "proofs": unknown[];
      };
      "status": "pending" | "verified" | "revoked";
      "as_of": string;
      "verifier_id": string;
      "verified_at": string | null;
      "revocation": {
        "schema": "ak.schema.handle_claim_revocation.v1";
        "claim_digest": string;
        "revoked_at": string;
        "revoker": {
          "role": "issuer";
          "issuer_id": string;
        } | {
          "role": "holder";
          "subject_account_id": {
            "principal_id": string;
            "station_id": string;
          };
        };
        "proof": {
          "kind": "detached_jws";
          "verification_method": string;
          "payload_digest": string;
          "created_at": string;
          "domain"?: string;
          "audience"?: string | string[];
          "proof_purpose"?: "issuer_attestation" | "holder_acceptance" | "status_attestation" | "revocation_authorization" | "governance_authorization";
          "jws": string;
        } & {
          "domain": "ak.handle_claim_revocation.v1";
          "proof_purpose": "revocation_authorization";
          [key: string]: unknown;
        };
      } | null;
      "fresh_until": string;
      "status_proof": {
        "kind": "detached_jws";
        "verification_method": string;
        "payload_digest": string;
        "created_at": string;
        "domain"?: string;
        "audience"?: string | string[];
        "proof_purpose"?: "issuer_attestation" | "holder_acceptance" | "status_attestation" | "revocation_authorization" | "governance_authorization";
        "jws": string;
      } & {
        "domain": "ak.handle_claim_status.v1";
        "proof_purpose": "status_attestation";
        [key: string]: unknown;
      };
    };
    "resolved_by"?: string;
    "resolved_at"?: string;
  } | {
    "kind": "explicit_address";
  };
  "idempotency_key": string;
};

/** `service-operation-dtos.schema.json#/$defs/RealmSealFrontierView` — closed object schema. */
export type RealmSealFrontierView = {
  "kind": "realm_seal";
  "realm_id": string;
  "seal_basis": {
    "leaves": string[];
  };
  "live_digest_suite": "sha256" | "blake3";
  "governance_health": {
    "status": "healthy" | "degraded";
    "pending_proposals": Array<{
      "control_proposal_ack": {
        "kind": "signed_ack";
        "realm_id": string;
        "proposal_digest": string;
        "received_at": string;
        "decision_due_at": string;
        "absolute_due_at": string;
        "defer_count": 0;
        "authority_set_ref": string;
        "signature": {
          "verification_method": string;
          "payload_digest": string;
          "created_at": string;
          "jws": string;
        };
      };
      "decisions": Array<{
        "kind": "signed_defer";
        "realm_id": string;
        "proposal_digest": string;
        "proposal_ack_digest": string;
        "decided_at": string;
        "decision_due_at": string;
        "absolute_due_at": string;
        "defer_count": number;
        "reason_code": "dependency_missing" | "temporarily_unavailable";
        "authority_set_ref": string;
        "proof": {
          "verification_method": string;
          "payload_digest": string;
          "created_at": string;
          "jws": string;
        };
      }>;
      "decision_state": "pending" | "deferred" | "overdue";
      "fault_reason"?: "control_proposal_decision_overdue";
      "device_revocation_state"?: {
        "schema": "ak.schema.device_revocation_state.v1";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
        "device_id": string;
        "target_device_authorize_event_id": string;
        "target_device_generation_ref": number;
        "proposal_event_id": string;
        "accepted_at": string;
        "acceptance_seq": number;
        "control_proposal_ack": {
          "kind": "signed_ack";
          "realm_id": string;
          "proposal_digest": string;
          "received_at": string;
          "decision_due_at": string;
          "absolute_due_at": string;
          "defer_count": 0;
          "authority_set_ref": string;
          "signature": {
            "verification_method": string;
            "payload_digest": string;
            "created_at": string;
            "jws": string;
          };
        };
        "status": "revocation_pending";
        "decision_state": "pending" | "deferred" | "overdue";
        "denied_actions": unknown[];
        "decisions"?: Array<{
          "kind": "signed_defer";
          "realm_id": string;
          "proposal_digest": string;
          "proposal_ack_digest": string;
          "decided_at": string;
          "decision_due_at": string;
          "absolute_due_at": string;
          "defer_count": number;
          "reason_code": "dependency_missing" | "temporarily_unavailable";
          "authority_set_ref": string;
          "proof": {
            "verification_method": string;
            "payload_digest": string;
            "created_at": string;
            "jws": string;
          };
        }>;
        "fault_reason"?: "control_proposal_decision_overdue";
        [key: string]: unknown;
      };
    }>;
    "pending_proposals_complete": boolean;
  };
  "observation_coordinate": {
    "service_id": string;
    "sequence": number;
    "observed_at": string;
  };
};

/** `service-operation-dtos.schema.json#/$defs/EventFederationSubmission` — closed object schema. */
export type EventFederationSubmission = {
  "event": {
    "event_id": string;
    "kind": "ak.actor.discovery" | "ak.agent.action_approve" | "ak.agent.key.authorize" | "ak.agent.key.revoke" | "ak.agent.provision" | "ak.agent.selector_claim" | "ak.agent.sidecar.exchange.control" | "ak.applet.bridge_error" | "ak.applet.discovery" | "ak.applet.managed_actor.provision" | "ak.applet.registration" | "ak.audit.accessed" | "ak.audit.applet_binding.create" | "ak.audit.applet_binding.state" | "ak.audit.erasure_receipt" | "ak.audit.release" | "ak.audit.ryw_receipt" | "ak.audit.session.authorize" | "ak.audit.session.close" | "ak.audit.session.notice" | "ak.audit.session.request" | "ak.call.create" | "ak.call.recording.start" | "ak.call.state" | "ak.call.summary" | "ak.capability.derived" | "ak.capability.grant" | "ak.capability.relinquish" | "ak.capability.revoke" | "ak.circle.archive" | "ak.circle.create" | "ak.circle.history_access" | "ak.circle.member.state" | "ak.circle.restore" | "ak.circle.tombstone" | "ak.circle.update" | "ak.consent.grant" | "ak.consent.revoke" | "ak.contact.accepted" | "ak.contact.rejected" | "ak.contact.requested" | "ak.contact.scope.update" | "ak.contact.tombstone" | "ak.container.move_item" | "ak.container.rebalance" | "ak.device.authorize" | "ak.device.list_update" | "ak.device.reanchor" | "ak.device.revoke" | "ak.direct_conversation.bound" | "ak.fork.resolution" | "ak.handle.discovery" | "ak.identity.accountability_grant" | "ak.identity.resolution.update" | "ak.invite.accept" | "ak.invite.cancel" | "ak.invite.claim" | "ak.invite.create" | "ak.invite.revoke" | "ak.invite.third_party" | "ak.key_backup.active_series" | "ak.member.identity.update" | "ak.member.state" | "ak.message.create" | "ak.message.redact" | "ak.message.revise" | "ak.mimi.room_binding" | "ak.mls.commit" | "ak.mls.commit_failed" | "ak.mls.genesis" | "ak.mls.keypackage" | "ak.mls.proposal" | "ak.mls.welcome" | "ak.moderation.decision" | "ak.moderation.decision.lift" | "ak.moderation.franking_proof" | "ak.morph.archive" | "ak.morph.create" | "ak.morph.restore" | "ak.morph.stage.set" | "ak.morph.update" | "ak.notary.fault.censorship" | "ak.notary.fault.equivocation" | "ak.organization.discovery" | "ak.organization.moderation_policy" | "ak.pin.add" | "ak.pin.remove" | "ak.pin.reorder" | "ak.policy.action" | "ak.policy.rule" | "ak.policy.set" | "ak.profile.create" | "ak.profile.realm_override" | "ak.profile.update" | "ak.reaction.add" | "ak.reaction.remove" | "ak.realm.alias" | "ak.realm.archive" | "ak.realm.asset_privacy_policy" | "ak.realm.authority.reset" | "ak.realm.create" | "ak.realm.destroy" | "ak.realm.digest_suite_transition" | "ak.realm.discovery" | "ak.realm.freeze" | "ak.realm.history_access" | "ak.realm.inheritance_policy" | "ak.realm.join_rule" | "ak.realm.link" | "ak.realm.media_service" | "ak.realm.notary" | "ak.realm.organization" | "ak.realm.organization_recovery_key.register" | "ak.realm.organization_recovery_key.rotate" | "ak.realm.owner.transfer" | "ak.realm.plaintext_visible_services" | "ak.realm.policy" | "ak.realm.policy_bundle" | "ak.realm.preview_policy" | "ak.realm.profile" | "ak.realm.read_receipt_policy" | "ak.realm.restore" | "ak.realm.schema" | "ak.realm.search_policy" | "ak.realm.set_default_strand" | "ak.realm.tombstone" | "ak.realm.unfreeze" | "ak.realm.upgrade" | "ak.redaction" | "ak.relation.create" | "ak.relation.resolve" | "ak.relation.tombstone" | "ak.relation.update" | "ak.rsvp.set" | "ak.schema.define" | "ak.self.agent.deactivate" | "ak.self.agent.pause" | "ak.self.agent.resume" | "ak.self.moderation.report" | "ak.sidecar.context.attach" | "ak.sidecar.create" | "ak.sovereign.did_policy" | "ak.space.archive" | "ak.space.create" | "ak.space.parent" | "ak.space.restore" | "ak.space.tombstone" | "ak.space.update" | "ak.strand.archive" | "ak.strand.create" | "ak.strand.move" | "ak.strand.reorder" | "ak.strand.restore" | "ak.strand.stage.set" | "ak.strand.tracks.update" | "ak.strand.update" | "ak.strand.watch.set" | "ak.view.create" | "ak.view.reconcile" | "ak.view.update";
    "realm_id"?: string;
    "scope_ref": {
      "kind": "realm";
      "realm_id": string;
    } | {
      "kind": "circle";
      "realm_id": string;
      "circle_id": string;
    } | {
      "kind": "sidecar";
      "realm_id": string;
      "sidecar_id": string;
    } | {
      "kind": "realm_genesis";
    };
    "actor_id": {
      "kind": "account";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
    } | {
      "kind": "service";
      "service_id": string;
    };
    "executed_by"?: {
      "kind": "account";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
    } | {
      "kind": "service";
      "service_id": string;
    };
    "authorization_ref"?: string | "ak:cell:ak.component.realm.authority_root.v1:null" | "ak.authority.direct_conversation_participant.v1" | "ak.authority.direct_conversation_bootstrap_participant.v1";
    "applet_id"?: string;
    "external_ref"?: {
      "schema"?: string;
      "protocol"?: string;
      "network_id"?: string;
      "instance_id"?: string;
      "user_id"?: string;
      "location_id"?: string;
      "event_id"?: string;
      "external_id"?: string;
      "uri"?: string;
      [key: string]: unknown;
    };
    "actor_seq": number;
    "created_at": string;
    "hlc"?: string;
    "prev_refs": string[];
    "refs"?: Array<{
      "id": string;
      "role": "state_witness" | "inclusion_proof";
      "critical": true;
      "proof": {
        "kind": "rfc6962_merkle";
        "root_field": "state_root" | "control_event_set_root";
        "root_digest": string;
        "leaf_canonical_preimage_b64u": string;
        "leaf_digest": string;
        "audit_path": string[];
        "leaf_index": number;
        "leaf_count": number;
      };
    } | {
      "id": string;
      "role": "authorized_by" | "attestation" | "parent_event" | "after" | "audit_pair" | "recovery_capability" | "did_inception" | "accountability" | "bootstrap_genesis" | "authorization_closure" | "disclosure_authorization" | "capture_stop";
      "critical": boolean;
    }>;
    "causal_refs"?: string[];
    "preconditions"?: Array<{
      "cell_id": string;
      "predicate": {
        "op": "head_eq" | "head_in" | "satisfies" | "contains";
        "value"?: unknown;
        "values"?: unknown[];
        "predicate_id"?: string;
      };
    }>;
    "auth_context"?: {
      "authority_refs": string[];
    };
    "data_basis"?: string;
    "seal_basis"?: {
      "leaves": string[];
    };
    "payload": Record<string, unknown>;
    "unsigned"?: Record<string, unknown>;
    "proofs": unknown;
    "requirements"?: {
      "schema"?: string[];
      "features"?: string[];
      "critical_extensions"?: Array<{
        "id": string;
        "extension_scope": "event" | "payload" | "proof" | "authz" | "reducer" | "projection" | "encryption";
        "schema_ref"?: string;
        "profile_ref"?: string;
        "parameters"?: Record<string, unknown>;
        "material_digest"?: string;
        "evidence_ref"?: string;
        "fail_closed": true;
      }>;
    };
  };
  "mls_frontier_leaves"?: Array<{
    "leaf_index": number;
    "actor_id": {
      "kind": "account";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
    } | {
      "kind": "service";
      "service_id": string;
    };
    "credential_ref": string;
  }>;
  "authorization_lease"?: {
    "authorization_lease_id": string;
    "basis_ref": string | {
      "leaves": string[];
    } | {
      "anchor_unit": {
        "realm_id": string;
        "event_digests": string[];
        "unit_digest": string;
      };
    };
    "actor_id": {
      "kind": "account";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
    } | {
      "kind": "service";
      "service_id": string;
    };
    "device_id": string;
    "scope_ref": {
      "kind": "realm";
      "realm_id": string;
    } | {
      "kind": "circle";
      "realm_id": string;
      "circle_id": string;
    } | {
      "kind": "sidecar";
      "realm_id": string;
      "sidecar_id": string;
    } | {
      "kind": "realm_genesis";
    };
    "action": string;
    "authorization_rule_id": string;
    "risk_tier": "low" | "medium" | "high";
    "issued_at": string;
    "expires_at": string;
    "authority_set_ref": {
      "authority_set_id": string;
      "authority_set_digest": string;
    };
    "authority_set_policy": {
      "schema": "ak.schema.authority_set_policy.v1";
      "authority_set_id": string;
      "policy_kind": "principal_control" | "realm_admission";
      "scope_ref": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      } | {
        "kind": "sidecar";
        "realm_id": string;
        "sidecar_id": string;
      } | {
        "kind": "realm_genesis";
      };
      "source": {
        "source_kind": "did_document" | "pcr_device_directory" | "recovery_policy" | "realm_control";
        "source_ref": string;
        "source_digest": string;
        "generation_ref": string;
      };
      "authorization_rules": Array<{
        "rule_id": string;
        "issuer_role": "identity_recovery" | "accepted_device" | "realm_admission";
        "allowed_actions": string[];
        "issuers": Array<{
          "verification_method": string;
        }>;
        "threshold": number;
      }>;
    };
    "proofs": Array<{
      "kind": "detached_jws";
      "verification_method": string;
      "payload_digest": string;
      "created_at": string;
      "domain"?: string;
      "audience"?: string | string[];
      "proof_purpose"?: "issuer_attestation" | "holder_acceptance" | "status_attestation" | "revocation_authorization" | "governance_authorization";
      "jws": string;
    }>;
  };
  "ingress_receipts": Array<{
    "receipt_id": string;
    "event_digest": string;
    "qualified_ingress_did": string;
    "received_at": string;
    "ingress_frontier": string[];
    "proofs": Array<{
      "kind": "detached_jws";
      "verification_method": string;
      "payload_digest": string;
      "created_at": string;
      "domain"?: string;
      "audience"?: string | string[];
      "proof_purpose"?: "issuer_attestation" | "holder_acceptance" | "status_attestation" | "revocation_authorization" | "governance_authorization";
      "jws": string;
    }>;
  }>;
  "control_proposal_ack"?: {
    "kind": "signed_ack";
    "realm_id": string;
    "proposal_digest": string;
    "received_at": string;
    "decision_due_at": string;
    "absolute_due_at": string;
    "defer_count": 0;
    "authority_set_ref": string;
    "signature": {
      "verification_method": string;
      "payload_digest": string;
      "created_at": string;
      "jws": string;
    };
  };
  "ackless_self_principal_admission_evidence"?: {
    "device_id": string;
    "device_authorize_event_id": string;
    "device_generation_ref": number;
    "seal_basis_digest": string;
  };
  "membership_compensation_evidence"?: {
    "delegation": {
      "delegation_id": string;
      "core": {
        "authority": "ak.authority.membership_compensation.v1";
        "admission_id": string;
        "join_event_id": string;
        "membership_cell_id": string;
        "member_id": {
          "kind": "account";
          "account_id": {
            "principal_id": string;
            "station_id": string;
          };
        } | {
          "kind": "service";
          "service_id": string;
        };
        "join_actor_id": {
          "kind": "account";
          "account_id": {
            "principal_id": string;
            "station_id": string;
          };
        } | {
          "kind": "service";
          "service_id": string;
        };
        "executed_by"?: {
          "kind": "account";
          "account_id": {
            "principal_id": string;
            "station_id": string;
          };
        } | {
          "kind": "service";
          "service_id": string;
        };
        "authorization_ref"?: string | "ak:cell:ak.component.realm.authority_root.v1:null" | "ak.authority.direct_conversation_participant.v1" | "ak.authority.direct_conversation_bootstrap_participant.v1";
        "verification_method": string;
        "executor_id": {
          "kind": "account";
          "account_id": {
            "principal_id": string;
            "station_id": string;
          };
        } | {
          "kind": "service";
          "service_id": string;
        };
        "executor_proof_key_kid": string;
        "resource_id": string;
        "action": "ak.member.compensate.leave" | "ak.member.compensate.remove";
        "deadline": string;
      };
      "signature": {
        "verification_method": string;
        "created_at": string;
        "jws": string;
      };
    };
    "join_accepted_proof": {
      "admission_id": string;
      "join_event_id": string;
      "accepted_at": string;
      "issuer_id": string;
      "signature": {
        "verification_method": string;
        "created_at": string;
        "jws": string;
      };
    };
    "terminal_certificate": {
      "domain": "ak.membership_compensation.terminal_certificate.v1";
      "admission_id": string;
      "delegation_id": string;
      "operation_id": string;
      "terminal_state": "failed_after_membership_acceptance" | "failed_after_mls_add";
      "certified_at": string;
      "issuer_id": string;
      "signature": {
        "verification_method": string;
        "created_at": string;
        "jws": string;
      };
    };
    "single_use_cas_token": {
      "domain": "ak.membership_compensation.single_use_cas.v1";
      "admission_id": string;
      "delegation_id": string;
      "expected_state": "unused";
      "destination_id": string;
      "issued_at": string;
      "expires_at": string;
      "issuer_id": string;
      "signature": {
        "verification_method": string;
        "created_at": string;
        "jws": string;
      };
    };
  };
  "publication_event"?: {
    "kind"?: "ak.actor.discovery" | "ak.agent.action_approve" | "ak.agent.key.authorize" | "ak.agent.key.revoke" | "ak.agent.provision" | "ak.agent.selector_claim" | "ak.agent.sidecar.exchange.control" | "ak.applet.bridge_error" | "ak.applet.discovery" | "ak.applet.managed_actor.provision" | "ak.applet.registration" | "ak.audit.accessed" | "ak.audit.applet_binding.create" | "ak.audit.applet_binding.state" | "ak.audit.release" | "ak.audit.session.authorize" | "ak.audit.session.close" | "ak.audit.session.notice" | "ak.audit.session.request" | "ak.call.create" | "ak.call.recording.start" | "ak.call.state" | "ak.call.summary" | "ak.capability.derived" | "ak.capability.grant" | "ak.capability.relinquish" | "ak.capability.revoke" | "ak.circle.archive" | "ak.circle.create" | "ak.circle.history_access" | "ak.circle.member.state" | "ak.circle.restore" | "ak.circle.tombstone" | "ak.circle.update" | "ak.consent.grant" | "ak.consent.revoke" | "ak.contact.accepted" | "ak.contact.rejected" | "ak.contact.requested" | "ak.contact.scope.update" | "ak.contact.tombstone" | "ak.container.move_item" | "ak.container.rebalance" | "ak.device.authorize" | "ak.device.list_update" | "ak.device.reanchor" | "ak.device.revoke" | "ak.direct_conversation.bound" | "ak.fork.resolution" | "ak.handle.discovery" | "ak.identity.accountability_grant" | "ak.identity.resolution.update" | "ak.invite.accept" | "ak.invite.cancel" | "ak.invite.claim" | "ak.invite.create" | "ak.invite.revoke" | "ak.invite.third_party" | "ak.key_backup.active_series" | "ak.member.identity.update" | "ak.member.state" | "ak.message.create" | "ak.message.redact" | "ak.message.revise" | "ak.mimi.room_binding" | "ak.mls.commit" | "ak.mls.commit_failed" | "ak.mls.genesis" | "ak.mls.keypackage" | "ak.mls.proposal" | "ak.mls.welcome" | "ak.moderation.decision" | "ak.moderation.decision.lift" | "ak.moderation.franking_proof" | "ak.morph.archive" | "ak.morph.create" | "ak.morph.restore" | "ak.morph.stage.set" | "ak.morph.update" | "ak.notary.fault.censorship" | "ak.notary.fault.equivocation" | "ak.organization.discovery" | "ak.organization.moderation_policy" | "ak.pin.add" | "ak.pin.remove" | "ak.pin.reorder" | "ak.policy.action" | "ak.policy.rule" | "ak.policy.set" | "ak.profile.create" | "ak.profile.realm_override" | "ak.profile.update" | "ak.reaction.add" | "ak.reaction.remove" | "ak.realm.alias" | "ak.realm.archive" | "ak.realm.asset_privacy_policy" | "ak.realm.authority.reset" | "ak.realm.create" | "ak.realm.destroy" | "ak.realm.digest_suite_transition" | "ak.realm.discovery" | "ak.realm.freeze" | "ak.realm.history_access" | "ak.realm.inheritance_policy" | "ak.realm.join_rule" | "ak.realm.link" | "ak.realm.media_service" | "ak.realm.notary" | "ak.realm.organization" | "ak.realm.organization_recovery_key.register" | "ak.realm.organization_recovery_key.rotate" | "ak.realm.owner.transfer" | "ak.realm.plaintext_visible_services" | "ak.realm.policy" | "ak.realm.policy_bundle" | "ak.realm.preview_policy" | "ak.realm.profile" | "ak.realm.read_receipt_policy" | "ak.realm.restore" | "ak.realm.schema" | "ak.realm.search_policy" | "ak.realm.set_default_strand" | "ak.realm.tombstone" | "ak.realm.unfreeze" | "ak.realm.upgrade" | "ak.redaction" | "ak.relation.create" | "ak.relation.resolve" | "ak.relation.tombstone" | "ak.relation.update" | "ak.rsvp.set" | "ak.schema.define" | "ak.self.agent.deactivate" | "ak.self.agent.pause" | "ak.self.agent.resume" | "ak.self.moderation.report" | "ak.sidecar.context.attach" | "ak.sidecar.create" | "ak.sovereign.did_policy" | "ak.space.archive" | "ak.space.create" | "ak.space.parent" | "ak.space.restore" | "ak.space.tombstone" | "ak.space.update" | "ak.strand.archive" | "ak.strand.create" | "ak.strand.move" | "ak.strand.reorder" | "ak.strand.restore" | "ak.strand.stage.set" | "ak.strand.tracks.update" | "ak.strand.update" | "ak.strand.watch.set" | "ak.view.create" | "ak.view.reconcile" | "ak.view.update";
    "refs"?: unknown;
    [key: string]: unknown;
  };
};
