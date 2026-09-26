use serde_json::Value;

/// The Event a single self submit committed or found already committed.
///
/// The submit answers with the closed `AuthoritySubmitOutcome`: an accepted
/// `{status: committed | duplicate, commit}` names the Event only through its
/// RealmCommit's `event_ref`; a rejection names none.
pub(crate) fn submitted_event_id(response: &Value) -> Option<&str> {
    match response.get("status").and_then(Value::as_str) {
        Some("committed" | "duplicate") => response
            .get("commit")
            .and_then(|commit| commit.get("event_ref"))
            .and_then(Value::as_str),
        _ => None,
    }
}
