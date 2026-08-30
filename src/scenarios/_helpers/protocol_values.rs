use serde_json::Value;

pub(crate) fn submitted_event_id(response: &Value) -> Option<&str> {
    response
        .get("accepted")
        .and_then(Value::as_array)
        .and_then(|accepted| accepted.first())
        .and_then(Value::as_str)
        .or_else(|| {
            response
                .get("duplicate")
                .and_then(Value::as_array)
                .and_then(|duplicate| duplicate.first())
                .and_then(Value::as_str)
        })
}
