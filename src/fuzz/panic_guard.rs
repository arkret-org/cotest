use std::panic;

pub(super) fn catch<F: FnOnce() + panic::UnwindSafe>(f: F) -> Result<(), String> {
    match panic::catch_unwind(f) {
        Ok(()) => Ok(()),
        Err(payload) => {
            let message = if let Some(message) = payload.downcast_ref::<&'static str>() {
                (*message).to_owned()
            } else if let Some(message) = payload.downcast_ref::<String>() {
                message.clone()
            } else {
                "<non-string panic payload>".to_owned()
            };
            Err(message)
        }
    }
}
