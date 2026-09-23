//! Shared Event publication carrier for Cotest.

use anyhow::Result;
use arkret_wire::{Event, EventAdmissionSubmission};

/// Package an authored Event for the current self submit rail.
pub fn initial_submission(event: Event, _action: &str) -> Result<EventAdmissionSubmission> {
    Ok(EventAdmissionSubmission::new(event))
}
