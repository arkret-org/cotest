//! Exact ordinary Event replay for a registered transient governance response.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use reqwest::StatusCode;
use reqwest::header::{CONTENT_TYPE, HeaderMap, RETRY_AFTER};
use serde_json::Value;

use super::TestActorClient;
use crate::harness::assertions::{HTTP_REQUEST_DEADLINE, send_recorded};

type RetryHistory = BTreeMap<(String, String), VecDeque<Instant>>;

const RETRY_WINDOW: Duration = Duration::from_secs(300);
const MAX_WINDOW_RETRIES: usize = 5;
static RETRY_HISTORY: OnceLock<Mutex<RetryHistory>> = OnceLock::new();

impl TestActorClient {
    /// Keep the full canonical request and producer proof unchanged when a
    /// governing stream advances before its candidate RealmCommit is stored.
    pub(super) async fn submit_authored_event(&self, event: &arkret_wire::Event) -> Result<Value> {
        let submission = crate::publication::initial_submission(event.clone(), "")?;
        let frozen_body = arkret_canonical::canonical_json_bytes(&submission)?;
        let operation =
            arkret_wire::ServiceOperationId::from_wire("ak.self.events.command.submit.v1")
                .context("self Event submit operation is unregistered")?;
        let descriptor = operation.descriptor();
        let replay_safe = descriptor.retry_safe == Some(true)
            && descriptor.idempotency_mechanism == Some("canonical_hash");
        let policy = arkret_http_client::RetryConfig::standard(2);
        let deadline = tokio::time::Instant::now() + HTTP_REQUEST_DEADLINE;
        tokio::time::timeout_at(deadline, async {
            let mut retries = 0;
            loop {
                // A new transport proof may be issued, never a new Event or
                // a modified canonical-hash replay identity.
                let response = send_recorded(
                    self.post("/_arkret/self/events")
                        .header(CONTENT_TYPE, "application/json")
                        .body(frozen_body.clone()),
                )
                .await?;
                if response.status == StatusCode::OK {
                    return response.json();
                }
                let rejected = || {
                    anyhow!(
                        "expected HTTP 200 OK, got {}:\n{}",
                        response.status,
                        response.context()
                    )
                };
                if !replay_safe || retries >= policy.max_retries {
                    return Err(rejected());
                }
                let Some(server_delay) = retry_hint(
                    response.status,
                    &response.headers,
                    &response.body,
                    chrono::Utc::now(),
                ) else {
                    return Err(rejected());
                };
                let Some(local_delay) = retry_delay(&policy, retries + 1) else {
                    return Err(rejected());
                };
                let delay = local_delay.max(server_delay);
                if delay >= deadline.saturating_duration_since(tokio::time::Instant::now()) {
                    return Err(rejected());
                }
                tokio::time::sleep(delay).await;
                if !reserve_retry(&self.service_id, &self.actor) {
                    return Err(rejected());
                }
                retries += 1;
            }
        })
        .await
        .context("exact Event submission exhausted the existing HTTP request budget")?
    }
}

fn retry_hint(
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
    now: chrono::DateTime<chrono::Utc>,
) -> Option<Duration> {
    if status != StatusCode::SERVICE_UNAVAILABLE
        || !headers
            .get(CONTENT_TYPE)?
            .to_str()
            .ok()?
            .split(';')
            .next()?
            .trim()
            .eq_ignore_ascii_case("application/problem+json")
    {
        return None;
    }
    let value: Value = serde_json::from_slice(body).ok()?;
    if ["ok", "error", "request_id"]
        .iter()
        .any(|key| value.get(key).is_some())
    {
        return None;
    }
    let problem: arkret_wire::Problem = serde_json::from_value(value).ok()?;
    let code = arkret_wire::error_codes::ErrorCode::from_wire("temporarily_unavailable")?;
    if problem.status != status.as_u16() || problem.problem_type != code.type_uri() {
        return None;
    }
    let Some(hint) = headers.get(RETRY_AFTER) else {
        // A registered HTTP body hint must also carry Retry-After. Do not
        // silently accelerate a malformed server-directed retry contract.
        return (!problem.extensions.contains_key("retry_after_ms")).then_some(Duration::ZERO);
    };
    if headers.get_all(RETRY_AFTER).iter().count() != 1 {
        return None;
    }
    let hint = hint.to_str().ok()?.trim();
    if !hint.is_empty() && hint.bytes().all(|byte| byte.is_ascii_digit()) {
        return hint.parse::<u64>().ok().map(Duration::from_secs);
    }
    let target = chrono::DateTime::parse_from_rfc2822(hint).ok()?;
    Some(
        target
            .signed_duration_since(now)
            .to_std()
            .unwrap_or(Duration::ZERO),
    )
}

fn retry_delay(policy: &arkret_http_client::RetryConfig, attempt: usize) -> Option<Duration> {
    let factor = 1u32.checked_shl(attempt.saturating_sub(1).min(31) as u32)?;
    let delay = policy
        .base_delay
        .saturating_mul(factor)
        .min(policy.max_delay);
    if !policy.jitter {
        return Some(delay);
    }
    let mut entropy = [0u8; 4];
    getrandom::fill(&mut entropy).ok()?;
    let jitter = f64::from(u32::from_le_bytes(entropy)) / f64::from(u32::MAX);
    Some(delay.mul_f64(1.0 + 0.2 * jitter))
}

fn reserve_retry(service: &str, actor: &str) -> bool {
    let Ok(mut history) = RETRY_HISTORY.get_or_init(Mutex::default).lock() else {
        return false;
    };
    reserve_retry_at(&mut history, service, actor, Instant::now())
}

fn reserve_retry_at(history: &mut RetryHistory, service: &str, actor: &str, now: Instant) -> bool {
    let retries = history
        .entry((service.to_owned(), actor.to_owned()))
        .or_default();
    retries.retain(|sent| now.saturating_duration_since(*sent) < RETRY_WINDOW);
    if retries.len() >= MAX_WINDOW_RETRIES {
        return false;
    }
    retries.push_back(now);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_problem() -> (HeaderMap, Vec<u8>) {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/problem+json".parse().unwrap());
        let body = serde_json::to_vec(&arkret_wire::Problem::new(
            "temporarily_unavailable",
            503,
            "stream head advanced before this RealmCommit",
        ))
        .unwrap();
        (headers, body)
    }

    #[test]
    fn only_registered_temporary_problem_responses_allow_replay() {
        let (mut headers, body) = temporary_problem();
        let now = chrono::Utc::now();
        assert_eq!(
            retry_hint(StatusCode::SERVICE_UNAVAILABLE, &headers, &body, now),
            Some(Duration::ZERO)
        );
        assert!(retry_hint(StatusCode::CONFLICT, &headers, &body, now).is_none());
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        assert!(retry_hint(StatusCode::SERVICE_UNAVAILABLE, &headers, &body, now).is_none());
        let (headers, _) = temporary_problem();
        let canonical: Value = serde_json::from_slice(&body).unwrap();
        for (field, invalid) in [
            ("status", serde_json::json!(409)),
            (
                "type",
                serde_json::json!("https://untrusted.example/temporarily_unavailable"),
            ),
            ("ok", serde_json::json!(false)),
        ] {
            let mut body = canonical.clone();
            body[field] = invalid;
            assert!(
                retry_hint(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &headers,
                    &serde_json::to_vec(&body).unwrap(),
                    now
                )
                .is_none()
            );
        }
    }

    #[test]
    fn retry_after_is_a_lower_bound_and_invalid_hints_fail_closed() {
        let (mut headers, body) = temporary_problem();
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-29T19:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        headers.insert(RETRY_AFTER, "120".parse().unwrap());
        assert_eq!(
            retry_hint(StatusCode::SERVICE_UNAVAILABLE, &headers, &body, now),
            Some(Duration::from_secs(120))
        );
        headers.insert(
            RETRY_AFTER,
            "Thu, 29 Oct 2026 19:00:03 GMT".parse().unwrap(),
        );
        assert_eq!(
            retry_hint(StatusCode::SERVICE_UNAVAILABLE, &headers, &body, now),
            Some(Duration::from_secs(3))
        );
        headers.insert(
            RETRY_AFTER,
            "Wed, 28 Oct 2026 19:00:00 GMT".parse().unwrap(),
        );
        assert_eq!(
            retry_hint(StatusCode::SERVICE_UNAVAILABLE, &headers, &body, now),
            Some(Duration::ZERO)
        );
        headers.insert(RETRY_AFTER, "not-a-date".parse().unwrap());
        assert!(retry_hint(StatusCode::SERVICE_UNAVAILABLE, &headers, &body, now).is_none());
        headers.insert(RETRY_AFTER, "+1".parse().unwrap());
        assert!(retry_hint(StatusCode::SERVICE_UNAVAILABLE, &headers, &body, now).is_none());
        let (headers, body) = temporary_problem();
        let mut decoded: Value = serde_json::from_slice(&body).unwrap();
        decoded["retry_after_ms"] = 1000.into();
        assert!(
            retry_hint(
                StatusCode::SERVICE_UNAVAILABLE,
                &headers,
                &serde_json::to_vec(&decoded).unwrap(),
                now
            )
            .is_none()
        );
    }

    #[test]
    fn actor_service_retry_window_is_shared_and_expires_without_sleep() {
        let mut history = RetryHistory::new();
        let now = Instant::now();
        for _ in 0..5 {
            assert!(reserve_retry_at(&mut history, "station-a", "alice", now));
        }
        assert!(!reserve_retry_at(&mut history, "station-a", "alice", now));
        assert!(reserve_retry_at(&mut history, "station-a", "bob", now));
        assert!(reserve_retry_at(&mut history, "station-b", "alice", now));
        assert!(reserve_retry_at(
            &mut history,
            "station-a",
            "alice",
            now + RETRY_WINDOW
        ));
    }

    #[test]
    fn backoff_keeps_the_spec_ladder_and_jitter_bounds() {
        let fixed = arkret_http_client::RetryConfig::standard(2).with_jitter(false);
        assert_eq!(retry_delay(&fixed, 1), Some(Duration::from_secs(1)));
        assert_eq!(retry_delay(&fixed, 2), Some(Duration::from_secs(2)));
        assert_eq!(retry_delay(&fixed, 10), Some(Duration::from_secs(60)));
        let policy = arkret_http_client::RetryConfig::standard(2);
        let actual = retry_delay(&policy, 1).unwrap();
        assert!(actual >= Duration::from_secs(1));
        assert!(actual <= Duration::from_millis(1200));
    }
}
