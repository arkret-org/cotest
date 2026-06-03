//! Minimal HTTP server primitives shared by in-process mock servers across
//! scenarios (e.g. `bridge::MockCoauthIntrospectionServer` and the push-sink
//! `MockPushReceiver`). These are the stateless request/parse/response helpers;
//! each scenario keeps its own server struct because their accept-loop handlers
//! differ (auth checks, response shapes, async wait vs. sync capture).
//!
//! Extracted during the round-28 dedup pass (review report 09 §9.3). Behaviour
//! is byte-for-byte identical to the inline copies these replace.

use std::io::Write;
use std::net::TcpStream;

use serde_json::Value;

/// Returns `true` once `buffer` holds a complete HTTP request: headers
/// terminated by `\r\n\r\n` plus a body at least as long as `content-length`
/// (absent header treated as zero).
pub fn request_complete(buffer: &[u8]) -> bool {
    let Some(header_end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let body_start = header_end + 4;
    let headers = String::from_utf8_lossy(&buffer[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    buffer.len() >= body_start + content_length
}

/// Parses the request body (everything after the `\r\n\r\n` header terminator)
/// as JSON, returning `None` if the terminator is missing or the body is not
/// valid JSON.
pub fn parse_json_body(buffer: &[u8]) -> Option<Value> {
    let header_end = buffer.windows(4).position(|window| window == b"\r\n\r\n")?;
    let body = &buffer[header_end + 4..];
    serde_json::from_slice(body).ok()
}

/// Writes a `HTTP/1.1 <status> <reason>` JSON response with a `content-length`
/// header and `connection: close`. Errors writing to the stream are ignored,
/// matching the best-effort behaviour of the mock servers.
pub fn write_json_response(stream: &mut TcpStream, status: u16, body: &Value) {
    let body = body.to_string();
    let reason = if status == 200 { "OK" } else { "Unauthorized" };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}
