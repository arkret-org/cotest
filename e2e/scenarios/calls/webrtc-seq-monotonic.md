# WebRTC Seq Monotonicity

Verifies that `ck.call.signal` rejects non-monotonic cursors. A rollback from
`N` to `N-1` must fail without removing accepted events. A future gap must also
fail without consuming the next cursor.
