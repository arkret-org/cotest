// A failed fixture request must not terminate the mock and mask later failures.
export function isolateRequestFailure(handler) {
  return (req, res) => {
    Promise.resolve().then(() => handler(req, res)).catch(() => {
      if (res.writableEnded) return;
      if (res.headersSent) {
        res.destroy();
        return;
      }
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "mock_request_failed" }));
    });
  };
}
