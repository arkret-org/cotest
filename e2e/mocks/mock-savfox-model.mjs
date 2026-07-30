import http from "node:http";
import fs from "node:fs";

const port = Number(process.env.MOCK_SAVFOX_MODEL_PORT ?? "0");
const receiptPath = process.env.MOCK_SAVFOX_MODEL_RECEIPT_PATH?.trim();

if (!Number.isInteger(port) || port <= 0 || port > 65535) {
  throw new Error("MOCK_SAVFOX_MODEL_PORT must be a valid TCP port");
}

function writeJson(response, status, body) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

const server = http.createServer((request, response) => {
  const url = new URL(request.url ?? "/", `http://127.0.0.1:${port}`);
  if (request.method === "GET" && url.pathname === "/health") {
    writeJson(response, 200, { ok: true });
    return;
  }
  if (
    request.method === "GET" &&
    (url.pathname === "/v1/models" || url.pathname === "/models")
  ) {
    writeJson(response, 200, { object: "list", data: [] });
    return;
  }
  if (request.method !== "POST" || url.pathname !== "/v1/responses") {
    writeJson(response, 404, { error: { message: "not found" } });
    return;
  }

  const chunks = [];
  request.on("data", (chunk) => chunks.push(chunk));
  request.on("end", () => {
    const raw = Buffer.concat(chunks).toString("utf8");
    const requestBody = raw ? JSON.parse(raw) : {};
    if (receiptPath) {
      fs.appendFileSync(
        receiptPath,
        `${JSON.stringify({
          received_at: new Date().toISOString(),
          request: requestBody,
        })}\n`,
        "utf8",
      );
    }

    const suffix = Date.now().toString(36);
    const responseId = `resp_joint_${suffix}`;
    const events = [
      {
        type: "response.created",
        response: { id: responseId },
      },
      {
        type: "response.output_item.done",
        item: {
          type: "message",
          role: "assistant",
          id: `msg_joint_${suffix}`,
          content: [{ type: "output_text", text: "pong" }],
        },
      },
      {
        type: "response.completed",
        response: {
          id: responseId,
          usage: {
            input_tokens: 0,
            input_tokens_details: null,
            output_tokens: 0,
            output_tokens_details: null,
            total_tokens: 0,
          },
        },
      },
    ];
    response.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
      connection: "keep-alive",
    });
    for (const event of events) {
      response.write(`event: ${event.type}\n`);
      response.write(`data: ${JSON.stringify(event)}\n\n`);
    }
    response.end();
  });
});

server.listen(port, "127.0.0.1", () => {
  process.stdout.write(`mock savfox model listening on 127.0.0.1:${port}\n`);
});
