import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import path from "node:path";

const [rootArg, portArg, hostArg = "127.0.0.1"] = process.argv.slice(2);
if (!rootArg || !portArg) {
  throw new Error("usage: node serve-static.mjs <root> <port> [host]");
}

const root = path.resolve(rootArg);
const port = Number.parseInt(portArg, 10);
const indexPath = path.join(root, "index.html");
if (!existsSync(indexPath)) {
  throw new Error(`static root does not contain index.html: ${root}`);
}

const contentTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".ico", "image/x-icon"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".png", "image/png"],
  [".svg", "image/svg+xml"],
  [".wasm", "application/wasm"],
  [".webp", "image/webp"],
]);

createServer((request, response) => {
  const url = new URL(request.url ?? "/", "http://localhost");
  const relative = decodeURIComponent(url.pathname).replace(/^\/+/, "");
  const candidate = path.resolve(root, relative);
  const insideRoot = candidate === root || candidate.startsWith(`${root}${path.sep}`);
  const filePath =
    insideRoot && existsSync(candidate) && statSync(candidate).isFile()
      ? candidate
      : indexPath;

  response.writeHead(200, {
    "cache-control": "no-store",
    "content-type": contentTypes.get(path.extname(filePath)) ?? "application/octet-stream",
  });
  createReadStream(filePath).pipe(response);
}).listen(port, hostArg, () => {
  console.log(`serving ${root} at http://${hostArg}:${port}`);
});
