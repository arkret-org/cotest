// Stale-bundle gate for the browser lanes.
//
// This was `global-setup.ts`, which ran unconditionally: every Playwright
// invocation launched Chromium and demanded a served Inkson bundle, including
// runs whose whole selection reaches no browser. As a setup project it runs
// only for the projects that declare it in `dependencies`, so `joint-api` no
// longer pays for a check that says nothing about it.
//
// The check itself is unchanged, and so are its limits: it compares the bundle's
// build id against the Inkson checkout's short HEAD and tolerates a `+dirty`
// suffix, so it catches a bundle built from a different commit, not every
// difference a dirty working tree can produce within one commit. The runner's
// own freshness and marker verification stays the other half of that guard.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { test } from "@playwright/test";

test("served Inkson bundle was built from the checked-out source", async ({
  page,
  baseURL,
}, testInfo) => {
  if (!baseURL) {
    throw new Error("build identity gate cannot resolve the Inkson base URL");
  }
  const here = path.dirname(fileURLToPath(import.meta.url));
  const workspaceRoot = path.resolve(here, "../../..");
  const inksonRoot =
    process.env.COTEST_INKSON_ROOT?.trim() || path.join(workspaceRoot, "inkson");
  const expectedSourceSha = execFileSync(
    "git",
    ["-C", inksonRoot, "rev-parse", "--short", "HEAD"],
    { encoding: "utf8" },
  ).trim();

  // Opt-in dirty-source binding for long queued acceptance runs. The normal
  // HEAD check below is still necessary but cannot distinguish two WIP builds.
  const freezePath = process.env.COTEST_INKSON_SOURCE_FREEZE;
  const artifactPath = process.env.COTEST_INKSON_ARTIFACT_STATUS;
  const publicRoot = process.env.COTEST_INKSON_FROZEN_PUBLIC_ROOT;
  if (freezePath || artifactPath || publicRoot) {
    if (!freezePath || !artifactPath || !publicRoot) {
      throw new Error("Inkson source/artifact guard requires all three paths");
    }
    const sha256 = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");
    const freezeBytes = readFileSync(freezePath);
    const freeze = JSON.parse(freezeBytes.toString("utf8")) as Array<{ path: string; sha256: string }>;
    const artifacts = JSON.parse(readFileSync(artifactPath, "utf8")) as {
      state: string; source_freeze_sha256: string;
      wasm: Array<{ path: string; sha256: string }>;
      wire_artifact: { path: string; sha256: string };
    };
    if (artifacts.state !== "passed" || artifacts.source_freeze_sha256.toLowerCase() !== sha256(freezeBytes)) {
      throw new Error("Inkson artifacts do not bind the frozen source");
    }
    if (!Array.isArray(freeze) || freeze.length === 0 || !Array.isArray(artifacts.wasm) || artifacts.wasm.length === 0) {
      throw new Error("Inkson source/artifact guard has an empty inventory");
    }
    const inside = (root: string, file: string) => {
      const relative = path.relative(path.resolve(root), path.resolve(file));
      if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) throw new Error("Inkson guard path escaped its root");
      return relative;
    };
    let inputFreezeSha256: string | null = null;
    const inputPath = process.env.COTEST_INKSON_INPUT_FREEZE;
    if (inputPath) {
      const inputBytes = readFileSync(inputPath);
      inputFreezeSha256 = sha256(inputBytes);
      const inputs = JSON.parse(inputBytes.toString("utf8")) as { repositories: Record<string, {
        head: string; changed_paths: string[]; files: Record<string, string>;
      }> };
      for (const [repo, input] of Object.entries(inputs.repositories)) {
        const repoRoot = repo === "inkson" ? path.resolve(inksonRoot) : path.resolve(inksonRoot, "..", repo);
        inside(path.resolve(inksonRoot, ".."), repoRoot);
        const git = (args: string[]) => execFileSync("git", ["-C", repoRoot, ...args], { encoding: "utf8" });
        if (git(["rev-parse", "HEAD"]).trim() !== input.head) throw new Error(`Queued source HEAD changed: ${repo}`);
        const changed = [...new Set([
          ...git(["ls-files", "-m", "-z"]).split("\0"),
          ...git(["diff", "--name-only", "--cached", "-z"]).split("\0"),
          ...git(["ls-files", "--others", "--exclude-standard", "-z"]).split("\0"),
        ].filter(Boolean))].sort();
        if (JSON.stringify(changed) !== JSON.stringify([...input.changed_paths].sort())) {
          throw new Error(`Queued source inventory changed: ${repo}`);
        }
        for (const [relative, digest] of Object.entries(input.files)) {
          const file = path.resolve(repoRoot, relative); inside(repoRoot, file);
          if (sha256(readFileSync(file)) !== digest.toLowerCase()) throw new Error(`Queued source bytes changed: ${repo}/${relative}`);
        }
      }
    }
    for (const entry of freeze) {
      const file = path.resolve(inksonRoot, entry.path);
      inside(inksonRoot, file);
      if (sha256(readFileSync(file)) !== entry.sha256.toLowerCase()) {
        throw new Error(`Inkson frozen source changed while queued: ${entry.path}`);
      }
    }
    const served: Array<{ path: string; sha256: string; bytes: number }> = [];
    for (const artifact of artifacts.wasm) {
      const relative = inside(publicRoot, artifact.path).split(path.sep).join("/");
      if (sha256(readFileSync(artifact.path)) !== artifact.sha256.toLowerCase()) throw new Error("Inkson WASM artifact bytes changed");
      const url = new URL(relative, baseURL.endsWith("/") ? baseURL : `${baseURL}/`).toString();
      const response = await page.request.get(url);
      if (!response.ok()) throw new Error(`Inkson served WASM returned ${response.status()}`);
      const body = await response.body();
      const digest = sha256(body);
      if (digest !== artifact.sha256.toLowerCase()) throw new Error("Inkson served WASM differs from the verified artifact");
      served.push({ path: relative, sha256: digest, bytes: body.length });
    }
    if (sha256(readFileSync(artifacts.wire_artifact.path)) !== artifacts.wire_artifact.sha256.toLowerCase()) {
      throw new Error("Inkson wire artifact bytes changed");
    }
    await testInfo.attach("inkson-source-artifact-guard.json", { contentType: "application/json",
      body: JSON.stringify({ frozen_files: freeze.length, source_freeze_sha256: sha256(freezeBytes),
        input_freeze_sha256: inputFreezeSha256, served_wasm: served, checked_before_business: true }) });
  }

  await page.goto(baseURL, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(
    () => document.documentElement.hasAttribute("data-inkson-build-id"),
    undefined,
    { timeout: 30_000 },
  );
  const buildId = await page
    .locator("html")
    .getAttribute("data-inkson-build-id");
  if (!buildId?.match(new RegExp(`\\b${expectedSourceSha}(?:\\+dirty)?$`))) {
    throw new Error(
      `stale Inkson bundle: expected source ${expectedSourceSha}, loaded ${buildId ?? "<missing>"}`,
    );
  }
});
