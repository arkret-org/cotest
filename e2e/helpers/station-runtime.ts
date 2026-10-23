import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import { expect, type APIRequestContext } from "@playwright/test";
import { colandBaseUrl } from "./env";

// The runner controller owns PID/start-time/command verification and the
// original config, database and home. Never discover or stop unrelated hosts.
export async function restartRunnerStation(request: APIRequestContext) {
  const topologyPath = process.env.COTEST_TOPOLOGY_PATH;
  if (!topologyPath) throw new Error("Station recovery requires runner-owned process topology");
  const topology = JSON.parse(await readFile(topologyPath, "utf8")) as {
    servers: Array<{ name: string; coland: { process_id: number | null;
      control?: { kind: string; script_path: string; state_path: string } } }>;
  };
  const server = topology.servers.find(server => server.name === "server1");
  const control = server?.coland.control;
  if (!server?.coland.process_id || control?.kind !== "process") {
    throw new Error("Station recovery requires the original runner process controller");
  }
  const before = await readFile(control.state_path, "utf8").then(text => JSON.parse(text)).catch(error => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return {};
    throw error;
  }) as { current_process_id?: number };
  const oldPid = before.current_process_id ?? server.coland.process_id;
  await promisify(execFile)("pwsh", ["-NoProfile", "-File", control.script_path,
    "-TopologyPath", topologyPath, "-ServerName", "server1", "-ServiceName", "coland", "-Action", "restart"],
    { timeout: 90_000, windowsHide: true });
  const after = JSON.parse(await readFile(control.state_path, "utf8")) as {
    restarted?: boolean; current_process_id?: number; current_process_started_at?: string;
    terminated_processes?: Array<{ process_id: number }>;
  };
  expect(after.restarted).toBe(true);
  expect(Number.isInteger(after.current_process_id) && after.current_process_id! > 0).toBe(true);
  expect(after.current_process_id).not.toBe(oldPid);
  expect(typeof after.current_process_started_at).toBe("string");
  expect(after.terminated_processes?.some(identity => identity.process_id === oldPid)).toBe(true);
  await expect.poll(async () => {
    try { return (await request.get(`${colandBaseUrl()}/_arkret/describe`, { timeout: 5_000 })).ok(); }
    catch { return false; }
  }, { timeout: 120_000 }).toBe(true);
  return { old_station_pid: oldPid, new_station_pid: after.current_process_id,
    current_process_started_at: after.current_process_started_at, whole_owned_tree_restarted: true };
}
