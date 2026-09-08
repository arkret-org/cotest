import { renameSync } from "node:fs";

const transientRenameErrors = new Set(["EPERM", "EACCES", "EBUSY"]);
const sleeper = new Int32Array(new SharedArrayBuffer(4));

// Windows readers may briefly deny replacement while inspecting the old file.
// Keep the old state intact until rename succeeds; never unlink or truncate it.
export function replaceStateFileSync(source, destination, {
  rename = renameSync,
  pause = (milliseconds) => Atomics.wait(sleeper, 0, 0, milliseconds),
} = {}) {
  for (let attempt = 0; ; attempt += 1) {
    try {
      rename(source, destination);
      return;
    } catch (error) {
      if (!transientRenameErrors.has(error?.code) || attempt >= 9) throw error;
      pause(Math.min(20 * 2 ** attempt, 250));
    }
  }
}
