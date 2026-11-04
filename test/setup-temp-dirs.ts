// Step 6 (vitest setupFiles): after each test file, remove the temporary directories and files it tracked
// (helpers/temp-dirs.ts). Registered before the file's own hooks, this one runs after them: the file's servers and
// processes have stopped by then.

import { afterAll } from "vitest";
import { removeTrackedTemp } from "./helpers/temp-dirs.js";

afterAll(async () => {
  const r = await removeTrackedTemp();
  if (r.failures.length > 0) {
    const first = r.failures[0]!;
    console.warn(`temp-dirs: ${r.failures.length} temporary entr${r.failures.length === 1 ? "y" : "ies"} could not be removed and stay (first: ${first.path}: ${first.code})`);
  }
}, 300_000);
