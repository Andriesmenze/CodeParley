// The run-wide build of src/ (M1.6-17): test/global-setup.ts compiles it once per test run and
// writes the MCP test-server entry into it, instead of every suite compiling its own copy.
// Suites add their own files beside it under unique names and never delete it; the global
// teardown does. Where it is absent (an unsupported platform, or a suite run on its own), a
// suite builds its own as before.

import { inject } from "vitest";

declare module "vitest" {
  export interface ProvidedContext {
    compiledSrcDir: string;
  }
}

/** The shared build's directory, or null when this run has none. */
export function sharedCompiledSrc(): string | null {
  try {
    const dir = inject("compiledSrcDir");
    return typeof dir === "string" && dir.length > 0 ? dir : null;
  } catch {
    return null;
  }
}
