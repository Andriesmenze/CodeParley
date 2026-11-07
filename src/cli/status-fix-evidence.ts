// Step 7.2 (F-S71-2): the stored FIX self-test a delegated fix would use, for `status` and `setup` to compare with the
// custodian's FIX confirmations. It reads only: the record exactly as the delegation reads it (engine/fix-confirmation.ts
// storedFixSelfTest, on the delegation's own backend rule) — it launches nothing and confirms nothing. It lives in the
// CLI so engine/protected-status.ts imports no fixer module (test/delegated-fix-layering.test.ts).

import { isDomainError } from "../common/errors.js";
import { fixBackendFor, storedFixSelfTest } from "../engine/fix-confirmation.js";
import type { Loaded } from "../engine/engine-env.js";
import type { FixEvidenceReader } from "../engine/protected-status.js";

export function fixEvidenceReader(le: Loaded): FixEvidenceReader {
  return async (probe) => {
    // The delegation's platform and backend (engine/fix-operation.ts).
    const platform = le.env.testHooks?.custodian?.platform ?? process.platform;
    const backend = fixBackendFor(platform, le.cfg.config.codex.windows_sandbox ?? null, probe);
    try {
      const l = await storedFixSelfTest(le.layout.selftestDir, le.dataHome, backend, probe);
      return { codexVersion: probe.version, backend, local: { selftestId: l.record.selftest_id, codexSha256: l.codexSha256, profileDigest: l.profileDigest }, why: null };
    } catch (e) {
      // The delegation's own refusal for want of a usable stored record (none, not confined, binary unreadable).
      if (isDomainError(e) && e.code === "CODEX_ISOLATION_UNAVAILABLE") return { codexVersion: probe.version, backend, local: null, why: e.message };
      throw e;
    }
  };
}
