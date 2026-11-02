// The protected-loop capability gate (P3.4C-0). Product-owner decision 2026-10-09 (Option A, Windows
// first): a protected autonomous loop proceeds only through a VALIDATED custodian's authorization.
//
//  - Windows: the custodian is reached through PipeCustodianTransport, which authenticates the
//    custodian's pipe (owner + access list) on every exchange. A Windows installation without the
//    custodian is refused at the first exchange (CUSTODIAN_UNAVAILABLE): fail-closed.
//  - Linux (Phase 5, contract §4.4): the custodian is reached through UnixSocketCustodianTransport, which
//    verifies the root-owned runtime directory and the socket's owner on every exchange; a Linux host without
//    the custodian is refused at the first exchange (CUSTODIAN_UNAVAILABLE): fail-closed. The Linux custodian's
//    own start-time checks refuse an unsupported host (Ubuntu 24.04 x86_64, kernel 6.8, ext4; D5-E).
//  - Every other platform: no validated custodian exists, so a protected loop is refused up front.
//
// There is no fallback to grants.json or any weaker authority, no attended-loop substitute and no silent
// downgrade. Independent review, checks, implementer responses, the discussion with Codex and the user's
// own decisions never pass through this gate: they stay available on every supported platform.

import { DomainError } from "../common/errors.js";
import { PipeCustodianTransport } from "./pipe-transport.js";
import { UnixSocketCustodianTransport } from "./socket-transport.js";
import { CUSTODIAN_UNAVAILABLE } from "./protocol.js";
import { custodianServicePresence, type CustodianPresence } from "./service-presence.js";
import type { CustodianTransport } from "./transport.js";

/** TEST ONLY: the custodian the engine talks to and the platform the gate decides for. Never set by
 * configuration, an environment variable or a tool argument: only test entry points construct these. */
export interface CustodianTestHooks {
  /** The custodian (a SimulatedCustodianTransport). It is used only where the gate opens. */
  transport?: CustodianTransport;
  /** The platform the gate decides for (default: process.platform). */
  platform?: NodeJS.Platform;
  /** P3.4C-3: what the host's service manager answers for the custodian service (default "registered" on win32 and linux);
   * "host" asks the host's own service manager, as production does (the VM acceptance harness, with the real service). */
  presence?: CustodianPresence | "host";
}

/**
 * P3.4C-3 (contract §5.4): whether the custodian service is registered on this host — the host's service manager in
 * production; under test (`underTest`), only what the test injected: a test without a custodian hook never consults
 * the host's own service ("absent"), one with a hook on win32 models a registered service unless it says otherwise.
 */
export function custodianPresence(underTest: boolean, hooks: CustodianTestHooks | undefined): Promise<CustodianPresence> {
  if (!underTest) return custodianServicePresence();
  if (!hooks || !CUSTODIAN_PLATFORMS.has(hooks.platform ?? process.platform)) return Promise.resolve("absent");
  if (hooks.presence === "host") return custodianServicePresence();
  return Promise.resolve(hooks.presence ?? "registered");
}

/** The platforms with a custodian implementation (Windows; Linux from Phase 5). */
export const CUSTODIAN_PLATFORMS: ReadonlySet<NodeJS.Platform> = new Set<NodeJS.Platform>(["win32", "linux"]);

export type ProtectedLoopGate =
  | { available: true; transport: CustodianTransport }
  | { available: false; error: DomainError };

/** Decide whether a protected loop may ask the custodian for authority on this platform. */
export function protectedLoopGate(hooks?: CustodianTestHooks): ProtectedLoopGate {
  const platform = hooks?.platform ?? process.platform;
  if (!CUSTODIAN_PLATFORMS.has(platform)) {
    return {
      available: false,
      error: new DomainError(
        CUSTODIAN_UNAVAILABLE,
        `protected autonomous loops need a validated CodeParley custodian, and none exists on ${platform} (Windows and Linux only). Nothing was started or granted, and nothing falls back to a weaker authority. Independent review, checks, responses, the discussion with Codex and your own decisions are unaffected`,
        { retryable: false, details: { outcome: "not_delivered", platform, reason: "no_validated_custodian_for_platform" } },
      ),
    };
  }
  return { available: true, transport: hooks?.transport ?? (platform === "linux" ? new UnixSocketCustodianTransport() : new PipeCustodianTransport()) };
}
