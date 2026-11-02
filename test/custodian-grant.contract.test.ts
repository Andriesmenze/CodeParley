// P3.4C-0 contract tests: the TypeScript custodian grant store (CustodianGrants / CustodianOperator)
// against the in-process SimulatedCustodianTransport — a faithful stand-in for the Windows custodian's
// observable behaviour, including its repository identity (established from the filesystem by the
// custodian, never computed by the client). These run on any OS (no pipe, no service), proving the
// store's two-phase mint, reduce-only consume, dedup/crash-retry recovery, ceilings, expiry, revocation,
// caller-class refusals, identity refusals and fail-closed mapping. The real Windows transport is tested
// in custodian-pipe.test.ts; the real service on the disposable VM (increment 3).

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { createHash } from "node:crypto";
import { isDomainError } from "../src/common/errors.js";
import { custodianError, custodianServiceSid, type ConsumeResult, type RunTransitionFields } from "../src/custodian/protocol.js";
import { SimulatedCustodianTransport, filesystemIdentity } from "../src/custodian/transport.js";
import { CustodianGrants } from "../src/custodian/grants.js";
import { CustodianOperator } from "../src/custodian/operator.js";
import { CustodianRuns } from "../src/custodian/runs.js";
import { amendmentContentKey } from "../src/policy/amendments.js";

let scratch = "";
let REPO = "";
// P3.4C-2: the custodian mints ONE loop per run, so each consumption here is for its own run.
let runSeq = 0;
const run = (): string => `run-${++runSeq}`;
beforeEach(() => {
  scratch = realpathSync.native(mkdtempSync(join(tmpdir(), "cp-contract-")));
  REPO = join(scratch, "Demo");
  mkdirSync(REPO);
});
afterEach(() => rmSync(scratch, { recursive: true, force: true }));

const OPEN: RunTransitionFields["open"] = { runJsonDigest: "a".repeat(64), budgets: { maxReviews: 5, maxCheckExecutions: 50 }, baseline: null };

/** P3.4C-3: the engine registers a run with the custodian (run_transition open) before it consumes a loop for it;
 * a refused open is the consumption's refusal (an open without a grant is LOOP_NOT_AUTHORIZED and registers nothing). */
async function openRun(t: SimulatedCustodianTransport, repositoryRoot: string, runId: string): Promise<void> {
  // P3.4C-4: a run is opened only under the repository's protected configuration (a path the custodian refuses as a
  // repository identity is left to `open` to refuse).
  try {
    t.seedConfig(repositoryRoot);
  } catch {
    /* refused identity: open refuses it below */
  }
  const opened = await new CustodianRuns(t).transition("implementer", { repositoryRoot, runId }, "open", OPEN);
  if (!opened.ok) throw custodianError(opened.code, opened.message);
}

class RegisteringGrants extends CustodianGrants {
  constructor(private readonly t: SimulatedCustodianTransport) {
    super(t);
  }

  override async consume(repositoryRoot: string, runId: string, requestId?: string): Promise<ConsumeResult> {
    await openRun(this.t, repositoryRoot, runId);
    return super.consume(repositoryRoot, runId, requestId);
  }
}

function harness(now?: () => number) {
  const t = new SimulatedCustodianTransport(now ? { now } : {});
  return { t, op: new CustodianOperator(t), grants: new RegisteringGrants(t) };
}

async function asOperator<T>(t: SimulatedCustodianTransport, fn: () => Promise<T>): Promise<T> {
  t.setCaller("operator");
  return fn();
}
async function asImplementer<T>(t: SimulatedCustodianTransport, fn: () => Promise<T>): Promise<T> {
  t.setCaller("implementer");
  return fn();
}

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return "NO_ERROR";
  } catch (e) {
    return isDomainError(e) ? e.code : `UNEXPECTED:${String(e)}`;
  }
}

/** A directory link (a junction on Windows, a symlink elsewhere), or null when this host cannot make one. */
function dirLink(target: string, link: string): string | null {
  try {
    symlinkSync(target, link, "junction");
    return link;
  } catch {
    return null;
  }
}

describe("custodian service SID", () => {
  it("derives the known NT SERVICE\\CodeParleyCustodian SID", () => {
    expect(custodianServiceSid()).toBe("S-1-5-80-659706850-1613669462-1527091787-2025843764-534861470");
  });
});

describe("repository identity: established by the custodian, not the client (decision 3)", () => {
  it("one directory, many spellings: one identity; another directory: another", () => {
    const id = filesystemIdentity(REPO);
    expect(id.canonicalPath).toBe(REPO);
    expect(filesystemIdentity(REPO + (process.platform === "win32" ? "\\" : "/")).key).toBe(id.key);
    if (process.platform === "win32") {
      expect(filesystemIdentity(REPO.toUpperCase()).key).toBe(id.key);
      expect(filesystemIdentity(REPO.replace(/\\/g, "/")).key).toBe(id.key);
    }
    mkdirSync(join(scratch, "Other"));
    expect(filesystemIdentity(join(scratch, "Other")).key).not.toBe(id.key);
  });

  it("refuses rather than guesses: links in any component, '..', relative paths, missing directories", () => {
    const refused = (p: string) => {
      try {
        filesystemIdentity(p);
        return "RESOLVED";
      } catch (e) {
        return String((e as Error).message);
      }
    };
    const link = dirLink(REPO, join(scratch, "link"));
    if (link) {
      expect(refused(link)).toMatch(/repository identity refused: 'link': it is a symbolic link, junction or mount point/);
      const parentLink = dirLink(scratch, join(scratch, "via"));
      if (parentLink) expect(refused(join(parentLink, "Demo"))).toMatch(/'via': it is a symbolic link/);
    }
    expect(refused([REPO, "..", "Demo"].join(sep))).toMatch(/repository identity refused: the path has a '\.\.' component/);
    expect(refused("relative/Demo")).toMatch(/must be absolute/);
    expect(refused(join(scratch, "missing"))).toMatch(/'missing': it does not exist/);
  });

  it("a grant follows the directory: a replaced directory at the same path is not granted", async () => {
    const { t, op, grants } = harness();
    await asOperator(t, () => op.mint(REPO, 2, 60, "req-repl"));
    rmSync(REPO, { recursive: true });
    mkdirSync(REPO);
    expect(await code(asImplementer(t, () => grants.consume(REPO, run())))).toBe("LOOP_NOT_AUTHORIZED");
  });

  it("a grant made through one spelling is consumed and revoked through another", async () => {
    const { t, op, grants } = harness();
    await asOperator(t, () => op.mint(REPO, 3, 60, "req-alias"));
    const other = process.platform === "win32" ? REPO.toUpperCase() + "\\" : REPO + "/";
    expect((await asImplementer(t, () => grants.consume(other, run()))).loopsUsed).toBe(1);
    expect(await asOperator(t, () => op.revoke(other))).toBe(1);
    expect(await code(asImplementer(t, () => grants.consume(REPO, run())))).toBe("LOOP_NOT_AUTHORIZED");
  });

  it("a link to a granted directory is refused (INVALID_ARGUMENT) and consumes nothing", async () => {
    const { t, op, grants } = harness();
    await asOperator(t, () => op.mint(REPO, 1, 60, "req-link"));
    const link = dirLink(REPO, join(scratch, "link"));
    if (!link) return;
    expect(await code(asImplementer(t, () => grants.consume(link, run())))).toBe("INVALID_ARGUMENT");
    expect((await asOperator(t, () => op.list())).grants[0]!.loopsUsed).toBe(0);
  });

  it("the client never sends a key: only the repository path travels", async () => {
    const { t, op, grants } = harness();
    await asOperator(t, () => op.mint(REPO, 1, 60, "req-path"));
    await asImplementer(t, () => grants.consume(REPO, run()));
    for (const r of t.received) expect(Object.keys(r.args).filter((k) => /key/i.test(k))).toEqual([]);
  });

  it("a directory replaced between prepare and commit is refused (STALE_FINDING_STATE): nothing is granted", async () => {
    const { t, op } = harness();
    t.setCaller("operator");
    const prepared = await op.prepareGrant(REPO, 1, 60, "req-race");
    expect(prepared.rendering).toContain(REPO);
    rmSync(REPO, { recursive: true });
    mkdirSync(REPO);
    expect(await code(op.commitGrant(prepared.authorizationRequestId))).toBe("STALE_FINDING_STATE");
    expect((await op.list()).grants).toHaveLength(0);
  });
});

describe("mint → list → consume → exhaust", () => {
  it("mints a grant the operator can see and the implementer can consume to exhaustion", async () => {
    const { t, op, grants } = harness();
    const mint = await asOperator(t, () => op.mint(REPO, 2, 60, "req-1"));
    expect(mint.deduplicated).toBe(false);
    expect(mint.grantId).toBeTruthy();
    expect(mint.loopsTotal).toBe(2);
    expect(mint.assurance).toBe("local_admin_elevation");

    const list = await asOperator(t, () => op.list());
    expect(list.grants).toHaveLength(1);
    expect(list.grants[0]!.active).toBe(true);
    expect(list.grants[0]!.loopsUsed).toBe(0);
    expect(list.grants[0]!.repositoryRoot).toBe(REPO);
    expect(list.grants[0]!.repoKey).toBe(filesystemIdentity(REPO).key);

    const c1 = await asImplementer(t, () => grants.consume(REPO, run()));
    expect(c1.loopsUsed).toBe(1);
    expect(c1.loopsTotal).toBe(2);
    const c2 = await asImplementer(t, () => grants.consume(REPO, run()));
    expect(c2.loopsUsed).toBe(2);
    expect(await code(asImplementer(t, () => grants.consume(REPO, run())))).toBe("LOOP_NOT_AUTHORIZED");
  });
});

describe("revoke", () => {
  it("revokes active grants so consume then fails", async () => {
    const { t, op, grants } = harness();
    await asOperator(t, () => op.mint(REPO, 3, 60, "req-rev"));
    const revoked = await asOperator(t, () => op.revoke(REPO));
    expect(revoked).toBe(1);
    expect(await code(asImplementer(t, () => grants.consume(REPO, run())))).toBe("LOOP_NOT_AUTHORIZED");
    // A second revoke revokes nothing (idempotent).
    expect(await asOperator(t, () => op.revoke(REPO))).toBe(0);
  });
});

describe("expiry", () => {
  it("a prepared authorization expires; a grant expires with its minutes", async () => {
    let now = Date.parse("2026-10-09T12:00:00Z");
    const { t, op, grants } = harness(() => now);
    t.setCaller("operator");
    const prepared = await op.prepareGrant(REPO, 1, 60, "req-ttl");
    now += 121_000;
    expect(await code(op.commitGrant(prepared.authorizationRequestId))).toBe("AUTHORIZATION_EXPIRED");
    await op.mint(REPO, 1, 1, "req-short");
    now += 61_000;
    expect(await code(asImplementer(t, () => grants.consume(REPO, run())))).toBe("LOOP_NOT_AUTHORIZED");
  });
});

describe("dedup / crash-retry (decision 4)", () => {
  it("a repeated mint with the same request id mints no extra authority", async () => {
    const { t, op } = harness();
    const first = await asOperator(t, () => op.mint(REPO, 2, 60, "same-id"));
    expect(first.deduplicated).toBe(false);
    const second = await asOperator(t, () => op.mint(REPO, 2, 60, "same-id"));
    expect(second.deduplicated).toBe(true);
    expect(second.grantId).toBeNull();
    const list = await asOperator(t, () => op.list());
    expect(list.grants).toHaveLength(1); // only one grant was minted
  });

  it("a lost consume response is reported as outcome 'unknown' (the loop WAS consumed); a not-delivered one as retryable", async () => {
    const { t, op, grants } = harness();
    await asOperator(t, () => op.mint(REPO, 2, 60, "req-lost"));
    t.setCaller("implementer");
    t.failNext("consume_loop", "lost_response");
    const lost = await grants.consume(REPO, run()).catch((e: unknown) => e);
    expect(isDomainError(lost) && [lost.code, lost.retryable, lost.details?.["outcome"]]).toEqual(["CUSTODIAN_UNAVAILABLE", false, "unknown"]);
    t.failNext("consume_loop", "not_delivered");
    const off = await grants.consume(REPO, run()).catch((e: unknown) => e);
    expect(isDomainError(off) && [off.code, off.retryable, off.details?.["outcome"]]).toEqual(["CUSTODIAN_UNAVAILABLE", true, "not_delivered"]);
    expect((await asOperator(t, () => op.list())).grants[0]!.loopsUsed).toBe(1);
  });
});

describe("ceilings (decision 1: 8 loops / 180 minutes authoritative, and reported)", () => {
  it("refuses more than 8 loops or 180 minutes, and list_grants reports the ceilings", async () => {
    const { t, op } = harness();
    expect(await code(asOperator(t, () => op.mint(REPO, 9, 60, "too-many")))).toBe("INVALID_ARGUMENT");
    expect(await code(asOperator(t, () => op.mint(REPO, 1, 181, "too-long")))).toBe("INVALID_ARGUMENT");
    const okMint = await asOperator(t, () => op.mint(REPO, 8, 180, "at-ceiling"));
    expect(okMint.loopsTotal).toBe(8);
    expect((await asOperator(t, () => op.list())).ceilings).toEqual({ loops: 8, minutes: 180 });
  });
});

describe("caller classification (decision 5)", () => {
  it("refuses operator operations from an implementer-class caller", async () => {
    const { t, op } = harness();
    expect(await code(asImplementer(t, () => op.mint(REPO, 1, 60, "nope")))).toBe("CALLER_NOT_AUTHORIZED");
    expect(await code(asImplementer(t, () => op.revoke(REPO)))).toBe("CALLER_NOT_AUTHORIZED");
  });
  it("lets the operator class also consume (reduce-only is allowed from either surface); only the engine registers a run", async () => {
    const { t, op } = harness();
    await asOperator(t, () => op.mint(REPO, 1, 60, "op-consume"));
    const r = run();
    expect(await code(asOperator(t, () => openRun(t, REPO, r)))).toBe("CALLER_NOT_AUTHORIZED");
    await asImplementer(t, () => openRun(t, REPO, r));
    t.setCaller("operator");
    const c = await new CustodianGrants(t).consume(REPO, r);
    expect(c.loopsUsed).toBe(1);
  });
  it("by surface (a single-account host): the operator surface is the elevated operator, the implementer surface the implementer", async () => {
    const t = new SimulatedCustodianTransport({ caller: "by_surface" });
    const op = new CustodianOperator(t);
    await op.mint(REPO, 1, 60, "by-surface");
    expect((await new RegisteringGrants(t).consume(REPO, run())).loopsUsed).toBe(1);
    expect(t.received.map((r) => `${r.surface}:${r.op}`)).toEqual(["operator:prepare_grant", "operator:commit", "implementer:run_transition", "implementer:consume_loop"]);
  });
});

describe("P3.4C-3: a loop is consumed only for a run the custodian holds open", () => {
  it("consume_loop for an unregistered run is RUN_NOT_OPEN, for an ended one RUN_TERMINAL; neither consumes a loop", async () => {
    const { t, op } = harness();
    await asOperator(t, () => op.mint(REPO, 2, 60, "req-open"));
    t.setCaller("implementer");
    const grants = new CustodianGrants(t);
    expect(await code(grants.consume(REPO, "run-unregistered"))).toBe("RUN_NOT_OPEN");
    await openRun(t, REPO, "run-ended");
    const ended = await new CustodianRuns(t).transition("implementer", { repositoryRoot: REPO, runId: "run-ended" }, "end", { status: "stopped", reason: "test" });
    expect(ended.ok).toBe(true);
    expect(await code(grants.consume(REPO, "run-ended"))).toBe("RUN_TERMINAL");
    expect((await asOperator(t, () => op.list())).grants[0]!.loopsUsed).toBe(0);
  });

  it("open needs a grant with a loop left and registers nothing without one; it is idempotent on its declaration", async () => {
    const { t, op } = harness();
    t.setCaller("implementer");
    expect(await code(openRun(t, REPO, "run-early"))).toBe("LOOP_NOT_AUTHORIZED");
    expect(t.snapshot().runs).toEqual([]);
    await asOperator(t, () => op.mint(REPO, 1, 60, "req-open2"));
    t.setCaller("implementer");
    await openRun(t, REPO, "run-early");
    await openRun(t, REPO, "run-early"); // another request id, the same declaration: the same record
    expect(t.snapshot().runs.map((r) => [r.runId, r.runRevision])).toEqual([["run-early", 1]]);
    const changed = await new CustodianRuns(t).transition("implementer", { repositoryRoot: REPO, runId: "run-early" }, "open", { ...OPEN, runJsonDigest: "c".repeat(64) });
    expect(changed).toMatchObject({ ok: false, code: "RUN_DECLARATION_CONFLICT" });
  });
});

describe("fail-closed (decision 7)", () => {
  it("maps an unreachable custodian to a retryable CUSTODIAN_UNAVAILABLE and an impostor to SERVER_NOT_TRUSTED, never a fallback", async () => {
    const { t, op, grants } = harness();
    t.setUnavailable("pipe not found");
    expect(await code(asImplementer(t, () => grants.consume(REPO, run())))).toBe("CUSTODIAN_UNAVAILABLE");
    expect(await code(asOperator(t, () => op.mint(REPO, 1, 60, "x")))).toBe("CUSTODIAN_UNAVAILABLE");
    t.setUnavailable(null);
    t.failNext("run_transition", "untrusted");
    expect(await code(asImplementer(t, () => grants.consume(REPO, run())))).toBe("SERVER_NOT_TRUSTED");
    expect(t.received).toHaveLength(0);
  });
});

describe("a shared (file-backed) simulated custodian", () => {
  it("two transports over one state file see one ledger (an in-process CLI and a separate server)", async () => {
    const state = join(scratch, "custodian-state.json");
    const cli = new SimulatedCustodianTransport({ caller: "by_surface", statePath: state });
    const server = new SimulatedCustodianTransport({ caller: "by_surface", statePath: state });
    await new CustodianOperator(cli).mint(REPO, 2, 60, "shared");
    expect((await new RegisteringGrants(server).consume(REPO, run())).loopsUsed).toBe(1);
    expect((await new CustodianGrants(cli).list()).grants[0]!.loopsUsed).toBe(1);
  });
});

// P3.4C-1 confidentiality correction: the custodian DERIVES the amendment content-equivalence key as a
// KEYED HMAC (not an engine-supplied unkeyed hash), so the implementer-visible value is equality-comparable
// but not offline-guessable. These assert the SAME contract the C# `self-test-ledger` asserts for the real
// custodian — the simulator and the real custodian obey one contract.
const DD = "a".repeat(64); // a well-formed (test) redacted-artifact digest
describe("P3.4C-1 protected amendment content key (keyed HMAC) — contract", () => {
  /** Record an amendment via the operator surface and return its implementer-projection record. */
  async function record(h: ReturnType<typeof harness>, run: string, kind: string, text: string, rid: string = run, baseRev = 0): Promise<Record<string, unknown>> {
    const prep = await asOperator(h.t, () => h.op.prepareUserRecord(REPO, run, "amendment", { kind, text, disclosure_digest: DD }, baseRev, rid));
    await asOperator(h.t, () => h.op.commitUserRecord(prep.authorizationRequestId));
    const listing = await asImplementer(h.t, () => h.grants.listUserRecords("implementer", REPO, run));
    return listing.records.at(-1) as Record<string, unknown>;
  }

  it("rejects a client-supplied content_key_hash or text_bytes (the custodian derives them)", async () => {
    const h = harness();
    for (const extra of [{ content_key_hash: "b".repeat(64) }, { text_bytes: 5 }]) {
      await expect(asOperator(h.t, () => h.op.prepareUserRecord(REPO, "run-x", "amendment", { kind: "scope", text: "x", disclosure_digest: DD, ...extra }, 0, `rid-${Object.keys(extra)[0]}`))).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    }
  });

  it("equivalent normalized content gets identical keys; different content or kind differs; the key is keyed (not an offline unkeyed hash)", async () => {
    const h = harness();
    const a = await record(h, "run-a", "clarification", "Prefer an explicit loop");
    const b = await record(h, "run-b", "clarification", "Prefer  an   EXPLICIT\tloop"); // case/whitespace-equivalent
    const c = await record(h, "run-c", "clarification", "totally different");
    const d = await record(h, "run-d", "scope", "Prefer an explicit loop"); // same text, other kind
    expect(a.contentKeyHash).toBe(b.contentKeyHash);
    expect(a.contentKeyHash).not.toBe(c.contentKeyHash);
    expect(a.contentKeyHash).not.toBe(d.contentKeyHash);
    expect(typeof a.contentKeyHash).toBe("string");
    expect(a.textBytes).toBe(Buffer.byteLength("Prefer an explicit loop", "utf8"));
    // A dictionary attacker who knows the text and the public normalization, but not the secret, cannot
    // reproduce the value: it is NOT the unkeyed SHA-256 of the normalized content.
    const unkeyed = createHash("sha256").update(`arl.amendment-content-key.v1\u0000${amendmentContentKey("clarification", "Prefer an explicit loop")}`, "utf8").digest("hex");
    expect(a.contentKeyHash).not.toBe(unkeyed);
  });

  it("the implementer projection carries neither the raw amendment text nor the secret", async () => {
    const h = harness();
    const rec = await record(h, "run-conf", "clarification", "secret guidance text");
    expect(rec.text).toBeUndefined();
    const listing = await asImplementer(h.t, () => h.grants.listUserRecords("implementer", REPO, "run-conf"));
    const json = JSON.stringify(listing);
    expect(json).not.toContain("secret guidance text");
    expect(json).not.toContain("contentKeySecret");
    // The OPERATOR surface does carry the raw text (operator-only).
    const op = await asOperator(h.t, () => h.grants.listUserRecords("operator", REPO, "run-conf"));
    expect((op.records.at(-1) as Record<string, unknown>).text).toBe("secret guidance text");
  });

  it("the secret persists across a restart (a fresh transport over the same state): equal content keeps equal keys", async () => {
    const sp = join(scratch, "sim-state.json");
    const t1 = new SimulatedCustodianTransport({ caller: "by_surface", statePath: sp });
    const key1 = (await record({ t: t1, op: new CustodianOperator(t1), grants: new RegisteringGrants(t1) }, "run-r", "clarification", "Prefer an explicit loop")).contentKeyHash;
    const t2 = new SimulatedCustodianTransport({ caller: "by_surface", statePath: sp }); // a "restart": same persisted state
    const key2 = (await record({ t: t2, op: new CustodianOperator(t2), grants: new RegisteringGrants(t2) }, "run-r2", "clarification", "prefer an explicit loop")).contentKeyHash;
    expect(key2).toBe(key1);
  });
});
