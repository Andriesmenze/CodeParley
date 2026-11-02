// P3.4C-3 C6 (contract §4.2, §6.5): on a protected run, coverage conditions are derived only from a manifest with the
// digest the custodian bound, and the withheld set used for redaction only from capture records with the custodian's
// digest. A mismatch fails closed: the coverage cannot be established and the review is not current; a host view that
// cannot establish the withheld set refuses rather than under-redact. Boundary: detects tampering after recording; it
// does not authenticate the capture's producer.

import { describe, it, expect } from "vitest";
import { appendFile, readFile, writeFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { sha256OfCanonicalJson } from "../src/common/hash.js";
import { disclosureFor } from "../src/engine/host-view.js";
import { withAuthoritativeUserRecords } from "../src/engine/protected-user-records.js";
import { engineConditions, reviewFreshnessNow } from "../src/engine/review-operation.js";
import { resolveArtifact } from "../src/store/artifacts.js";
import { readState } from "../src/store/state-store.js";
import type { RunHandle } from "../src/engine/engine-env.js";
import { supported } from "./helpers/git-fixture.js";
import { defect, okScenario, output } from "./helpers/review-fixture.js";
import { contFixture, grant, HostSession, newRun, reviewCtx, runChecks, startReview, type ContFixture } from "./helpers/continuation-fixture.js";

const scenario = () => okScenario(output({ findings: [defect()] }));

async function protectedReviewed(f: ContFixture, sessionId: string, pid: number): Promise<RunHandle> {
  const run = await newRun(f);
  await grant(f, 1);
  await new HostSession(f, sessionId, pid).startLoop(run);
  await runChecks(f, run);
  await (await startReview(f, run)).done;
  return run;
}

async function view(f: ContFixture, run: RunHandle) {
  return withAuthoritativeUserRecords(f.le, run, await readState(run.paths), { protected: true });
}

describe.skipIf(!supported)("C6 — verified coverage and withheld sets on a protected run", () => {
  it("an export manifest edited and re-sealed after recording: coverage cannot be established, and the review is not current", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedReviewed(f, "sess-c6-1", 9601);
    const ctx = await reviewCtx(f, run);
    let st = await view(f, run);
    const review = st.reviews.find((r) => r.accepted)!;
    expect((await engineConditions(ctx, review.source_id, review)).map((c) => c.code)).not.toContain("coverage_unverifiable");

    // Rewrite the manifest's limitations and its own digest consistently (only the custodian's digest still differs).
    // P3.4C-5: a protected review's export is the custodian's published one (an absolute path).
    const path = join(isAbsolute(review.export_ref) ? review.export_ref : join(run.paths.runDir, ...review.export_ref.split("/")), "review", "manifest.json");
    const m = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown> & { limitations: unknown[] };
    const { manifest_digest: _old, ...rest } = m;
    rest["limitations"] = [];
    await writeFile(path, JSON.stringify({ ...rest, manifest_digest: sha256OfCanonicalJson(rest) }, null, 2));

    st = await view(f, run);
    const r2 = st.reviews.find((r) => r.review_id === review.review_id)!;
    const codes = (await engineConditions(ctx, r2.source_id, r2)).map((c) => c.code);
    expect(codes).toContain("coverage_unverifiable");
    expect((await reviewFreshnessNow(ctx, r2))?.current).toBe(false);
  });

  it("a capture record altered after recording: the host view refuses rather than under-redact", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await protectedReviewed(f, "sess-c6-2", 9602);
    await expect(disclosureFor(f.le, run, { state: await view(f, run) })).resolves.toBeTruthy();
    const st = await readState(run.paths);
    await appendFile(resolveArtifact(run.paths.runDir, st.reviews[0]!.artifacts["capture"]!), " ");
    await expect(disclosureFor(f.le, run, { state: await view(f, run) })).rejects.toMatchObject({ code: "INTERNAL" });
    // The same from the raw cache (no hydrated state given): the custodian is asked.
    await expect(disclosureFor(f.le, run)).rejects.toMatchObject({ code: "INTERNAL" });
  });

  it("an attended run keeps Phase 2 behaviour (no custodian digests): its host view still renders", async () => {
    const f = await contFixture(scenario(), { accounts: true });
    const run = await newRun(f);
    await runChecks(f, run);
    await (await startReview(f, run)).done;
    await expect(disclosureFor(f.le, run)).resolves.toBeTruthy();
  });
});
