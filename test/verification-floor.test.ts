import { describe, it, expect } from "vitest";
import {
  checkStatus,
  deriveCheckConditions,
  effectiveRequirements,
  evaluateExecutionFreshness,
  evaluateFloor,
  resolveRunFloor,
  resolveSelection,
  type CurrentCheckInputs,
  type TrustedView,
} from "../src/policy/verification-floor.js";
import type { CheckExecutionRecord } from "../src/schemas/checks.js";

function view(over: Partial<TrustedView> = {}): TrustedView {
  return {
    status: "approved",
    defined: new Map([
      ["unit", "d-unit"],
      ["lint", "d-lint"],
      ["e2e", "d-e2e"],
    ]),
    approved: new Set(["unit", "lint", "e2e"]),
    profiles: { default: ["unit", "lint"], full: ["unit", "lint", "e2e"] },
    requiredProfiles: ["default"],
    noRequiredChecks: false,
    floorConfigured: true,
    ...over,
  };
}

const S1 = "1".repeat(64);
const S2 = "2".repeat(64);

let seq = 0;
function exec(check: string, status: CheckExecutionRecord["status"], over: Partial<CheckExecutionRecord> = {}): CheckExecutionRecord {
  seq++;
  return {
    execution_id: `e${seq}`,
    operation_id: "op",
    check,
    status,
    definition_digest: `d-${check}`,
    check_spec_id: `spec-${check}`,
    execution_input_id: `in-${check}`,
    resolved_executable: null,
    env_digest: "env",
    env_names: [],
    passthrough_missing: [],
    freshness_inputs: [],
    freshness_digest: "fr",
    source_id_at_start: S1,
    source_id_at_end: S1,
    source_stable: true,
    started_at: null,
    ended_at: null,
    duration_ms: 1,
    exit_code: status === "passed" ? 0 : 1,
    pid: 1,
    timed_out: status === "timed_out",
    cancelled: status === "cancelled",
    stdout: null,
    stderr: null,
    stdio_held_after_exit: false,
    descendants: null,
    result_artifact: null,
    environment_bound: "partial",
    limitations: [],
    ...over,
  };
}

function cur(check: string, over: Partial<CurrentCheckInputs> = {}): CurrentCheckInputs {
  return { check, state: "runnable", definitionDigest: `d-${check}`, checkSpecId: `spec-${check}`, envDigest: "env", freshnessDigest: "fr", executionInputId: `in-${check}`, ...over };
}

describe("verification floor resolution (D-29)", () => {
  it("run arguments add requirements and can never remove trusted ones", () => {
    const r = resolveRunFloor(view(), ["e2e"]);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.floor.required.map((x) => `${x.check}:${x.source}`)).toEqual(["unit:trusted_config", "lint:trusted_config", "e2e:run_argument"]);
    // There is no argument shape that drops `unit`: an empty list still includes it.
    const r2 = resolveRunFloor(view(), []);
    expect(r2.ok && r2.floor.required.map((x) => x.check)).toEqual(["unit", "lint"]);
  });

  it("unknown or unapproved additions are errors, not silently ignored", () => {
    const r = resolveRunFloor(view(), ["ghost"]);
    expect(!r.ok && r.errors[0]!.code).toBe("UNKNOWN_PROFILE");
    const r2 = resolveRunFloor(view({ approved: new Set(["unit", "lint"]) }), ["e2e"]);
    expect(!r2.ok && r2.errors[0]!.code).toBe("CHECK_NOT_APPROVED");
  });

  it("the effective floor is the run's fixed floor ∪ the current trusted floor", () => {
    const created = resolveRunFloor(view(), ["e2e"]);
    if (!created.ok) throw new Error();
    // Trusted configuration later drops `lint` from the required profile: the run keeps it.
    const later = view({ profiles: { default: ["unit"], full: ["unit", "lint", "e2e"] } });
    expect(effectiveRequirements(created.floor, later).map((r) => r.check).sort()).toEqual(["e2e", "lint", "unit"]);
  });
});

describe("selection (capability: any approved subset)", () => {
  it("defaults to the floor and keeps removed/unapproved requirements as skipped items", () => {
    const reqs = effectiveRequirements(null, view());
    const t = view({ approved: new Set(["unit"]), defined: new Map([["unit", "d-unit"]]) });
    const s = resolveSelection(t, {}, reqs);
    expect(s.ok && s.items).toEqual([
      { check: "unit", disposition: "runnable" },
      { check: "lint", disposition: "definition_removed" },
    ]);
  });

  it("explicit names must all be approved; profiles expand in order, without duplicates", () => {
    const s = resolveSelection(view(), { profiles: ["full"], checks: ["unit"] }, []);
    expect(s.ok && s.items.map((i) => i.check)).toEqual(["unit", "lint", "e2e"]);
    const bad = resolveSelection(view({ approved: new Set(["unit"]) }), { checks: ["unit", "lint"] }, []);
    expect(!bad.ok && bad.errors.map((e) => e.code)).toEqual(["CHECK_NOT_APPROVED"]);
    const unk = resolveSelection(view(), { profiles: ["nope"] }, []);
    expect(!unk.ok && unk.errors[0]!.code).toBe("UNKNOWN_PROFILE");
  });
});

describe("execution freshness: source, spec and environment are distinct (MR-G)", () => {
  it("fresh only when all three dimensions match", () => {
    const f = evaluateExecutionFreshness(exec("unit", "passed"), S1, cur("unit"));
    expect(f).toMatchObject({ fresh: true, source: "fresh", spec: "fresh", environment: "fresh" });
  });

  it("source changed", () => {
    const f = evaluateExecutionFreshness(exec("unit", "passed"), S2, cur("unit"));
    expect(f).toMatchObject({ fresh: false, source: "changed", spec: "fresh", environment: "fresh" });
  });

  it("source changed DURING the execution (repository code wrote files): never fresh", () => {
    const e = exec("unit", "passed", { source_id_at_end: S2, source_stable: false });
    expect(evaluateExecutionFreshness(e, S1, cur("unit"))).toMatchObject({ fresh: false, source: "unstable" });
    expect(evaluateExecutionFreshness(e, S2, cur("unit"))).toMatchObject({ fresh: false, source: "unstable" });
  });

  it("same source, changed check spec", () => {
    const f = evaluateExecutionFreshness(exec("unit", "passed"), S1, cur("unit", { checkSpecId: "spec-other", executionInputId: "in-other" }));
    expect(f).toMatchObject({ fresh: false, source: "fresh", spec: "changed", environment: "fresh" });
    expect(f.reasons).toContain("spec_changed");
  });

  it("environment value changed (passthrough/PATH) vs freshness input changed", () => {
    const env = evaluateExecutionFreshness(exec("unit", "passed"), S1, cur("unit", { envDigest: "env2", executionInputId: "in2" }));
    expect(env).toMatchObject({ fresh: false, source: "fresh", spec: "fresh", environment: "changed" });
    expect(env.reasons).toEqual(["environment_values_changed"]);
    const fr = evaluateExecutionFreshness(exec("unit", "passed"), S1, cur("unit", { freshnessDigest: "fr2", executionInputId: "in2" }));
    expect(fr.reasons).toEqual(["freshness_inputs_changed"]);
  });

  it("removed and unapproved definitions", () => {
    expect(evaluateExecutionFreshness(exec("unit", "passed"), S1, undefined).spec).toBe("removed");
    expect(evaluateExecutionFreshness(exec("unit", "passed"), S1, cur("unit", { state: "unapproved" })).spec).toBe("unapproved");
  });

  it("an unknown current source is never fresh", () => {
    expect(evaluateExecutionFreshness(exec("unit", "passed"), null, cur("unit")).fresh).toBe(false);
  });
});

describe("check status and supersession (engine-owned; MR-D)", () => {
  it("a successful re-run on current inputs supersedes an earlier failure", () => {
    const execs = [exec("unit", "failed"), exec("unit", "passed")];
    const s = checkStatus("unit", execs, S1, cur("unit"));
    expect(s.status).toBe("satisfied");
    expect(s.superseded_failures).toBe(1);
  });

  it("a later failure on current inputs supersedes an earlier pass", () => {
    expect(checkStatus("unit", [exec("unit", "passed"), exec("unit", "failed")], S1, cur("unit")).status).toBe("failed");
  });

  it("ABA: back on an earlier source, the evidence for THAT source decides", () => {
    const execs = [exec("unit", "failed"), exec("unit", "passed", { source_id_at_start: S2, source_id_at_end: S2 })];
    expect(checkStatus("unit", execs, S1, cur("unit")).status).toBe("failed");
    expect(checkStatus("unit", execs, S2, cur("unit")).status).toBe("satisfied");
  });

  it("cancelled, errored and skipped attempts do not supersede a fresh pass", () => {
    const execs = [exec("unit", "passed"), exec("unit", "cancelled"), exec("unit", "error"), exec("unit", "skipped", { skip_reason: "operation_cancelled" })];
    expect(checkStatus("unit", execs, S1, cur("unit")).status).toBe("satisfied");
  });

  it("timed_out is conclusive (a failure on these inputs)", () => {
    expect(checkStatus("unit", [exec("unit", "passed"), exec("unit", "timed_out")], S1, cur("unit")).status).toBe("timed_out");
  });

  it("stale when no fresh conclusive execution exists; missing when none ran", () => {
    expect(checkStatus("unit", [exec("unit", "passed")], S2, cur("unit")).status).toBe("stale");
    expect(checkStatus("unit", [], S1, cur("unit")).status).toBe("missing");
    expect(checkStatus("unit", [exec("unit", "skipped", { skip_reason: "definition_changed" })], S1, cur("unit")).status).toBe("missing");
  });
});

describe("floor evaluation and conditions", () => {
  const reqs = effectiveRequirements(null, view());

  it("satisfied only when every required check has a fresh pass on the current source", () => {
    const execs = [exec("unit", "passed"), exec("lint", "passed")];
    const current = new Map([
      ["unit", cur("unit")],
      ["lint", cur("lint")],
    ]);
    expect(evaluateFloor(true, false, reqs, execs, S1, current).satisfied_for_current_source).toBe(true);
    expect(evaluateFloor(true, false, reqs, execs, S2, current).satisfied_for_current_source).toBe(false);
    expect(evaluateFloor(true, false, reqs, execs, null, current).satisfied_for_current_source).toBe(false);
  });

  it("reports failed, stale, missing, removed and unapproved distinctly, with conditions", () => {
    const reqs5 = [...reqs, { check: "e2e", source: "run_argument" as const, via: "check", definition_digest: "d-e2e" }, { check: "gone", source: "trusted_config" as const, via: "default", definition_digest: "d-gone" }, { check: "bad", source: "trusted_config" as const, via: "default", definition_digest: "d-bad" }];
    const execs = [exec("unit", "failed"), exec("lint", "passed", { source_id_at_start: S2, source_id_at_end: S2 })];
    const current = new Map([
      ["unit", cur("unit")],
      ["lint", cur("lint")],
      ["e2e", cur("e2e")],
      ["bad", cur("bad", { state: "unapproved" })],
    ]);
    const f = evaluateFloor(true, false, reqs5, execs, S1, current);
    expect(f.failed).toEqual(["unit"]);
    expect(f.stale).toEqual(["lint"]);
    expect(f.missing).toEqual(["e2e"]);
    expect(f.removed).toEqual(["gone"]);
    expect(f.unapproved).toEqual(["bad"]);
    expect(f.satisfied_for_current_source).toBe(false);
    const conds = deriveCheckConditions(f);
    expect(conds.map((c) => `${c.check}:${c.kind}`)).toEqual(["unit:check_failed", "lint:check_stale", "e2e:check_missing", "gone:check_missing", "bad:check_missing"]);
    expect(conds.every((c) => c.source === "engine")).toBe(true);
  });

  it("an explicit 'no required checks' floor is satisfied; an unconfigured one is not", () => {
    expect(evaluateFloor(true, true, [], [], S1, new Map()).satisfied_for_current_source).toBe(true);
    expect(evaluateFloor(false, false, [], [], S1, new Map()).satisfied_for_current_source).toBe(false);
  });

  it("flags a required check whose definition changed since the floor was fixed", () => {
    const f = evaluateFloor(true, false, reqs, [], S1, new Map([["unit", cur("unit", { definitionDigest: "d-unit-v2" })], ["lint", cur("lint")]]));
    expect(f.checks.find((c) => c.check === "unit")!.definition_changed_since_floor).toBe(true);
    expect(f.checks.find((c) => c.check === "lint")!.definition_changed_since_floor).toBe(false);
  });
});

describe("tests_removed (plan §14.5)", () => {
  it("reports deleted and renamed-away test files; confidential paths are counted, never named", async () => {
    const { testsRemoved } = await import("../src/policy/verification-floor.js");
    const isTest = (p: string) => p.startsWith("test/") || p.endsWith(".test.ts");
    const r = testsRemoved(
      [
        { path: "test/a.test.ts", status: "deleted", confidential: false },
        { path: "src/b.ts", status: "renamed", old_path: "src/b.test.ts", confidential: false },
        { path: "test/c.test.ts", status: "renamed", old_path: "test/old.test.ts", confidential: false }, // still a test
        { path: "test/secret.env", status: "deleted", confidential: true },
        { path: "src/d.ts", status: "deleted", confidential: false },
        { path: "test/e.test.ts", status: "modified", confidential: false },
      ],
      isTest,
    );
    expect(r).toEqual({ paths: ["src/b.test.ts", "test/a.test.ts"], confidential_count: 1 });
  });
});
