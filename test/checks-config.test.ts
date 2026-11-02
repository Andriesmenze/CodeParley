import { describe, it, expect } from "vitest";
import {
  buildApprovedEntry,
  checkDefinitionDigest,
  evaluateProject,
  isRunnable,
  normalizeCheckDefinition,
  normalizeRepoRelative,
  parseProposals,
  pendingApprovals,
  type ApprovalRequest,
} from "../src/checks/project-config.js";
import type { TrustProjects } from "../src/schemas/trust.js";

const win = process.platform === "win32";
const ROOT = win ? "C:\\src\\proj" : "/src/proj";
const RC = "a".repeat(40);

function request(over: Partial<ApprovalRequest> = {}): ApprovalRequest {
  return {
    canonicalRoot: ROOT,
    rootCommit: RC,
    checks: {
      unit: { argv: ["npm", "test"], env: { CI: "1" }, freshness_inputs: ["node_modules/.package-lock.json"] },
      lint: { argv: ["npm", "run", "lint"], timeout_seconds: 300 },
    },
    profiles: { default: ["unit", "lint"] },
    requiredProfiles: ["default"],
    noRequiredChecks: false,
    testGlobs: ["test/**"],
    ...over,
  };
}

function approvedProjects(over: Partial<ApprovalRequest> = {}): TrustProjects {
  const b = buildApprovedEntry(request(over), "2026-10-04T00:00:00Z", "test");
  if (!b.ok) throw new Error(b.problems.join("; "));
  return { [ROOT]: b.entry };
}

describe("check definitions (strict, canonical)", () => {
  it("fills defaults explicitly and sorts sets", () => {
    const n = normalizeCheckDefinition({ argv: ["node", "t.js"], env_passthrough: ["NODE_ENV", "CI_FLAG"], freshness_inputs: ["b.txt", "./a.txt"] });
    expect(n.ok).toBe(true);
    if (!n.ok) return;
    expect(n.def).toEqual({ argv: ["node", "t.js"], cwd: ".", timeout_seconds: 900, env: {}, env_passthrough: ["CI_FLAG", "NODE_ENV"], freshness_inputs: ["a.txt", "b.txt"] });
  });

  it("refuses unknown keys (fail closed on constraints this version does not honour)", () => {
    const n = normalizeCheckDefinition({ argv: ["x"], concurrent: true });
    expect(n.ok).toBe(false);
  });

  it("refuses a shell string, empty argv, timeouts over the hard cap", () => {
    expect(normalizeCheckDefinition({ argv: "npm test" }).ok).toBe(false);
    expect(normalizeCheckDefinition({ argv: [] }).ok).toBe(false);
    expect(normalizeCheckDefinition({ argv: [""] }).ok).toBe(false);
    expect(normalizeCheckDefinition({ argv: ["x"], timeout_seconds: 3601 }).ok).toBe(false);
  });

  it("refuses cwd and freshness paths that escape the repository or name .git", () => {
    // Windows-only names (`con`, `a:b`) are refused on Windows; on Linux they are ordinary names.
    const windowsOnly = win ? ["con", "a:b"] : [];
    for (const cwd of ["..", "../x", "C:\\x", "/abs", "a/../../b", ".git/hooks", ...windowsOnly]) {
      expect(normalizeCheckDefinition({ argv: ["x"], cwd }).ok, cwd).toBe(false);
    }
    expect(normalizeCheckDefinition({ argv: ["x"], freshness_inputs: ["*.json"] }).ok).toBe(false);
    expect(normalizeCheckDefinition({ argv: ["x"], freshness_inputs: ["."] }).ok).toBe(false);
    // A backslash is a separator on Windows and refused on Linux.
    expect(normalizeRepoRelative("a\\b/./c", { allowRoot: false })).toEqual(win ? { ok: true, path: "a/b/c" } : { ok: false, reason: "backslash" });
    if (!win) expect(normalizeCheckDefinition({ argv: ["x"], cwd: "con" }).ok).toBe(true);
  });

  it("refuses secret-shaped passthrough names and Claude/Anthropic variables", () => {
    for (const n of ["ANTHROPIC_API_KEY", "CLAUDE_CODE_TOKEN", "GITHUB_TOKEN", "MY_SECRET", "CODEX_API_KEY"]) {
      expect(normalizeCheckDefinition({ argv: ["x"], env_passthrough: [n] }).ok, n).toBe(false);
    }
    expect(normalizeCheckDefinition({ argv: ["x"], env: { ANTHROPIC_BASE_URL: "x" } }).ok).toBe(false);
    // Variable names differing only in case are one variable on Windows (refused as a duplicate)
    // and two on Linux.
    expect(normalizeCheckDefinition({ argv: ["x"], env: { CI: "1", ci: "2" } }).ok).toBe(!win);
  });

  it("gives a stable digest that changes with any field", () => {
    const a = normalizeCheckDefinition({ argv: ["npm", "test"] });
    const b = normalizeCheckDefinition({ argv: ["npm", "test"], cwd: "." });
    const c = normalizeCheckDefinition({ argv: ["npm", "test", "--"] });
    if (!a.ok || !b.ok || !c.ok) throw new Error("normalize");
    expect(checkDefinitionDigest("u", a.def)).toBe(checkDefinitionDigest("u", b.def));
    expect(checkDefinitionDigest("u", a.def)).not.toBe(checkDefinitionDigest("u", c.def));
    expect(checkDefinitionDigest("u", a.def)).not.toBe(checkDefinitionDigest("v", a.def));
  });
});

describe("approval building (CLI)", () => {
  it("requires an explicit verification floor", () => {
    const b = buildApprovedEntry(request({ requiredProfiles: [], noRequiredChecks: false }), "t", "v");
    expect(b.ok).toBe(false);
    expect(!b.ok && b.problems.join()).toMatch(/verification floor is required/);
    expect(buildApprovedEntry(request({ requiredProfiles: [], noRequiredChecks: true }), "t", "v").ok).toBe(true);
    expect(buildApprovedEntry(request({ requiredProfiles: ["default"], noRequiredChecks: true }), "t", "v").ok).toBe(false);
  });

  it("refuses undefined profile members, unknown required profiles and name collisions", () => {
    expect(buildApprovedEntry(request({ profiles: { default: ["unit", "ghost"] } }), "t", "v").ok).toBe(false);
    expect(buildApprovedEntry(request({ requiredProfiles: ["nope"] }), "t", "v").ok).toBe(false);
    expect(buildApprovedEntry(request({ profiles: { default: ["unit"], unit: ["lint"] } }), "t", "v").ok).toBe(false);
  });
});

describe("evaluateProject", () => {
  it("approved entry: every check runnable", () => {
    const ev = evaluateProject(approvedProjects(), ROOT, RC);
    expect(ev.status).toBe("approved");
    expect(isRunnable(ev, "unit")).toBe(true);
    expect(ev.requiredProfiles).toEqual(["default"]);
  });

  it("matches the worktree key case-insensitively on Windows and exactly on Linux (a case variant is another directory there)", () => {
    expect(evaluateProject(approvedProjects(), ROOT.toUpperCase(), RC).status).toBe(win ? "approved" : "no_entry");
    expect(evaluateProject(approvedProjects(), ROOT, RC).status).toBe("approved");
  });

  it("a changed approved command definition invalidates the whole approval and names the check", () => {
    const p = approvedProjects();
    (p[ROOT]!.checks!["unit"] as { argv: string[] }).argv = ["npm", "test", "--", "--bail"];
    const ev = evaluateProject(p, ROOT, RC);
    expect(ev.status).toBe("approval_invalid");
    expect(ev.checks.get("unit")!.state).toBe("changed");
    expect(ev.checks.get("lint")!.state).toBe("approved");
    expect(isRunnable(ev, "lint")).toBe(false); // nothing runs until re-approved
  });

  it("detects an added check, a removed check and a changed floor", () => {
    const added = approvedProjects();
    added[ROOT]!.checks!["extra"] = { argv: ["x"] };
    expect(evaluateProject(added, ROOT, RC).checks.get("extra")!.state).toBe("added");
    expect(evaluateProject(added, ROOT, RC).status).toBe("approval_invalid");

    const removed = approvedProjects();
    delete removed[ROOT]!.checks!["lint"];
    removed[ROOT]!.profiles = { default: ["unit"] };
    const ev = evaluateProject(removed, ROOT, RC);
    expect(ev.status).toBe("approval_invalid");
    expect(ev.removed).toEqual(["lint"]);

    const floor = approvedProjects();
    floor[ROOT]!.required_profiles = [];
    floor[ROOT]!.no_required_checks = true;
    expect(evaluateProject(floor, ROOT, RC).status).toBe("approval_invalid");
  });

  it("an approval copied to another worktree path does not apply there", () => {
    const p = approvedProjects();
    const moved: TrustProjects = { "C:\\src\\other": p[ROOT]! };
    expect(evaluateProject(moved, "C:\\src\\other", RC).status).toBe("approval_invalid");
  });

  it("root-commit mismatch: entry recorded for a different repository (R-35)", () => {
    const ev = evaluateProject(approvedProjects(), ROOT, "b".repeat(40));
    expect(ev.status).toBe("root_commit_mismatch");
    expect(isRunnable(ev, "unit")).toBe(false);
  });

  it("a recorded root commit and a repository without one (HEAD unborn) mismatch too (PR #2 review)", () => {
    const ev = evaluateProject(approvedProjects(), ROOT, null);
    expect(ev.status).toBe("root_commit_mismatch");
    expect(isRunnable(ev, "unit")).toBe(false);
  });

  it("unapproved, missing and malformed entries run nothing", () => {
    expect(evaluateProject({}, ROOT, RC).status).toBe("no_entry");
    const p = approvedProjects();
    delete p[ROOT]!.approval;
    expect(evaluateProject(p, ROOT, RC).status).toBe("unapproved");
    const bad = approvedProjects();
    (bad[ROOT]!.checks!["unit"] as Record<string, unknown>)["argv"] = "npm test";
    const ev = evaluateProject(bad, ROOT, RC);
    expect(ev.status).toBe("approval_invalid");
    expect(ev.checks.get("unit")!.state).toBe("invalid");
  });
});

describe("repository proposals (inert until approved)", () => {
  it("lists new, changed and invalid proposals as pending", () => {
    const ev = evaluateProject(approvedProjects(), ROOT, RC);
    const pr = parseProposals({
      proposed_checks: {
        unit: { argv: ["npm", "test"], env: { CI: "1" }, freshness_inputs: ["node_modules/.package-lock.json"] }, // identical
        lint: { argv: ["npm", "run", "lint", "--fix"] }, // changed
        e2e: { argv: ["npm", "run", "e2e"] }, // new
        bad: { argv: "rm -rf /" }, // invalid
      },
      proposed_profiles: { all: ["unit", "e2e"], broken: "x" },
    });
    expect(pr.profiles).toEqual({ all: ["unit", "e2e"] });
    expect(pr.warnings.join()).toMatch(/broken/);
    const pending = pendingApprovals(pr, ev);
    expect(pending.map((p) => [p.name, p.state])).toEqual([
      ["bad", "invalid"],
      ["e2e", "new"],
      ["lint", "changed"],
    ]);
  });

  it("never throws on hostile JSON", () => {
    expect(parseProposals(null).warnings.length).toBe(1);
    expect(parseProposals([1, 2]).warnings.length).toBe(1);
    expect(parseProposals({ proposed_checks: "x" }).warnings.length).toBe(1);
  });
});
