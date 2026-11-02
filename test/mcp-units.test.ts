// M1.5 unit tests: the tool surface (names, annotations, schemas, description lengths), strict
// argument schemas (no field can carry engine-owned evidence), the host-disclosure policy
// (withheld names/hashes, local paths) and the result size bound.

import { describe, it, expect } from "vitest";
import { TOOL_NAMES, SERVER_INSTRUCTIONS, toolDefinitions } from "../src/server/tools.js";
import { CreateReviewRunInput, GetReviewHistoryInput, GetReviewStatusInput, RespondToReviewInput, ReviewWithCodexInput, RunChecksInput, StopReviewLoopInput } from "../src/server/tool-schemas.js";
import { fitToLimit, invalidArgument, MAX_RESULT_CHARS } from "../src/server/result.js";
import { assertHostConfidential, hostText, hostValue, scrubLocalPaths, type HostDisclosure } from "../src/policy/host-disclosure.js";
import { fileUriToPath } from "../src/server/sdk.js";

const RUN = "01a10737-5c4b-7bd1-9ca4-57bf27dd42dc";

describe("tool surface (plan §11)", () => {
  it("registers the six M1 tools, respond_to_review (Phase 2.1), start_review_loop (Phase 3.3a) and delegate_fix / apply_fix (Phase 4 Increment 3); diag_echo only with --diagnostics; nothing else", () => {
    expect(TOOL_NAMES).toEqual(["create_review_run", "run_checks", "review_with_codex", "get_review_status", "get_review_history", "respond_to_review", "start_review_loop", "stop_review_loop", "delegate_fix", "apply_fix"]);
    expect(toolDefinitions(false).map((t) => t.name)).toEqual(TOOL_NAMES);
    expect(toolDefinitions(true).map((t) => t.name)).toEqual([...TOOL_NAMES, "diag_echo"]);
    for (const reserved of ["amend_task_envelope", "delegate_fix_to_codex", "approve_checks", "accept_reduced_isolation", "record_user_decision", "send_responses_to_codex", "allow_loop", "grant_loop", "resume_loop", "bind_session"]) {
      expect(toolDefinitions(true).map((t) => t.name)).not.toContain(reserved);
    }
  });

  it("annotations match the plan's table (§11.1) — destructive where the capability is", () => {
    const a = Object.fromEntries(toolDefinitions(true).map((t) => [t.name, t.annotations]));
    expect(a["create_review_run"]).toEqual({ readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false });
    expect(a["run_checks"]).toEqual({ readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true });
    expect(a["review_with_codex"]).toEqual({ readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true });
    expect(a["get_review_status"]).toEqual({ readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false });
    expect(a["get_review_history"]).toEqual({ readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false });
    // Phase 4 Increment 3: delegate_fix runs Codex (open world) but writes no worktree file; apply_fix writes the worktree.
    expect(a["delegate_fix"]).toEqual({ readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true });
    expect(a["apply_fix"]).toEqual({ readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false });
    expect(a["stop_review_loop"]).toEqual({ readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false });
    // Phase 2.1: writes only the run store, additively (append-only records; nothing deleted or
    // overwritten; no repository change); a repeated identical call changes nothing (its tokens
    // are stale, or its request_id replays); nothing leaves the machine.
    expect(a["respond_to_review"]).toEqual({ readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false });
    expect(a["diag_echo"]).toEqual({ readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false });
    // Phase 3.3a: writes only the run store and consumes an operator grant; calling again returns
    // the same loop (one per run); no repository change; nothing leaves the machine.
    expect(a["start_review_loop"]).toEqual({ readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false });
  });

  it("descriptions and instructions stay under 2 000 characters (K6); MR-J wording is present", () => {
    expect(SERVER_INSTRUCTIONS.length).toBeLessThan(2000);
    for (const t of toolDefinitions(true)) expect(t.description.length, t.name).toBeLessThan(2000);
    for (const n of ["create_review_run", "run_checks", "review_with_codex"]) expect(toolDefinitions(false).find((t) => t.name === n)!.description.toLowerCase()).toContain("cancelling this call does not stop");
    expect(SERVER_INSTRUCTIONS).toContain("ends only that wait");
  });

  it("schemas have object roots and refuse unknown keys (tool-list snapshot)", () => {
    for (const t of toolDefinitions(true)) {
      expect(t.inputSchema["type"], t.name).toBe("object");
      expect(t.inputSchema["additionalProperties"], t.name).toBe(false);
      expect(t.outputSchema["type"], t.name).toBe("object");
      expect((t.outputSchema["required"] as string[]) ?? [], t.name).toContain("summary");
    }
    expect(toolDefinitions(true).map((t) => ({ name: t.name, title: t.title, annotations: t.annotations, inputSchema: t.inputSchema, outputSchema: t.outputSchema, description_chars: t.description.length }))).toMatchSnapshot();
  });
});

describe("engine-owned inputs cannot be supplied (R-12, D-29, T2)", () => {
  const spoofKeys = ["diff", "files", "source_files", "manifest", "capture_manifest", "check_results", "results", "findings", "review_findings", "history", "isolation", "sandbox", "effective_isolation", "allowed_roots", "security_roots", "roots", "verification_floor", "no_required_checks", "required_profiles", "budgets"];
  const bases: [string, { safeParse(v: unknown): { success: boolean } }, Record<string, unknown>][] = [
    ["create_review_run", CreateReviewRunInput, { task_envelope: { goal: "g" } }],
    ["run_checks", RunChecksInput, { run_id: RUN }],
    ["review_with_codex", ReviewWithCodexInput, { run_id: RUN }],
    ["get_review_status", GetReviewStatusInput, { run_id: RUN }],
    ["get_review_history", GetReviewHistoryInput, { run_id: RUN }],
    ["stop_review_loop", StopReviewLoopInput, { run_id: RUN, mode: "close" }],
    ["respond_to_review", RespondToReviewInput, { run_id: RUN, responses: [{ finding_id: RUN, response_token: "t", disposition: "accepted" }] }],
  ];
  for (const [name, schema, base] of bases) {
    it(`${name}: the plain call parses; every spoofed evidence key is refused`, () => {
      expect(schema.safeParse(base).success).toBe(true);
      for (const k of spoofKeys) expect(schema.safeParse({ ...base, [k]: k === "results" ? [] : "x" }).success, `${name}.${k}`).toBe(false);
    });
  }
  it("nested objects are strict too (task envelope, review target, budget overrides, artifact)", () => {
    expect(CreateReviewRunInput.safeParse({ task_envelope: { goal: "g", diff: "x" } }).success).toBe(false);
    expect(CreateReviewRunInput.safeParse({ task_envelope: { goal: "g" }, review_target: { kind: "uncommitted", files: [] } }).success).toBe(false);
    expect(CreateReviewRunInput.safeParse({ task_envelope: { goal: "g" }, budget_overrides: { max_reviews: 1, unlimited: true } }).success).toBe(false);
    expect(CreateReviewRunInput.safeParse({ task_envelope: { goal: "g" }, budget_overrides: { max_reviews: 0 } }).success).toBe(false);
    expect(GetReviewHistoryInput.safeParse({ run_id: RUN, artifact: { operation_id: RUN, part: "result", path: "C:\\x" } }).success).toBe(false);
    expect(GetReviewHistoryInput.safeParse({ run_id: RUN, artifact: { operation_id: RUN, part: "result", length: 30_001 } }).success).toBe(false);
    expect(StopReviewLoopInput.safeParse({ run_id: RUN, mode: "finalize" }).success).toBe(false); // no PASS in M1
  });
  it("INVALID_ARGUMENT names paths and keys, never values", () => {
    const r = RunChecksInput.safeParse({ run_id: RUN, diff: "SECRET-DIFF-CONTENT" });
    expect(r.success).toBe(false);
    if (r.success) return;
    const e = invalidArgument(r.error);
    expect(e.code).toBe("INVALID_ARGUMENT");
    expect(e.message).toContain("diff");
    expect(JSON.stringify(e)).not.toContain("SECRET-DIFF-CONTENT");
  });
});

describe("host disclosure (MR-F, §16.2)", () => {
  const d: HostDisclosure = {
    withheldPaths: new Set(["config/db.env", ".env", "config/Ä.env"]),
    withheldHashes: new Set(["a".repeat(64)]),
    keepRoots: ["C:\\Users\\Pat Smith\\src\\repo", "L:\\Repos"],
    hiddenDirs: [
      { dir: "C:\\Users\\Pat Smith\\AppData\\Local\\CodeParley", label: "[data home]" },
      { dir: "C:\\Users\\Pat Smith", label: "[user profile]" },
      { dir: "C:\\Users\\Pat Smith\\AppData\\Local\\Temp", label: "[temp]" },
    ],
  };
  it("redacts withheld names in any spelling and withheld hashes", () => {
    expect(hostText("see config/db.env and CONFIG\\DB.ENV and config\\\\db.env", d)).toBe("see [withheld path] and [withheld path] and [withheld path]");
    expect(hostText("FILE=config/ä.env", d)).toBe("FILE=[withheld path]");
    expect(hostText(`hash ${"a".repeat(64)} end`, d)).toBe("hash [withheld hash] end");
    expect(hostText("config/db.env.ts and app.env.ts stay", d)).toBe("config/db.env.ts and app.env.ts stay");
  });
  it("keeps the repository and allowed roots, hides the data home, profile, temp and foreign paths", () => {
    expect(scrubLocalPaths("repo C:\\Users\\Pat Smith\\src\\repo\\a.js ok", d)).toBe("repo C:\\Users\\Pat Smith\\src\\repo\\a.js ok");
    expect(scrubLocalPaths("store C:\\Users\\Pat Smith\\AppData\\Local\\CodeParley\\runs\\x", d)).toBe("store [data home]\\runs\\x");
    expect(scrubLocalPaths("profile c:/users/pat smith/.ssh/id", d)).toBe("profile [user profile]/.ssh/id");
    expect(scrubLocalPaths('json "C:\\\\Users\\\\Pat Smith\\\\x"', d)).toBe('json "[user profile]\\\\x"');
    expect(scrubLocalPaths("other D:\\secret\\notes.txt and \\\\server\\share\\x and L:\\Repos\\y", d)).toBe("other [local path] and [local path] and L:\\Repos\\y");
    expect(scrubLocalPaths("relative src\\a.js and ratio 3:2 stay", d)).toBe("relative src\\a.js and ratio 3:2 stay");
  });
  it("deep values: every string transformed; the invariant fails closed on what redaction cannot fix", () => {
    const v = hostValue({ a: ["config/db.env"], b: { c: "C:\\Users\\Pat Smith\\x" } }, d);
    expect(v).toEqual({ a: ["[withheld path]"], b: { c: "[user profile]\\x" } });
    expect(() => assertHostConfidential(v, d)).not.toThrow();
    expect(() => assertHostConfidential({ k: "config/db.env" }, d)).toThrow();
    expect(() => assertHostConfidential({ "config/db.env": 1 }, d)).toThrow(); // keys are checked too
  });
  it("is linear on hostile inputs (no backtracking)", () => {
    const t0 = Date.now();
    hostText("C:" + "\\".repeat(200_000) + "x " + "\\\\a".repeat(50_000), d);
    expect(Date.now() - t0).toBeLessThan(3000);
  });
});

describe("host disclosure with POSIX paths (Linux, plan §1.13)", () => {
  const d: HostDisclosure = {
    withheldPaths: new Set(["config/db.env"]),
    withheldHashes: new Set(),
    keepRoots: ["/home/pat/src/repo", "/srv/Repos"],
    hiddenDirs: [
      { dir: "/home/pat/.local/state/code-parley", label: "[data home]" },
      { dir: "/home/pat", label: "[user profile]" },
      { dir: "/tmp", label: "[temp]" },
    ],
    posixPaths: true,
  };
  it("keeps the repository and allowed roots, hides the data home, home, temp and foreign absolute paths", () => {
    expect(scrubLocalPaths("repo /home/pat/src/repo/a.js ok", d)).toBe("repo /home/pat/src/repo/a.js ok");
    expect(scrubLocalPaths("store /home/pat/.local/state/code-parley/runs/x", d)).toBe("store [data home]/runs/x");
    expect(scrubLocalPaths("key /home/pat/.ssh/id_ed25519 and scratch /tmp/arl-x/y", d)).toBe("key [user profile]/.ssh/id_ed25519 and scratch [temp]/arl-x/y");
    expect(scrubLocalPaths('other /etc/shadow, "/var/lib/x" and file:///opt/y and /srv/Repos/z', d)).toBe('other [local path], "[local path]" and [local path] and /srv/Repos/z');
    // Names are case-sensitive: another spelling of a kept root is another directory.
    expect(scrubLocalPaths("near /srv/repos/z", d)).toBe("near [local path]");
    // Relative paths, URLs, fractions, N/A and code comments are not local paths.
    expect(scrubLocalPaths("relative src/a.js ./b and https://example.com/x and N/A and 3/4 and // note", d)).toBe("relative src/a.js ./b and https://example.com/x and N/A and 3/4 and // note");
  });
  it("recognises absolute paths whatever their first character (dogfood review): Unicode, punctuation, doubled or escaped slashes, file URLs", () => {
    const bare: HostDisclosure = { ...d, keepRoots: [], hiddenDirs: [] };
    for (const p of ["/資料/private.txt", "/.hidden/key", "/#tmp/x", "/$HOME/x", "//etc/passwd", "\\/etc\\/shadow", "file:///資料/x", "file://host/share/x"]) {
      expect(scrubLocalPaths(`failed at ${p} here`, bare), p).toBe("failed at [local path] here");
    }
    expect(scrubLocalPaths('{"path":"/資料/x"}', bare)).toBe('{"path":"[local path]"}');
  });
  it("withheld names and the invariant work the same way", () => {
    const v = hostValue({ a: "see config/db.env at /home/pat/src/repo/config/db.env", b: ["/home/pat/notes"] }, d);
    expect(v).toEqual({ a: "see [withheld path] at /home/pat/src/repo/[withheld path]", b: ["[user profile]/notes"] });
    expect(() => assertHostConfidential(v, d)).not.toThrow();
  });
  it("is linear on hostile inputs (no backtracking)", () => {
    const t0 = Date.now();
    hostText(`${" /".repeat(100_000)}${"/a".repeat(100_000)} file://${"/".repeat(100_000)}`, d);
    expect(Date.now() - t0).toBeLessThan(3000);
  });
});

describe("result size bound (K6)", () => {
  it("halves the largest lists, records every cut and stays under the bound", () => {
    const big = { summary: "s", findings: Array.from({ length: 400 }, (_, i) => ({ id: i, text: "x".repeat(300) })), conditions: [{ a: 1 }] };
    const out = fitToLimit(big);
    expect(JSON.stringify(out).length).toBeLessThanOrEqual(MAX_RESULT_CHARS);
    const tr = out["truncation"] as { truncated: boolean; cut_lists: { field: string; kept: number; total: number }[]; next: string };
    expect(tr.truncated).toBe(true);
    expect(tr.cut_lists[0]).toMatchObject({ field: "findings", total: 400 });
    expect((out["findings"] as unknown[]).length).toBe(tr.cut_lists[0]!.kept);
    expect(tr.next).toContain("get_review_history");
    expect(out["summary"]).toBe("s");
  });
  it("leaves small results unchanged", () => {
    const small = { summary: "s", list: [1, 2, 3] };
    expect(fitToLimit(small)).toBe(small);
  });
  it("falls back to identifiers when no list can be cut enough", () => {
    const out = fitToLimit({ summary: "s", run_id: "r", blob: { a: "y".repeat(8000), b: "y".repeat(8000), c: "y".repeat(8000), d: "y".repeat(8000), e: "y".repeat(8000), f: "y".repeat(8000) } });
    expect(JSON.stringify(out).length).toBeLessThanOrEqual(MAX_RESULT_CHARS);
    expect(out["run_id"]).toBe("r");
  });
});

describe("client roots are local paths only (advisory)", () => {
  it("file URIs map to Windows paths; anything else is dropped", () => {
    expect(fileUriToPath("file:///C:/src/repo", "win32")).toBe("C:\\src\\repo");
    expect(fileUriToPath("file:///c%3A/My%20Repo", "win32")).toBe("c:\\My Repo");
    expect(fileUriToPath("file://server/share/x", "win32")).toBe("\\\\server\\share\\x");
    expect(fileUriToPath("https://example.com/x", "win32")).toBeNull();
    expect(fileUriToPath("not a uri", "win32")).toBeNull();
  });

  it("file URIs map to Linux paths; another host's file and anything else is dropped", () => {
    expect(fileUriToPath("file:///home/me/src/repo", "linux")).toBe("/home/me/src/repo");
    expect(fileUriToPath("file:///home/me/My%20Repo", "linux")).toBe("/home/me/My Repo");
    expect(fileUriToPath("file://localhost/srv/repo", "linux")).toBe("/srv/repo");
    expect(fileUriToPath("file://server/share/x", "linux")).toBeNull();
    expect(fileUriToPath("file:///a%00b", "linux")).toBeNull();
    expect(fileUriToPath("https://example.com/x", "linux")).toBeNull();
  });
});
