// Step 7.1: `code-parley fix review` (src/cli/fix-review.ts), the operator's guided decision on a delegated fix, against the
// simulated custodian with the real engine (a delegated fix proposed by the fake fixer), and with a transport that alters
// the custodian's answers for the cases a correct custodian never produces. The custodian's side (list_fix_proposals, the
// expected values) is in the shared run corpus; the real custodians run it too.
import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { runCli, type CliIo } from "../src/cli/cli.js";
import { applyFix } from "../src/engine/fix-apply.js";
import { delegateFix } from "../src/engine/fix-operation.js";
import { preparedMismatch, renderingFault } from "../src/cli/fix-review.js";
import type { CustodianOp, CustodianResponse, CustodianSurface } from "../src/custodian/protocol.js";
import type { CustodianTransport } from "../src/custodian/transport.js";
import type { FixListingEntry, PreparedFixDecision } from "../src/custodian/operator.js";
import type { FixRendering } from "../src/custodian/grants.js";
import { supported } from "./helpers/git-fixture.js";
import { MATH_V1 } from "./helpers/review-fixture.js";
import type { ContFixture } from "./helpers/continuation-fixture.js";
import { TASK, confirmFix, editing, protectedRun, storeFixSelfTest_ } from "./helpers/delegated-fix.js";
import type { RunHandle } from "../src/engine/engine-env.js";

const BOUND = { timeout: 240_000 };

async function proposed(maxFixes = 2): Promise<{ f: ContFixture; run: RunHandle; op: string }> {
  const { f, run } = await protectedRun(maxFixes);
  await storeFixSelfTest_(f);
  await confirmFix(f);
  const r = await delegateFix(f.le, run, TASK, { launch: editing("src/math.js", MATH_V1) });
  expect(r.status, r.detail ?? "").toBe("proposed");
  return { f, run, op: r.operation_id };
}

/** A scripted operator at an interactive terminal: `answer` gets each question and what was printed before it. */
function terminal(answer: (question: string, printed: string[]) => string, size = { columns: 120, rows: 400 }, interactive = true) {
  const lines: string[] = [];
  const errors: string[] = [];
  const questions: string[] = [];
  const io: CliIo & { lines: string[]; errors: string[]; questions: string[] } = {
    lines, errors, questions, interactive, env: process.env, cwd: process.cwd(), terminalSize: () => size,
    out: (l) => lines.push(l), err: (l) => errors.push(l),
    prompt: interactive ? async (q) => {
      questions.push(q);
      if (questions.length > 200) throw new Error(`the terminal script ran away at: ${q}`);
      return answer(q, lines);
    } : null,
  };
  return io;
}

/** Answers in order, by the kind of question asked. */
const script = (...answers: string[]) => (q: string) => {
  const a = answers.shift();
  if (a === undefined) throw new Error(`no scripted answer for: ${q}`);
  return a;
};

const review = (f: ContFixture, io: CliIo, args: string[] = [], transport?: CustodianTransport) =>
  runCli(["fix", "review", ...args, "--home", f.dataHome, "--git", f.git], {
    ...io, engineTestHooks: transport ? { ...f.le.env.testHooks!, custodian: { ...f.le.env.testHooks!.custodian!, transport } } : f.le.env.testHooks!,
  });

const sent = (f: ContFixture, op: CustodianOp) => f.custodian.received.filter((r) => r.op === op).length;
const math = (f: ContFixture): Promise<string> => readFile(join(f.repo, "src", "math.js"), "utf8");

/** A transport that passes requests to `inner` and lets a test change the answer to one operation. */
function altered(inner: CustodianTransport, op: CustodianOp, change: (res: CustodianResponse) => CustodianResponse): CustodianTransport {
  return { send: async (surface: CustodianSurface, o: CustodianOp, args: Record<string, unknown>, requestId: string) => {
    const res = await inner.send(surface, o, args, requestId);
    return o === op ? change(structuredClone(res)) : res;
  } } as CustodianTransport;
}

describe.skipIf(!supported)("Step 7.1: fix review, the guided decision (simulated custodian, real engine)", BOUND, () => {
  it("lists the fix by number, shows the custodian's whole rendering, confirms it with the typed word; apply_fix then applies it — no run id, fix id or path typed", async () => {
    const { f, run, op } = await proposed();
    const io = terminal(script("1", "c", "confirm", "q"));
    expect(await review(f, io), io.errors.join(" | ")).toBe(0);
    const out = io.lines.join("\n");
    expect(out).toMatch(/^ +1 {2}.*run .*fix .*1 file, \d+ bytes {2}waiting for your decision/m);
    expect(out).toContain("+  return a + b;");
    expect(out).toContain("[end of the custodian's rendering: all");
    expect(out).toContain("The custodian prepared this decision for exactly the rendering you reviewed");
    expect(out).toContain("It authorizes no commit, push, merge, tag or release.");
    expect(out).toMatch(/Confirmed by the custodian: delegated fix .* bound to rendering [0-9a-f]{64}; single use/);
    // Nothing the operator typed named the run, the fix or the repository.
    for (const typed of ["1", "c", "confirm", "q"]) expect([run.runId, op, f.repo]).not.toContain(typed);
    // The guided preparation named all three expected values.
    const prepare = f.custodian.received.find((r) => r.op === "prepare_fix_decision")!;
    expect(Object.keys(prepare.args).filter((k) => k.startsWith("expected")).sort()).toEqual(["expectedProposalDigest", "expectedRenderingDigest", "expectedRepoKey"]);
    // After the decision the listing is read again: the fix now waits for the session.
    expect(out).toMatch(/ +- .*confirmed, waiting for the session to apply it/);
    const applied = await applyFix(f.le, run, { proposal_id: op });
    expect(applied.status, JSON.stringify(applied)).toBe("applied");
    expect(await math(f)).toBe(MATH_V1);
  });

  it("a rejection through fix review closes the proposal: apply_fix is refused and nothing is written", async () => {
    const { f, run, op } = await proposed();
    const before = await math(f);
    const io = terminal(script("1", "r", "reject", "q"));
    expect(await review(f, io), io.errors.join(" | ")).toBe(0);
    expect(io.lines.join("\n")).toMatch(/Rejected by the custodian: delegated fix .*nothing is applied/);
    await expect(applyFix(f.le, run, { proposal_id: op })).rejects.toThrow(/FIX_DECLINED|not confirmed|declined/i);
    expect(await math(f)).toBe(before);
  });

  it("leaving, quitting or typing anything but the word records nothing; a decision is never offered before the last page was shown", async () => {
    const { f } = await proposed();
    const commits0 = sent(f, "commit");
    // q at the first page of a small terminal: nothing prepared.
    const small = { columns: 100, rows: 8 };
    const io1 = terminal(script("1", "q", "q"), small);
    expect(await review(f, io1)).toBe(0);
    expect(io1.questions.some((q) => q.startsWith("[c]onfirm"))).toBe(false);
    // Paging to the end with G, then Enter: the decision appears only once every page was shown.
    let rendered = 0;
    const io2 = terminal((q, printed) => {
      if (q.startsWith("Choose")) return io2.questions.filter((x) => x.startsWith("Choose")).length === 1 ? "1" : "q";
      if (q.startsWith("[c]onfirm")) {
        rendered = printed.filter((l) => /^ {0,5}\d+ \| /.test(l)).length;
        return "l";
      }
      if (q.startsWith("[lines")) return io2.questions.filter((x) => x.startsWith("[lines")).length === 1 ? "G" : "";
      throw new Error(`unexpected: ${q}`);
    }, small);
    expect(await review(f, io2)).toBe(0);
    const total = Number(/all (\d+) lines shown/.exec(io2.lines.join("\n"))![1]);
    expect(rendered).toBeGreaterThanOrEqual(total);
    // A wrong word after preparation: not recorded.
    const io3 = terminal(script("1", "c", "yes", "q"));
    expect(await review(f, io3)).toBe(0);
    expect(io3.lines.join("\n")).toContain("Not recorded (the prepared decision expires unused).");
    expect(sent(f, "commit")).toBe(commits0); // none from these reviews
  });

  it("--no-pager writes the custodian's rendering byte for byte before the decision is offered", async () => {
    const { f, run, op } = await proposed();
    const shown = await f.custodian.send("operator", "render_fix_proposal", { repositoryRoot: f.repo, runId: run.runId, operationId: op }, "render-for-test");
    const io = terminal(script("1", "l", "q"));
    expect(await review(f, io, ["--no-pager"])).toBe(0);
    const text = String(shown.data?.["rendering"]);
    const at = io.lines.indexOf(text.split("\n")[0]!);
    expect(io.lines.slice(at, at + text.replace(/\n$/, "").split("\n").length).join("\n") + "\n").toBe(text);
  });

  it("needs an interactive terminal and takes no positional argument or decision flag; nothing is listed otherwise", async () => {
    const { f } = await proposed();
    const io = terminal(script(), undefined, false);
    expect(await review(f, io)).not.toBe(0);
    expect(io.errors.join(" ")).toMatch(/INTERACTIVE_TERMINAL_REQUIRED|interactive terminal/);
    expect(sent(f, "list_fix_proposals")).toBe(0);
    for (const extra of [["1"], ["--confirm", "x"]]) {
      const io2 = terminal(script("q"));
      expect(await review(f, io2, extra), extra.join(" ")).not.toBe(0);
    }
    expect(sent(f, "list_fix_proposals")).toBe(0);
  });

  it("the implementer's surface is refused the listing, with nothing listed", async () => {
    const { f } = await proposed();
    const res = await f.custodian.send("implementer", "list_fix_proposals", {}, "list-as-implementer");
    expect(res).toMatchObject({ ok: false, code: "CALLER_NOT_AUTHORIZED" });
    expect(res.data).toBeUndefined();
  });

  it("an older custodian (no list_fix_proposals) gets the fallback commands and exit 2", async () => {
    const { f } = await proposed();
    const old = altered(f.custodian, "list_fix_proposals", () => ({ ok: false, code: "UNKNOWN_OPERATION", error: "unknown operation 'list_fix_proposals'" }));
    const io = terminal(script());
    expect(await review(f, io, [], old)).toBe(2);
    expect(io.errors.join(" ")).toContain("This custodian predates `fix review`");
  });

  it("a prepared decision that is not the one reviewed is refused before the word is asked: nothing is committed", async () => {
    const { f } = await proposed();
    const commits0 = sent(f, "commit");
    for (const tamper of [
      (d: Record<string, unknown>) => ((d["fixDecision"] as Record<string, unknown>)["renderingDigest"] = "f".repeat(64)),
      (d: Record<string, unknown>) => (d["rendering"] = `${String(d["rendering"])}\nAlso apply something else.`),
      (d: Record<string, unknown>) => ((d["fixDecision"] as Record<string, unknown>)["repoKey"] = "sim1-0-0"),
      (d: Record<string, unknown>) => delete d["fixDecision"],
    ]) {
      const t = altered(f.custodian, "prepare_fix_decision", (res) => {
        if (res.ok) tamper(res.data!);
        return res;
      });
      const io = terminal(script("1", "c", "q"));
      expect(await review(f, io, [], t)).toBe(0);
      expect(io.errors.join(" ")).toContain("The prepared decision does not match what you reviewed");
      expect(io.questions.some((q) => q.startsWith("Type "))).toBe(false);
    }
    expect(sent(f, "commit")).toBe(commits0);
  });

  it("a stale selection (the custodian's SELECTION_STALE) and a lost answer after the commit was sent are reported, never retried or called confirmed", async () => {
    const { f } = await proposed(3);
    const stale = altered(f.custodian, "prepare_fix_decision", () => ({ ok: false, code: "SELECTION_STALE", error: "the custodian's rendering of delegated fix x is not the one that was reviewed" }));
    const io = terminal(script("1", "c", "q"));
    expect(await review(f, io, [], stale)).toBe(0);
    expect(io.errors.join(" ")).toMatch(/SELECTION_STALE.*\n?.*|Nothing was recorded/);
    // The answer to the commit is lost after the custodian applied it: the CLI does not know, says so, does not resend.
    const commitsBefore = sent(f, "commit");
    f.custodian.failNext("commit", "lost_response");
    const io2 = terminal(script("1", "c", "confirm", "q"));
    expect(await review(f, io2)).toBe(0);
    expect(io2.errors.join(" ")).toContain("does not know whether it was recorded and does not send it again");
    expect(io2.lines.join("\n")).not.toMatch(/Confirmed by the custodian/);
    expect(sent(f, "commit")).toBe(commitsBefore + 1);
    expect(io2.lines.join("\n")).toMatch(/confirmed, waiting for the session to apply it/); // the custodian's record shows the outcome
  });
});

describe("Step 7.1: the checks before a rendering is shown and before a decision is accepted", () => {
  const body = "delegated fix f1 of run r1\n+x = 1;\n";
  const digest = createHash("sha256").update(body, "utf8").digest("hex");
  const rendering: FixRendering = { operationId: "f1", status: "proposed", proposalDigest: "a".repeat(64), expiresAt: null, rendering: `${body}rendering sha256: ${digest}\n`, renderingDigest: digest, confirmation: null };
  const entry = { proposalDigest: "a".repeat(64), renderingDigest: digest, repoKey: "sim1-1-2", runId: "r1", operationId: "f1" } as FixListingEntry;

  it("refuses a rendering that changed since the listing, whose SHA-256 is not its bytes, or that holds an unescaped control or bidi character", () => {
    expect(renderingFault(rendering, entry)).toBeNull();
    expect(renderingFault({ ...rendering, proposalDigest: "b".repeat(64) }, entry)).toMatch(/proposal changed/);
    expect(renderingFault({ ...rendering, rendering: rendering.rendering.replace("x = 1", "x = 2") }, entry)).toMatch(/does not match its bytes/);
    for (const bad of ["\u001b[2J", "‮", "\u0085", "​", "\r"]) {
      const b = `delegated fix f1 of run r1\n+x = 1;${bad}\n`;
      const d = createHash("sha256").update(b, "utf8").digest("hex");
      expect(renderingFault({ ...rendering, rendering: `${b}rendering sha256: ${d}\n`, renderingDigest: d }, { ...entry, renderingDigest: d }), JSON.stringify(bad)).toMatch(/unescaped U\+/);
    }
  });

  it("accepts a prepared decision only when its facts equal the selection and its text is header + the reviewed bytes + footer", () => {
    const facts = { decision: "confirm" as const, repoKey: entry.repoKey, repositoryRoot: "/r", runId: "r1", operationId: "f1", proposalDigest: entry.proposalDigest, renderingDigest: digest, baselineSourceId: null, authorityHeader: "Confirm …\n\n", authorityFooter: "\nIt authorizes no commit.", consequences: [] };
    const ok: PreparedFixDecision = { authorizationRequestId: "a", expiresAt: "t", rendering: facts.authorityHeader + rendering.rendering + facts.authorityFooter, facts };
    expect(preparedMismatch(ok, entry, rendering, "confirm")).toBeNull();
    expect(preparedMismatch(ok, entry, rendering, "reject")).toMatch(/another decision/);
    expect(preparedMismatch({ ...ok, facts: { ...facts, runId: "r2" } }, entry, rendering, "confirm")).toMatch(/another run or fix/);
    expect(preparedMismatch({ ...ok, rendering: ok.rendering.replace("+x = 1;", "+x = 9;") }, entry, rendering, "confirm")).toMatch(/not the reviewed rendering/);
    expect(preparedMismatch({ ...ok, facts: { ...facts, authorityFooter: "\nok\u001b[0m" }, rendering: facts.authorityHeader + rendering.rendering + "\nok\u001b[0m" }, entry, rendering, "confirm")).toMatch(/unescaped/);
    expect(preparedMismatch({ ...ok, facts: null }, entry, rendering, "confirm")).toMatch(/no structured decision/);
  });
});
