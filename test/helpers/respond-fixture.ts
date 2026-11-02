// Phase 2.1 test helpers: the respond engine on a review fixture (real git, fake Codex). The
// source identity is the engine's own computation under the capture lock, as the MCP path
// reads it; tests that need another answer pass their own.

import { computeSourceIdentity } from "../../src/capture/capture.js";
import { uuidv7 } from "../../src/common/ids.js";
import { respondToReview, type RespondContext, type RespondRequest, type RespondTestHooks, type SourceForResponse } from "../../src/engine/respond.js";
import { withheldOfEntries } from "../../src/engine/host-view.js";
import { custodianPresence } from "../../src/custodian/protected-loops.js";
import type { ReviewEngineContext } from "../../src/engine/review-operation.js";
import { itemDiscussion, reportDiscussion, type DiscussionState } from "../../src/policy/responses.js";
import { readState } from "../../src/store/state-store.js";

/** The working tree's source identity now, as the MCP path records it (fresh and stable, else null). */
export async function sourceNow(ctx: ReviewEngineContext): Promise<SourceForResponse> {
  try {
    const r = await computeSourceIdentity({ repoRoot: ctx.meta.repository_root, gitExe: ctx.gitExe, rules: ctx.rules, lock: { dataHome: ctx.dataHome, owner: ctx.owner }, operationId: `respond-${uuidv7()}` });
    // As the MCP path: what the read withheld, whatever its stability.
    const withheld = withheldOfEntries(r.entries);
    return r.stable ? { source_id: r.source_id, note: null, withheld } : { source_id: null, note: "the working tree changed while it was being read", withheld };
  } catch (e) {
    // No read: the responses' text is withheld from every view.
    return { source_id: null, note: `not recomputed (${(e as { code?: string }).code ?? String(e)})` };
  }
}

export function respondContext(ctx: ReviewEngineContext, o: { source?: () => Promise<SourceForResponse>; hooks?: RespondTestHooks } = {}): RespondContext {
  return {
    runId: ctx.meta.run_id,
    runPaths: ctx.runPaths,
    owner: ctx.owner,
    currentSource: o.source ?? (() => sourceNow(ctx)),
    evidence: { custodian: ctx.custodian, presence: ctx.custodianPresence ?? (() => custodianPresence(true, ctx.custodian)), repositoryRoot: ctx.meta.repository_root, runId: ctx.meta.run_id },
    ...(o.hooks ? { testHooks: o.hooks } : {}),
  };
}

export function respond(ctx: ReviewEngineContext, req: RespondRequest, o: { source?: () => Promise<SourceForResponse>; hooks?: RespondTestHooks } = {}) {
  return respondToReview(respondContext(ctx, o), req);
}

export interface ItemNow {
  id: string;
  token: string | null;
  state: DiscussionState;
  status: string;
}

/** The run's reviewer items by title, with their response tokens and discussion states now. */
export async function items(ctx: ReviewEngineContext): Promise<Map<string, ItemNow>> {
  const st = await readState(ctx.runPaths);
  const out = new Map<string, ItemNow>();
  for (const it of st.findings) {
    const d = itemDiscussion(it, reportDiscussion(st, null).view, null);
    out.set(it.title, { id: it.id, token: d.response_token, state: d.discussion_state, status: it.status });
  }
  return out;
}

export async function itemNow(ctx: ReviewEngineContext, title: string): Promise<ItemNow> {
  const it = (await items(ctx)).get(title);
  if (!it) throw new Error(`no reviewer item titled ${JSON.stringify(title)}`);
  return it;
}

/** The prior items a review prompt presented (the JSON between the "prior" data markers). */
export function priorItemsIn(prompt: string): { id: string; title: string }[] {
  const start = prompt.indexOf(" prior\n");
  if (start < 0) return [];
  const body = prompt.slice(start + " prior\n".length, prompt.indexOf("\nDATA ", start));
  return body.trim() === "none" ? [] : (JSON.parse(body) as { id: string; title: string }[]);
}

/** The bundle alias (PF-n) a review prompt gave the item with this title. */
export function aliasIn(prompt: string, title: string): string {
  const hit = priorItemsIn(prompt).find((p) => p.title === title);
  if (!hit) throw new Error(`no alias for ${title}`);
  return hit.id;
}
