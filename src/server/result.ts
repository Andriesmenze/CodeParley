// Result shaping for tool calls (plan §11.1; M1.5). Every result — errors included — is a
// complete `structuredContent` object with a `summary` (Claude Code gives the model only
// this JSON, K7) plus the same JSON as one text block (added by the SDK adapter). Results are
// kept under a conservative character bound (K6: ~40 000): the largest lists are cut first,
// with an explicit `truncation` record naming what was cut and how to page it, never
// silently.

import { z } from "zod";
import { isDomainError, type ErrorCode } from "../common/errors.js";
import { remedyFor } from "../common/remedies.js";
import type { ToolOutcome } from "./sdk.js";

export const MAX_RESULT_CHARS = 40_000;
const MAX_STRING_CHARS = 8_000;

/** A successful result; `next` says where a shortened result's complete content can be read. */
export function ok(structured: Record<string, unknown>, next?: string): ToolOutcome {
  return { kind: "result", structuredContent: fitToLimit(structured, MAX_RESULT_CHARS, next), isError: false };
}

export interface ToolError {
  code: ErrorCode | string;
  message: string;
  retryable: boolean;
  details?: Record<string, unknown>;
}

export function errorStructure(e: ToolError): Record<string, unknown> {
  // Phase 6 Increment 3: the remediation catalog's cause and fix (wording only; nothing reads it to decide anything).
  const remedy = remedyFor(String(e.code), process.platform, e.message);
  return {
    summary: `error ${e.code}: ${e.message}`.slice(0, 2000) + (remedy ? ` — fix: ${remedy.fix}`.slice(0, 1200) : ""),
    error: { code: e.code, message: e.message.slice(0, 4000), retryable: e.retryable, ...(e.details ? { details: e.details } : {}), ...(remedy ? { remedy } : {}) },
  };
}

export function fail(e: ToolError): ToolOutcome {
  return { kind: "result", structuredContent: fitToLimit(errorStructure(e)), isError: true };
}

/** Map a thrown value to a tool error (domain codes kept; anything else is INTERNAL). */
export function toToolError(e: unknown): ToolError {
  if (isDomainError(e)) {
    const details = e.details && typeof e.details === "object" ? (JSON.parse(JSON.stringify(e.details)) as Record<string, unknown>) : undefined;
    return { code: e.code, message: e.message, retryable: e.retryable, ...(details ? { details } : {}) };
  }
  return { code: "INTERNAL", message: `internal error: ${e instanceof Error ? e.message : String(e)}`, retryable: false };
}

/** INVALID_ARGUMENT from a zod error (paths and messages only, never echoing values). */
export function invalidArgument(err: z.ZodError): ToolError {
  const issues = err.issues.slice(0, 20).map((i) => {
    const path = i.path.map(String).join(".") || "$";
    const keys = i.code === "unrecognized_keys" ? ` (${(i as { keys?: string[] }).keys?.join(", ")})` : "";
    return `${path}: ${i.message}${keys}`;
  });
  return { code: "INVALID_ARGUMENT", message: `invalid arguments: ${issues.join("; ")}`, retryable: false, details: { issues } };
}

// ---------------------------------------------------------------------------
// Size bound
// ---------------------------------------------------------------------------

interface Cut {
  field: string;
  kept: number;
  total: number;
}

function clampStrings(v: unknown, cuts: { n: number }): unknown {
  if (typeof v === "string") {
    if (v.length <= MAX_STRING_CHARS) return v;
    cuts.n++;
    return `${v.slice(0, MAX_STRING_CHARS)}… [${v.length - MAX_STRING_CHARS} characters cut]`;
  }
  if (Array.isArray(v)) return v.map((x) => clampStrings(x, cuts));
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, clampStrings(x, cuts)]));
  return v;
}

/** The largest array (by serialized size) anywhere in `v`, with its path. */
function largestArray(v: unknown, path: string[] = []): { path: string[]; arr: unknown[]; size: number } | null {
  let best: { path: string[]; arr: unknown[]; size: number } | null = null;
  if (Array.isArray(v)) {
    if (v.length > 1) best = { path, arr: v, size: JSON.stringify(v).length };
    v.forEach((x, i) => {
      const b = largestArray(x, [...path, String(i)]);
      if (b && (!best || b.size > best.size)) best = b;
    });
  } else if (v && typeof v === "object") {
    for (const [k, x] of Object.entries(v)) {
      if (k === "truncation") continue;
      const b = largestArray(x, [...path, k]);
      if (b && (!best || b.size > best.size)) best = b;
    }
  }
  return best;
}

/**
 * Keep the result under MAX_RESULT_CHARS: clamp very long strings, then repeatedly halve the
 * largest list. Every cut is recorded in `truncation`; the full document stays available
 * through get_review_history (artifact part "result").
 */
export function fitToLimit(o: Record<string, unknown>, limit = MAX_RESULT_CHARS, next?: string): Record<string, unknown> {
  if (JSON.stringify(o).length <= limit) return o;
  const strCuts = { n: 0 };
  let v = clampStrings(o, strCuts) as Record<string, unknown>;
  const cuts = new Map<string, Cut>();
  for (let guard = 0; guard < 200 && JSON.stringify(v).length > limit - 600; guard++) {
    const big = largestArray(v);
    if (!big) break;
    const field = big.path.join(".");
    const prev = cuts.get(field);
    const total = prev?.total ?? big.arr.length;
    const keep = Math.max(1, Math.floor(big.arr.length / 2));
    if (keep >= big.arr.length) break;
    big.arr.splice(keep);
    cuts.set(field, { field, kept: keep, total });
  }
  let out: Record<string, unknown> = {
    ...v,
    truncation: {
      truncated: true,
      cut_lists: [...cuts.values()],
      clamped_strings: strCuts.n,
      next: next ?? "The result was shortened to stay within host limits. Page the complete document with get_review_history(run_id, artifact: {operation_id, part: \"result\"}).",
    },
  };
  if (JSON.stringify(out).length > limit) {
    // Still too large (deeply nested or many fields): keep only the summary and identifiers.
    const keepKeys = ["summary", "run_id", "operation_id", "review_id", "status", "state", "error", "kind", "next"];
    out = Object.fromEntries(Object.entries(v).filter(([k]) => keepKeys.includes(k)));
    out["truncation"] = { truncated: true, cut_lists: [], clamped_strings: strCuts.n, next: next ?? "The result was too large for the host; only identifiers are shown. Page the full document with get_review_history(run_id, artifact: {operation_id, part: \"result\"})." };
  }
  return out;
}
