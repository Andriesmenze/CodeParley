// Codex `exec --json` event stream: validation, bounded audit and outcome (plan X2, X4,
// §12.3, §12.7). No I/O.
//
// Each stdout line must be a JSON object with a string `type`. Known event types are
// thread.*, turn.*, item.* and error; anything else is counted, never trusted. Item types
// are counted per type. Under S1 any `file_change`, `mcp_tool_call` or `web_search` item is
// an isolation/configuration violation (§12.7): Codex must not have changed files, called
// an MCP server or searched the web, so each is surfaced, never ignored.
//
// Everything is bounded: a line over the line cap is dropped and counted (the process layer
// enforces it), `aggregated_output` is truncated per item in the stored copy, the stored
// stream has a byte cap, the audit keeps a capped command list. The stored copy stays in
// the local run store; validation records commit summaries only (§19.1).
//
// Failure is never inferred from a specific exit code (X4): any non-zero exit is a
// failure, classified from turn.failed, error events and stderr.

import { z } from "zod";
import type { CodexAudit } from "../../schemas/review.js";
import { isNoDesktopExit, NO_DESKTOP_REMEDY, NO_DESKTOP_SESSION } from "./isolation.js";

/**
 * Caps on every in-memory audit structure a model-controlled stream can grow (F8). Beyond a
 * cap the stream keeps counting but stops retaining, and `audit_truncated` is set.
 */
export const AUDIT_CAPS = {
  /** Item ids remembered for de-duplication (command completions, violation items). */
  trackedIds: 10_000,
  /** Characters of an item id that are retained. */
  idChars: 128,
  /** Violation items retained with their detail (all are counted). */
  violationItems: 1000,
  /** Distinct item-type names counted separately; the rest count as "other". */
  itemTypes: 64,
  itemTypeChars: 64,
  errorEvents: 50,
  turnFailedChars: 2000,
} as const;

export interface EventLimits {
  /** Bytes of sanitized JSONL kept for the events artifact. */
  maxStoredBytes: number;
  /** Per-item cap on `aggregated_output` in the stored copy. */
  maxAggregatedOutputChars: number;
  /** Commands kept in the audit (all are counted). */
  maxAuditCommands: number;
  maxCommandChars: number;
}

export const DEFAULT_EVENT_LIMITS: EventLimits = {
  maxStoredBytes: 50 * 1024 * 1024,
  maxAggregatedOutputChars: 8 * 1024,
  maxAuditCommands: 200,
  maxCommandChars: 500,
};

/** Longest accepted JSONL line (§12.3: 1 MiB). */
export const MAX_EVENT_LINE_CHARS = 1024 * 1024;

const EventEnvelope = z.object({ type: z.string().min(1).max(64) }).catchall(z.unknown());
const ItemShape = z.object({ id: z.string().optional(), type: z.string().optional(), item_type: z.string().optional() }).catchall(z.unknown());
const Usage = z
  .object({
    input_tokens: z.number().optional(),
    cached_input_tokens: z.number().optional(),
    output_tokens: z.number().optional(),
    reasoning_output_tokens: z.number().optional(),
  })
  .catchall(z.unknown());

const KNOWN_EVENT_TYPES = new Set(["thread.started", "turn.started", "turn.completed", "turn.failed", "item.started", "item.updated", "item.completed", "error"]);
const KNOWN_ITEM_TYPES = new Set(["agent_message", "reasoning", "command_execution", "file_change", "mcp_tool_call", "web_search", "todo_list", "error"]);
const VIOLATION_ITEM_TYPES = new Set(["file_change", "mcp_tool_call", "web_search"]);

export class CodexEventStream {
  private readonly limits: EventLimits;
  private stored: string[] = [];
  private storedBytes = 0;
  private truncated = false;
  private total = 0;
  private malformed = 0;
  private oversize = 0;
  private unknownType = 0;
  private streamBytes = 0;
  private threadStarted = false;
  private turnCompleted = false;
  private turnFailed: string | null = null;
  private errors: string[] = [];
  private commandsRun = 0;
  private commands: CodexAudit["commands"] = [];
  private itemTypes = new Map<string, number>();
  private violationItems = new Map<string, { kind: string; detail: string }>();
  /** Every violation, counted per kind even after the retained list is full. */
  private violationCounts = { file_change: 0, mcp_tool_call: 0, web_search: 0 };
  private usage: CodexAudit["usage"] = null;
  private seenCompletedCommandIds = new Set<string>();
  private auditTruncated = false;
  /** Final agent message text of the completed turn (fallback when -o is missing). */
  lastAgentMessage: string | null = null;

  constructor(limits: Partial<EventLimits> = {}) {
    this.limits = { ...DEFAULT_EVENT_LIMITS, ...limits };
  }

  /** A line longer than the line cap was discarded by the process layer. */
  overflow(chars: number): void {
    this.total++;
    this.oversize++;
    this.streamBytes += chars;
    this.store(JSON.stringify({ type: "arl.line_dropped", reason: "line_over_cap", chars }));
  }

  push(line: string): void {
    this.total++;
    this.streamBytes += Buffer.byteLength(line, "utf8") + 1;
    let raw: unknown;
    try {
      raw = JSON.parse(line);
    } catch {
      this.malformed++;
      this.store(JSON.stringify({ type: "arl.malformed_line", excerpt: line.slice(0, 200) }));
      return;
    }
    const ev = EventEnvelope.safeParse(raw);
    if (!ev.success) {
      this.malformed++;
      this.store(JSON.stringify({ type: "arl.malformed_event", excerpt: line.slice(0, 200) }));
      return;
    }
    const e = ev.data;
    if (!KNOWN_EVENT_TYPES.has(e.type)) this.unknownType++;

    switch (e.type) {
      case "thread.started":
        this.threadStarted = true;
        break;
      case "turn.completed": {
        this.turnCompleted = true;
        const u = Usage.safeParse(e["usage"]);
        if (u.success) {
          this.usage = {
            input_tokens: u.data.input_tokens ?? null,
            cached_input_tokens: u.data.cached_input_tokens ?? null,
            output_tokens: u.data.output_tokens ?? null,
            reasoning_output_tokens: u.data.reasoning_output_tokens ?? null,
          };
        }
        break;
      }
      case "turn.failed":
        this.turnFailed = (messageOf(e["error"]) ?? messageOf(e) ?? "turn.failed").slice(0, AUDIT_CAPS.turnFailedChars);
        break;
      case "error":
        // Also carries non-fatal retry notices ("Reconnecting… n/5"), X2: recorded, not fatal.
        if (this.errors.length < AUDIT_CAPS.errorEvents) this.errors.push((messageOf(e) ?? "error").slice(0, 500));
        else this.auditTruncated = true;
        break;
      default:
        break;
    }

    let storedEvent: Record<string, unknown> = e;
    if (e.type.startsWith("item.")) {
      const it = ItemShape.safeParse(e["item"]);
      if (!it.success) {
        this.malformed++;
      } else {
        const item = it.data;
        const itype = (item.type ?? item.item_type ?? "unknown").slice(0, AUDIT_CAPS.itemTypeChars);
        const id = item.id === undefined ? null : item.id.slice(0, AUDIT_CAPS.idChars);
        if (e.type === "item.completed") this.countItemType(itype);
        if (!KNOWN_ITEM_TYPES.has(itype)) this.unknownType++;
        if (VIOLATION_ITEM_TYPES.has(itype) && this.firstSighting(`${itype}:${id ?? ""}`, id, e.type, true)) {
          this.violationCounts[itype as keyof typeof this.violationCounts]++;
          if (this.violationItems.size < AUDIT_CAPS.violationItems) this.violationItems.set(`${itype}:${id ?? `anon-${this.violationItems.size}`}`, { kind: itype, detail: excerpt(item, 300) });
          else this.auditTruncated = true;
        }
        if (itype === "command_execution" && e.type === "item.completed") {
          if (this.firstSighting(`cmd:${id ?? ""}`, id, "item.completed")) {
            this.commandsRun++;
            if (this.commands.length < this.limits.maxAuditCommands) {
              this.commands.push({
                command: String(item["command"] ?? "").slice(0, this.limits.maxCommandChars),
                exit_code: typeof item["exit_code"] === "number" && Number.isInteger(item["exit_code"]) ? (item["exit_code"] as number) : null,
                status: typeof item["status"] === "string" ? (item["status"] as string).slice(0, 32) : null,
              });
            }
          }
        }
        if (itype === "agent_message" && e.type === "item.completed" && typeof item["text"] === "string") {
          this.lastAgentMessage = item["text"] as string;
        }
        if (typeof item["aggregated_output"] === "string" && (item["aggregated_output"] as string).length > this.limits.maxAggregatedOutputChars) {
          const out = item["aggregated_output"] as string;
          storedEvent = { ...e, item: { ...item, aggregated_output: out.slice(0, this.limits.maxAggregatedOutputChars), arl_aggregated_output_truncated: out.length } };
        }
      }
    }
    this.store(JSON.stringify(storedEvent));
  }

  /** Count an item type, folding names beyond the cap into "other" (F8). */
  private countItemType(t: string): void {
    const key = this.itemTypes.has(t) || this.itemTypes.size < AUDIT_CAPS.itemTypes ? t : "other";
    if (key === "other" && t !== "other") this.auditTruncated = true;
    this.itemTypes.set(key, (this.itemTypes.get(key) ?? 0) + 1);
  }

  /**
   * True the first time an item is seen (de-duplicating started/completed pairs by id).
   * Items without an id count on their completion only — except violations, which count on
   * every sighting (over-counting is safe, missing one is not). Once the remembered-id set is
   * full the same applies to every item and the audit is marked truncated.
   */
  private firstSighting(key: string, id: string | null, eventType: string, countEverySighting = false): boolean {
    if (id === null) return countEverySighting || eventType === "item.completed";
    if (this.seenCompletedCommandIds.has(key)) return false;
    if (this.seenCompletedCommandIds.size >= AUDIT_CAPS.trackedIds) {
      this.auditTruncated = true;
      return countEverySighting || eventType === "item.completed";
    }
    this.seenCompletedCommandIds.add(key);
    return true;
  }

  private store(line: string): void {
    const n = Buffer.byteLength(line, "utf8") + 1;
    if (this.storedBytes + n > this.limits.maxStoredBytes) {
      this.truncated = true;
      return;
    }
    this.stored.push(line);
    this.storedBytes += n;
  }

  /** Sanitized, bounded JSONL for the local events artifact. */
  storedJsonl(): string {
    return this.stored.join("\n") + (this.stored.length ? "\n" : "") + (this.truncated ? JSON.stringify({ type: "arl.stream_truncated", cap_bytes: this.limits.maxStoredBytes }) + "\n" : "");
  }

  audit(): CodexAudit {
    const violations = [...this.violationItems.values()];
    return {
      events_total: this.total,
      events_malformed: this.malformed,
      events_oversize: this.oversize,
      events_unknown_type: this.unknownType,
      stream_bytes: this.streamBytes,
      stream_truncated: this.truncated,
      thread_started: this.threadStarted,
      turn_completed: this.turnCompleted,
      turn_failed: this.turnFailed,
      error_events: [...this.errors],
      commands_run: this.commandsRun,
      commands: [...this.commands],
      file_changes: this.violationCounts.file_change,
      mcp_tool_calls: this.violationCounts.mcp_tool_call,
      web_searches: this.violationCounts.web_search,
      item_types: Object.fromEntries(this.itemTypes),
      usage: this.usage,
      isolation_violations: violations,
      audit_truncated: this.auditTruncated,
    };
  }
}

function messageOf(v: unknown): string | null {
  if (typeof v === "string") return v;
  if (v && typeof v === "object") {
    const m = (v as { message?: unknown }).message;
    if (typeof m === "string") return m;
    const inner = (v as { error?: unknown }).error;
    if (inner !== undefined && inner !== v) return messageOf(inner);
  }
  return null;
}

function excerpt(v: unknown, max: number): string {
  try {
    const s = JSON.stringify(v);
    return s.length > max ? `${s.slice(0, max)}…` : s;
  } catch {
    return "<unserializable>";
  }
}

// ---------------------------------------------------------------------------
// Outcome classification
// ---------------------------------------------------------------------------

export type ProcessOutcomeStatus = "completed" | "failed" | "timed_out" | "cancelled" | "no_output";

export interface ProcessOutcome {
  status: ProcessOutcomeStatus;
  failureClass: string | null;
  detail: string;
}

export interface OutcomeInput {
  exitStatus: number | null;
  spawnError: string | null;
  timedOut: boolean;
  idleTimedOut: boolean;
  cancelled: boolean;
  stderrTail: string;
  audit: CodexAudit;
  lastMessage: string | null;
}

/** Classify a finished `codex exec` (X4: no meaning attached to specific exit codes). */
export function classifyOutcome(i: OutcomeInput): ProcessOutcome {
  if (i.cancelled) return { status: "cancelled", failureClass: "cancelled", detail: "cancelled on request" };
  if (i.timedOut || i.idleTimedOut) {
    return { status: "timed_out", failureClass: i.idleTimedOut ? "idle_timeout" : "wall_timeout", detail: i.idleTimedOut ? "no event within the idle timeout" : "wall-clock timeout" };
  }
  if (i.spawnError) return { status: "failed", failureClass: "spawn_error", detail: `spawn error: ${i.spawnError}` };
  // §6 (N5-9): Codex, or the commands it ran under its isolation profile, could not start for want of an interactive desktop
  // (0xC0000142): the review fails closed and says why, with the remedy.
  if (isNoDesktopExit(i.exitStatus) || i.audit.commands.some((c) => isNoDesktopExit(c.exit_code))) {
    return { status: "failed", failureClass: NO_DESKTOP_SESSION, detail: `CODEX_ISOLATION_UNAVAILABLE (${NO_DESKTOP_SESSION}): the isolation profile could not start a process (exit 0xC0000142, STATUS_DLL_INIT_FAILED) — this context has no interactive desktop session; ${NO_DESKTOP_REMEDY}` };
  }
  if (i.audit.turn_failed) return { status: "failed", failureClass: classifyText(i.audit.turn_failed) ?? "turn_failed", detail: `turn.failed: ${i.audit.turn_failed.slice(0, 500)}` };
  if (i.exitStatus !== 0) {
    const tail = i.stderrTail.trim().split(/\r?\n/).slice(-3).join(" | ").slice(0, 500);
    const hint = classifyText(`${tail}\n${i.audit.error_events.join("\n")}`);
    return { status: "failed", failureClass: hint ?? "non_zero_exit", detail: `codex exited with status ${String(i.exitStatus)}${tail ? `: ${tail}` : ""}` };
  }
  if (!i.audit.turn_completed) return { status: "failed", failureClass: "incomplete_stream", detail: "exit 0 without a turn.completed event" };
  if (!i.lastMessage || !i.lastMessage.trim()) return { status: "no_output", failureClass: "no_output", detail: "the completed turn produced no final message" };
  return { status: "completed", failureClass: null, detail: "turn completed with a final message" };
}

/** Coarse cause from Codex/stderr text. Classification only; never a security decision. */
export function classifyText(t: string): string | null {
  if (/not logged in|unauthori[sz]ed|\b401\b|authentication|please log ?in|login required|invalid api key/i.test(t)) return "auth";
  if (/usage limit|rate limit|quota|\b429\b/i.test(t)) return "usage_limit";
  if (/windows sandbox|sandbox (setup )?failed|requires effective ':root'|restricted read-only access requires/i.test(t)) return "isolation_rejected";
  if (/stream disconnected|error sending request|connection (refused|reset)|dns|could not resolve|network/i.test(t)) return "network";
  return null;
}
