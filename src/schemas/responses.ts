// Implementer responses to reviewer items (Phase 2.1, plan §1.14). Source of truth (§5.3
// rule 5).
//
// A response is the IMPLEMENTER's position on one reviewer item: a separate, append-only
// record keyed by the item's engine id. It never changes the reviewer's text, the item's
// triage or its status: a response is a claim, not a resolution. A newer response to the same
// item supersedes the older one, which stays in the history.
//
// Persisted fields are lenient where a later version may add values (the disposition kind, the
// recording role and channel), so that a record written by a newer version never makes a run
// unreadable (plan §5.6); the tool input is strict.

import { z } from "zod";

const Sha256 = z.string().regex(/^[0-9a-f]{64}$/);
/** A per-file hash: a content SHA-256, or a git object id (SHA-1 or SHA-256 repository). */
const FileHash = z.string().regex(/^[0-9a-f]{40}$|^[0-9a-f]{64}$/);

/** What the implementer says about a reviewer item. */
export const DISPOSITIONS = ["accepted", "disputed", "deferred", "fix_claimed"] as const;
export type DispositionKind = (typeof DISPOSITIONS)[number];

/** Dispositions whose response needs a rationale (accepted may come without one). */
export const RATIONALE_REQUIRED: ReadonlySet<string> = new Set(["disputed", "deferred", "fix_claimed"]);

export const RESPONSE_LIMITS = {
  /** Responses in one call (one atomic batch). */
  perCall: 50,
  rationaleChars: 2000,
  referencesPerResponse: 8,
  referencePathChars: 1024,
  /** Responses kept per item, and per run: state.json stays small (§15.3). */
  perItem: 20,
  perRun: 1000,
} as const;

/** A location the implementer points to: a claim, never validated evidence in Phase 2.1. */
export const ResponseReferenceSchema = z
  .object({
    path: z.string(),
    start_line: z.number().int().nullable(),
    end_line: z.number().int().nullable(),
  })
  .catchall(z.unknown());
export type ResponseReference = z.infer<typeof ResponseReferenceSchema>;

export const ImplementerResponseSchema = z
  .object({
    response_id: z.string(),
    /** The reviewer item (finding or question) responded to. */
    item_id: z.string(),
    /** accepted | disputed | deferred | fix_claimed (lenient: a later version may add kinds). */
    disposition: z.string(),
    /** The concise rationale the implementer submitted, as written (redacted on every output). */
    rationale: z.string(),
    references: z.array(ResponseReferenceSchema).default([]),
    /** The reviewer state the response answers, derived by the engine when it was recorded. */
    answers: z
      .object({
        /** The latest accepted review that raised or assessed the item. */
        review_id: z.string(),
        round: z.number().int(),
        /** The response token the caller presented (equal to the item's token at that time). */
        token: z.string(),
        /**
         * Phase 2.2: the run's current accepted review when the response was recorded (null: none
         * yet). It orders turns against reviewer replies without clocks (P2.2-6). Absent on
         * records written before Phase 2.2.
         */
        run_review_id: z.string().nullable().optional(),
        run_round: z.number().int().nullable().optional(),
        /** Phase 2.2: the latest reviewer reply in the item's thread when recorded (null: none). */
        reviewer_reply_id: z.string().nullable().optional(),
      })
      .catchall(z.unknown()),
    /**
     * The working tree's source identity when the response was recorded, computed by the
     * engine in the same call (null when it could not be computed fresh and stable; `note`
     * says why). A fix claim always has one.
     */
    source: z.object({ source_id: Sha256.nullable(), note: z.string().nullable() }).catchall(z.unknown()),
    /**
     * An immutable artifact holding the withheld (confidential) names and hashes the response's
     * source read saw, so that every later host view keeps them withheld in the response text —
     * also when no capture record of the run knows them (a file made confidential after the last
     * capture). Null when the source read saw none or did not succeed. A record the state refers
     * to that is missing fails closed (engine/host-view.ts).
     */
    disclosure_ref: z.string().nullable().default(null),
    /**
     * The working tree could not be read completely when the response was recorded (no read, or
     * one that saw the tree change), so its text was never checked against everything
     * confidential then: every view withholds the rationale and the
     * references whole (fail closed, as MR-F does for any text it cannot check; Codex review of
     * PR #10). The disposition stays visible; a response recorded later supersedes it.
     */
    text_withheld: z.boolean().default(false),
    /** The previous response to the same item that this one supersedes. */
    supersedes: z.string().nullable(),
    /** Phase 2.2: the item's discussion thread when recorded (informational; threads are derived, P2.2-1). */
    thread_id: z.string().optional(),
    /** Who recorded it, set by the engine from the channel — never from tool arguments. */
    recorded_by: z.object({ role: z.string(), channel: z.string() }).catchall(z.unknown()),
    /** The call that recorded it (one atomic batch). */
    response_set_id: z.string(),
    request_id: z.string().nullable(),
    request_digest: Sha256,
    recorded_at: z.string(),
  })
  .catchall(z.unknown());
export type ImplementerResponse = z.infer<typeof ImplementerResponseSchema>;

/**
 * The disclosure artifact a response refers to: what its source read had to withhold — the
 * confidential names, and each such file's content SHA-256 and git object id; and, separately,
 * the files the repository's review.exclude_paths keep out of a review, with their hashes
 * (a view withholds those unless a capture of the run exported the name as a reviewed change).
 */
export const ResponseDisclosureSchema = z.object({
  schema: z.literal("arl.response-disclosure.v1"),
  withheld_paths: z.array(z.string()),
  withheld_hashes: z.array(FileHash),
  repo_context: z.array(z.object({ path: z.string(), hashes: z.array(FileHash) })).default([]),
});
export type ResponseDisclosure = z.infer<typeof ResponseDisclosureSchema>;
