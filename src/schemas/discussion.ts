// The bounded reviewer–implementer discussion (Phase 2.2, plan §1.15). Source of truth (§5.3
// rule 5).
//
// Two record kinds join P2.1's implementer responses:
//  - REVIEWER REPLIES (`reviewer_replies[]` in state.json): the reviewer's structured stance on
//    an item in reply to the implementer, append-only, written only by an ACCEPTED review in its
//    single completion commit. A stance is a claim by the reviewer: it never changes the item's
//    lifecycle (only the carry-forward rules do) and never stands for a user decision.
//  - DELIVERY RECORDS (`discussion` on a review record): exactly which implementer turns a
//    review's bundle presented, and whether a reply was sought. A turn counts as seen by the
//    reviewer only through the delivery record of an accepted review (P2.2-6).
// Persisted fields are lenient where a later version may add values (the stance, the recorder),
// so that a record written by a newer version never makes a run unreadable (plan §5.6).

import { z } from "zod";

const Sha256 = z.string().regex(/^[0-9a-f]{64}$/);

/** The reviewer's stance on a finding, in reply to the implementer (P2.2-3). */
export const STANCES = ["maintain", "withdraw", "revise", "need_information"] as const;
export type Stance = (typeof STANCES)[number];

/** The reviewer's judgment: did the implementer's latest turn bring materially new evidence or argument? */
export const NEW_INFORMATION = ["yes", "no", "not_applicable"] as const;
export type NewInformation = (typeof NEW_INFORMATION)[number];

/** Conservative constants (P2.2-4, -7). */
export const DISCUSSION_LIMITS = {
  /** Exchanges per thread, counted over every item of its lineage. */
  exchangesPerThread: 3,
  /** Exchanges per run. */
  exchangesPerRun: 50,
  /** Items for which one review seeks a reply (the rest wait for the next review). */
  replySoughtPerReview: 20,
  /** Context turns (no reply sought) one review presents. */
  contextPerReview: 50,
  /** Earlier delivered turns and replies shown with one item. */
  historyPerItem: 4,
  /** Characters of one turn's text in a bundle (shrinks further under the bundle cap). */
  bundleTextChars: 2000,
  /** A reviewer reply as stored. */
  replyChars: 4000,
  /** Lineage bounds (P2.2-1): links read per item, link operations per run. */
  linksPerItem: 200,
  linkOperations: 100_000,
} as const;

export const ReviewerReplySchema = z
  .object({
    reply_id: z.string(),
    /** The reviewer item replied to. */
    item_id: z.string(),
    review_id: z.string(),
    round: z.number().int(),
    /** maintain | withdraw | revise | need_information (lenient: a later version may add kinds). */
    stance: z.string(),
    /** The reviewer's reasoning addressed to the implementer (redacted on every output). */
    reply: z.string(),
    /** yes | no | not_applicable. */
    new_information: z.string(),
    /** The implementer turn the reply answers (the one the review sought a reply for). */
    answers: z.object({ response_id: z.string().nullable() }).catchall(z.unknown()),
    /** The same review's lifecycle assessment of the item (null: informational, not assessed). */
    assessment: z.string().nullable(),
    /** The reviewed source. */
    source_id: Sha256,
    /** Engine notes (consistency with the assessment). */
    notes: z.array(z.string()).default([]),
    /** Set by the engine, never by the reviewer. */
    recorded_by: z.object({ role: z.string(), channel: z.string() }).catchall(z.unknown()),
    recorded_at: z.string(),
  })
  .catchall(z.unknown());
export type ReviewerReply = z.infer<typeof ReviewerReplySchema>;

/** One implementer turn a review's bundle presented. */
export const DeliverySchema = z
  .object({
    response_id: z.string(),
    item_id: z.string(),
    /** The review asked the reviewer to reply to it (an exchange, P2.2-7); otherwise context. */
    reply_sought: z.boolean(),
    /** Why it earned the exchange (the new-information gate), or why it was context. */
    basis: z.array(z.string()).default([]),
    /** Its text was shortened to fit the bundle. */
    truncated: z.boolean().default(false),
  })
  .catchall(z.unknown());
export type Delivery = z.infer<typeof DeliverySchema>;

/** A review's delivery record (P2.2-2): written before Codex starts; counts only if accepted. */
export const ReviewDiscussionSchema = z
  .object({
    schema: z.string(),
    /** SHA-256 of the discussion as presented (also bound into review_input_id, P2.2-5). */
    digest: Sha256,
    delivered: z.array(DeliverySchema).default([]),
    /** Item ids presented for a reply only (informational items, IN-n). */
    informational_presented: z.array(z.string()).default([]),
    /**
     * What the checks found for the reviewed source (`checkResultsDigest`: results, never
     * durations), the base of the gate's "check evidence changed" (P2.2-7). Absent on reviews
     * recorded before it existed.
     */
    check_results_digest: Sha256.optional(),
    /** Latest implementer turns this review did not present, and why (reports, P2.2-10). */
    not_delivered: z.array(z.object({ response_id: z.string(), item_id: z.string(), reason: z.string() }).catchall(z.unknown())).default([]),
  })
  .catchall(z.unknown());
export type ReviewDiscussion = z.infer<typeof ReviewDiscussionSchema>;

export const REVIEW_DISCUSSION_SCHEMA = "arl.review-discussion.v1";
