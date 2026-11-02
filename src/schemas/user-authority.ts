// The operator-authoritative user layer (Phase 2.3, plan §1.16). Source of truth (§5.3 rule 5).
//
// Two record kinds, written ONLY by CodeParley's local operator interface (the interactive
// `code-parley decide` / `amend` commands, P2.3-1) — never through MCP, never from repository
// content, Codex output or another record:
//  - USER DECISIONS (`user_decisions[]` in state.json): the user's decision on a discussion
//    thread — require_resolution, waive, defer or revoke — bound to the exact thread state the
//    user was shown (the decision token, P2.3-5). Never written into reviewer items, implementer
//    responses or reviewer replies. A later decision supersedes an earlier one, which stays in the
//    history; whether a decision still applies is derived on read (P2.3-6).
//  - TASK AMENDMENTS (`task_amendments[]`): the user's append-only amendments to the immutable
//    task envelope (P2.3-8), presented to later reviews that the user or host requests (P2.3-9).
// The engine sets `recorded_by` — role, channel and assurance; no input can. The assurance says
// what CodeParley relied on (P2.3-2): `local_operator` is trust in the local OS user, the
// CodeParley installation and its state store, not verified human presence. Persisted values are
// lenient strings, so that a record written by a newer version never makes a run unreadable
// (plan §5.6); only recognized provenance counts as user authority.

import { z } from "zod";

const Sha256 = z.string().regex(/^[0-9a-f]{64}$/);

/** What the user can decide about a thread (P2.3-4). */
export const DECISION_KINDS = ["require_resolution", "waive", "defer", "revoke"] as const;
export type DecisionKind = (typeof DECISION_KINDS)[number];

/** What a task amendment changes (P2.3-8); a withdrawal ends an earlier amendment. */
export const AMENDMENT_KINDS = ["scope", "constraint", "acceptance_criteria", "priority", "clarification", "withdrawal"] as const;
export type AmendmentKind = (typeof AMENDMENT_KINDS)[number];

export const USER_LIMITS = {
  noteChars: 2000,
  amendmentChars: 4000,
  /** The effective amendments' text in all (UTF-8 bytes), as the envelope (§11.2): a bundle never shortens it. */
  effectiveAmendmentBytes: 32 * 1024,
  amendmentsPerRun: 50,
  relatesToPerAmendment: 10,
  decisionsPerRun: 500,
  decisionsPerThread: 50,
} as const;

/** The provenance the engine sets on every user record it writes to the legacy TS store today (P2.3-2). */
export const USER_ROLE = "user";
export const USER_CHANNEL = "local_cli";
export const USER_ASSURANCE = "local_operator";

/** P3.4C-1: the provenance of a PROTECTED user record, set by the custodian (never by the engine or a
 * request) when an elevated operator commits it through the custodian's operator surface. A record with
 * this (channel, assurance) pair is custodian-authoritative; a legacy `local_cli`/`local_operator` record
 * in the user-writable TS store is NOT, and the two are kept distinct (D-G): legacy records are shown
 * labeled non-protected and are never imported or promoted. */
export const CUSTODIAN_CHANNEL = "custodian_operator";
export const CUSTODIAN_ASSURANCE = "local_admin_elevation";
/** Phase 5 (contract §4.5): the Linux custodian's operator assurance (a separate operator account, SO_PEERCRED). */
export const CUSTODIAN_LINUX_ASSURANCE = "local_operator_account";
/** Every assurance a custodian sets: a record with one is authority only when the custodian served it. */
export const CUSTODIAN_ASSURANCES: readonly string[] = [CUSTODIAN_ASSURANCE, CUSTODIAN_LINUX_ASSURANCE];
/** The operator assurance of this host's custodian (for the CLI's messages; the record carries the custodian's own). */
export const hostOperatorAssurance = (): string => (process.platform === "linux" ? CUSTODIAN_LINUX_ASSURANCE : CUSTODIAN_ASSURANCE);

/**
 * P3.4C-3 (contract §6.5 C3): set, in this process's memory only, on a user record the engine built from the
 * custodian's answer. The custodian's provenance pair is user authority only on such a record: a symbol is neither
 * written to nor read from JSON, so the same label on a record in the user-writable store is never honoured.
 */
export const CUSTODIAN_SERVED: unique symbol = Symbol("codeparley.custodian-served");

/**
 * What each recognized (channel, assurance) pair means. A user record counts as user authority
 * only with one of these; any other value — a typo, a forged label, a value of a later version
 * this one does not know — is never treated as user authority (fail closed). A later, stronger
 * mechanism (for example an OS-protected writer) adds its own pair; it never changes the meaning
 * of a pair already recorded.
 */
export const USER_ASSURANCES: Readonly<Record<string, { channel: string; definition: string }>> = {
  local_operator: {
    channel: "local_cli",
    definition:
      "Recorded by CodeParley's interactive local operator interface (`code-parley decide` / `code-parley amend`) under the local OS user's account, after the confirmation was typed at an interactive terminal. CodeParley trusts the local OS user, its own installation and code, and its state store: it does not verify that a person, rather than a process running with the same user's permissions, operated the terminal. A same-user process with arbitrary code or filesystem access can create such a record (adversarial evidence A4–A7) and can already forge other CodeParley evidence, such as reviews or checks; protecting against that attacker requires a broader trusted-state boundary and is outside Phase 2.3. No MCP call, repository content, Codex output or implementer response can create one through supported CodeParley behaviour.",
  },
  local_operator_account: {
    channel: "custodian_operator",
    definition:
      "Recorded (Phase 5) in the Linux custodian's protected store, through its operator socket, for a caller the kernel identified (SO_PEERCRED) as the configured operator account — a login account separate from the implementer's, with no administrative group — after the operator confirmed it by typing at an interactive terminal, running CodeParley through the root-owned operator wrapper. The record's provenance, ordering and identifiers are the custodian's; a model-reachable or implementer channel can neither create nor alter one, and the user-writable TS store is not consulted on the protected path. It establishes the operator ACCOUNT, not the presence of a person, and gives no protection against an administrator (root).",
  },
  local_admin_elevation: {
    channel: "custodian_operator",
    definition:
      "Recorded (P3.4C-1) in the Windows custodian's protected store, through its operator surface, for a caller the custodian's OS token classification found to be the configured operator SID with an elevated (full/High) token. The record's provenance, ordering and identifiers are the custodian's, set after the elevated operator confirmed it at an interactive terminal; a model-reachable or non-operator channel can neither create nor alter one, and the user-writable TS store is not consulted on the protected path. This is the L1 development assurance (local administrator elevation), not production-grade operator authentication (L2/L3), and this checkpoint does not yet independently verify the run state a decision summarizes (the engine-supplied decision token stays advisory until a later P3.4C checkpoint).",
  },
};

export const UserProvenanceSchema = z
  .object({
    role: z.string(),
    channel: z.string(),
    /** What CodeParley relied on for this record (USER_ASSURANCES); set by the engine, never by input. */
    assurance: z.string().optional(),
    tool_version: z.string().optional(),
  })
  .catchall(z.unknown());
export type UserProvenance = z.infer<typeof UserProvenanceSchema>;

/** The source read made for a record's text (P2.3-14); null when the record carries no text. */
const SourceRefSchema = z.object({ source_id: Sha256.nullable(), note: z.string().nullable() }).catchall(z.unknown());

export const UserDecisionSchema = z
  .object({
    decision_id: z.string(),
    /** The thread's id at recording (informational: threads are derived, P2.2-1). */
    thread_id: z.string(),
    /** The thread's newest open item, shown to the user as current. */
    current_item_id: z.string(),
    /** Every open item of the thread at recording: exactly what the decision is about (P2.3-6). */
    covered_items: z.array(z.string()),
    /** require_resolution | waive | defer | revoke (lenient: a later version may add kinds). */
    kind: z.string(),
    /** The user's note, as typed (redacted on every output; never sent to Codex). */
    note: z.string().default(""),
    /** The state the user decided against (P2.3-5). */
    decided_against: z
      .object({
        /** The decision token of the state shown. */
        token: z.string(),
        /** The run's current accepted review then (null: none yet). */
        run_review_id: z.string().nullable(),
        run_round: z.number().int().nullable(),
        latest_reply_id: z.string().nullable(),
        latest_response_id: z.string().nullable(),
        /** How many task amendments existed then. */
        amendments_seq: z.number().int(),
      })
      .catchall(z.unknown()),
    /** What the display showed (engine-derived): who was awaited, why, and the two positions. */
    context: z
      .object({
        awaiting: z.string(),
        escalation_reasons: z.array(z.string()),
        reviewer_stance: z.string().nullable(),
        implementer_position: z.string().nullable(),
      })
      .catchall(z.unknown()),
    /** The decisions this one replaces (the latest on the thread's items when it was recorded). */
    supersedes: z.array(z.string()).default([]),
    source: SourceRefSchema.nullable(),
    /** The withheld names and hashes of the record's source read (the response disclosure format). */
    disclosure_ref: z.string().nullable().default(null),
    /** Set by the engine from the channel — never from any input. */
    recorded_by: UserProvenanceSchema,
    request_id: z.string().nullable(),
    request_digest: Sha256,
    recorded_at: z.string(),
  })
  .catchall(z.unknown());
export type UserDecision = z.infer<typeof UserDecisionSchema>;

export const TaskAmendmentSchema = z
  .object({
    amendment_id: z.string(),
    /** 1, 2, … in recording order within the run. */
    seq: z.number().int(),
    /** scope | constraint | acceptance_criteria | priority | clarification | withdrawal (lenient). */
    kind: z.string(),
    /** The user's text as confirmed at the terminal (redacted on every output; prepared before it reaches
     * Codex). For a PROTECTED (custodian-backed) amendment the raw text lives only in the custodian's
     * protected store (operator surface); the engine's hydrated copy carries no text (empty) and uses the
     * custodian metadata below instead. */
    text: z.string().default(""),
    /** P3.4C-1 (protected amendments only): a non-reversible hash of the content-equivalence key the
     * custodian derived from the raw text, used by the new-information gate in place of the text. */
    content_key_hash: z.string().optional(),
    /** P3.4C-1 (protected amendments only): the original text's UTF-8 byte length, for the effective-bytes
     * budget without the text. */
    text_bytes: z.number().int().optional(),
    /** P3.4C-1 (protected amendments only): the sha256 of the operator-confirmed redacted reviewer-visible
     * artifact (engine-side), bound by the custodian; a review validates the artifact against it. */
    disclosure_digest: z.string().optional(),
    /** Phase 5 F-i2-5 (protected amendments the custodian redacted): the reviewer-visible representation the custodian
     * holds with the record — never the raw text; a review presents it when the run store has no artifact of the digest,
     * and only when it hashes to `disclosure_digest`. */
    disclosure_text: z.string().optional(),
    /** Threads (their ids at recording) the amendment bears on: the new-information gate's scope (P2.3-10). */
    relates_to: z.array(z.string()).default([]),
    /** An earlier effective amendment this one replaces (required for a withdrawal). */
    replaces: z.string().nullable().default(null),
    source: SourceRefSchema.nullable(),
    disclosure_ref: z.string().nullable().default(null),
    recorded_by: UserProvenanceSchema,
    request_id: z.string().nullable(),
    request_digest: Sha256,
    recorded_at: z.string(),
  })
  .catchall(z.unknown());
export type TaskAmendment = z.infer<typeof TaskAmendmentSchema>;

/** A review's amendment delivery record (P2.3-9): written before Codex starts; counts only if accepted. */
export const ReviewAmendmentsSchema = z
  .object({
    schema: z.string(),
    /** SHA-256 of the amendments section as presented (also bound into review_input_id). */
    digest: Sha256,
    presented: z.array(z.object({ amendment_id: z.string(), seq: z.number().int() }).catchall(z.unknown())).default([]),
    /** Effective amendments the review did not present, and why (their text could not be prepared safely). */
    withheld: z.array(z.object({ amendment_id: z.string(), reason: z.string() }).catchall(z.unknown())).default([]),
  })
  .catchall(z.unknown());
export type ReviewAmendments = z.infer<typeof ReviewAmendmentsSchema>;

export const REVIEW_AMENDMENTS_SCHEMA = "arl.review-amendments.v1";
