// The request the custodian sends its helper (P3.4C-5, Amendment A §A.2, §A.5), validated strictly: unknown fields are
// refused. `launch` is what the helper service used to start this runtime (the validated repository, its single
// safe.directory, the approved git, the custodian's read-only per-request directories); `workload` is the measurement.
// The derivation snapshot is the custodian's SCRUBBED copy of its held records — identities, statuses and digests the
// derivation consumes; no raw text, no secret, no operator identity facts (§A.5).

import { z } from "zod";

const Hex64 = z.string().regex(/^[0-9a-f]{64}$/);
const Token = z.string().min(1).max(128).regex(/^[A-Za-z0-9._:-]+$/);
const AbsPath = z.string().min(3).max(1024);

export const LaunchSchema = z
  .object({
    node: AbsPath,
    nodeSha256: Hex64,
    entry: AbsPath,
    entrySha256: Hex64,
    git: AbsPath,
    home: AbsPath,
    gitconfig: AbsPath,
    hooks: AbsPath,
    repository: AbsPath,
    safeDirectory: AbsPath,
    maxFrameBody: z.number().int().positive(),
  })
  .strict();

export const CaptureRulesSchema = z
  .object({
    exclude_globs: z.array(z.string().max(512)).max(256),
    context_include: z.array(z.string().max(512)).max(256),
    max_file_bytes: z.number().int().positive(),
    max_export_bytes: z.number().int().positive(),
    max_diff_bytes: z.number().int().positive(),
  })
  .strict();

export const CaptureWorkloadSchema = z
  .object({
    operationId: Token,
    target: z.discriminatedUnion("kind", [
      z.object({ kind: z.literal("uncommitted") }).strict(),
      z.object({ kind: z.literal("base_ref"), ref: z.string().min(1).max(256) }).strict(),
    ]),
    rules: CaptureRulesSchema,
  })
  .strict();

const Iso = z.string().max(40);
const Hex64OrNull = Hex64.nullable();
const Id = z.string().min(1).max(160);
const Name = z.string().min(1).max(64);

/** One check the measurement covers: its held definition (normalized by the helper as the engine does), the digest the
 * operator approved, and the executable path the session resolved for it (an engine claim; its STAT is measured). */
const MeasuredCheckRequest = z
  .object({ name: Name, definition: z.unknown(), definitionDigest: Hex64, executable: z.string().min(3).max(1024).nullable() })
  .strict();

/** P3.4C-5 Increment 3 (§5.1, §A.5): the custodian's SCRUBBED snapshot of its held records — identities, statuses and
 * digests; no raw note, amendment or response text, no secret, no operator identity facts. */
export const SnapshotSchema = z
  .object({
    schema: z.literal("arl.derivation-snapshot.v2"),
    repositoryRoot: z.string().min(1).max(1024),
    revision: z
      .object({
        runRevision: z.number().int().nullable(),
        loopRevision: z.number().int().nullable(),
        evidenceEpoch: z.number().int().nullable(),
        configRevision: z.number().int().nullable(),
        globalRevision: z.number().int(),
        userRevision: z.number().int(),
      })
      .strict(),
    run: z
      .object({
        status: z.enum(["idle", "checking", "reviewing", "fixing", "applying", "stopped", "closed"]),
        evidenceEpoch: z.number().int(),
        used: z.object({ reviews: z.number().int(), checkExecutions: z.number().int() }).strict(),
        limits: z.object({ maxReviews: z.number().int(), maxCheckExecutions: z.number().int() }).strict(),
        operations: z.array(z.object({ operationId: Token, kind: z.string().max(32), status: z.string().max(32), beganAt: Iso, endedAt: Iso.nullable(), planned: z.array(Name).max(64) }).strict()).max(2000),
        checkExecutions: z
          .array(
            z
              .object({
                executionId: Id,
                operationId: Token,
                check: Name,
                status: z.string().max(32),
                exitCode: z.number().int().nullable(),
                timedOut: z.boolean(),
                cancelled: z.boolean(),
                durationMs: z.number().int().nullable(),
                definitionDigest: Hex64OrNull,
                checkSpecId: Hex64OrNull,
                envDigest: Hex64OrNull,
                freshnessDigest: Hex64OrNull,
                executionInputId: Hex64OrNull,
                sourceIdAtStart: Hex64OrNull,
                sourceIdAtEnd: Hex64OrNull,
                sourceStable: z.boolean(),
                evidenceEpoch: z.number().int(),
              })
              .strict(),
          )
          .max(2000),
        reviews: z
          .array(
            z
              .object({
                reviewId: Id,
                operationId: Token,
                round: z.number().int(),
                accepted: z.boolean().nullable(),
                notAcceptedReasons: z.array(z.string().max(64)).max(50),
                evidenceEpoch: z.number().int(),
                status: z.string().max(32).nullable(),
                verdict: z.string().max(32).nullable(),
                basisUsable: z.boolean(),
                isolationMode: z.string().max(8).nullable(),
                bindings: z
                  .object({
                    sourceId: Hex64,
                    reviewInputId: Hex64,
                    checkEvidenceDigest: Hex64,
                    checkResultsDigest: Hex64OrNull,
                    checkExecutionIds: z.array(Id).max(200),
                    captureStable: z.boolean(),
                    manifestDigest: Hex64,
                    exportDigest: Hex64,
                    captureDigest: Hex64,
                  })
                  .strict()
                  .nullable(),
                exportIntact: z.boolean(),
                itemIds: z.array(Id).max(1000),
                presented: z
                  .object({
                    deliveries: z.array(z.object({ responseId: Id, itemId: Id, replySought: z.boolean(), basis: z.array(z.string().max(48)).max(16) }).strict()).max(1000),
                    amendments: z.array(Id).max(50),
                    withheld: z.array(Id).max(50),
                  })
                  .strict()
                  .nullable(),
              })
              .strict(),
          )
          .max(100),
        items: z
          .array(
            z
              .object({
                itemId: Id,
                reviewId: Id,
                round: z.number().int(),
                sourceId: z.string().max(64),
                itemKind: z.string().max(32),
                status: z.string().max(32),
                triage: z.string().max(32),
                severity: z.string().max(32).nullable(),
                claimType: z.string().max(32).nullable(),
                category: z.string().max(32).nullable(),
                confidence: z.string().max(32).nullable(),
                impacts: z.array(z.string().max(32)).max(14),
                relatedPriorId: Id.nullable(),
                relatedFindingId: Id.nullable(),
                supersedes: z.array(Id).max(50),
                supersededBy: Id.nullable(),
                restates: z.array(Id).max(20),
                assessments: z.array(z.object({ reviewId: Id, round: z.number().int(), sourceId: z.string().max(64), assessment: z.string().max(32), effect: z.string().max(32) }).strict()).max(100),
              })
              .strict(),
          )
          .max(2000),
        responses: z
          .array(
            z
              .object({
                responseId: Id,
                responseSetId: Id,
                itemId: Id,
                disposition: z.string().max(32),
                textWithheld: z.boolean(),
                answers: z.object({ reviewId: Id.nullable(), round: z.number().int().nullable(), runReviewId: Id.nullable(), runRound: z.number().int().nullable(), reviewerReplyId: Id.nullable() }).strict(),
                sourceId: Hex64OrNull,
                supersedes: Id.nullable(),
                threadId: Id,
                referenceKeys: z.array(Hex64).max(20),
                rationalePresent: z.boolean(),
              })
              .strict(),
          )
          .max(5000),
        replies: z
          .array(z.object({ replyId: Id, reviewId: Id, round: z.number().int(), itemId: Id, stance: z.string().max(32), newInformation: z.string().max(32), answersResponseId: Id.nullable(), assessment: z.string().max(32).nullable() }).strict())
          .max(5000),
        incidents: z.array(z.object({ incidentId: Id, kind: z.string().max(64), reviewId: Id.nullable(), operationId: Token }).strict()).max(400),
      })
      .strict()
      .nullable(),
    loop: z.object({ status: z.string().max(32), startedAt: Iso, resumedAt: Iso.nullable() }).strict().nullable(),
    user: z
      .object({ governed: z.boolean(), revision: z.number().int(), recoveredAtRevision: z.number().int().nullable(), records: z.array(z.record(z.string(), z.unknown())).max(1200) })
      .strict(),
    config: z.object({ globalRevision: z.number().int(), repository: z.record(z.string(), z.unknown()).nullable(), acceptances: z.array(z.unknown()).max(0), selftestConfirmations: z.array(z.unknown()).max(0) }).strict(),
    runFloor: z.record(z.string(), z.unknown()).nullable(),
    executables: z.record(Name, z.string().min(3).max(1024)),
  })
  .strict();

/** Phase 5 F-i2-5: an amendment text the custodian has the helper redact for review, and the roots whose paths may show. */
const HeldRecord = z.object({ kind: z.enum(["capture", "disclosure"]), sha256: Hex64, text: z.string().max(64 << 20) }).strict();
const RedactRequest = z.object({ text: z.string().max(40_000), keepRoots: z.array(AbsPath).min(1).max(8), evidence: z.array(HeldRecord).max(2000) }).strict();

export const DeriveWorkloadSchema = z
  .object({ rules: CaptureRulesSchema, checks: z.array(MeasuredCheckRequest).max(64), snapshot: SnapshotSchema.nullable(), redact: RedactRequest.optional() })
  .strict();

export const HelperRequestSchema = z.object({ launch: LaunchSchema, workload: z.unknown() }).strict();

export type Launch = z.infer<typeof LaunchSchema>;
export type CaptureWorkload = z.infer<typeof CaptureWorkloadSchema>;
export type DeriveWorkload = z.infer<typeof DeriveWorkloadSchema>;
export type MeasuredCheckRequest = z.infer<typeof MeasuredCheckRequest>;
