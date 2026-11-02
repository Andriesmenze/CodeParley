// Trusted project configuration (plan §14.1), keyed by canonical worktree path with the
// root commit as a consistency check (§7.1, R-35). In M1.1 this is loaded read-only to
// establish trusted scope; the `checks approve` CLI and the check runner are M1.3, so
// check/profile fields are tolerated-but-not-executed here. Lenient to forward changes.

import { z } from "zod";

export const CheckSchema = z
  .object({
    argv: z.array(z.string()),
    cwd: z.string().optional(),
    timeout_seconds: z.number().int().positive().optional(),
    env: z.record(z.string(), z.string()).optional(),
    env_passthrough: z.array(z.string()).optional(),
    freshness_inputs: z.array(z.string()).optional(),
  })
  .catchall(z.unknown());

export const ProjectEntrySchema = z
  .object({
    root_commit: z.string().optional(),
    checks: z.record(z.string(), CheckSchema).optional(),
    profiles: z.record(z.string(), z.array(z.string())).optional(),
    required_profiles: z.array(z.string()).optional(),
    no_required_checks: z.boolean().optional(),
    test_globs: z.array(z.string()).optional(),
    approval: z.record(z.string(), z.unknown()).optional(),
  })
  .catchall(z.unknown());
export type ProjectEntry = z.infer<typeof ProjectEntrySchema>;

/** The whole trust/projects.json: a map of canonical worktree path -> entry. */
export const TrustProjectsSchema = z.record(z.string(), ProjectEntrySchema);
export type TrustProjects = z.infer<typeof TrustProjectsSchema>;

export function parseTrustProjects(raw: unknown): TrustProjects {
  return TrustProjectsSchema.parse(raw ?? {});
}
