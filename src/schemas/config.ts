// User configuration schema (plan §7.4, schema version 1). Source of truth (§5.3 rule 5).
// Defaults are filled so a minimal config still produces a complete, valid object. The
// rev-0.4 default Windows backend is "mxc" (§1.7, §7.4), still subject to the probe.

import { z } from "zod";

export const CONFIG_SCHEMA_VERSION = 1;

export const WindowsBackendEnum = z.enum(["mxc", "elevated", "unelevated"]);
export type WindowsBackend = z.infer<typeof WindowsBackendEnum>;

export const ClientRootsSchema = z
  .object({ enforce: z.boolean().default(false) })
  .default({ enforce: false });

export const WaitsSchema = z
  .object({
    default_wait_seconds: z.number().int().positive().default(45),
    max_wait_seconds: z.number().int().positive().default(50),
  })
  .default({ default_wait_seconds: 45, max_wait_seconds: 50 });

export const BudgetsSchema = z
  .object({
    max_reviews_per_run: z.number().int().positive().default(5),
    max_check_executions_per_run: z.number().int().positive().default(20),
    // Phase 4 Increment 2: delegated fixes a protected run may begin (0: none; the custodian caps it at 10).
    max_fixes_per_run: z.number().int().min(0).max(10).default(0),
  })
  .default({ max_reviews_per_run: 5, max_check_executions_per_run: 20, max_fixes_per_run: 0 });

export const CodexConfigSchema = z
  .object({
    executable: z.string().nullable().default(null),
    model: z.string().nullable().default(null),
    reasoning_effort: z.string().nullable().default(null),
    // rev 0.4: mxc preferred where the probe confirms it; null = auto-detect (plan §1.7).
    windows_sandbox: WindowsBackendEnum.nullable().default("mxc"),
    review_timeout_seconds: z.number().int().positive().default(1200),
    idle_timeout_seconds: z.number().int().positive().default(300),
    env_passthrough: z.array(z.string()).default([]),
    max_concurrent: z.number().int().positive().default(2),
    load_project_instructions: z.boolean().default(false),
  })
  .prefault({});

/**
 * Default trusted confidentiality exclusions (plan §7.4, §9.3, MR-F). Conservative by
 * design: every pattern names a file shape that is used for secrets and essentially never
 * for source code. Deliberately NOT included because they would hide legitimate source:
 * `*.env.*` (matches `app.env.ts`), `env.*`, `secrets.*`, `credentials.json`, `*.json`,
 * `.npmrc`. A user's explicit `capture.exclude_globs` replaces this list.
 */
export const DEFAULT_EXCLUDE_GLOBS: readonly string[] = [
  // dotenv-style environment files
  "**/.env", // .env
  "**/.env.*", // .env.local, .env.production, .env.example
  "**/.env-*", // .env-staging
  "**/.env_*", // .env_dev
  "**/*.env", // prod.env, production.env, config/db.env
  "**/*.env.local", // prod.env.local
  "**/.envrc", // direnv
  // private keys, certificates, keystores
  "**/*.pem",
  "**/*.key",
  "**/*.pfx",
  "**/*.p12",
  "**/id_rsa*",
  "**/id_dsa*",
  "**/id_ecdsa*",
  "**/id_ed25519*",
  // credential stores
  "**/*.kdbx",
  "**/.netrc",
  "**/_netrc",
];

export const CaptureConfigSchema = z
  .object({
    exclude_globs: z.array(z.string()).default(() => [...DEFAULT_EXCLUDE_GLOBS]),
    context_include: z.array(z.string()).default([]),
    max_file_bytes: z.number().int().positive().default(2_097_152),
    max_export_bytes: z.number().int().positive().default(536_870_912),
    max_diff_bytes: z.number().int().positive().default(400_000),
  })
  .prefault({});

/**
 * Retention (plan §15.6; M1.6). Runs whose last activity is older than `max_age_days` are
 * deleted when a server starts, unless they are active or unresolved (policy/retention.ts);
 * `purge_on_startup: false` keeps everything until `code-parley runs purge`.
 */
export const RetentionConfigSchema = z
  .object({ max_age_days: z.number().int().positive().default(30), purge_on_startup: z.boolean().default(true) })
  .default({ max_age_days: 30, purge_on_startup: true });

export const UserConfigSchema = z.object({
  schema_version: z.number().int().default(CONFIG_SCHEMA_VERSION),
  allowed_roots: z.array(z.string()).default([]),
  client_roots: ClientRootsSchema,
  waits: WaitsSchema,
  budgets: BudgetsSchema,
  codex: CodexConfigSchema,
  capture: CaptureConfigSchema,
  retention: RetentionConfigSchema,
});
export type UserConfig = z.infer<typeof UserConfigSchema>;

/** Parse a user config (or `{}`) into a complete config with defaults applied. */
export function parseUserConfig(raw: unknown): UserConfig {
  return UserConfigSchema.parse(raw ?? {});
}
