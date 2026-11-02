// Repository preferences `.code-parley/config.json` (plan §7.1 layer 7, §7.4; legacy name
// `.ai-loop/config.json`, §1.12). UNTRUSTED: read from the working tree, they can only
// propose. `review.exclude_paths` may drop UNCHANGED files from the context export (never a
// changed file, plan §7.2); proposed checks stay inert until approved through the CLI
// (M1.3). Unknown keys produce a warning and are ignored.

import { z } from "zod";

/** Repository-relative location of the repository's preferences (M1.6). */
export const REPO_PREFERENCES_PATH = ".code-parley/config.json";
/** The location used before the CodeParley rename; read only when the new file is absent. */
export const LEGACY_REPO_PREFERENCES_PATH = ".ai-loop/config.json";

export interface RepoPreferencesChoice {
  /** The file to read, or null when neither exists. */
  path: string | null;
  warnings: string[];
}

/**
 * Which preferences file to read (pure): the new location wins; the legacy one is read only
 * when the new one is absent. `hidden(p)` is true for a path that may not be named (a
 * confidentiality exclusion): such a file is never chosen or mentioned.
 */
export function chooseRepoPreferences(exists: (p: string) => boolean, hidden: (p: string) => boolean = () => false): RepoPreferencesChoice {
  const current = exists(REPO_PREFERENCES_PATH);
  const legacy = exists(LEGACY_REPO_PREFERENCES_PATH);
  if (current) {
    if (hidden(REPO_PREFERENCES_PATH)) return { path: null, warnings: [] };
    return { path: REPO_PREFERENCES_PATH, warnings: legacy && !hidden(LEGACY_REPO_PREFERENCES_PATH) ? [`${LEGACY_REPO_PREFERENCES_PATH} is ignored because ${REPO_PREFERENCES_PATH} exists`] : [] };
  }
  if (legacy && !hidden(LEGACY_REPO_PREFERENCES_PATH)) {
    return { path: LEGACY_REPO_PREFERENCES_PATH, warnings: [`repository preferences were read from the legacy location ${LEGACY_REPO_PREFERENCES_PATH}; move them to ${REPO_PREFERENCES_PATH}`] };
  }
  return { path: null, warnings: [] };
}

const PathList = z.array(z.string().min(1).max(512)).max(200);

export const RepoPreferencesSchema = z.object({
  review: z
    .object({
      focus_paths: PathList.optional(),
      exclude_paths: PathList.optional(),
    })
    .partial()
    .optional(),
  proposed_checks: z.unknown().optional(),
  proposed_profiles: z.unknown().optional(),
});
export type RepoPreferences = z.infer<typeof RepoPreferencesSchema>;

const KNOWN_TOP = new Set(["review", "proposed_checks", "proposed_profiles"]);
const KNOWN_REVIEW = new Set(["focus_paths", "exclude_paths"]);

export interface ParsedRepoPreferences {
  prefs: RepoPreferences;
  warnings: string[];
}

/** Parse untrusted repository preferences; never throws (invalid content yields a warning). */
export function parseRepoPreferences(raw: unknown): ParsedRepoPreferences {
  const warnings: string[] = [];
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { prefs: {}, warnings: ["repository preferences are not a JSON object; ignored"] };
  }
  const obj = raw as Record<string, unknown>;
  for (const k of Object.keys(obj)) if (!KNOWN_TOP.has(k)) warnings.push(`unknown repository preference ignored: ${k}`);
  const review = obj["review"];
  if (review && typeof review === "object" && !Array.isArray(review)) {
    for (const k of Object.keys(review)) if (!KNOWN_REVIEW.has(k)) warnings.push(`unknown repository preference ignored: review.${k}`);
  }
  const picked = {
    ...(review && typeof review === "object" && !Array.isArray(review)
      ? {
          review: Object.fromEntries(Object.entries(review as Record<string, unknown>).filter(([k]) => KNOWN_REVIEW.has(k))),
        }
      : {}),
  };
  const parsed = RepoPreferencesSchema.safeParse(picked);
  if (!parsed.success) return { prefs: {}, warnings: [...warnings, "repository preferences failed validation; ignored"] };
  return { prefs: parsed.data, warnings };
}
