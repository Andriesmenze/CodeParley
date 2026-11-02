// Default confidentiality exclusions (plan §7.4, §9.3, MR-F): env-file variants and other
// secret file shapes are excluded by default; legitimate source files with similar names
// are not; excluded files are redacted from every model-facing form.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { DEFAULT_EXCLUDE_GLOBS, parseUserConfig } from "../src/schemas/config.js";
import { compileGlobs, matchesAny } from "../src/capture/globs.js";
import { supported, gitExe, tempDir, initRepo, writeFiles, commitAll, harness, capture, exportCorpus, exportFileList, cleanup, type Harness } from "./helpers/git-fixture.js";

const defaults = compileGlobs(DEFAULT_EXCLUDE_GLOBS);

/** Secret-shaped names the defaults must exclude. */
const EXCLUDED = [
  ".env",
  "app/.env",
  ".env.local",
  ".env.production",
  ".env.example", // templates are withheld too: fail toward excluding
  ".env-staging",
  ".env_dev",
  "prod.env",
  "production.env",
  "config/db.env",
  "deploy/PROD.ENV", // case-insensitive
  "prod.env.local",
  ".envrc",
  "services/api/.envrc",
  "certs/server.pem",
  "tls/server.key",
  "store/cert.pfx",
  "store/cert.p12",
  ".ssh/id_rsa",
  ".ssh/id_rsa.pub",
  ".ssh/id_dsa",
  ".ssh/id_ecdsa",
  "keys/id_ed25519",
  "keys/id_ed25519.pub",
  "vault.kdbx",
  ".netrc",
  "home/_netrc",
  "secrets.env/inner.txt", // a matching directory excludes its contents
];

/** Legitimate source/config files with similar names the defaults must NOT exclude. */
const NOT_EXCLUDED = [
  "src/env.ts",
  "src/env.js",
  "src/env.d.ts",
  "vite-env.d.ts",
  "src/app.env.ts",
  "config/config.env.js",
  "src/environment.ts",
  "src/environments/environment.prod.ts",
  ".environment",
  "docs/env.md",
  "docs/environment-variables.md",
  "scripts/setenv.sh",
  "scripts/load-env.ps1",
  "envoy.yaml",
  "Dockerfile.env-builder",
  "src/keys.ts",
  "src/keyboard.key.ts",
  "src/secrets.ts",
  "credentials.json",
  ".npmrc",
  "src/netrc.ts",
  "pkg/parse_rsa.go",
];

describe("default confidentiality exclusions", () => {
  it("are the shipped config default", () => {
    expect(parseUserConfig({}).capture.exclude_globs).toEqual([...DEFAULT_EXCLUDE_GLOBS]);
    // An explicit user list replaces (does not merge with) the defaults.
    expect(parseUserConfig({ capture: { exclude_globs: ["**/custom.secret"] } }).capture.exclude_globs).toEqual(["**/custom.secret"]);
  });

  it.each(EXCLUDED)("excludes %s", (p) => {
    expect(matchesAny(defaults, p)).toBe(true);
  });

  it.each(NOT_EXCLUDED)("does not exclude %s", (p) => {
    expect(matchesAny(defaults, p)).toBe(false);
  });

  it("contains no broad source-code extension pattern", () => {
    for (const g of DEFAULT_EXCLUDE_GLOBS) {
      expect(g).not.toMatch(/\*\.(ts|js|json|ya?ml|toml|md|txt|cfg|conf|config|ini|xml|sh|ps1|py|go|rs|java|cs)$/i);
      expect(g).not.toBe("**/*.env.*");
    }
  });
});

describe.skipIf(!supported)("default exclusions in a capture: model-facing redaction", () => {
  let repo: string;
  let h: Harness;
  beforeAll(async () => {
    await gitExe();
    repo = await initRepo(join(await tempDir("arl-defexcl-"), "repo"));
    h = await harness();
    await writeFiles(repo, {
      "prod.env": "DB_PASSWORD=SECRET-PROD-ENV-1\n",
      "config/staging.env": "TOKEN=SECRET-STAGING-ENV-2\n",
      "src/app.env.ts": "export const appEnv = 'v1';\n",
      "src/env.ts": "export const env = process.env;\n",
    });
    commitAll(repo, "init");
    await writeFiles(repo, {
      "prod.env": "DB_PASSWORD=SECRET-PROD-ENV-1-ROTATED\n", // changed tracked env file
      ".envrc": "export API_KEY=SECRET-ENVRC-3\n", // new untracked direnv file
      ".env-staging": "KEY=SECRET-DASH-ENV-4\n",
      "keys/id_ed25519": "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET-ED25519-5\n",
      "src/app.env.ts": "export const appEnv = 'v2';\n", // legitimate source, changed
    });
  });
  afterAll(async () => cleanup(repo, h.dataHome));

  it("withholds env-file variants' content, names and hashes; still reviews look-alike source files", async () => {
    const r = await capture(h, repo); // helper rules = shipped defaults
    const corpus = await exportCorpus(r.exportDir!);
    for (const s of ["SECRET-PROD-ENV-1", "SECRET-STAGING-ENV-2", "SECRET-ENVRC-3", "SECRET-DASH-ENV-4", "SECRET-ED25519-5"]) {
      expect(corpus, s).not.toContain(s);
    }
    const confidential = ["prod.env", "config/staging.env", ".envrc", ".env-staging", "keys/id_ed25519"];
    const manifestText = readFileSync(join(r.exportDir!, "review", "manifest.json"), "utf8");
    for (const p of confidential) expect(manifestText, p).not.toContain(JSON.stringify(p));
    expect(corpus).not.toContain("staging.env");
    expect(corpus).not.toContain("id_ed25519");
    for (const e of r.record.entries.filter((x) => confidential.includes(x.path))) {
      expect(e.class).toBe("excluded");
      expect(corpus).not.toContain(e.sha256!);
    }

    // Counts and the coverage limitation, without names.
    expect(r.manifest!.exclusions.confidential).toEqual({ count: 5, changed_count: 4 }); // prod.env, .envrc, .env-staging, id_ed25519
    const lim = r.manifest!.limitations.find((l) => l.code === "excluded_changed_file");
    expect(lim).toMatchObject({ count: 4 });
    expect(lim?.paths).toBeUndefined();

    // Look-alike legitimate source is exported and reviewed normally.
    const files = exportFileList(r.exportDir!);
    expect(files).toEqual(expect.arrayContaining(["tree/src/app.env.ts", "tree/src/env.ts", "review/head/src/app.env.ts"]));
    expect(r.manifest!.changes.map((c) => c.path)).toEqual(["src/app.env.ts"]);

    // The local record still names everything.
    expect(r.record.limitations.find((l) => l.code === "excluded_changed_file")?.paths?.sort()).toEqual(
      [".env-staging", ".envrc", "keys/id_ed25519", "prod.env"].sort(),
    );
  });
});
