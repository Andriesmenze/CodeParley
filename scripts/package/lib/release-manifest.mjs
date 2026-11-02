// Phase 6 Increment 2 (contract §8, A-1 to A-3, A-5): the build identity every release artifact carries and the
// unsigned release manifest that lists them. Pure functions, shared by the staging script and its tests; the
// installers check an artifact against the manifest with the same rule (its name, size and SHA-256).

export const BUILD_ID_SCHEMA = "codeparley.build-id.v1";
export const MANIFEST_SCHEMA = "codeparley.release-manifest.v1";

/** The release artifacts, in manifest order: their names, archive kinds and the platform each serves. */
export const ARTIFACTS = Object.freeze([
  { name: "npm-tarball", platform: "any" },
  { name: "plugin-windows", platform: "windows" },
  { name: "plugin-linux", platform: "linux" },
  { name: "custodian-windows-x64", platform: "windows" },
  { name: "custodian-linux-x64", platform: "linux" },
  { name: "engine-runtime-windows-x64", platform: "windows" },
  { name: "engine-runtime-linux-x64", platform: "linux" },
  { name: "installer-windows", platform: "windows" },
  { name: "installer-linux", platform: "linux" },
]);

const HEX64 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;

/**
 * The BUILD-ID of one artifact (A-2): the source commit and whether its signature verified, the version and the
 * toolchain. A build from a tree with changes, or from a commit whose signature did not verify, is marked so, and
 * is never a release candidate.
 */
export function buildId({ artifact, version, commit, signature, dirty, toolchain, builtAt, testBuild = false }) {
  if (!ARTIFACTS.some((a) => a.name === artifact)) throw new Error(`unknown artifact ${artifact}`);
  if (!COMMIT.test(commit ?? "")) throw new Error("the source commit must be a full 40-character id");
  if (!["verified", "unverified"].includes(signature)) throw new Error("signature must be verified or unverified");
  for (const k of ["dotnetSdk", "node", "npm"]) if (typeof toolchain?.[k] !== "string" || toolchain[k].length === 0) throw new Error(`toolchain.${k} is required`);
  return {
    schema: BUILD_ID_SCHEMA,
    artifact,
    version,
    commit,
    signature,
    dirty: Boolean(dirty),
    ...(testBuild ? { testBuild: true } : {}),
    releaseCandidate: signature === "verified" && !dirty && !testBuild,
    toolchain: { dotnetSdk: toolchain.dotnetSdk, node: toolchain.node, npm: toolchain.npm },
    builtAt,
  };
}

/** The unsigned release manifest (A-3): every artifact with its file, size, SHA-256 and BUILD-ID. */
export function buildManifest({ version, commit, signature, dirty, entries, testBuild = false }) {
  const names = entries.map((e) => e.name);
  for (const a of ARTIFACTS) if (!names.includes(a.name)) throw new Error(`the manifest lacks the artifact ${a.name}`);
  if (new Set(names).size !== names.length) throw new Error("an artifact is listed twice");
  for (const e of entries) {
    if (!HEX64.test(e.sha256)) throw new Error(`${e.name}: sha256 must be 64 lowercase hex digits`);
    if (!Number.isInteger(e.size) || e.size <= 0) throw new Error(`${e.name}: size must be a positive integer`);
    if (e.buildId.commit !== commit || e.buildId.version !== version) throw new Error(`${e.name}: its BUILD-ID names another commit or version`);
  }
  const order = (n) => ARTIFACTS.findIndex((a) => a.name === n);
  return {
    schema: MANIFEST_SCHEMA,
    version,
    commit,
    signature,
    dirty: Boolean(dirty),
    ...(testBuild ? { testBuild: true } : {}),
    releaseCandidate: signature === "verified" && !dirty && !testBuild,
    signed: false, // A-4: the owner signs it with the release key, outside this environment
    artifacts: [...entries].sort((a, b) => order(a.name) - order(b.name)).map((e) => ({ name: e.name, file: e.file, size: e.size, sha256: e.sha256, buildId: e.buildId })),
  };
}

/** Does a file match its manifest entry (A-5)? Returns null when it does, else why not. */
export function artifactProblem(manifest, name, file, { size, sha256 }) {
  if (manifest?.schema !== MANIFEST_SCHEMA) return "not a CodeParley release manifest";
  const e = manifest.artifacts.find((a) => a.name === name);
  if (!e) return `the manifest lists no artifact ${name}`;
  if (e.file !== file) return `the manifest names ${e.file} for ${name}, not ${file}`;
  if (e.size !== size) return `${file} is ${size} bytes, the manifest says ${e.size}`;
  if (e.sha256 !== sha256) return `${file} has SHA-256 ${sha256}, the manifest says ${e.sha256}`;
  return null;
}
