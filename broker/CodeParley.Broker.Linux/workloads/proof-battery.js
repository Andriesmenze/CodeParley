'use strict';
// CodeParley Linux broker — deterministic worker probe (Phase 3.1B). Installed root-owned beside the
// broker; the broker runs it AS the dedicated worker identity inside the run's transient unit. It
// confirms the worker can do normal development work in its workspace and records, for each target
// the broker marks off-limits, whether the OS refused the write. It never throws and never mutates a
// protected target: a directory gets a uniquely named canary attempt; a file is only opened for
// append (no bytes written). One JSON result is written into the workspace for the broker to read.

const fs = require('fs');
const cp = require('child_process');
const path = require('path');

const spec = JSON.parse(Buffer.from(process.argv[2] || '', 'base64').toString('utf8'));
const canary = 'cp_probe_' + spec.runId;
const out = { runId: spec.runId, workload: spec.workloadKey, startedAt: new Date().toISOString(), identity: {}, tooling: {}, workspace: {}, denied: {} };

function runTool(file, args, opts) {
  if (!file) return { ok: false, err: 'not available' };
  try {
    const stdout = cp.execFileSync(file, args, Object.assign({ encoding: 'utf8', timeout: 60000, stdio: ['ignore', 'pipe', 'pipe'] }, opts || {}));
    return { ok: true, out: String(stdout).trim().slice(0, 500) };
  } catch (e) {
    return { ok: false, status: e.status ?? null, signal: e.signal || null, err: (String(e.stderr || '') + ' ' + String(e.message || '')).trim().slice(0, 500) };
  }
}

// --- worker identity (as the kernel sees it) ---
try {
  const status = fs.readFileSync('/proc/self/status', 'utf8');
  for (const key of ['Uid', 'Gid', 'Groups', 'NoNewPrivs', 'Seccomp']) {
    const m = new RegExp('^' + key + ':\\s*(.*)$', 'm').exec(status);
    if (m) out.identity[key] = m[1].trim();
  }
} catch (e) { out.identity.error = String(e); }
out.identity.id = runTool('/usr/bin/id', []);
out.identity.nodeVersion = process.version;
out.identity.home = process.env.HOME || null;
out.identity.cwd = (() => { try { return process.cwd(); } catch (e) { return String(e); } })();
out.identity.tmpdir = process.env.TMPDIR || null;

// --- normal development tooling, in the standalone clone (nested path included) ---
const git = spec.git, repo = spec.repo, nested = spec.nested;
out.tooling.gitToplevel = runTool(git, ['rev-parse', '--show-toplevel'], { cwd: repo });
out.tooling.gitStatus = runTool(git, ['status', '--porcelain=v1', '-b'], { cwd: repo });
out.tooling.gitLog = runTool(git, ['log', '--oneline', '-1'], { cwd: repo });
out.tooling.gitRevParseNested = runTool(git, ['rev-parse', '--show-toplevel'], { cwd: nested });
// edit a tracked file, then confirm git sees the change
try { fs.appendFileSync(path.join(repo, 'a.txt'), 'edit-' + spec.runId + '\n'); } catch (e) { out.tooling.editError = String(e); }
out.tooling.gitDiff = runTool(git, ['diff', '--stat'], { cwd: repo });
out.tooling.nodeInline = runTool(process.execPath, ['-e', 'process.stdout.write("node-inline-ok")']);
out.tooling.nodeChildInNested = runTool(process.execPath, ['-e', 'process.stdout.write("child-cwd:" + process.cwd())'], { cwd: nested });
out.tooling.npmNoop = runTool(process.execPath, [path.join(path.dirname(process.execPath), 'npm'), 'run', '--silent', 'noop'], { cwd: repo });

// --- the worker's own writable surfaces must work ---
function writeInto(dir, label) {
  const target = path.join(dir, canary + '.txt');
  try { fs.writeFileSync(target, 'ok', { flag: 'wx' }); fs.unlinkSync(target); out.workspace[label] = { ok: true }; }
  catch (e) { out.workspace[label] = { ok: false, code: e.code || String(e) }; }
}
writeInto(spec.workspace, 'workspaceRoot');
writeInto(spec.repo, 'repo');
writeInto(spec.tmp, 'tmpdir');
try { fs.mkdirSync(path.join(spec.repo, 'newdir-' + spec.runId)); out.workspace.mkdirInRepo = { ok: true }; }
catch (e) { out.workspace.mkdirInRepo = { ok: false, code: e.code || String(e) }; }

// --- denied surfaces: record the refusal for each broker-supplied target ---
// A directory: attempt to create a uniquely named file and subdirectory in it.
// A file: open for append only (no write), which still requires write permission.
function attemptDir(dir) {
  const fileRes = (() => { try { const p = path.join(dir, canary + '.txt'); fs.writeFileSync(p, 'x', { flag: 'wx' }); return { wrote: true, path: p }; } catch (e) { return { wrote: false, code: e.code || String(e) }; } })();
  const dirRes = (() => { try { const p = path.join(dir, canary + '.d'); fs.mkdirSync(p); return { wrote: true, path: p }; } catch (e) { return { wrote: false, code: e.code || String(e) }; } })();
  return { dir, createFile: fileRes, mkdir: dirRes };
}
function attemptFile(file) {
  try { const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_APPEND); fs.closeSync(fd); return { file, openedForWrite: true }; }
  catch (e) { return { file, openedForWrite: false, code: e.code || String(e) }; }
}
for (const [category, dirs] of Object.entries(spec.denyDirs || {})) {
  out.denied[category] = (dirs || []).map(attemptDir);
}
out.denied.files = (spec.denyFiles || []).map(attemptFile);

// Shared world-writable host locations: attempt a write and LEAVE the canary. The worker may be
// allowed to write its own PRIVATE view (e.g. a private /dev/shm or /tmp), so success here is not a
// boundary breach on its own; the authoritative check is the broker confirming, on the host, that no
// canary escaped the sandbox. The canary is intentionally not removed.
out.shared = (spec.sharedDirs || []).map((dir) => {
  const target = path.join(dir, canary + '.txt');
  try { fs.writeFileSync(target, 'ok', { flag: 'wx' }); return { dir, wrote: true, note: 'left for host-side leak check' }; }
  catch (e) { return { dir, wrote: false, code: e.code || String(e) }; }
});

// --- summary the broker can assert on ---
out.summary = {
  toolingAllOk: ['gitToplevel', 'gitStatus', 'gitLog', 'gitRevParseNested', 'gitDiff', 'nodeInline', 'nodeChildInNested', 'npmNoop'].every((k) => out.tooling[k] && out.tooling[k].ok),
  ownSurfacesWritable: ['workspaceRoot', 'repo', 'tmpdir'].every((k) => out.workspace[k] && out.workspace[k].ok) && out.workspace.mkdirInRepo.ok,
  anyDeniedWriteSucceeded:
    Object.entries(out.denied).some(([k, v]) => k === 'files'
      ? v.some((f) => f.openedForWrite)
      : v.some((d) => d.createFile.wrote || d.mkdir.wrote)),
};
out.finishedAt = new Date().toISOString();

fs.writeFileSync(spec.resultPath, JSON.stringify(out, null, 1));
process.stdout.write('proof-battery done: ' + JSON.stringify(out.summary) + '\n');
