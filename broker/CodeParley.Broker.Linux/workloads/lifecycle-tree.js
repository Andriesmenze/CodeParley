'use strict';
// Lifecycle workload: build a small process tree (main -> child -> grandchild) that stays alive and
// ignores SIGTERM, so the broker can prove that Terminate/timeout kills the WHOLE cgroup (not just
// the main PID) and that unrelated processes are untouched. Each process records its pid so the
// broker can confirm from the cgroup membership. It runs until the unit is stopped or RuntimeMaxSec
// fires; it never exits on its own.

const fs = require('fs');
const cp = require('child_process');
const spec = JSON.parse(Buffer.from(process.argv[2] || '', 'base64').toString('utf8'));

const role = process.env.CP_ROLE || 'main';
const depth = Number(process.env.CP_DEPTH || '0');

process.on('SIGTERM', () => { /* deliberately ignore, so only the cgroup kill (SIGKILL) ends us */ });

if (role === 'main') {
  const pids = { main: process.pid, children: [] };
  // two independent branches, each one level deeper, to make the tree non-trivial
  for (let i = 0; i < 2; i++) {
    const child = cp.spawn(process.execPath, [__filename, process.argv[2]], {
      env: Object.assign({}, process.env, { CP_ROLE: 'child', CP_DEPTH: '1', CP_BRANCH: String(i) }),
      detached: true, stdio: 'ignore',
    });
    child.unref();
    pids.children.push(child.pid);
  }
  try { fs.writeFileSync(spec.resultPath, JSON.stringify({ workload: 'lifecycle-tree', pids, startedAt: new Date().toISOString() }, null, 1)); } catch (_) { /* ignore */ }
  process.stdout.write('lifecycle-tree main pid=' + process.pid + ' children=' + pids.children.join(',') + '\n');
} else if (depth < 2) {
  const gc = cp.spawn(process.execPath, [__filename, process.argv[2]], {
    env: Object.assign({}, process.env, { CP_ROLE: 'child', CP_DEPTH: String(depth + 1) }),
    detached: true, stdio: 'ignore',
  });
  gc.unref();
}

// Keep this process alive until the cgroup is killed.
setInterval(() => {}, 1 << 30);
