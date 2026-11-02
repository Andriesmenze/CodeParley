'use strict';
// Lifecycle workload: start a fully detached grandchild (its own session via setsid) that ignores
// SIGTERM, record its pid, then let the main process exit 0. A parent-PID or session-based tree-kill
// would miss this straggler; the broker's cgroup boundary (KillMode=control-group) must still catch
// it — when the main process exits, the unit stops, the straggler ignores the SIGTERM and is
// SIGKILLed after the stop timeout, so the service result is "timeout" and the cgroup ends empty.
// This is the Linux counterpart of the Windows "detached descendant" Job-Object case.

const fs = require('fs');
const cp = require('child_process');
const spec = JSON.parse(Buffer.from(process.argv[2] || '', 'base64').toString('utf8'));

if (process.env.CP_ROLE === 'straggler') {
  // Ignore the polite stop signals; only the cgroup SIGKILL ends us.
  process.on('SIGTERM', () => {});
  process.on('SIGHUP', () => {});
  process.on('SIGINT', () => {});
  setInterval(() => {}, 1 << 30);
} else {
  const child = cp.spawn(process.execPath, [__filename, process.argv[2]], {
    env: Object.assign({}, process.env, { CP_ROLE: 'straggler' }),
    detached: true,
    stdio: 'ignore',
  });
  child.unref();
  try {
    fs.writeFileSync(spec.resultPath, JSON.stringify({
      workload: 'lifecycle-detached', main: process.pid, detachedGrandchild: child.pid, startedAt: new Date().toISOString(),
    }, null, 1));
  } catch (_) { /* ignore */ }
  process.stdout.write('lifecycle-detached main pid=' + process.pid + ' detached=' + child.pid + '; main exiting 0\n');
  // Give the detached straggler a moment to install its signal handlers before the unit stops.
  setTimeout(() => process.exit(0), 1500);
}
