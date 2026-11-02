// Human-readable output of the packaging checks (Phase 5): one line per check, then its details and
// the hint that says what to do. Machine output is the JSON report itself.

const LABEL = { pass: "PASS", fail: "FAIL", warn: "WARN", skip: "SKIP" };

/** Lines for a list of checks ({ id, status, summary, details, hint }). */
export function formatChecks(checks, { indent = "" } = {}) {
  const width = Math.max(0, ...checks.map((c) => c.id.length));
  const lines = [];
  for (const c of checks) {
    lines.push(`${indent}${LABEL[c.status] ?? c.status.toUpperCase()}  ${c.id.padEnd(width)}  ${c.summary}`);
    for (const d of c.details ?? []) for (const l of String(d).split("\n")) lines.push(`${indent}      ${" ".repeat(width)}  - ${l}`);
    if (c.hint && c.status !== "pass") lines.push(`${indent}      ${" ".repeat(width)}  → ${c.hint}`);
  }
  return lines;
}

/** The overall verdict line. */
export function verdict(checks) {
  const n = (s) => checks.filter((c) => c.status === s).length;
  return `${n("fail") ? "FAILED" : "OK"}: ${n("pass")} passed, ${n("fail")} failed, ${n("warn")} warning(s), ${n("skip")} skipped`;
}
