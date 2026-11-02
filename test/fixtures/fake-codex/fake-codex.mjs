// A scripted stand-in for codex.exe (plan §18.1 "Fake Codex"). Zero dependencies.
//
// Launched as `node fake-codex.mjs <codex args…>` through the engine's TEST-ONLY launcher
// hook. Behaviour comes from `scenario.json` next to this script (tests write it). Every
// invocation is recorded to `calls/<n>.json` (argv, cwd, environment, stdin) so tests can
// assert on exactly what Codex was given.
//
//   --version                      prints scenario.version
//   exec --help                    prints the 0.160 flag list (minus scenario.help_missing)
//   sandbox … -- <powershell …>    emulates the offline self-test probes (scenario.sandbox)
//   sandbox … -- /bin/bash … -c …  the same for the Linux (bubblewrap) probes
//   exec --json … -                emits scenario.exec events, writes the final message

import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, appendFileSync, renameSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const here = dirname(fileURLToPath(import.meta.url));
const scenarioPath = process.env.CODEPARLEY_FAKE_SCENARIO_DIR ? join(process.env.CODEPARLEY_FAKE_SCENARIO_DIR, "scenario.json") : join(here, "scenario.json");
const dir = dirname(scenarioPath);
const scenario = existsSync(scenarioPath) ? JSON.parse(readFileSync(scenarioPath, "utf8")) : {};
const args = process.argv.slice(2);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function readStdin() {
  return new Promise((resolve) => {
    const chunks = [];
    process.stdin.on("data", (c) => chunks.push(c));
    process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    process.stdin.on("error", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
}

function record(extra) {
  const calls = join(dir, "calls");
  mkdirSync(calls, { recursive: true });
  const n = readdirSync(calls).length;
  // Written whole beside calls/, then renamed into it: a test polling calls/ never reads a
  // record half-written (seen on PR #11's Windows CI).
  const tmp = join(dir, `.call-${process.pid}-${n}.tmp`);
  writeFileSync(tmp, JSON.stringify({ argv: args, cwd: process.cwd(), env: process.env, ...extra }, null, 2));
  renameSync(tmp, join(calls, `${String(n).padStart(4, "0")}.json`));
}

const HELP_FLAGS = ["--json", "--ephemeral", "--color", "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check", "--cd", "--output-schema", "--output-last-message", "--sandbox", "--model", "--config"];

async function main() {
  if (args[0] === "--version") {
    process.stdout.write(`${scenario.version ?? "codex-cli 0.160.0"}\n`);
    return 0;
  }
  if (args[0] === "exec" && args[1] === "--help") {
    const missing = new Set(scenario.help_missing ?? []);
    process.stdout.write("Usage: codex exec [OPTIONS] [PROMPT]\n\nOptions:\n" + HELP_FLAGS.filter((f) => !missing.has(f)).map((f) => `      ${f} <VALUE>\n`).join(""));
    return 0;
  }
  if (args[0] === "sandbox") return sandbox();
  if (args[0] === "exec") return exec();
  process.stderr.write(`fake codex: unsupported invocation ${args.join(" ")}\n`);
  return 2;
}

function sandbox() {
  const sb = scenario.sandbox ?? { mode: "pass" };
  const sep = args.indexOf("--");
  const cmd = args.slice(sep + 1);
  const script = cmd[cmd.length - 1] ?? "";
  record({ kind: "sandbox" });
  if (sb.mode === "reject") {
    process.stderr.write(cmd[0] === "/bin/bash" ? "bwrap: Creating new namespace failed: Operation not permitted\n" : "Error: windows sandbox failed: elevated Windows sandbox requires effective ':root' read access\n");
    return 1;
  }
  const out = (s) => process.stdout.write(s);
  if (cmd[0] === "/bin/bash") return linuxSandbox(sb, script, out);
  if (script.includes("'ALIVE'")) return out("ALIVE"), 0;
  if (script.includes("-File")) return out("CHILD:C_DENIED:UnauthorizedAccessException"), 0;
  if (script.includes("TcpClient")) return out(sb.mode === "net_open" ? "NET_OK" : "NET_FAIL:An attempt was made to access a socket in a way forbidden"), 0;
  if (script.includes("GetHostAddresses")) return out(sb.mode === "net_open" ? "DNS_OK:1.2.3.4" : "DNS_FAIL:No such host is known"), 0;
  if (script.includes("Set-Content")) return out("WRITE_FAIL:UnauthorizedAccessException:Access to the path is denied."), 0;
  const m = /-LiteralPath '((?:[^']|'')*)'/.exec(script);
  const path = m ? m[1].replace(/''/g, "'") : "";
  if (script.includes("Get-Content")) {
    if (path.includes("in-scope") || (sb.mode === "leak_canary" && existsSync(path))) return out("READ_OK:" + readFileSync(path, "utf8").trim()), 0;
    return out("READ_FAIL:UnauthorizedAccessException:PermissionDenied:Access to the path is denied."), 0;
  }
  return out("UNKNOWN"), 0;
}

// The Linux (bubblewrap) self-test probes are bash scripts: answer them as an isolated sandbox
// would (paths outside the export are absent, writes are refused or contained, no network, own
// namespaces, no outside processes, stdio only).
function linuxSandbox(sb, script, out) {
  out(linuxAnswer(sb, script));
  return 0;
}

function linuxAnswer(sb, script) {
  const quoted = /'((?:[^']|'\\'')*)'/.exec(script)?.[1]?.replace(/'\\''/g, "'") ?? "";
  if (script === "printf ALIVE") return "ALIVE";
  if (script.startsWith("printf 'CHILD:'")) return "CHILD:READ_FAIL:cat: canary: No such file or directory";
  if (script.includes("/dev/tcp/")) return sb.mode === "net_open" ? "NET_OK" : "NET_FAIL:/bin/bash: socket: Operation not permitted";
  if (script.includes("getent hosts")) return sb.mode === "net_open" ? "DNS_OK:1.2.3.4 example.com" : "DNS_FAIL:exit 2 ";
  if (script.includes("CAPEFF=")) return "CAPEFF=0000000000000000;USERNS=user:[4026599994];";
  if (script.includes("unshare -rm")) return "UNSHARE_FAIL:unshare: write failed /proc/self/uid_map: Operation not permitted";
  if (script.includes("readlink /proc/self/ns/")) return "net=net:[4026599991];pid=pid:[4026599992];mnt=mnt:[4026599993];user=user:[4026599994];";
  if (script.includes("kill -0")) return "KILL_FAIL";
  if (script.includes("/environ")) return "ENV_FAIL:absent";
  if (script.includes("ls /proc/self/fd")) return "FD:0 1 2 3 ";
  if (script.includes("EXEC_OK")) return "EXEC_FAIL:cannot execute binary file";
  if (script.includes("printf arl >")) return "WRITE_FAIL:/bin/bash: line 1: target: Read-only file system";
  if (script.includes("cat -- ")) {
    if (quoted.includes("in-scope") || (sb.mode === "leak_canary" && existsSync(quoted))) return `READ_OK:${readFileSync(quoted, "utf8").trim()}`;
    return `READ_FAIL:cat: ${quoted}: No such file or directory`;
  }
  return "UNKNOWN";
}

async function exec() {
  const ex = scenario.exec ?? {};
  const prompt = await readStdin();
  const lastIdx = args.indexOf("--output-last-message");
  const lastPath = lastIdx >= 0 ? args[lastIdx + 1] : null;
  record({ kind: "exec", prompt });
  const emit = (o) => process.stdout.write((typeof o === "string" ? o : JSON.stringify(o)) + "\n");

  if (ex.spawn_orphaned_grandchild) {
    // An intermediate that starts a DETACHED grandchild and exits at once: the grandchild's
    // parent PID then names an exited process, so it cannot be linked to this tree.
    const script = `const {spawn}=require('child_process');const g=spawn(process.execPath,['-e','setTimeout(()=>{},300000)'],{detached:true,stdio:'ignore',windowsHide:true});g.unref();require('fs').writeFileSync(${JSON.stringify(join(dir, "grandchild.pid"))},String(g.pid));`;
    const mid = spawn(process.execPath, ["-e", script], { stdio: "ignore", windowsHide: true });
    await new Promise((r) => mid.on("exit", r));
  }
  if (ex.spawn_grandchild) {
    const g = spawn(process.execPath, ["-e", "setTimeout(()=>{}, 300000)"], { detached: true, stdio: "ignore", windowsHide: true });
    g.unref();
    writeFileSync(join(dir, "grandchild.pid"), String(g.pid));
  }
  if (ex.write_into_cwd) {
    try {
      writeFileSync(join(process.cwd(), ex.write_into_cwd), "tampered");
    } catch {
      /* ignore */
    }
  }
  if (ex.touch_on_start) appendFileSync(ex.touch_on_start, "x");

  emit({ type: "thread.started", thread_id: "fake-thread" });
  emit({ type: "turn.started" });
  for (const raw of ex.raw_lines ?? []) emit(raw);
  if (ex.huge_line_chars) process.stdout.write(`{"type":"item.completed","item":{"type":"agent_message","text":"${"x".repeat(ex.huge_line_chars)}"}}\n`);
  for (let k = 0; k < (ex.flood_lines ?? 0); k++) emit({ type: "item.completed", item: { id: `flood-${k}`, type: "reasoning", text: "y".repeat(ex.flood_line_bytes ?? 100) } });
  for (const e of ex.events ?? []) {
    emit(e);
    if (ex.delay_between_events_ms) await sleep(ex.delay_between_events_ms);
  }
  if (ex.hang === "silent") {
    await sleep(10 * 60_000);
    return 0;
  }
  if (ex.hang === "chatty") {
    for (;;) {
      emit({ type: "item.updated", item: { id: "r", type: "reasoning", text: "." } });
      await sleep(200);
    }
  }
  if (ex.sleep_ms) await sleep(ex.sleep_ms);

  let final = null;
  if (ex.final_raw !== undefined) final = ex.final_raw;
  else if (ex.final !== undefined && ex.final !== null) final = JSON.stringify(ex.final);
  if (ex.final_bytes) final = JSON.stringify({ blob: "z".repeat(ex.final_bytes) });
  if (ex.final_from_file) final = readFileSync(ex.final_from_file, "utf8");

  const turn = ex.turn ?? "completed";
  if (turn === "failed") {
    emit({ type: "turn.failed", error: { message: ex.turn_failed_message ?? "model error" } });
  } else if (turn === "completed") {
    // The event carries the whole final message, as Codex's does. no_last_message_file: the -o file is not written;
    // last_message_file_text: the -o file holds other text (C5).
    if (final !== null) emit({ type: "item.completed", item: { id: "msg", type: "agent_message", text: final } });
    emit({ type: "turn.completed", usage: { input_tokens: 1234, cached_input_tokens: 100, output_tokens: 56 } });
    if (lastPath && final !== null && !ex.no_last_message_file) writeFileSync(lastPath, ex.last_message_file_text ?? final);
    if (lastPath && final === null && ex.last_message_file_text !== undefined) writeFileSync(lastPath, ex.last_message_file_text);
  }
  if (ex.stderr) process.stderr.write(ex.stderr);
  return ex.exit ?? (turn === "failed" ? 1 : 0);
}

process.exitCode = await main();
