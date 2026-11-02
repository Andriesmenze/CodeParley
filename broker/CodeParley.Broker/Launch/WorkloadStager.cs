using System.Text.Json;

namespace CodeParley.Broker.Launch;

/// <summary>Targets the proof battery must be unable to write (so the broker can verify, as SYSTEM,
/// that none was written). Directories: the worker attempts a uniquely named canary; files: the worker
/// opens for append (no bytes), and the broker confirms size/mtime unchanged.</summary>
internal sealed record DenyTargets(Dictionary<string, List<string>> Dirs, List<string> Files);

/// <summary>
/// Stages the fixed, allowlisted deterministic workloads. The broker chooses the interpreter (its
/// trusted Node), the embedded script and every argument; the caller names only the key. Workloads:
/// <c>proof-battery</c> (Git/Node/npm compatibility + negative write checks), <c>lifecycle-tree</c>
/// (a process tree that runs until killed — for whole-tree terminate/timeout), and
/// <c>lifecycle-detached</c> (main exits 0 leaving a detached straggler — for the <c>unclean</c> path).
/// </summary>
internal static class WorkloadStager
{
    /// <summary>Create (once) a deterministic throwaway source repo under the trusted state root.</summary>
    internal static string EnsureSourceRepo()
    {
        string src = Path.Combine(BrokerConstants.TrustedStateRoot, "proof-src");
        if (Directory.Exists(Path.Combine(src, ".git"))) return src;
        Directory.CreateDirectory(src);
        string git = HostTools.GitExe;
        ProcessRunner.RunChecked(git, ["init", "-q"], src);
        Directory.CreateDirectory(Path.Combine(src, "sub", "nested"));
        File.WriteAllText(Path.Combine(src, "a.txt"), "hello\n");
        File.WriteAllText(Path.Combine(src, "sub", "nested", "n.txt"), "nested\n");
        File.WriteAllText(Path.Combine(src, "package.json"), "{\n  \"name\": \"cp-proof-src\",\n  \"private\": true,\n  \"scripts\": { \"noop\": \"node -e \\\"process.stdout.write('noop-ok:'+process.cwd())\\\"\" }\n}\n");
        string[] ident = ["-c", "user.name=broker", "-c", "user.email=broker@local", "-c", "commit.gpgsign=false"];
        ProcessRunner.RunChecked(git, [.. ident, "add", "-A"], src);
        ProcessRunner.RunChecked(git, [.. ident, "commit", "-q", "-m", "seed"], src);
        return src;
    }

    /// <summary>A real ambient (Authenticated Users-writable) directory the worker can reach but whose
    /// write must still be denied by the write-restricted token (AuthUsers is not a restricting SID).</summary>
    internal static string EnsureAmbientProbe()
    {
        string dir = Path.Combine(Path.GetDirectoryName(BrokerConstants.TrustedStateRoot)!, "ambient");
        Directory.CreateDirectory(dir);
        ProcessRunner.Run("icacls.exe", [dir, "/grant", "*S-1-5-11:(OI)(CI)M"]);
        return dir;
    }

    /// <summary>A repo-shaped Authenticated Users-writable "sibling" fixture (worktree + .git/hooks), so
    /// the proof shows a neighbouring repository is not writable by the worker. Never a real sibling.</summary>
    internal static string EnsureSiblingProbe()
    {
        string dir = Path.Combine(Path.GetDirectoryName(BrokerConstants.TrustedStateRoot)!, "sibling-repo");
        Directory.CreateDirectory(Path.Combine(dir, ".git", "hooks"));
        File.WriteAllText(Path.Combine(dir, "a.txt"), "sibling\n");
        File.WriteAllText(Path.Combine(dir, ".git", "HEAD"), "ref: refs/heads/main\n");
        ProcessRunner.Run("icacls.exe", [dir, "/grant", "*S-1-5-11:(OI)(CI)M"]);
        return dir;
    }

    /// <summary>The directories/files the proof battery must be unable to write, by category (for the
    /// worker's attempts and the broker's independent post-run verification). Only existing paths.</summary>
    internal static DenyTargets ComputeDenyTargets()
    {
        string ambient = EnsureAmbientProbe();
        string sibling = EnsureSiblingProbe();
        var dirs = new Dictionary<string, List<string>>(StringComparer.Ordinal)
        {
            ["trusted"] = [BrokerConstants.TrustedStateRoot, BrokerConstants.TrustedWorkspaceRoot, BrokerConstants.RunsRoot],
            ["install"] = [Path.GetDirectoryName(HostTools.NodeExe)!],
            ["ambient"] = [ambient],
            ["sibling"] = [sibling, Path.Combine(sibling, ".git", "hooks")],
        };
        var files = new List<string>
        {
            BrokerConstants.ConfigPath,
            Path.Combine(sibling, "a.txt"),
            Path.Combine(sibling, ".git", "HEAD"),
        };
        foreach (List<string> list in dirs.Values) list.RemoveAll(d => !Directory.Exists(d));
        files.RemoveAll(f => !File.Exists(f));
        return new DenyTargets(dirs, files);
    }

    /// <summary>Build the worker command line + cwd for a workload; the result/spec files live in the
    /// worker-writable workspace and are read back by the broker (as SYSTEM) after the run.</summary>
    internal static (string CommandLine, string WorkingDirectory, string ResultPath) BuildCommand(
        string workloadKey, string repoDir, string workspaceDir, string runId, DenyTargets? deny)
    {
        string script = workloadKey switch
        {
            "proof-battery" => ProofBatteryJs,
            "lifecycle-tree" => LifecycleTreeJs,
            "lifecycle-detached" => LifecycleDetachedJs,
            _ => throw new InvalidOperationException($"unknown workload '{workloadKey}'"),
        };
        string scriptPath = Path.Combine(workspaceDir, "workload.js");
        File.WriteAllText(scriptPath, script);
        string resultPath = Path.Combine(workspaceDir, "result.json");

        var spec = new
        {
            runId,
            workloadKey,
            workspace = workspaceDir,
            repo = repoDir,
            nested = Path.Combine(repoDir, "sub", "nested"),
            tmp = Path.Combine(workspaceDir, "tmp"),
            resultPath,
            git = HostTools.GitExe,
            node = HostTools.NodeExe,
            denyDirs = deny?.Dirs,
            denyFiles = deny?.Files,
        };
        string specPath = Path.Combine(workspaceDir, "spec.json");
        File.WriteAllText(specPath, JsonSerializer.Serialize(spec));
        Directory.CreateDirectory(spec.tmp);

        string cmd = $"\"{HostTools.NodeExe}\" \"{scriptPath}\" \"{specPath}\"";
        return (cmd, repoDir, resultPath);
    }

    // Broker-owned, fixed NATIVE node.js worker probe. Runs AS the worker under the restricted token in
    // the private station; writes a JSON result into the worker-writable workspace. Never throws; never
    // mutates a protected target (a directory gets a uniquely named canary attempt; a file is only
    // opened for append with no bytes written).
    private const string ProofBatteryJs = """
        'use strict';
        const fs = require('fs'), cp = require('child_process'), path = require('path');
        const spec = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
        const canary = 'cp_probe_' + spec.runId;
        const out = { runId: spec.runId, workload: spec.workloadKey, startedAt: new Date().toISOString(), identity: {}, tooling: {}, workspace: {}, denied: {} };
        function runTool(file, args, opts) {
          try { const o = cp.execFileSync(file, args, Object.assign({ encoding: 'utf8', timeout: 60000 }, opts || {})); return { ok: true, out: String(o).trim().slice(0, 400) }; }
          catch (e) { return { ok: false, status: e.status ?? null, out: (String(e.stderr || '') + ' ' + String(e.message || '')).trim().slice(0, 400) }; }
        }
        const cmd = process.env.ComSpec || 'cmd.exe', git = spec.git, repo = spec.repo, nested = spec.nested;
        out.identity.whoami = runTool(cmd, ['/c', 'whoami']);
        out.identity.nodeVersion = process.version;
        out.identity.cwd = (() => { try { return process.cwd(); } catch (e) { return String(e); } })();
        out.tooling.gitToplevel = runTool(git, ['rev-parse', '--show-toplevel'], { cwd: repo });
        out.tooling.gitStatus = runTool(git, ['status', '--porcelain=v1', '-b'], { cwd: repo });
        out.tooling.gitLog = runTool(git, ['log', '--oneline', '-1'], { cwd: repo });
        out.tooling.gitRevParseNested = runTool(git, ['rev-parse', '--show-toplevel'], { cwd: nested });
        try { fs.appendFileSync(path.join(repo, 'a.txt'), 'edit-' + spec.runId + '\n'); } catch (e) { out.tooling.editError = String(e); }
        out.tooling.gitDiff = runTool(git, ['diff', '--stat'], { cwd: repo });
        out.tooling.nodeInline = runTool(process.execPath, ['-e', 'process.stdout.write("node-inline-ok")']);
        out.tooling.nodeChildInNested = runTool(process.execPath, ['-e', 'process.stdout.write("child-cwd:" + process.cwd())'], { cwd: nested });
        out.tooling.npmNoop = runTool(cmd, ['/c', 'npm', 'run', '--silent', 'noop'], { cwd: repo });
        function writeOwn(dir, label) { const p = path.join(dir, canary + '.txt'); try { fs.writeFileSync(p, 'ok', { flag: 'wx' }); fs.unlinkSync(p); out.workspace[label] = { ok: true }; } catch (e) { out.workspace[label] = { ok: false, code: e.code || String(e) }; } }
        writeOwn(spec.workspace, 'workspaceRoot'); writeOwn(spec.repo, 'repo'); writeOwn(spec.tmp, 'tmpdir');
        try { fs.mkdirSync(path.join(spec.repo, 'newdir-' + spec.runId)); out.workspace.mkdirInRepo = { ok: true }; } catch (e) { out.workspace.mkdirInRepo = { ok: false, code: e.code || String(e) }; }
        function attemptDir(dir) {
          const f = (() => { try { fs.writeFileSync(path.join(dir, canary + '.txt'), 'x', { flag: 'wx' }); return { wrote: true }; } catch (e) { return { wrote: false, code: e.code || String(e) }; } })();
          const d = (() => { try { fs.mkdirSync(path.join(dir, canary + '.d')); return { wrote: true }; } catch (e) { return { wrote: false, code: e.code || String(e) }; } })();
          return { dir, createFile: f, mkdir: d };
        }
        for (const [cat, dirs] of Object.entries(spec.denyDirs || {})) out.denied[cat] = (dirs || []).map(attemptDir);
        out.denied.files = (spec.denyFiles || []).map((file) => { try { const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_APPEND); fs.closeSync(fd); return { file, openedForWrite: true }; } catch (e) { return { file, openedForWrite: false, code: e.code || String(e) }; } });
        out.anyDeniedWriteSucceeded = Object.entries(out.denied).some(([k, v]) => k === 'files' ? v.some((x) => x.openedForWrite) : v.some((x) => x.createFile.wrote || x.mkdir.wrote));
        fs.writeFileSync(spec.resultPath, JSON.stringify(out, null, 1));
        """;

    // A process tree (main -> two children -> grandchildren) that ignores SIGTERM/CTRL and runs until
    // the Job Object kills it; proves whole-tree Terminate/timeout. Records its pids for the broker.
    private const string LifecycleTreeJs = """
        'use strict';
        const fs = require('fs'), cp = require('child_process');
        const spec = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
        const role = process.env.CP_ROLE || 'main', depth = Number(process.env.CP_DEPTH || '0');
        if (role === 'main') {
          const pids = { main: process.pid, children: [] };
          for (let i = 0; i < 2; i++) { const c = cp.spawn(process.execPath, [__filename, process.argv[2]], { env: Object.assign({}, process.env, { CP_ROLE: 'child', CP_DEPTH: '1' }), detached: true, stdio: 'ignore' }); c.unref(); pids.children.push(c.pid); }
          try { fs.writeFileSync(spec.resultPath, JSON.stringify({ workload: 'lifecycle-tree', pids, startedAt: new Date().toISOString() }, null, 1)); } catch (e) {}
        } else if (depth < 2) { const g = cp.spawn(process.execPath, [__filename, process.argv[2]], { env: Object.assign({}, process.env, { CP_ROLE: 'child', CP_DEPTH: String(depth + 1) }), detached: true, stdio: 'ignore' }); g.unref(); }
        setInterval(() => {}, 1 << 30);
        """;

    // Main spawns a fully detached grandchild and exits 0; a parent/tree walk would miss the straggler,
    // but the Job Object must still contain it -> the broker observes descendants-remain -> `unclean`.
    private const string LifecycleDetachedJs = """
        'use strict';
        const fs = require('fs'), cp = require('child_process');
        const spec = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
        if (process.env.CP_ROLE === 'straggler') { setInterval(() => {}, 1 << 30); }
        else {
          const c = cp.spawn(process.execPath, [__filename, process.argv[2]], { env: Object.assign({}, process.env, { CP_ROLE: 'straggler' }), detached: true, stdio: 'ignore' }); c.unref();
          try { fs.writeFileSync(spec.resultPath, JSON.stringify({ workload: 'lifecycle-detached', main: process.pid, detached: c.pid, startedAt: new Date().toISOString() }, null, 1)); } catch (e) {}
          setTimeout(() => process.exit(0), 1200);
        }
        """;
}
