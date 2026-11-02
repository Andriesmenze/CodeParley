using System.Globalization;
using System.Text.RegularExpressions;

namespace CodeParley.Broker.Linux.Host;

/// <summary>
/// The service manager (PID 1) is the lifetime owner of every worker run: one transient service
/// unit per run, i.e. one cgroup, killed as a whole (KillMode=control-group), time-limited by PID 1
/// (RuntimeMaxSec=) and stopped together with the broker socket (BindsTo=). This class only invokes
/// systemctl/systemd-run by verified absolute paths and parses their machine-readable output.
/// </summary>
internal static partial class Systemd
{
    private static readonly string[] SystemctlCandidates = ["/usr/bin/systemctl", "/bin/systemctl"];
    private static readonly string[] SystemdRunCandidates = ["/usr/bin/systemd-run", "/bin/systemd-run"];

    private static readonly Lazy<string> SystemctlPath = new(() => Resolve(SystemctlCandidates));
    private static readonly Lazy<string> SystemdRunPath = new(() => Resolve(SystemdRunCandidates));
    private static readonly Lazy<int> VersionLazy = new(ReadVersion);

    internal static string Systemctl => SystemctlPath.Value;
    internal static string SystemdRun => SystemdRunPath.Value;
    internal static int Version => VersionLazy.Value;

    /// <summary>systemd is the running init (sd_booted() semantics).</summary>
    internal static bool IsInit => Directory.Exists("/run/systemd/system");

    private static string Resolve(string[] candidates)
    {
        var errors = new List<string>();
        foreach (string c in candidates)
        {
            try { if (File.Exists(c)) { Trust.VerifyRootChain(c); return c; } }
            catch (Exception e) { errors.Add($"{c}: {e.Message}"); }
        }
        throw new InvalidOperationException("no trusted systemd tool found: " + (errors.Count > 0 ? string.Join("; ", errors) : string.Join(", ", candidates)));
    }

    [GeneratedRegex(@"^systemd (\d+)")]
    private static partial Regex VersionLine();

    private static int ReadVersion()
    {
        ProcessRunner.Result r = ProcessRunner.RunChecked(Systemctl, ["--version"], timeoutMs: 15_000);
        Match m = VersionLine().Match(r.StdOut);
        return m.Success ? int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture) : 0;
    }

    internal static ProcessRunner.Result Ctl(IReadOnlyList<string> args, int timeoutMs = 60_000) =>
        ProcessRunner.Run(Systemctl, ["--no-pager", "--no-ask-password", .. args], timeoutMs: timeoutMs);

    /// <summary>`systemctl show` → property map (missing units report LoadState=not-found).</summary>
    internal static Dictionary<string, string> Show(string unit, IEnumerable<string> properties)
    {
        ProcessRunner.Result r = Ctl(["show", unit, "--property=" + string.Join(',', properties)], 30_000);
        if (r.ExitCode != 0) throw new InvalidOperationException($"systemctl show {unit} failed: {r.Combined}");
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in r.StdOut.Split('\n'))
        {
            int eq = line.IndexOf('=');
            if (eq > 0) map[line[..eq]] = line[(eq + 1)..].TrimEnd('\r');
        }
        return map;
    }

    /// <summary>Loaded run units (any state) matching the broker's prefix.</summary>
    internal static List<(string Unit, string Active, string Sub)> ListRunUnits()
    {
        ProcessRunner.Result r = Ctl(["list-units", "--all", "--plain", "--no-legend", "--type=service", Layout.RunUnitPrefix + "*"], 30_000);
        if (r.ExitCode != 0) throw new InvalidOperationException("systemctl list-units failed: " + r.Combined);
        var units = new List<(string, string, string)>();
        foreach (string raw in r.StdOut.Split('\n'))
        {
            string[] f = raw.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (f.Length >= 4 && f[0].StartsWith(Layout.RunUnitPrefix, StringComparison.Ordinal)) units.Add((f[0], f[2], f[3]));
        }
        return units;
    }

    internal static string IsActive(string unit)
    {
        ProcessRunner.Result r = Ctl(["is-active", unit], 15_000);
        return r.StdOut.Trim();
    }

    /// <summary>Cgroup layout of this host: "v2" (unified), "hybrid" or "v1".</summary>
    internal static string CgroupMode()
    {
        string? root = null, unified = null;
        foreach (string line in File.ReadLines("/proc/self/mountinfo"))
        {
            // mountinfo: id parent major:minor root mountpoint options ... - fstype source superopts
            string[] f = line.Split(' ');
            int dash = Array.IndexOf(f, "-");
            if (dash < 0 || dash + 1 >= f.Length || f.Length < 5) continue;
            if (f[4] == "/sys/fs/cgroup") root = f[dash + 1];
            else if (f[4] == "/sys/fs/cgroup/unified") unified = f[dash + 1];
        }
        if (root == "cgroup2") return "v2";
        return unified == "cgroup2" ? "hybrid" : "v1";
    }

    /// <summary>The cgroupfs directory holding a unit's process list for this host's layout.</summary>
    internal static string? CgroupDir(string controlGroup)
    {
        if (string.IsNullOrEmpty(controlGroup) || !controlGroup.StartsWith('/') || controlGroup.Contains("..")) return null;
        string mode = CgroupMode();
        string baseDir = mode switch { "v2" => "/sys/fs/cgroup", "hybrid" => "/sys/fs/cgroup/unified", _ => "/sys/fs/cgroup/systemd" };
        return baseDir + controlGroup;
    }

    /// <summary>PIDs currently in a unit's cgroup, recursively (sub-cgroups included).</summary>
    internal static List<int> CgroupPids(string controlGroup)
    {
        var pids = new List<int>();
        string? dir = CgroupDir(controlGroup);
        if (dir is null || !Directory.Exists(dir)) return pids;
        var stack = new Stack<string>();
        stack.Push(dir);
        while (stack.Count > 0)
        {
            string d = stack.Pop();
            try
            {
                foreach (string line in File.ReadAllLines(Path.Combine(d, "cgroup.procs")))
                    if (int.TryParse(line.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out int pid)) pids.Add(pid);
                foreach (string sub in Directory.GetDirectories(d)) stack.Push(sub);
            }
            catch (IOException) { /* the cgroup is being torn down */ }
            catch (UnauthorizedAccessException) { }
        }
        return pids;
    }

    /// <summary>"pid=N uid=U start=TICKS comm=NAME" from /proc, or null if the process is gone.</summary>
    internal static string? ProcessIdentity(int pid)
    {
        try
        {
            string stat = File.ReadAllText($"/proc/{pid}/stat");
            int open = stat.IndexOf('('), close = stat.LastIndexOf(')');
            if (open < 0 || close < open) return null;
            string comm = stat[(open + 1)..close];
            string[] rest = stat[(close + 2)..].Split(' ');
            string startTicks = rest.Length > 19 ? rest[19] : "?";
            string uid = "?";
            foreach (string line in File.ReadLines($"/proc/{pid}/status"))
                if (line.StartsWith("Uid:", StringComparison.Ordinal)) { uid = line.Split('\t', StringSplitOptions.RemoveEmptyEntries)[1]; break; }
            return $"pid={pid} uid={uid} start={startTicks} comm={Sanitize(comm)}";
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    private static string Sanitize(string s)
    {
        var chars = s.Where(c => c >= 0x20 && c < 0x7F && c != ' ').Take(32).ToArray();
        return new string(chars);
    }
}
