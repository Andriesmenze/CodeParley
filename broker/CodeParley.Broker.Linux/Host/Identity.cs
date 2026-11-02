using CodeParley.Broker.Linux.Native;

namespace CodeParley.Broker.Linux.Host;

internal sealed record WorkerIdentity(string User, uint Uid, uint Gid, string Home, string Shell, uint[] Groups)
{
    internal uint[] SupplementaryGroups => Groups.Where(g => g != Gid).ToArray();
}

/// <summary>
/// Resolves and verifies the dedicated worker account. The worker's write authority on Linux comes
/// only from its UID and GIDs, so the checks are: a distinct non-root, non-controller UID; NO
/// supplementary groups (systemd applies the NSS group list for User=, exactly what
/// getgrouplist returns); not a member of the controller group; a private home it owns.
/// </summary>
internal static class Identity
{
    internal static WorkerIdentity ResolveWorker(BrokerSettings s)
    {
        Libc.PasswdEntry pw = Libc.GetPasswdByName(s.WorkerUser)
            ?? throw new InvalidOperationException($"worker account '{s.WorkerUser}' does not exist");
        uint[] groups = Libc.GetGroupList(pw.Name, pw.Gid);
        return new WorkerIdentity(pw.Name, pw.Uid, pw.Gid, pw.Home, pw.Shell, groups);
    }

    /// <summary>Every violated worker-identity requirement (empty = verified).</summary>
    internal static List<string> WorkerProblems(WorkerIdentity w, BrokerSettings s)
    {
        var problems = new List<string>();
        if (w.Uid == 0) problems.Add("worker uid is 0 (root)");
        if (w.Gid == 0) problems.Add("worker primary gid is 0 (root)");
        if (w.Uid == s.ControllerUid) problems.Add("worker uid equals the controller uid");
        if (w.SupplementaryGroups.Length > 0)
            problems.Add("worker has supplementary groups: " + string.Join(",", w.SupplementaryGroups.Select(GroupLabel)));
        Libc.GroupEntry? ctl = Libc.GetGroupByName(s.ControllerGroup);
        if (ctl is not null && (w.Groups.Contains(ctl.Gid) || ctl.Members.Contains(w.User)))
            problems.Add($"worker is a member of the controller group '{s.ControllerGroup}'");
        Libc.GroupEntry? primary = Libc.GetGroupByGid(w.Gid);
        if (primary is not null && primary.Members.Any(m => m != w.User))
            problems.Add($"worker primary group '{primary.Name}' has other members: {string.Join(",", primary.Members.Where(m => m != w.User))}");

        try
        {
            if (!w.Home.StartsWith('/') || w.Home == "/") throw new InvalidOperationException("home is not an absolute private directory");
            using Fd home = SafeFs.OpenAbsoluteDir(w.Home);
            Libc.Statx st = SafeFs.Stat(home);
            if (st.Uid != w.Uid) problems.Add($"worker home {w.Home} is not owned by the worker (uid {st.Uid})");
            if ((st.Perm & 0b000_111_111) != 0) problems.Add($"worker home {w.Home} is not private ({Convert.ToString(st.Perm, 8)}, expected 0700)");
            string parent = Path.GetDirectoryName(w.Home) ?? "/";
            Trust.VerifyRootChain(parent);   // the worker cannot replace its own home directory entry
        }
        catch (Exception e) when (e is IOException or InvalidOperationException)
        {
            problems.Add($"worker home {w.Home}: {e.Message}");
        }
        return problems;
    }

    internal static string GroupLabel(uint gid) => Libc.GetGroupByGid(gid)?.Name is { } n ? $"{n}({gid})" : gid.ToString();
}
