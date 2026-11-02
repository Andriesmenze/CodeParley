using CodeParley.Custodian.Linux.Native;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Linux.Security;

/// <summary>
/// Phase 5 NL-4 (c) and (f): the identity key function with INJECTED descriptor facts — the cases a real filesystem cannot
/// be made to produce on demand. (c) a forced-equal generation with a later birth time is another identity (the
/// brute-force generation collision is defeated by the birth time; collision-RESISTANT, not collision-proof). (f) handle
/// type other than 1/2, a short handle, generation 0, no birth time, a non-ext4 or an unprovisioned filesystem, and no
/// handle are refused. Plus the immediate replacement (same inode, new generation). Exit 0 only when every case holds.
/// </summary>
internal static class IdentitySelfTest
{
    private const ulong Fsid = 0x3808f3152b23b358;

    private static byte[] Handle(uint ino, uint gen)
    {
        var h = new byte[8];
        BitConverter.TryWriteBytes(h.AsSpan(0, 4), ino);
        BitConverter.TryWriteBytes(h.AsSpan(4, 4), gen);
        return h;
    }

    private static LinuxRepoIdentities.IdentityFacts Ok(uint ino = 131081, uint gen = 0x5eed1234, long btime = 1761000000, uint nsec = 123456789)
        => new(true, btime, nsec, Libc.EXT4_SUPER_MAGIC, Fsid, true, 1, Handle(ino, gen));

    internal static int Run()
    {
        int failed = 0, passed = 0;
        void Check(string name, bool ok, string detail)
        {
            if (ok) passed++; else failed++;
            Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {name}: {detail}");
        }
        string? KeyOrNull(LinuxRepoIdentities.IdentityFacts f, out string refusal)
        {
            try { refusal = ""; return LinuxRepoIdentities.KeyOf(f); }
            catch (RepoIdentityRefused e) { refusal = e.Message; return null; }
        }
        void Refused(string name, LinuxRepoIdentities.IdentityFacts f)
        {
            string? k = KeyOrNull(f, out string why);
            Check(name, k is null, k is null ? $"refused: {why}" : $"NOT refused: {k}");
        }

        string? baseKey = KeyOrNull(Ok(), out string r0);
        Check("valid facts give a fid2 key of safe tokens", baseKey is not null && baseKey.StartsWith("fid2-3808f3152b23b358-1-", StringComparison.Ordinal) && baseKey.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'), baseKey ?? r0);
        Check("the same facts give the same key (stable)", KeyOrNull(Ok(), out _) == baseKey, baseKey ?? "");
        string? fast = KeyOrNull(Ok(gen: 0x0badf00d), out _);
        Check("(a) immediate replacement: same inode, new generation -> another identity", fast is not null && fast != baseKey, fast ?? "");
        string? brute = KeyOrNull(Ok(btime: 1761000000 + 3600), out _);
        Check("(c) brute force: generation forced EQUAL, birth time later -> another identity", brute is not null && brute != baseKey, brute ?? "");
        string? nsOnly = KeyOrNull(Ok(nsec: 123456790), out _);
        Check("(c) birth time differing by 1 ns -> another identity", nsOnly is not null && nsOnly != baseKey, nsOnly ?? "");
        Check("handle type 2 (FILEID_INO32_GEN_PARENT) is accepted", KeyOrNull(Ok() with { HandleType = 2 }, out _) is not null, "");

        Refused("(f) handle type 3", Ok() with { HandleType = 3 });
        Refused("(f) handle type 0x81 (an exported/opaque type)", Ok() with { HandleType = 0x81 });
        Refused("(f) a handle shorter than 8 bytes", Ok() with { Handle = new byte[4] });
        Refused("(f) generation 0 (wildcard)", Ok(gen: 0));
        Refused("(f) no birth time (STATX_BTIME absent)", Ok() with { HasBtime = false });
        Refused("(f) no file handle", Ok() with { HandleType = null, Handle = null });
        Refused("(e) tmpfs (magic 0x01021994)", Ok() with { FsType = 0x01021994 });
        Refused("(e) btrfs (magic 0x9123683e)", Ok() with { FsType = 0x9123683E });
        Refused("(e) an ext4 filesystem the operator has not provisioned", Ok() with { Provisioned = false });

        Console.WriteLine($"identity self-test: {passed} passed, {failed} failed");
        return failed == 0 ? 0 : 1;
    }
}
