using System.Runtime.InteropServices;
using System.Security.Principal;
using CodeParley.Custodian.Interop;
using CodeParley.Custodian.Ledger;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ipc;

/// <summary>
/// Classifies a connected pipe client from the OS, never from request content. The server impersonates
/// the client (identification level is enough; no <c>SeImpersonatePrivilege</c> is needed for a
/// same-user or self client) and reads the token's user SID, elevation type and integrity level.
///
/// Implementer surface: the client's SID must equal the configured implementer SID. Operator surface:
/// the client's SID must equal the configured operator SID AND the token must be elevated (full
/// elevation type, High integrity) — the L1 vehicle, explicitly not a production boundary. Helper surface
/// (P3.4C-5 §A.2): the client's SID must equal the configured helper service SID exactly; integrity confers
/// nothing there (the helper runs at the service's High integrity), and the helper SID is neither caller
/// identity, so it is refused on the other two surfaces. The result carries a proof digest recording exactly
/// what was checked, stored on any committed record.
/// </summary>
internal static class CallerClassifier
{
    internal sealed record Result(CallerClass Class, string Detail, string ProofDigest);

    /// <summary>The raw token facts read UNDER impersonation. Nothing that touches the filesystem runs
    /// here: an identification-level token (the level a pipe server gets without SeImpersonatePrivilege)
    /// cannot open files, so a first-time assembly/JIT load under it throws. Only token queries run here.</summary>
    internal readonly record struct TokenFacts(string? Sid, int ElevationType, int Integrity);

    /// <summary>Read the client's token facts; call this inside <c>RunAsClient</c>.</summary>
    internal static TokenFacts ReadFacts()
    {
        using WindowsIdentity id = WindowsIdentity.GetCurrent();
        return new TokenFacts(id.User?.Value, TokenInt(id.Token, Native.TokenElevationType), IntegrityRid(id.Token));
    }

    /// <summary>Decide the caller class from already-read facts; call this AFTER reverting to self (it
    /// hashes the proof digest, which must not run under the identification-level impersonation).</summary>
    internal static Result Decide(PipeSurface surface, CustodianConfig cfg, TokenFacts facts)
    {
        string? sid = facts.Sid;
        int elevationType = facts.ElevationType;
        int integrity = facts.Integrity;
        bool operatorSurface = surface == PipeSurface.Operator;
        // The implementer/operator proof text is unchanged from P3.4C-4 (held proof digests stay comparable); the helper
        // surface names itself.
        string proof = surface == PipeSurface.Helper
            ? Digest.Sha256Hex($"sid={sid};elevationType={elevationType};integrity={integrity};surface=helper")
            : Digest.Sha256Hex($"sid={sid};elevationType={elevationType};integrity={integrity};operatorSurface={operatorSurface}");

        // A low-integrity (or untrusted) caller is refused on every surface (contract §2.2, kept as defence in depth).
        if (integrity < 0x2000) return new Result(CallerClass.Unknown, $"low-integrity caller (integrity=0x{integrity:x}) refused", proof);
        if (surface == PipeSurface.Helper)
        {
            // By SID alone (§A.2): an elevated or High-integrity token that is not the helper gains nothing here.
            string? helper = cfg.HelperSid;
            if (helper is null) return new Result(CallerClass.Unknown, "no helper identity is configured", proof);
            if (sid != helper) return new Result(CallerClass.Unknown, $"client {sid} is not the helper service", proof);
            return new Result(CallerClass.Helper, $"helper {sid}, integrity=0x{integrity:x}", proof);
        }
        // The helper identity is neither caller identity (the configuration refuses that), so it fails both checks below;
        // the refusal names it so the audit says why.
        string NotThe(string role) => cfg.HelperSid is not null && sid == cfg.HelperSid
            ? $"the helper service {sid} has no {role} capability"
            : $"client {sid} is not the {role}";
        if (operatorSurface)
        {
            if (sid != cfg.OperatorSid) return new Result(CallerClass.Unknown, NotThe("operator"), proof);
            if (!IsElevated(elevationType, integrity)) return new Result(CallerClass.Unknown, "operator token is not elevated (full/High)", proof);
            return new Result(CallerClass.Operator, $"operator {sid}, elevationType={elevationType}, integrity=0x{integrity:x}", proof);
        }
        if (sid != cfg.ImplementerSid) return new Result(CallerClass.Unknown, NotThe("implementer"), proof);
        return new Result(CallerClass.Implementer, $"implementer {sid}", proof);
    }

    /// <summary>The operator surface's elevation rule: a full (elevated) token or High integrity (0x3000) and above.</summary>
    internal static bool IsElevated(int elevationType, int integrity) => elevationType == Native.TokenElevationTypeFull || integrity >= 0x3000;

    private static int TokenInt(IntPtr token, int infoClass)
    {
        IntPtr buf = Marshal.AllocHGlobal(sizeof(int));
        try
        {
            return Native.GetTokenInformation(token, infoClass, buf, sizeof(int), out _) ? Marshal.ReadInt32(buf) : 0;
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    /// <summary>The integrity RID (e.g. 0x2000 Medium, 0x3000 High, 0x4000 System) from the token's
    /// mandatory label.</summary>
    private static int IntegrityRid(IntPtr token)
    {
        Native.GetTokenInformation(token, Native.TokenIntegrityLevel, IntPtr.Zero, 0, out int len);
        if (len <= 0) return 0;
        IntPtr buf = Marshal.AllocHGlobal(len);
        try
        {
            if (!Native.GetTokenInformation(token, Native.TokenIntegrityLevel, buf, len, out _)) return 0;
            // TOKEN_MANDATORY_LABEL { SID_AND_ATTRIBUTES Label }; Label.Sid is first field.
            IntPtr sidPtr = Marshal.ReadIntPtr(buf);
            var sid = new SecurityIdentifier(sidPtr);
            string[] parts = sid.Value.Split('-');
            return int.TryParse(parts[^1], out int rid) ? rid : 0;
        }
        finally { Marshal.FreeHGlobal(buf); }
    }
}
