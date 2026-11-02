using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace CodeParley.Custodian.Security;

/// <summary>
/// The deterministic per-service SID (<c>S-1-5-80-&lt;5 sub-authorities&gt;</c>), computed from the
/// SHA-1 of the upper-cased, UTF-16LE service name — the same value <c>sc showsid &lt;name&gt;</c>
/// prints. The installer needs it to build the store DACL before the service (and therefore its token)
/// exists. A non-privileged self-test checks this against a known pair.
/// </summary>
internal static class ServiceSid
{
    /// <summary>The virtual service account SID for a service name. NT SERVICE SID: prefix S-1-5-80,
    /// then the five 32-bit little-endian words of SHA-1(UPPER(name) as UTF-16LE), each read as an
    /// unsigned sub-authority.</summary>
    internal static SecurityIdentifier Of(string serviceName)
    {
        byte[] hash = SHA1.HashData(Encoding.Unicode.GetBytes(serviceName.ToUpperInvariant()));
        var sb = new StringBuilder("S-1-5-80");
        for (int i = 0; i < 5; i++)
            sb.Append('-').Append(BitConverter.ToUInt32(hash, i * 4));
        return new SecurityIdentifier(sb.ToString());
    }

    /// <summary>The custodian's own service SID.</summary>
    internal static SecurityIdentifier Custodian() => Of(CustodianConstants.ServiceName);
}
