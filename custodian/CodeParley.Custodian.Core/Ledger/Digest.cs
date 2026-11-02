using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace CodeParley.Custodian.Ledger;

/// <summary>
/// Canonical digests for the two-phase operator authorization. A prepared action's digest binds the
/// action, its canonical arguments, the state the operator was shown, the custodian id, the request id,
/// a custodian-generated nonce and the expiry. The custodian re-derives all of it at commit and refuses
/// on any difference (TD amendment 3) — so a replayed, re-pointed or stale authorization cannot commit.
/// </summary>
internal static class Digest
{
    /// <summary>Deterministic, key-sorted serialization of a JSON value.</summary>
    internal static string Canonical(JsonNode? node)
    {
        var sb = new StringBuilder();
        Write(node, sb);
        return sb.ToString();
    }

    private static void Write(JsonNode? node, StringBuilder sb)
    {
        switch (node)
        {
            case null: sb.Append("null"); break;
            case JsonObject o:
                sb.Append('{');
                bool first = true;
                foreach (var kv in o.OrderBy(k => k.Key, StringComparer.Ordinal))
                {
                    if (!first) sb.Append(',');
                    first = false;
                    sb.Append(JsonValue.Create(kv.Key)!.ToJsonString()).Append(':');
                    Write(kv.Value, sb);
                }
                sb.Append('}');
                break;
            case JsonArray a:
                sb.Append('[');
                for (int i = 0; i < a.Count; i++) { if (i > 0) sb.Append(','); Write(a[i], sb); }
                sb.Append(']');
                break;
            default: sb.Append(node.ToJsonString()); break;
        }
    }

    internal static string Sha256Hex(string s)
    {
        byte[] h = SHA256.HashData(Encoding.UTF8.GetBytes(s));
        return Convert.ToHexStringLower(h);
    }

    internal static string Nonce()
    {
        Span<byte> b = stackalloc byte[32];
        RandomNumberGenerator.Fill(b);
        return Convert.ToHexStringLower(b);
    }

    /// <summary>The authorization digest an operator action is bound to.</summary>
    internal static string AuthorizationDigest(string action, JsonObject canonicalArgs, string stateDigest, string custodianId, string requestId, string nonce, string expiresAt)
    {
        var bound = new JsonObject
        {
            ["action"] = action,
            ["args"] = canonicalArgs.DeepClone(),
            ["stateDigest"] = stateDigest,
            ["custodianId"] = custodianId,
            ["requestId"] = requestId,
            ["nonce"] = nonce,
            ["expiresAt"] = expiresAt,
        };
        return Sha256Hex(Canonical(bound));
    }
}
