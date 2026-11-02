using System.Security.Cryptography;
using System.Text.Json;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ledger;

/// <summary>The custodian's content-key secret plus the non-secret <see cref="KeyId"/> that binds it to the
/// records that depend on it.</summary>
internal sealed record ContentKey(string KeyId, byte[] Secret);

/// <summary>
/// P3.4C-1 confidentiality correction: the HMAC secret for protected amendment content-equivalence keys.
///
/// Generated ONCE with a CSPRNG the first time a keyed amendment is recorded, persisted crash-safe in the
/// custodian's protected store (inheriting Root's custodian-only DACL), preserved across service restarts,
/// and NEVER exposed through IPC, logs, errors, artifacts or configuration. It is never silently rotated or
/// regenerated: a corrupt secret, or one whose <see cref="ContentKey.KeyId"/> no longer matches the id the
/// records were bound to, fails closed (that binding is checked by the ledger, not here). This is NOT a
/// general key-management or rotation subsystem — it is one secret with crash-safe create-if-absent.
/// </summary>
internal static class ContentKeySecret
{
    private sealed record Stored(string keyId, string secret);

    /// <summary>Read the secret, creating it crash-safe on first use. Throws (fail closed) if the stored
    /// secret is unreadable or corrupt — it is never regenerated in place of a secret records may depend on.</summary>
    internal static ContentKey GetOrCreate()
    {
        string path = StorePaths.ContentKeySecretPath;
        for (int attempt = 0; ; attempt++)
        {
            if (File.Exists(path))
            {
                Stored? s;
                try { s = JsonSerializer.Deserialize<Stored>(File.ReadAllText(path)); }
                catch (Exception e) { throw new InvalidOperationException($"the custodian content-key secret is unreadable; protected amendments cannot be recorded (fail closed): {e.Message}"); }
                byte[] secret = [];
                try { if (s?.secret is not null) secret = Convert.FromBase64String(s.secret); } catch { /* corrupt → fail below */ }
                if (s is null || string.IsNullOrEmpty(s.keyId) || secret.Length != 32)
                    throw new InvalidOperationException("the custodian content-key secret is corrupt (fail closed); it is not regenerated while records may depend on it");
                return new ContentKey(s.keyId, secret);
            }
            byte[] fresh = RandomNumberGenerator.GetBytes(32);
            string keyId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
            string json = JsonSerializer.Serialize(new Stored(keyId, Convert.ToBase64String(fresh)));
            try
            {
                // Created once, never overwritten, and flushed before any record depends on it (P3.4C-3 §2.4).
                DurableStore.CreateNew(path, json);
                return new ContentKey(keyId, fresh);
            }
            catch (IOException) when (File.Exists(path) && attempt < 3)
            {
                // Created concurrently (or a restart race): re-read on the next loop.
            }
        }
    }
}
