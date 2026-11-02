namespace CodeParley.Custodian.Security;

/// <summary>
/// A repository's identity as the custodian itself establishes it (P3.4C-0, TD decision 3): the
/// <c>FILE_ID_INFO</c> (64-bit volume serial number + 128-bit file id) of the repository's root
/// directory, read from a handle the custodian opens with its OWN token by a no-follow walk from the
/// volume root. The client's path is only a locator: no client-computed key is ever trusted, and the
/// identity is the same for every supported spelling of the same directory (letter case, separators,
/// a trailing separator, an 8.3 short name), while a spelling that could name a different object
/// depending on how it is resolved — a link, junction or mount point in ANY component, a substituted,
/// mapped or network drive, <c>.</c>/<c>..</c>, a trailing dot or space, UNC/device/<c>\\?\</c> forms,
/// a non-NTFS/ReFS volume — is REFUSED rather than guessed.
///
/// The identity binds the directory OBJECT, not its content (a same-user implementer can always change
/// the files of its own repository; binding reviews to content is the Phase 2 source evidence). A grant
/// therefore follows the directory through a rename on the same volume, and does not survive its
/// replacement (a deleted and recreated directory gets a new file id; NTFS also stamps a reused MFT
/// record with a new sequence number).
/// </summary>
internal sealed record RepoIdentity(string Key, string CanonicalPath, string FileSystem);

/// <summary>A refused identity (INVALID_ARGUMENT). Classified by TYPE, never by message text: a refusal
/// quotes the client's path components, which must not be able to spell another error code.</summary>
internal sealed class RepoIdentityRefused(string message) : ArgumentException(message);

/// <summary>Phase 5 (§4.1): the repository identity the custodian derives, through the host's resolver (Windows:
/// <c>fid1</c>, the no-follow walk + FILE_ID_INFO; Linux: <c>fid2</c>, openat2 + fstatfs + name_to_handle_at + birth time).
/// A key without the host's scheme prefix is never matched against a resolved identity.</summary>
internal static class RepoIdentities
{
    internal const string RefusedPrefix = "repository identity refused: ";

    /// <summary>The scheme of every key this custodian derives.</summary>
    internal static string Scheme => Platform.Repo.Scheme;

    internal static bool IsCurrent(string? repoKey) => repoKey is not null && repoKey.StartsWith(Scheme + "-", StringComparison.Ordinal);

    /// <summary>Resolve the identity of the directory <paramref name="repositoryRoot"/> names. Throws
    /// <see cref="ArgumentException"/> (INVALID_ARGUMENT, message prefixed <see cref="RefusedPrefix"/>) for every refused form.</summary>
    internal static RepoIdentity Resolve(string repositoryRoot) => Platform.Repo.Resolve(repositoryRoot);
}
