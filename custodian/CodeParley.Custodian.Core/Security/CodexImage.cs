namespace CodeParley.Custodian.Security;

/// <summary>A Codex image as the custodian measured it through its own handle (P3.4C-4 §4.4).</summary>
internal sealed record MeasuredImage(string Path, string Form, string FileId, long Size, string Sha256);

/// <summary>
/// P3.4C-4 (§4.4, TD clarification II): the approved Codex installation is the native executable image CodeParley
/// launches, measured by the custodian itself with its own token. Phase 5 (§4.1): the measurement is the host's
/// (<see cref="Platform.Images"/>; Windows: the no-follow walk, one PE image); this is the portable surface.
/// </summary>
internal static class CodexImage
{
    internal const string NativePe = "native_pe";

    internal static MeasuredImage Measure(string path) => Platform.Images.MeasureCodex(path);

    /// <summary>The installation as held (and rendered): what <see cref="Measure"/> returned.</summary>
    internal static string Describe(MeasuredImage m) => $"{m.Path}\n    {KindOf(m.Form)} image, {m.Size} bytes, SHA-256 {m.Sha256}, file id {m.FileId}";

    /// <summary>How a rendering names an image form: "native PE" (Windows), "native ELF" (Linux, Phase 5).</summary>
    internal static string KindOf(string? form) => form == "native_elf" ? "native ELF" : "native PE";
}
