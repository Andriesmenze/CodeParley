using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace CodeParley.Custodian.Ipc;

/// <summary>One frame of the helper channel: a JSON header and an optional opaque body.</summary>
internal sealed record HelperFrame(JsonObject Header, byte[] Body)
{
    internal string Type => Header["t"] is JsonValue v && v.TryGetValue(out string? t) && t is not null ? t : "";
    internal string? Str(string key) => Header[key] is JsonValue v && v.TryGetValue(out string? s) ? s : null;
    internal long? Long(string key) => Header[key] is JsonValue v && v.TryGetValue(out long l) ? l : null;
}

/// <summary>A frame the channel refuses (too large, malformed, wrong shape). The connection ends fail-closed.</summary>
internal sealed class HelperFrameError(string message) : Exception(message);

/// <summary>
/// P3.4C-5 (§A.2): the bounded, length-prefixed framing of the custodian↔helper channel — and of the helper's Node child
/// on its standard output, which the helper relays. A frame is
/// <c>u32le header length · header (UTF-8 JSON object) · u32le body length · body</c>.
/// Every length is checked against its cap BEFORE anything is allocated, so a hostile peer cannot make the reader
/// buffer more than the caps allow; a header that is not a JSON object with a string <c>t</c> is refused.
/// </summary>
internal static class HelperFrames
{
    internal static async Task<HelperFrame?> ReadAsync(Stream s, long maxBody, CancellationToken ct)
    {
        byte[] len = new byte[4];
        int got = await ReadAtMostAsync(s, len, ct).ConfigureAwait(false);
        if (got == 0) return null; // clean end of stream between frames
        if (got != 4) throw new HelperFrameError("truncated frame header length");
        uint headerLen = BinaryPrimitives.ReadUInt32LittleEndian(len);
        if (headerLen == 0 || headerLen > CustodianConstants.MaxHelperHeaderBytes) throw new HelperFrameError($"frame header of {headerLen} bytes is outside 1..{CustodianConstants.MaxHelperHeaderBytes}");
        byte[] header = new byte[headerLen];
        if (await ReadAtMostAsync(s, header, ct).ConfigureAwait(false) != header.Length) throw new HelperFrameError("truncated frame header");
        if (await ReadAtMostAsync(s, len, ct).ConfigureAwait(false) != 4) throw new HelperFrameError("truncated frame body length");
        uint bodyLen = BinaryPrimitives.ReadUInt32LittleEndian(len);
        if (bodyLen > Math.Min(maxBody, CustodianConstants.MaxHelperBodyBytes)) throw new HelperFrameError($"frame body of {bodyLen} bytes exceeds the cap {Math.Min(maxBody, CustodianConstants.MaxHelperBodyBytes)}");
        byte[] body = bodyLen == 0 ? [] : new byte[bodyLen];
        if (bodyLen > 0 && await ReadAtMostAsync(s, body, ct).ConfigureAwait(false) != body.Length) throw new HelperFrameError("truncated frame body");
        JsonObject obj;
        try { obj = JsonNode.Parse(header) as JsonObject ?? throw new HelperFrameError("frame header is not a JSON object"); }
        catch (JsonException e) { throw new HelperFrameError("frame header is not JSON: " + e.Message); }
        if (obj["t"] is not JsonValue tv || !tv.TryGetValue(out string? t) || string.IsNullOrEmpty(t) || t.Length > 32)
            throw new HelperFrameError("frame header has no type");
        return new HelperFrame(obj, body);
    }

    internal static async Task WriteAsync(Stream s, JsonObject header, ReadOnlyMemory<byte> body, CancellationToken ct)
    {
        byte[] h = Encoding.UTF8.GetBytes(header.ToJsonString());
        if (h.Length > CustodianConstants.MaxHelperHeaderBytes) throw new HelperFrameError("frame header too large to send");
        if (body.Length > CustodianConstants.MaxHelperBodyBytes) throw new HelperFrameError("frame body too large to send");
        byte[] prefix = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(prefix, (uint)h.Length);
        await s.WriteAsync(prefix, ct).ConfigureAwait(false);
        await s.WriteAsync(h, ct).ConfigureAwait(false);
        BinaryPrimitives.WriteUInt32LittleEndian(prefix, (uint)body.Length);
        await s.WriteAsync(prefix, ct).ConfigureAwait(false);
        if (body.Length > 0) await s.WriteAsync(body, ct).ConfigureAwait(false);
        // No Flush: a pipe stream has no user-mode buffer (the write is already delivered), and FlushFileBuffers on a
        // pipe blocks — uncancellably — until the PEER has read everything, which a stalled or hostile peer never does.
    }

    internal static Task WriteAsync(Stream s, JsonObject header, CancellationToken ct) => WriteAsync(s, header, ReadOnlyMemory<byte>.Empty, ct);

    private static async Task<int> ReadAtMostAsync(Stream s, byte[] buffer, CancellationToken ct)
    {
        int off = 0;
        while (off < buffer.Length)
        {
            int n = await s.ReadAsync(buffer.AsMemory(off), ct).ConfigureAwait(false);
            if (n == 0) break;
            off += n;
        }
        return off;
    }
}
