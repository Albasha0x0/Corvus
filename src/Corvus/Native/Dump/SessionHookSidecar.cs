using System.Globalization;
using System.Text.Json;

namespace Corvus.Native.Dump;

/// <summary>A hook a session had placed when a snapshot was saved: its first address, the bytes it spans and its kind.</summary>
public sealed record SessionHookMark(ulong Address, int Length, string Kind);

/// <summary>Saves the hooks of a session beside its snapshot and reads them back to label changed code.</summary>
public static class SessionHookSidecar
{
    /// <summary>Largest sidecar read, in bytes.</summary>
    public const int MaxBytes = 4 * 1024 * 1024;

    private const string Suffix = ".hooks.json";

    /// <summary>The sidecar path of the dump at <paramref name="dump"/>: its base name with <c>.hooks.json</c>.</summary>
    public static string PathFor(string dump) => System.IO.Path.ChangeExtension(dump, null) + Suffix;

    /// <summary>Writes <paramref name="hooks"/> beside <paramref name="dump"/>; the dump itself is not changed.</summary>
    public static void Write(string dump, IReadOnlyList<SessionHookMark> hooks)
    {
        var rows = hooks.Select(h => new { address = $"0x{h.Address:X}", length = h.Length, kind = h.Kind });
        File.WriteAllText(PathFor(dump), JsonSerializer.Serialize(new { hooks = rows }));
    }

    /// <summary>The hooks saved beside <paramref name="dump"/>; null when there is no sidecar, or it is larger than <see cref="MaxBytes"/> or not a hook list. Rows with a malformed address are dropped.</summary>
    public static IReadOnlyList<SessionHookMark>? Read(string dump)
    {
        var path = PathFor(dump);
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > MaxBytes) return null;
            using var doc = Corvus.Core.InputJson.ParseDocument(File.ReadAllBytes(path));
            if (doc.RootElement.ValueKind != JsonValueKind.Object
                || !doc.RootElement.TryGetProperty("hooks", out var rows) || rows.ValueKind != JsonValueKind.Array) return null;
            var hooks = new List<SessionHookMark>();
            foreach (var row in rows.EnumerateArray())
            {
                if (row.ValueKind != JsonValueKind.Object
                    || !row.TryGetProperty("address", out var a) || a.ValueKind != JsonValueKind.String
                    || a.GetString() is not { } text || !text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                    || !ulong.TryParse(text.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong address)) continue;
                int length = row.TryGetProperty("length", out var l) && l.ValueKind == JsonValueKind.Number && l.TryGetInt32(out int n) && n > 0 ? n : 1;
                // Kinds are stop, watch, coverage or a + join of them; anything else reads as session.
                string kind = row.TryGetProperty("kind", out var k) && k.ValueKind == JsonValueKind.String && k.GetString() is { Length: > 0 and <= 32 } named
                    && named.All(c => c is >= 'a' and <= 'z' or '+') ? named : "session";
                hooks.Add(new SessionHookMark(address, length, kind));
            }
            return hooks;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    /// <summary>The kind of the hook whose bytes overlap <c>[start, start + length)</c>, or null when none does.</summary>
    public static string? KindAt(IReadOnlyList<SessionHookMark> hooks, ulong start, int length)
    {
        ulong end = start + (ulong)Math.Max(length, 1);
        foreach (var h in hooks)
            if (h.Address < end && start < h.Address + (ulong)h.Length) return h.Kind;
        return null;
    }
}
