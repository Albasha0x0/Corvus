using System.Globalization;
using System.Text.Json;
using Corvus.Native;
using Corvus.Native.Dump;

namespace Corvus.Services;

/// <summary>A hook a session placed in the program's code: where, which ids hold it, its kind and the bytes it replaced (null when unknown).</summary>
public sealed record LiveSessionHook(ulong Address, ulong Start, IReadOnlyList<string> Ids, string Kind, byte[]? Original)
{
    /// <summary>Whether the replaced bytes are known.</summary>
    public bool Restorable => Original != null;
}

/// <summary>Reads the hook records of a worker and shows the program's code without them.</summary>
public static class LiveSessionHooks
{
    /// <summary>Most rows save_modules lists per module.</summary>
    public const int MaxRows = 200;

    private const ulong MaxSpan = 32;

    /// <summary>The hooks a worker's "hooks" answer holds; kinds come from <paramref name="kindOf"/>. Null when the answer holds no hook list; rows with a malformed address are dropped.</summary>
    public static List<LiveSessionHook>? Parse(JsonElement reply, Func<string, string> kindOf)
    {
        var hooks = new List<LiveSessionHook>();
        if (reply.ValueKind != JsonValueKind.Object || !reply.TryGetProperty("hooks", out var rows) || rows.ValueKind != JsonValueKind.Array) return null;
        foreach (var row in rows.EnumerateArray())
        {
            if (!TryHex(row.GetProperty("address").GetString(), out ulong address)) continue;
            var ids = row.GetProperty("ids").EnumerateArray().Select(i => i.GetString() ?? "").ToList();
            ulong offset = row.TryGetProperty("offset", out var o) && o.ValueKind == JsonValueKind.Number ? o.GetUInt64() : 0;
            byte[]? original = null;
            if (row.TryGetProperty("original", out var h) && h.ValueKind == JsonValueKind.String)
            {
                try { original = Convert.FromHexString(h.GetString()!); }
                catch (FormatException) { }
            }
            var kinds = ids.Select(kindOf).Distinct().Order(StringComparer.Ordinal);
            hooks.Add(new LiveSessionHook(address, address + offset, ids, string.Join('+', kinds), original));
        }
        return hooks;
    }

    /// <summary>The hooks of <paramref name="session"/> as its worker reports them; null with the reason when the worker gave none.</summary>
    internal static async Task<(List<LiveSessionHook>? Hooks, string? Reason)> ReadAsync(LiveSession session, CancellationToken ct)
    {
        try
        {
            var reply = await session.Worker.RequestAsync("hooks", null, TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
            var hooks = Parse(reply, id => KindOf(session, id));
            return (hooks, hooks == null ? "the worker answered no hook list" : null);
        }
        catch (Core.ToolError e)
        {
            return (null, e.Message);
        }
    }

    /// <summary>The kind of the hook an id names: stop, watch, coverage or session.</summary>
    public static string KindOf(LiveSession session, string id)
    {
        lock (session.StopPoints) if (session.StopPoints.ContainsKey(id)) return "stop";
        lock (session.Watches) if (session.Watches.ContainsKey(id)) return "watch";
        return session.CoveragePoints.ContainsKey(id) ? "coverage" : "session";
    }

    private static bool TryHex(string? text, out ulong value)
    {
        value = 0;
        return text != null && text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            && ulong.TryParse(text.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
    }

    /// <summary>The process as it read before the hooks: reads that cross a restorable hook return its original bytes.</summary>
    public static IProcessMemory Restoring(IProcessMemory inner, IReadOnlyList<LiveSessionHook> hooks) =>
        hooks.Any(h => h.Restorable) ? new RestoredMemory(inner, [.. hooks.Where(h => h.Restorable).OrderBy(h => h.Start)]) : inner;

    private sealed class RestoredMemory(IProcessMemory inner, LiveSessionHook[] hooks) : IProcessMemory
    {
        public NativeArch Arch => inner.Arch;
        public bool Is64Bit => inner.Is64Bit;
        public string Identity => inner.Identity;
        public IReadOnlyList<DumpModule> Modules => inner.Modules;
        public IReadOnlyList<DumpUnloadedModule> UnloadedModules => inner.UnloadedModules;
        public DumpModule? ModuleAt(ulong address) => inner.ModuleAt(address);
        public DumpMemoryRegion? RegionAt(ulong address) => inner.RegionAt(address);
        public ulong ReadableExtent(ulong start, ulong size) => inner.ReadableExtent(start, size);

        public int ReadMemory(ulong address, Span<byte> destination)
        {
            int n = inner.ReadMemory(address, destination);
            if (n <= 0) return n;
            ulong end = address + (ulong)n;
            // A span is at most MaxSpan bytes: skip hooks that end before the read.
            int lo = 0, hi = hooks.Length;
            while (lo < hi)
            {
                int mid = (lo + hi) >>> 1;
                if (hooks[mid].Start + MaxSpan <= address) lo = mid + 1;
                else hi = mid;
            }
            for (int i = lo; i < hooks.Length && hooks[i].Start < end; i++)
            {
                var h = hooks[i];
                ulong from = Math.Max(address, h.Start), to = Math.Min(end, h.Start + (ulong)h.Original!.Length);
                if (from < to) h.Original.AsSpan((int)(from - h.Start), (int)(to - from)).CopyTo(destination[(int)(from - address)..]);
            }
            return n;
        }
    }
}
