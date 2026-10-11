using System.Text.Json;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ida;

namespace NetDecompilerMcp.Tools;

/// <summary>Query-surface worker ops that only IDA has: null from other engines, which the callers answer another way.</summary>
internal static class NativeEngineQueries
{
    /// <summary>An object pseudocode names: <see cref="Text"/> for a string literal, <see cref="Function"/> for a function start.</summary>
    public sealed record PseudocodeObject(uint Rva, string Name, string? Text, int Uses, bool Function);

    /// <summary>The objects (cot_obj) in the ctree of the function at <paramref name="rva"/>, in first-use order; null when the engine is not IDA.</summary>
    public static async Task<IReadOnlyList<PseudocodeObject>?> DecompileRefs(INativeDecompilerSession session, uint rva, CancellationToken ct)
    {
        if (session is not IdaSession ida) return null;
        var r = await ida.CallAsync("decompile_refs", IdaProvider.Args(("rva", rva)), ct).ConfigureAwait(false);
        return r.GetProperty("refs").EnumerateArray().Select(x => new PseudocodeObject(x[0].GetUInt32(), x[1].GetString() ?? "",
            x[2].ValueKind == JsonValueKind.String ? x[2].GetString() : null, x[3].GetInt32(), x[4].GetBoolean())).ToList();
    }
}
