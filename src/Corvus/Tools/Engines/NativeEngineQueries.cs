using System.Text.Json;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;
using Corvus.Native.Providers.Ida;

namespace Corvus.Tools;

/// <summary>Query-surface requests answered by IDA worker ops, and by other engines another way (or not at all: null).</summary>
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

    /// <summary>A named type of a list_native_types page, with its first members when asked (enum members carry the value in Offset and no type).</summary>
    public sealed record TypeRow(string Name, string Kind, long Size, int MemberCount, IReadOnlyList<NativeTypeMember>? Members);

    /// <summary>list_native_types selection: name filter, kind (also ptr and udt), order (ordinal: the engine's own, name or size), page and member rows per type.</summary>
    public sealed record TypeQuery(NameFilter? Filter, string? Kind, string Sort, bool Descending, int Members, int Offset, int Limit);

    /// <summary>One page of the engine's named types: IDA filters, sorts and pages in the worker; other engines are asked for every type and the rest is done here.</summary>
    public static async Task<(int Total, IReadOnlyList<TypeRow> Rows)> Types(INativeDecompilerSession session, TypeQuery q, CancellationToken ct)
    {
        if (session is IdaSession ida)
        {
            var args = IdaProvider.Args(("kind", q.Kind), ("sort", q.Sort), ("descending", q.Descending), ("members", q.Members), ("offset", q.Offset), ("limit", q.Limit));
            if (q.Filter is { Pattern: { } regex })
            {
                args["pattern"] = regex.ToString();
                args["flags"] = (regex.Options.HasFlag(RegexOptions.IgnoreCase) ? "i" : "") + (regex.Options.HasFlag(RegexOptions.Multiline) ? "m" : "") +
                                (regex.Options.HasFlag(RegexOptions.Singleline) ? "s" : "");
            }
            else if (q.Filter != null) args["filter"] = q.Filter.Text;
            var r = await ida.CallAsync("types", args, ct).ConfigureAwait(false);
            return (r.GetProperty("total").GetInt32(), r.GetProperty("rows").EnumerateArray().Select(x => new TypeRow(x[0].GetString() ?? "", x[1].GetString() ?? "",
                x[2].GetInt64(), x[3].GetInt32(), x.GetArrayLength() > 4 ? x[4].EnumerateArray().Select(m => new NativeTypeMember(m[0].GetInt64(), m[1].GetString() ?? "",
                    m[2].ValueKind == JsonValueKind.String ? m[2].GetString()! : "", m[3].GetInt64())).ToList() : null)).ToList());
        }
        if (q.Kind == "ptr" && session is not GhidraSession)
            throw new ToolError(ErrorCode.Unsupported, $"kind=ptr is known from IDA's and Ghidra's types; {session.ProviderId} lists structs, unions, enums, typedefs and functions.",
                "use engine=ida or engine=ghidra, or kind=typedef");
        var all = await session.ListTypesAsync(q.Filter is { Pattern: null } ? q.Filter.Text : null, q.Kind == "udt" ? null : q.Kind, 0, 1_000_000, ct).ConfigureAwait(false);
        IEnumerable<NativeTypeEntry> rows = all.Types.Where(t => (q.Kind != "udt" || t.Kind is "struct" or "union") && (q.Filter is not { Pattern: not null } || q.Filter.IsMatch(t.Name)));
        rows = q.Sort switch
        {
            "name" => q.Descending ? rows.OrderByDescending(t => t.Name, StringComparer.OrdinalIgnoreCase) : rows.OrderBy(t => t.Name, StringComparer.OrdinalIgnoreCase),
            "size" => q.Descending ? rows.OrderByDescending(t => t.Size) : rows.OrderBy(t => t.Size),
            _ => q.Descending ? rows.Reverse() : rows,
        };
        var list = rows.ToList();
        var page = new List<TypeRow>();
        foreach (var t in list.Skip(q.Offset).Take(q.Limit))
        {
            IReadOnlyList<NativeTypeMember>? members = null;
            if (q.Members > 0 && t.Members > 0 && page.Count < MaxDetailed)
                members = (await session.GetTypeAsync(t.Name, ct).ConfigureAwait(false)).Members.Take(q.Members).ToList();
            page.Add(new TypeRow(t.Name, t.Kind, t.Size, t.Members, members));
        }
        return (list.Count, page);
    }

    /// <summary>Types whose members another engine reads one request each, per page.</summary>
    private const int MaxDetailed = 50;
}
