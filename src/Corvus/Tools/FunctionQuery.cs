using Corvus.Core;

namespace Corvus.Tools;

/// <summary>
/// list_functions selection and order, shared by the built-in index and the engines: name filter, size bounds, a start
/// address range, a type requirement (engines only) and a sort with an optional direction.
/// </summary>
internal sealed record FunctionQuery(NameFilter? Filter, long? MinSize, long? MaxSize, uint? From, uint? To, bool? HasType, string Sort, bool? Descending)
{
    public static readonly string[] Sorts = ["address", "name", "size", "callers"];

    /// <summary>Checks the sort; the range is resolved by the caller.</summary>
    public static FunctionQuery Create(string? filter, long? minSize, long? maxSize, uint? from, uint? to, bool? hasType, string? sort, bool? descending)
    {
        var s = string.IsNullOrWhiteSpace(sort) ? "address" : sort.Trim().ToLowerInvariant();
        if (!Sorts.Contains(s)) throw new ToolError(ErrorCode.InvalidArgument, $"Unknown sort '{sort}'.", "use address, name, size or callers");
        if (minSize > maxSize) throw new ToolError(ErrorCode.InvalidArgument, $"minSize {minSize} is above maxSize {maxSize}.", "pass minSize <= maxSize");
        if (from >= to) throw new ToolError(ErrorCode.InvalidArgument, "from is not below to.", "pass from below to (to is exclusive)");
        return new FunctionQuery(NameFilter.Parse(filter), minSize, maxSize, from, to, hasType, s, descending);
    }

    /// <summary>Whether anything beyond the order narrows the list.</summary>
    public bool Narrows => Filter != null || MinSize != null || MaxSize != null || From != null || To != null || HasType != null;

    /// <summary>The conditions as text ("name ~ 'Get*', size >= 64"), for the header.</summary>
    public string Describe(Func<uint, string> va)
    {
        var parts = new List<string>();
        if (Filter != null) parts.Add($"name '{Filter.Text}'");
        if (MinSize != null) parts.Add($"size >= {MinSize}");
        if (MaxSize != null) parts.Add($"size <= {MaxSize}");
        if (From != null) parts.Add($"start >= {va(From.Value)}");
        if (To != null) parts.Add($"start < {va(To.Value)}");
        if (HasType != null) parts.Add(HasType.Value ? "typed" : "untyped");
        return string.Join(", ", parts);
    }

    /// <summary>The index of the only item named exactly as a plain (substring) filter, ignoring case; -1 when none or several are.</summary>
    public int ExactIndex<T>(IReadOnlyList<T> items, Func<T, string> name)
    {
        if (Filter is not { Pattern: null } plain) return -1;
        int found = -1;
        for (int i = 0; i < items.Count; i++)
            if (string.Equals(name(items[i]), plain.Text, StringComparison.OrdinalIgnoreCase))
            {
                if (found >= 0) return -1;
                found = i;
            }
        return found;
    }

    /// <summary>The matching items in order: address and name ascend, size and callers descend, unless <see cref="Descending"/> says otherwise.</summary>
    public List<T> Apply<T>(IEnumerable<T> items, Func<T, uint> start, Func<T, long> size, Func<T, string> name, Func<T, int> callers, Func<T, bool>? typed)
    {
        var list = items.Where(f => (MinSize == null || size(f) >= MinSize) && (MaxSize == null || size(f) <= MaxSize)
                                    && (From == null || start(f) >= From) && (To == null || start(f) < To)
                                    && (HasType == null || typed!(f) == HasType) && (Filter == null || Filter.IsMatch(name(f))));
        bool down = Descending ?? Sort is "size" or "callers";
        IOrderedEnumerable<T> ordered = Sort switch
        {
            "name" => down ? list.OrderByDescending(name, StringComparer.OrdinalIgnoreCase) : list.OrderBy(name, StringComparer.OrdinalIgnoreCase),
            "size" => down ? list.OrderByDescending(size) : list.OrderBy(size),
            "callers" => down ? list.OrderByDescending(callers) : list.OrderBy(callers),
            _ => down ? list.OrderByDescending(start) : list.OrderBy(start),
        };
        return ordered.ThenBy(start).ToList();
    }
}
