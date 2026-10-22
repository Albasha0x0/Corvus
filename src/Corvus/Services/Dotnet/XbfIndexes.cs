namespace Corvus.Services;

/// <summary>The stable type and property indexes XBF 2 writes for the system XAML types, with enum member names.</summary>
internal static partial class XbfIndexes
{
    private static readonly Lazy<string[]> Types = new(() => TypeTable.Split('\n'));
    private static readonly Lazy<string[]> Properties = new(() => PropertyTable.Split('\n'));

    /// <summary>The type name at <paramref name="index"/>; null for an index not in use or out of range.</summary>
    public static string? Type(int index) => Entry(Types.Value, index) is { } e ? e.Split('=', '|')[0] : null;

    /// <summary>"Owner.Name", ending in * for an attached property; null for an index not in use or out of range.</summary>
    public static string? Property(int index) => Entry(Properties.Value, index);

    /// <summary>
    /// The member of enum <paramref name="type"/> with <paramref name="value"/>, or for a flags enum the members joined
    /// with commas; null when the type is no enum or the value matches no member.
    /// </summary>
    public static string? EnumMember(int type, uint value)
    {
        if (Entry(Types.Value, type) is not { } e) return null;
        int cut = e.IndexOfAny(['=', '|']);
        if (cut < 0) return null;
        bool flags = e[cut] == '|';
        var members = e[(cut + 1)..].Split(',').Select((m, i) => m.IndexOf(':') is var c and > 0 ? (long.Parse(m[..c], System.Globalization.CultureInfo.InvariantCulture), m[(c + 1)..]) : ((long)i, m)).ToList();
        if (members.FirstOrDefault(m => m.Item1 == value) is { Item2: { } exact }) return exact;
        if (!flags || value == 0) return null;
        var parts = members.Where(m => m.Item1 != 0 && (value & m.Item1) == m.Item1).ToList();
        return parts.Aggregate(0L, (all, m) => all | m.Item1) == value ? string.Join(",", parts.Select(m => m.Item2)) : null;
    }

    private static string? Entry(string[] table, int index) => index > 0 && index < table.Length && table[index].Length > 0 ? table[index] : null;
}
