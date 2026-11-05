namespace Corvus.Native.Emulation;

/// <summary>
/// Runtime routines that raise a managed exception, one table keyed by the
/// routine name as symbols and exports spell it.
/// </summary>
internal static class ThrowHelpers
{
    // CoreCLR JIT helpers (jithelpers.cpp, release/6.0 to 8.0) and the managed
    // System.ThrowHelper and CastHelpers methods that replace them later.
    private static readonly Dictionary<string, string> Table = new(StringComparer.OrdinalIgnoreCase)
    {
        ["JIT_ThrowNullRef"] = "System.NullReferenceException",
        ["JIT_RngChkFail"] = "System.IndexOutOfRangeException",
        ["JIT_ThrowDivZero"] = "System.DivideByZeroException",
        ["JIT_Overflow"] = "System.OverflowException",
        ["ThrowNullReferenceException"] = "System.NullReferenceException",
        ["ThrowIndexOutOfRangeException"] = "System.IndexOutOfRangeException",
        ["ThrowDivideByZeroException"] = "System.DivideByZeroException",
        ["ThrowOverflowException"] = "System.OverflowException",
        ["ThrowInvalidCastException"] = "System.InvalidCastException",
        ["ThrowArgumentNullException"] = "System.ArgumentNullException",
        ["ThrowArgumentOutOfRangeException"] = "System.ArgumentOutOfRangeException",
    };

    /// <summary>
    /// The managed exception a call to the named routine raises, or null when
    /// the name is not a known throw helper. Accepts "lib!", "__imp_", "::",
    /// "." and Native AOT "__" qualified names.
    /// </summary>
    public static string? Find(string? name)
    {
        if (string.IsNullOrEmpty(name)) return null;
        var label = name[(name.IndexOf('!') + 1)..];
        if (label.StartsWith("__imp_", StringComparison.Ordinal)) label = label[6..];
        // Native AOT mangles Ns.Type.Method as Ns_Type__Method.
        int cut = Math.Max(Math.Max(label.LastIndexOf("::", StringComparison.Ordinal), label.LastIndexOf("__", StringComparison.Ordinal)) + 1, label.LastIndexOf('.'));
        if (cut > 0 && cut < label.Length - 1) label = label[(cut + 1)..];
        return Table.TryGetValue(label, out var ex) ? ex : null;
    }
}
