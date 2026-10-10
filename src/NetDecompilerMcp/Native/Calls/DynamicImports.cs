namespace NetDecompilerMcp.Native.Calls;

/// <summary>A function resolved at run time (GetProcAddress).</summary>
public sealed record DynamicImport(string? Module, string Name, uint CallSite, uint? PointerGlobal)
{
    public string FullName => $"{Module ?? "?"}!{Name}";
}

/// <summary>Late-bound imports of an image.</summary>
public sealed class DynamicImportSet
{
    public Dictionary<uint, DynamicImport> ByGlobal { get; } = [];
    public Dictionary<uint, DynamicImport> BySite { get; } = [];
}

public sealed partial class CallAnalysis
{
    private DynamicImportSet? _dynamic = null;

    /// <summary>Whether site results may be cached (late-bound imports are known).</summary>
    private bool DynamicReady => true;
}
