namespace NetDecompilerMcp.Native.Pe;

/// <summary>Hard limits that keep hostile images from causing unbounded work or memory; reaching one records an issue.</summary>
public static class PeLimits
{
    /// <summary>Largest file read into memory.</summary>
    public const long MaxFileSize = 1L << 30;
    public const int MaxSections = 4096;
    public const int MaxImportModules = 4096;
    public const int MaxImportsPerModule = 65536;
    public const int MaxImports = 1 << 20;
    public const int MaxExports = 1 << 20;
    public const int MaxBoundImports = 1024;
    public const int MaxNameLength = 4096;
    public const int MaxRelocations = 1 << 24;
    public const int MaxTlsCallbacks = 4096;
    public const int MaxRuntimeFunctions = 1 << 22;
    public const int MaxDebugEntries = 1024;
    public const int MaxGuardTableEntries = 1 << 20;
    public const int MaxResources = 1 << 18;
    public const int MaxResourceDepth = 8;
    public const int MaxResourceDirectories = 1 << 16;
    public const int MaxVersionDepth = 8;
    public const int MaxVersionBlocks = 4096;
    public const int MaxManifestBytes = 1 << 20;
    public const int MaxStringTableEntries = 1 << 18;
    public const int MaxRichEntries = 1024;
    /// <summary>Characters decoded per area across all names and strings.</summary>
    public const long MaxCharsPerArea = 64L << 20;
    /// <summary>Table entries, blocks and nodes visited per area.</summary>
    public const long MaxStepsPerArea = 64L << 20;
    public const int MaxIssuesPerArea = 100;
}

/// <summary>Issues of one parse area, capped at <see cref="PeLimits.MaxIssuesPerArea"/>.</summary>
internal sealed class IssueLog(string area)
{
    private readonly List<ParseIssue> items = [];
    private int dropped;

    public string Area => area;

    public void Add(string message, long? fileOffset = null)
    {
        if (items.Count < PeLimits.MaxIssuesPerArea) items.Add(new ParseIssue(area, message, fileOffset));
        else dropped++;
    }

    public IReadOnlyList<ParseIssue> ToList() =>
        dropped == 0 ? items.ToArray() : [.. items, new ParseIssue(area, $"{dropped} further issues not listed")];
}

/// <summary>Step and character budget of one parse area; the first overrun records an issue.</summary>
internal sealed class WorkBudget(IssueLog log)
{
    private long steps = PeLimits.MaxStepsPerArea;
    private long chars = PeLimits.MaxCharsPerArea;
    private bool reported;

    public bool Exhausted { get; private set; }

    public bool Step(long n = 1)
    {
        steps -= n;
        return steps >= 0 || Fail();
    }

    public bool Chars(long n)
    {
        chars -= n;
        return chars >= 0 || Fail();
    }

    private bool Fail()
    {
        Exhausted = true;
        if (!reported)
        {
            reported = true;
            log.Add("work limit reached; the rest of this area was not read");
        }
        return false;
    }
}
