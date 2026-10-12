namespace Corvus.Mcp;

// Contract rows of the dumps family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs and ParameterDomains.cs.

public static partial class ToolEffects
{
    private static Dictionary<string, Effects> DumpsTools() => new(StringComparer.Ordinal)
    {
        // Crash dumps (an open dump gets an id, as loading an image does)
        ["open_minidump"] = Reads(longRunning: true, openWorld: true), // downloadDac=true fetches the runtime's DAC from a symbol server
        ["dump_stack"] = Reads(),
        ["dump_heap"] = Reads(longRunning: true),
        ["dump_object"] = Reads(),
        ["read_dump_memory"] = Reads(),
        ["symbolize_stack_text"] = Reads(longRunning: true), // waits for the code index of the images it names
        ["bucket_minidumps"] = Reads(longRunning: true), // caches signatures privately
    };
}

public static partial class ParameterDomains
{
    private static Dictionary<string, IReadOnlyDictionary<string, Domain>> DumpsTools() => new(StringComparer.Ordinal)
    {
        ["dump_stack"] = new Dictionary<string, Domain> { ["managed"] = Of(["auto", "off"]) },
        ["dump_heap"] = new Dictionary<string, Domain> { ["mode"] = Of(["stats", "objects"]) },
        ["bucket_minidumps"] = new Dictionary<string, Domain> { ["managed"] = Of(["auto", "off"]) },
        ["symbolize_stack_text"] = new Dictionary<string, Domain> { ["format"] = Of(["auto", "unity", "dotnet", "wer", "eventlog", "windbg", "android"]) },
    };
}
