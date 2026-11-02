using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>Calls on built fixtures whose success reply carries an action line, per tool family; the sweep checks each reply like any other.</summary>
public static class SuccessNoteCases
{
    /// <summary>One call: the tool, what it constructs, its arguments and the marker its reply must carry at the start of an action line.</summary>
    public sealed record Entry(string Tool, string Label, Dictionary<string, object?> Args, string Expect);

    /// <summary>Families the cases cannot reach, with the reason; none while every family has a case.</summary>
    public static readonly IReadOnlyDictionary<string, string> NotReachable = OperatingSystem.IsWindows()
        ? new Dictionary<string, string>(StringComparer.Ordinal)
        : new Dictionary<string, string>(StringComparer.Ordinal) { ["live"] = "off Windows the module list of the test process depends on the host process-access policy" };

    private static Dictionary<string, object?> A(params (string Key, object? Value)[] pairs) => pairs.ToDictionary(p => p.Key, p => p.Value);

    /// <summary>The cases of every family in <see cref="ToolContract.ByFamily"/>.</summary>
    public static Dictionary<string, Entry[]> ByFamily(TempDir dir)
    {
        var native = McpProtocolTests.NativeSample(dir);
        var nativeV2 = McpProtocolTests.NativeSampleV2(dir);
        var apk = AndroidSamples.Save(dir, "notes.apk", AndroidSamples.Apk(30, ("classes.dex", AndroidSamples.Dex())));
        var dumps = dir.File("two-dumps");
        Directory.CreateDirectory(dumps);
        var dumpFolder = new TempDir(dumps);
        SyntheticCrash.Write(dumpFolder, "first.dmp");
        SyntheticCrash.Write(dumpFolder, "second.dmp");
        var cases = new Dictionary<string, Entry[]>(StringComparer.Ordinal)
        {
            ["session"] = [new("list_assemblies", "a capped list of loaded assemblies", A(("limit", 1)), "[More:")],
            ["dotnet"] = [new("list_types", "a capped list of types", A(("namespace", "Fixture.Model"), ("limit", 1)), "[More:")],
            ["containers"] = [new("summarize_build", "a build summary with next calls", A(("path", BuildSummaryTests.MonoSample(dir))), "Next:")],
            ["edit"] = [new("rename_symbol", "a dry run", A(("symbol", "Account"), ("newName", "Customer"), ("dryRun", true)), "Warning:")],
            ["aot"] = [new("apply_metadata_names", "names applied with the next call to read them back", A(("image", native), ("assembly", "TestFixture")), "Next:")],
            ["native"] = [new("analyze_native_function", "a function report with next calls", A(("image", native), ("address", "First")), "Next:")],
            ["native-edit"] = [new("rename_native", "a dry run", A(("image", native), ("address", "First"), ("name", "NoteFunc"), ("dryRun", true)), "Dry run:")],
            ["builds"] = [new("migrate_native_names", "a dry run over two builds", A(("oldImage", native), ("newImage", nativeV2), ("dryRun", true)), "Dry run:")],
            ["notes"] = [new("list_notes", "an address filter that names its scope", A(("anchor", native + "@First")), "Note:")],
            ["engine"] = [new("get_engine_status", "a cancel with nothing running", A(("image", native), ("cancel", true)), "Next:")],
            ["android"] = [new("list_jni_bindings", "a package without native libraries", A(("path", apk)), "Note:")],
            ["dumps"] = [new("bucket_minidumps", "a folder capped below its dump count", A(("folder", dumps), ("maxDumps", 1)), "Note:")],
            ["live"] = [new("inspect_process", "a capped list of modules", A(("process", Environment.ProcessId.ToString()), ("view", "modules"), ("limit", 1)), "[More:")],
            ["web"] = [new("analyze_js", "a view that names what it did not find", A(("path", McpProtocolTests.JsSample(dir)), ("view", "react")), "Note:")],
        };
        foreach (var family in NotReachable.Keys) cases.Remove(family);
        return cases;
    }
}
