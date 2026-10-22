using System.Runtime.InteropServices;
using System.Text.Json;

namespace Corvus.Tests;

/// <summary>
/// The YARA-X builds the tests use: the folder fetch-yara-x.ps1 fills (CORVUS_TEST_YARA_X), holding the C library and the
/// <c>yr</c> reference command line where upstream publishes them for this platform (yara-x-assets.json).
/// </summary>
internal static class YaraTestTools
{
    public const string Variable = "CORVUS_TEST_YARA_X";

    private static string? Folder => Environment.GetEnvironmentVariable(Variable) is { Length: > 0 } folder && Directory.Exists(folder) ? folder : null;

    /// <summary>The C library, or null.</summary>
    public static string? Library => Find("library");

    /// <summary>The yr command line, or null.</summary>
    public static string? Cli => Find("cli");

    private static string? Find(string part) =>
        Folder is { } folder && Member(part) is { } member && File.Exists(Path.Combine(folder, member)) ? Path.Combine(folder, member) : null;

    /// <summary>The file the asset table lists for <paramref name="part"/> on this platform, or null when upstream publishes none.</summary>
    private static string? Member(string part)
    {
        using var table = JsonDocument.Parse(File.ReadAllText(Path.Combine(DocsTests.RepoRoot(), "tests", "Corvus.Tests", "Support", "yara-x-assets.json")));
        foreach (var asset in table.RootElement.GetProperty("assets").EnumerateArray())
            if (asset.GetProperty("rid").GetString() == RuntimeInformation.RuntimeIdentifier && asset.GetProperty("part").GetString() == part)
                return asset.GetProperty("member").GetString();
        return null;
    }

    /// <summary>Why a test that needs <paramref name="part"/> cannot run here, or null when it can.</summary>
    public static string? Missing(string part)
    {
        if (Folder == null) return $"Set {Variable} to a folder filled by tests/Corvus.Tests/Support/fetch-yara-x.ps1 to run this test.";
        if (Member(part) == null) return $"YARA-X publishes no {part} build for {RuntimeInformation.RuntimeIdentifier}; release packaging builds it.";
        return Find(part) == null ? $"{Variable} holds no YARA-X {part}; run fetch-yara-x.ps1 into it." : null;
    }
}

/// <summary>A fact that needs the YARA-X library, and with <c>cli: true</c> the yr command line too.</summary>
public sealed class YaraFactAttribute : FactAttribute
{
    public YaraFactAttribute(bool cli = false)
    {
        Skip = YaraTestTools.Missing("library") ?? (cli ? YaraTestTools.Missing("cli") : null);
    }
}
