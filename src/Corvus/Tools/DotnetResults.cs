using System.ComponentModel;

namespace Corvus.Tools;

// Records of the dotnet read tools (browse, decompile, search, navigate, resources, ReadyToRun).

/// <summary>export_project's outcome (S4.2).</summary>
public sealed record ExportOutcome(
    [property: Description("The export completed and is in outputDirectory.")] bool Applied,
    string OutputDirectory,
    [property: Description("Files written.")] int Files,
    [property: Description(".csproj, or the Gradle build file of a package.")] string? ProjectFile,
    [property: Description("Types the decompiler failed on; their files hold the error.")] IReadOnlyList<string> FailedTypes)
{
    [Description("A previous export in the directory was replaced (overwrite=true).")] public bool Replaced { get; init; }
    [Description("Packages: what the sources are and other notes.")] public IReadOnlyList<string>? Notes { get; init; }
}
