using System.Collections.Concurrent;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace NetDecompilerMcp.Tests;

/// <summary>C# fixtures compiled against the running platform's libraries: references are read once per test run.</summary>
internal static class Roslyn
{
    private static readonly Lazy<MetadataReference[]> Platform = new(() =>
        ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Where(p => p.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            .Select(p => (MetadataReference)MetadataReference.CreateFromFile(p)).ToArray());

    private static readonly ConcurrentDictionary<(string Name, string Source), Lazy<byte[]>> Releases = new();

    public static IReadOnlyList<MetadataReference> PlatformReferences => Platform.Value;

    /// <summary>A release build of <paramref name="source"/>; the same name and source compile once per test run.</summary>
    public static byte[] Release(string name, string source) =>
        Releases.GetOrAdd((name, source), k => new Lazy<byte[]>(() => Compile(k.Name, k.Source,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, optimizationLevel: OptimizationLevel.Release)))).Value.ToArray();

    public static byte[] Compile(string name, string source, CSharpCompilationOptions options, IEnumerable<MetadataReference>? extra = null)
    {
        var compilation = CSharpCompilation.Create(name, [CSharpSyntaxTree.ParseText(source)], [.. PlatformReferences, .. extra ?? []], options);
        using var ms = new MemoryStream();
        var result = compilation.Emit(ms);
        Assert.True(result.Success, string.Join("\n", result.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error)));
        return ms.ToArray();
    }
}
