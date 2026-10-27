using System.Globalization;
using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary>Where each external tool is found, for test.ps1's family keys (<c>dotnet exec Corvus.Tests.dll --located-tools</c>).</summary>
internal static class LocatedTools
{
    public const string Flag = "--located-tools";

    /// <summary>One line per tool: <c>tool id=path @size ticks</c>, or <c>tool id=</c> when it is not found.</summary>
    public static IEnumerable<string> Lines(IEnumerable<ExternalTool> tools, Func<ExternalTool, string?> locate)
    {
        foreach (var tool in tools)
        {
            var path = locate(tool);
            var file = path == null ? null : new FileInfo(path);
            yield return file is { Exists: true }
                ? string.Create(CultureInfo.InvariantCulture, $"tool {tool.Id}={path} @{file.Length} {file.LastWriteTimeUtc.Ticks}")
                : $"tool {tool.Id}=";
        }
    }

    /// <summary>Prints <see cref="Lines"/> for <see cref="ExternalTools.Table"/>; exit code 0.</summary>
    public static int Main()
    {
        foreach (var line in Lines(ExternalTools.Table, t => ExternalTools.Locate(t)?.Path)) Console.WriteLine(line);
        return 0;
    }
}
