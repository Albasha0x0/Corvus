using System.Diagnostics;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Corvus.Native.Dump.Managed;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>
/// The .NET heap of a real Linux core: a program compiled here runs in WSL under the .NET runtime installed there and
/// crashes, the runtime's own dump writer writes an ELF core with the heap, and dump_heap reads it with the
/// Windows-hosted DAC for Linux targets downloaded from Microsoft's symbol server (CORVUS_NETWORK_TESTS=1).
/// </summary>
[Trait("Speed", "Slow")]
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class ElfCoreHeapRealTests
{
    private const int Items = 1234;

    private const string Source = """
        using System;
        using System.Collections.Generic;

        namespace Probe;

        public sealed class Item
        {
            public int Id;
            public string Label = "";
        }

        public static class Program
        {
            public static readonly List<Item> Kept = new();

            public static void Main()
            {
                for (int i = 0; i < 1234; i++) Kept.Add(new Item { Id = i, Label = "item-" + i });
                throw new InvalidOperationException("sample-core");
            }
        }
        """;

    /// <summary>Runs <paramref name="script"/> with sh in the default WSL distribution.</summary>
    private static (int Code, string Output) Wsl(string script, int timeoutMs = 120_000)
    {
        var psi = new ProcessStartInfo("wsl.exe") { UseShellExecute = false, RedirectStandardError = true, RedirectStandardOutput = true, CreateNoWindow = true };
        foreach (var a in new[] { "-e", "sh", "-c", script }) psi.ArgumentList.Add(a);
        return Tools.Run(psi, timeoutMs);
    }

    private static string Quote(string s) => "'" + s.Replace("'", "'\\''", StringComparison.Ordinal) + "'";

    [OptInFact("CORVUS_NETWORK_TESTS")]
    public async Task DumpHeapReadsTheHeapOfALinuxCore()
    {
        if (!OperatingSystem.IsWindows() || !File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "wsl.exe"))) return;
        // the runtime of the test's own major version installed in WSL: its dotnet and its folder
        var (found, listing) = Wsl($"d=$(command -v dotnet || echo $HOME/.dotnet/dotnet); [ -x \"$d\" ] && $d --list-runtimes | grep '^Microsoft.NETCore.App {Environment.Version.Major}\\.' | tail -1 && echo $d");
        var lines = listing.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (found != 0 || lines.Length < 2) return;
        var parts = lines[^2].Split(' ', 3);
        string version = parts[1], folder = parts[2].Trim('[', ']') + "/" + version, dotnet = lines[^1];

        using var dir = new TempDir();
        File.WriteAllBytes(dir.File("Probe.dll"), Roslyn.Compile("Probe", Source, new CSharpCompilationOptions(OutputKind.ConsoleApplication)));
        File.WriteAllText(dir.File("Probe.runtimeconfig.json"), System.Text.Json.JsonSerializer.Serialize(new
        {
            runtimeOptions = new { tfm = $"net{Environment.Version.Major}.0", framework = new { name = "Microsoft.NETCore.App", version } },
        }));
        var (_, mounted) = Wsl($"wslpath -a {Quote(dir.Path.Replace('\\', '/'))}");
        var here = mounted.Trim();
        // type 2: a dump with the heap; libcoreclr.so is copied beside it under its own path for the version check
        var (code, log) = Wsl($"cd {Quote(here)} && DOTNET_DbgEnableMiniDump=1 DOTNET_DbgMiniDumpType=2 DOTNET_DbgMiniDumpName={Quote(here + "/probe.core")} {Quote(dotnet)} Probe.dll; " +
                              $"mkdir -p libs && cp --parents {Quote(folder + "/libcoreclr.so")} libs/");
        var core = dir.File("probe.core");
        Assert.True(File.Exists(core), $"no core written (exit {code}): {log}");

        using var service = new MinidumpService();
        var summary = await service.Summarize(core, dir.File("libs"), new DacRequest(Download: true), CancellationToken.None);
        Assert.True(summary.Managed?.Dac.Status == "loaded", summary.Managed?.Dac.Detail);
        Assert.Equal("System.InvalidOperationException", summary.Managed!.Exception?.Type);
        var heap = await service.Heap(core, "stats", "Probe.Item", 0, 0, 10, 10_000_000, CancellationToken.None);
        var row = Assert.Single(heap.Items);
        Assert.Equal(Items, row.Count);
        var objects = await service.Heap(core, "objects", "Probe.Item", 0, 0, 1, 10_000_000, CancellationToken.None);
        var item = await service.Object(core, objects.Items[0].Address!, 1, 10, 0, CancellationToken.None);
        Assert.Equal("Probe.Item", item.Type);
        Assert.StartsWith("\"item-", item.Fields.Single(f => f.Path == "Label").Value);
    }
}
