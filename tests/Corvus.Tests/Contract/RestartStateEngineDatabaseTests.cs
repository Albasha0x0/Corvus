using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>The engine script, reanalysis and database export tools act on a database file that a second server process reads again.</summary>
public sealed partial class RestartStateEngineDatabaseTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [GeneratedRegex(@"\b\d+(\.\d+)? ?(ms|s)\b|""elapsedMs"":\d+")]
    private static partial Regex Timing();

    /// <summary>One server process on shared annotation, cache and engine database folders; disposing it ends its sessions.</summary>
    private sealed class Process : IDisposable
    {
        private readonly AssemblyWorkspace _workspace;
        public NativeEngineService Engines { get; }
        public LoadedNative Native { get; }
        public EngineScriptTools Scripts { get; }
        public NativeEngineControlTools Control { get; }
        public NativeAnalysisTools Decompile { get; }
        public NativeTypeTools Types { get; }
        public EngineExportTools Export { get; }

        public static Process Start(TempDir dir) => new(dir);

        private Process(TempDir dir)
        {
            var options = new ServerOptions { BackgroundIndexing = false, IdaScripting = true, GhidraScripting = true };
            _workspace = new AssemblyWorkspace(options);
            var code = new NativeCodeService(_workspace, options, null, new AnnotationStore(dir.File("annotations")));
            var database = new AnalysisCache(dir.File("engine-databases"));
            var engines = new[]
            {
                new ScriptedEngine { Id = IdaProvider.ProviderId, Cache = database },
                new ScriptedEngine { Id = GhidraProvider.ProviderId, Cache = database },
            };
            foreach (var e in engines)
            {
                e.Add(0x1000, "target", "int target(void)", "{ return 1; }");
                e.Add(0x1040, "caller", "int caller(void)", "{ return target(); }");
                e.Analyzers.Add(new("AF_FLIRT", "bool", "true", "use flirt signatures"));
            }
            Engines = new NativeEngineService(engines, dir.File("cache"), code, _workspace, options);
            Native = _workspace.LoadAny(McpProtocolTests.NativeSample(dir)).Native!;
            code.Index(Native, null, default).GetAwaiter().GetResult();
            var pager = new OutputPager(options);
            var names = new NativeNamePush(code);
            Scripts = new EngineScriptTools(_workspace, Engines, options, code, names);
            Control = new NativeEngineControlTools(_workspace, Engines, code);
            Decompile = new NativeAnalysisTools(_workspace, Engines, pager, names);
            Types = new NativeTypeTools(_workspace, Engines, new NativeUserTypePush(code), code);
            Export = new EngineExportTools(_workspace, Engines, code, names);
        }

        public void Dispose()
        {
            Engines.Dispose();
            _workspace.Dispose();
        }

        /// <summary>Waits for the image's background job to end.</summary>
        public Task Ended() => ((IBackgroundJobs)Engines.OpenSession(Native)!).Jobs.Job?.Task.WaitAsync(TimeSpan.FromSeconds(30)) ?? Task.CompletedTask;
    }

    private static async Task<Dictionary<string, string>> Reads(Process p) => new(StringComparer.Ordinal)
    {
        ["decompile_native"] = Timing().Replace(await p.Decompile.DecompileNative(p.Native.Id, "rva:0x1000", engine: "ida"), "~"),
        ["decompile_native ghidra"] = Timing().Replace(await p.Decompile.DecompileNative(p.Native.Id, "rva:0x1040", engine: "ghidra"), "~"),
        ["list_native_types"] = Timing().Replace(await p.Types.ListNativeTypes(p.Native.Id, filter: "Packet", engine: "ida"), "~"),
        ["list_native_types ghidra"] = Timing().Replace(await p.Types.ListNativeTypes(p.Native.Id, filter: "Frame", engine: "ghidra"), "~"),
        ["reanalyze_native analyzers"] = Timing().Replace(await p.Control.ReanalyzeNative(p.Native.Id, engine: "ida", analyzers: true), "~"),
    };

    // The second process runs no script and no reanalysis.
    [Fact]
    public async Task Script_reanalysis_and_export_effects_are_read_again_from_the_engine_database_after_a_restart()
    {
        Dictionary<string, string> first;
        byte[] exported;
        using (var a = Process.Start(_dir))
        {
            await a.Scripts.IdaPython(a.Native.Id, "name 0x1000 ScriptedName\ncomment 0x1000 kept note\ntype Packet struct 16 3", engine: "ida");
            await a.Scripts.GhidraScript(a.Native.Id, "name 0x1040 ScriptedCaller\ncomment 0x1040 ghidra note\ntype Frame struct 8 2", engine: "ghidra");
            await a.Control.ReanalyzeNative(a.Native.Id, engine: "ida", options: ["AF_FLIRT=false"]);
            await a.Ended();
            first = await Reads(a);
            await a.Export.ExportEngineDatabase(a.Native.Id, _dir.File("first.i64"), engine: "ida");
            exported = await File.ReadAllBytesAsync(_dir.File("first.i64"));
        }

        using var b = Process.Start(_dir);
        var second = await Reads(b);
        var differing = first.Where(p => p.Value != second[p.Key]).Select(p => p.Key).ToList();
        Assert.True(differing.Count == 0, "answers differ after a restart: "
            + string.Join("; ", differing.Select(t => $"{t}: [{first[t]}] vs [{second[t]}]")));
        Assert.Contains("ScriptedName", second["decompile_native"]);
        Assert.Contains("kept note", second["decompile_native"]);
        Assert.Contains("ScriptedCaller", second["decompile_native ghidra"]);
        Assert.Contains("ghidra note", second["decompile_native ghidra"]);
        Assert.Contains("Packet", second["list_native_types"]);
        Assert.Contains("Frame", second["list_native_types ghidra"]);
        Assert.Contains("AF_FLIRT = false", second["reanalyze_native analyzers"]);
        Assert.All(first, p => Assert.False(string.IsNullOrWhiteSpace(p.Value), p.Key));

        await b.Export.ExportEngineDatabase(b.Native.Id, _dir.File("second.i64"), engine: "ida");
        Assert.Equal(exported, await File.ReadAllBytesAsync(_dir.File("second.i64")));
    }
}
