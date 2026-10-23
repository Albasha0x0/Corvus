using System.Text.RegularExpressions;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Runs when programs for the target can be observed here and every variable is set (to a path that exists, or to 1),
/// checked when a test runs.
/// </summary>
[Xunit.Sdk.XunitTestCaseDiscoverer(RunTimeSkips.FactDiscoverer, RunTimeSkips.Assembly)]
public sealed class LiveRealDataFactAttribute(string target, params string[] variables) : FactAttribute, IRunTimeSkip
{
    public string? RunTimeSkip() => LiveTarget.Of(target).Missing
        ?? variables.Where(v => RealData.Get(v) is not { } value || value != "1" && !Path.Exists(value)).Select(v => $"Set {v} to run this real-data session test.").FirstOrDefault();
}

/// <summary>
/// A session stopped in managed code compiled ahead of time names its frames through the loaded image's code index:
/// an Il2Cpp game (CORVUS_IL2CPP_GAME) after apply_il2cpp_names, and a NativeAOT program (CORVUS_NATIVEAOT_SAMPLES=1)
/// without its PDB.
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
[Permit("live")]
public sealed class LiveCompiledNamesRealTests(ITestOutputHelper output) : LiveToolCalls(output), IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [LiveRealDataFact("win-x64", "CORVUS_IL2CPP_GAME")]
    public async Task Il2Cpp_game_frames_are_named()
    {
        var files = Il2CppGameFiles.Find(RealData.Path("CORVUS_IL2CPP_GAME")) ?? throw new InvalidOperationException("not an Il2Cpp game");
        var folder = Path.GetDirectoryName(files.Binary)!;
        var exe = Directory.EnumerateFiles(folder, "*.exe").Single(f => !Path.GetFileName(f).StartsWith("UnityCrashHandler", StringComparison.OrdinalIgnoreCase));
        await using var server = await Server();
        await Ok(server, "load_assembly", new() { ["path"] = folder }, log: false);
        await Ok(server, "apply_il2cpp_names", new() { ["image"] = Path.GetFileName(files.Binary) });
        // a game's per-frame method, by the layer's C identifier ("Ns.Type::Update()" as "Ns_Type__Update")
        var update = await Ok(server, "search_symbols", new() { ["query"] = "::Update()", ["assembly"] = "Assembly-CSharp", ["kind"] = "method", ["limit"] = 1 });
        var method = Regex.Match(update, @"method\s+(\S+)::Update\(\)").Groups[1].Value;
        Assert.NotEmpty(method);
        var function = Regex.Replace(method, "[^A-Za-z0-9]+", "_") + "__Update";
        var pid = await Spawn(server, exe, "live-1", "-batchmode", "-nographics", "-logFile", _dir.File("player.log"));
        try
        {
            await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = $"GameAssembly.dll!{function}" });
            var stop = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 120 });
            Assert.Matches($@"#0 0x[0-9A-F]+ GameAssembly\.dll!{function}\b", stop);
        }
        finally
        {
            await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        }
        Ended(pid);
        // The player's crash handler, a process of its own, can hold the log a while after the game ends.
        for (var clock = System.Diagnostics.Stopwatch.StartNew(); clock.Elapsed < TimeSpan.FromMinutes(1); await Task.Delay(200))
        {
            try
            {
                using (new FileStream(_dir.File("player.log"), FileMode.Open, FileAccess.Read, FileShare.None)) break;
            }
            catch (FileNotFoundException) { break; }
            catch (IOException) { }
        }
    }

    [LiveRealDataFact("win-x64", NativeAotSampleTests.Variable)]
    public async Task NativeAot_program_frames_are_named()
    {
        File.Copy(Path.Combine(AppContext.BaseDirectory, "NativeAotSample", "Program.cs"), _dir.File("Program.cs"));
        File.WriteAllText(_dir.File("Directory.Build.props"), "<Project />");
        File.WriteAllText(_dir.File("Directory.Build.targets"), "<Project />");
        File.WriteAllText(_dir.File("app.csproj"), """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <OutputType>Exe</OutputType>
                <TargetFramework>net10.0</TargetFramework>
                <PublishAot>true</PublishAot>
                <InvariantGlobalization>true</InvariantGlobalization>
                <NoWarn>$(NoWarn);IL2026;IL2075;IL2072;IL3050</NoWarn>
              </PropertyGroup>
            </Project>
            """);
        // no PDB at all: a deterministic build's PDB could still be found in a symbol cache by its signature
        var (code, log) = Tools.Dotnet(_dir.Path, "publish", "app.csproj", "-c", "Release", "-r", "win-x64", "-o", "out", "-nologo", "-p:DebugType=none", "-p:DebugSymbols=false");
        Assert.True(code == 0, log);
        var exe = _dir.File(Path.Combine("out", "app.exe"));
        Assert.False(File.Exists(Path.ChangeExtension(exe, ".pdb")));
        await using var server = await Server();
        await Ok(server, "load_assembly", new() { ["path"] = exe });
        await Ok(server, "list_functions", new() { ["image"] = "app.exe", ["filter"] = "Sample_Zoo", ["limit"] = 20 });
        var pid = await Spawn(server, exe, "live-1");
        try
        {
            await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "Sample_Zoo_Program__Compute" });
            var stop = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 });
            Assert.Matches(@"#0 0x[0-9A-F]+ app\.exe!Sample_Zoo_Program__Compute\b", stop);
        }
        finally
        {
            await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        }
        Ended(pid);
    }
}
