using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>A stopped emulator run resumes in a new server process on the same data folder.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class RestartStateEmulationTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        EmulationRuns.ResetFolder();
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private NativeEmulationTools Start(string image)
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var engines = new NativeEngineService(Array.Empty<INativeDecompilerProvider>(), _dir.File("cache"));
        _owned.Add(engines);
        _owned.Add(workspace);
        workspace.LoadAny(image);
        return new NativeEmulationTools(workspace, engines, new NativeCodeService(workspace, options));
    }

    private static string Line(string text, string prefix) => text.Split('\n').First(l => l.StartsWith(prefix, StringComparison.Ordinal));

    // The second process never repeats the start.
    [Fact]
    public async Task A_stopped_emulation_resumes_in_a_new_process_to_the_result_of_an_uninterrupted_run()
    {
        EmulationRuns.Folder = _dir.File("stopped");
        var image = NativeEmulationGhidraTests.Build(_dir, []);
        var input = $"\"{new string('a', 30_000)}\"";
        var first = Start(image);
        var whole = await first.EmulateNative("emu.dll", "Fnv1a", args: input, engine: "ours");
        var cut = await first.EmulateNative("emu.dll", "Fnv1a", args: input, maxInstructions: 50_000, engine: "ours");
        var id = System.Text.RegularExpressions.Regex.Match(cut, "resume=(emu-[0-9a-f]+)").Groups[1].Value;
        Assert.NotEmpty(id);

        EmulationRuns.ReleaseHeld();
        var resumed = await Start(image).EmulateNative("emu.dll", "Fnv1a", resume: id);
        Assert.Contains("Stopped: returned to the caller", resumed);
        Assert.Equal(Line(whole, "Return value:"), Line(resumed, "Return value:"));
        Assert.Equal(whole[..whole.IndexOf('\n')], resumed[..resumed.IndexOf('\n')]);
    }
}
