using System.Diagnostics;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// A database open in IDA, served by corvus_connect.py: idat loads a copy of a system DLL with
/// -S"corvus_connect.py once", serves one session, then exits.
/// </summary>
[Trait("Speed", "Slow")]
public sealed class IdaConnectedEngineTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    [IdaFact]
    public async Task A_rename_through_a_connected_session_reaches_the_database_IDA_has_open()
    {
        var image = Path.Combine(_dir.Path, "served.dll");
        File.Copy(NativeIdaProviderTests.System64, image);
        var script = Corvus.Setup.ToolCli.WriteIdaScripts(Path.Combine(_dir.Path, "scripts"));
        var usr = Path.Combine(_dir.Path, "usr");
        Directory.CreateDirectory(usr);
        var ida = IdaInstallation.Locate(null, out _, out _)!;
        var start = new ProcessStartInfo(Path.Combine(ida.Directory, OperatingSystem.IsWindows() ? "idat.exe" : "idat"))
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = _dir.Path,
        };
        start.ArgumentList.Add("-A");
        start.ArgumentList.Add("-c");
        start.ArgumentList.Add($"-S\"{script}\" once");
        start.ArgumentList.Add($"-L{Path.Combine(_dir.Path, "ida.log")}");
        start.ArgumentList.Add(image);
        // The serving IDA writes its connection file under IDAUSR; TVHEADLESS keeps idat off the console.
        start.Environment["IDAUSR"] = usr;
        start.Environment["TVHEADLESS"] = "1";
        using var idat = Process.Start(start)!;
        _ = idat.StandardOutput.ReadToEndAsync();
        _ = idat.StandardError.ReadToEndAsync();
        try
        {
            var folder = Path.Combine(usr, "corvus");
            var clock = Stopwatch.StartNew();
            while (IdaConnection.List(folder).Count == 0)
            {
                Assert.False(idat.HasExited, $"idat exited with {(idat.HasExited ? idat.ExitCode : 0)} before serving: {Log()}");
                Assert.True(clock.Elapsed < TimeSpan.FromMinutes(5), "idat did not serve the database within 5 min: " + Log());
                await Task.Delay(250);
            }
            output.WriteLine($"served after {clock.Elapsed.TotalSeconds:0.0} s");

            using var provider = new IdaProvider(new IdaProviderOptions { CacheRoot = Path.Combine(_dir.Path, "cache"), Connect = true, ConnectFolder = folder });
            await using (var session = (IdaSession)await provider.OpenAsync(image, null, new NativeOpenOptions { Symbols = SymbolMode.Off }))
            {
                Assert.Equal(idat.Id, session.ConnectedPid);
                var function = (await session.ListFunctionsAsync()).First(f => !f.Name.StartsWith("sub_", StringComparison.Ordinal));
                await session.ApplyNamesAsync([new NativeNameItem(function.StartRva, "renamed_in_open_database", null)]);
                var read = await session.RunScriptAsync($"import ida_name, ida_nalt\nida_name.get_name(ida_nalt.get_imagebase() + {function.StartRva})");
                Assert.Equal("renamed_in_open_database", read.Result?.Trim('\'', '"'));
            }
            // The once mode closes IDA after its client detaches; a session never closes it.
            Assert.True(idat.WaitForExit(TimeSpan.FromMinutes(2)), "idat kept running after the session detached");
            Assert.Empty(IdaConnection.List(folder));
        }
        finally
        {
            if (!idat.HasExited) idat.Kill();
        }
    }

    private string Log()
    {
        var path = Path.Combine(_dir.Path, "ida.log");
        try { return File.Exists(path) ? File.ReadAllText(path)[^Math.Min(4000, (int)new FileInfo(path).Length)..] : "(no log)"; }
        catch (IOException) { return "(log unreadable)"; }
    }

    public void Dispose() => _dir.Dispose();
}
