using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Live;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>The private Frida environment (--live-install-frida) with a scripted process runner, and the order sessions choose an interpreter in.</summary>
public sealed class FridaEnvironmentTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<(string Exe, string[] Args)> _runs = [];

    public void Dispose() => _dir.Dispose();

    private static readonly PythonInterpreter Base = new("/py/base", new Version(3, 12), 64, "PATH");

    /// <summary>
    /// A runner where venv creates the interpreter file, pip exits with <paramref name="pipExit"/>, and the base pip
    /// reports <paramref name="basePip"/> (null: no pip).
    /// </summary>
    private FridaEnvironment Scripted(int pipExit = 0, bool offline = false, string platform = "windows-x64", string? basePip = null) => new(_dir.File("env"))
    {
        Offline = offline,
        Platform = platform,
        Run = (exe, args, _) =>
        {
            _runs.Add((exe, [.. args]));
            if (args.Contains("--version"))
                return basePip == null ? new(1, "", "No module named pip", false, null) : new(0, $"pip {basePip} from /py/lib/pip (python 3.12)", "", false, null);
            if (args.Contains("venv"))
            {
                var python = OperatingSystem.IsWindows() ? Path.Combine(args[^1], "Scripts", "python.exe") : Path.Combine(args[^1], "bin", "python3");
                Directory.CreateDirectory(Path.GetDirectoryName(python)!);
                File.WriteAllText(python, "");
                return new(0, "", "", false, null);
            }
            return new(pipExit, "", pipExit == 0 ? "" : "ERROR: THESE PACKAGES DO NOT MATCH THE HASHES", false, null);
        },
    };

    [Fact]
    public void Offline_refuses_the_download_and_runs_nothing()
    {
        var env = Scripted(offline: true);
        Assert.Null(env.Create(Base, out var problem));
        Assert.Contains("CORVUS_OFFLINE", problem);
        Assert.Empty(_runs);
        Assert.False(env.Complete);
    }

    [Fact]
    public void Each_platform_pins_its_own_wheel_hashes()
    {
        foreach (var (platform, hashes) in FridaVersions.WheelHashes)
        {
            var list = FridaVersions.Requirements(platform)!;
            Assert.StartsWith($"frida=={FridaVersions.Pinned} ", list);
            Assert.All(hashes, h => Assert.Contains("--hash=sha256:" + h, list));
            // no other platform's wheel is accepted
            Assert.All(FridaVersions.WheelHashes.Where(o => o.Key != platform).SelectMany(o => o.Value), h => Assert.DoesNotContain(h, list));
            Assert.Contains("typing_extensions==", list);
        }
        Assert.Equal("windows-x64", FridaVersions.Platform(true, false, System.Runtime.InteropServices.Architecture.X64));
        Assert.Equal("linux-arm64", FridaVersions.Platform(false, true, System.Runtime.InteropServices.Architecture.Arm64));
        Assert.Null(FridaVersions.Requirements("windows-x86"));
        Assert.Null(Scripted(platform: "windows-x86").Create(Base, out var problem));
        Assert.Contains("windows-x86", problem);
        Assert.Empty(_runs);
    }

    [Fact]
    public void Venv_then_hash_checked_pip_then_the_marker_and_a_failed_install_is_made_again()
    {
        var failed = Scripted(pipExit: 1);
        Assert.Null(failed.Create(Base, out var problem));
        Assert.Contains("DO NOT MATCH THE HASHES", problem);
        Assert.False(failed.Complete);
        _runs.Clear();

        // Without a base pip the venv gets its own (ensurepip), which installs.
        var env = Scripted();
        Assert.Equal(env.Python, env.Create(Base, out problem));
        Assert.Null(problem);
        Assert.Equal([Base.Executable, Base.Executable, env.Python], _runs.Select(r => r.Exe));
        Assert.Equal(["-I", "-m", "venv", env.Folder], _runs[1].Args);
        Assert.Contains("--require-hashes", _runs[2].Args);
        Assert.Contains(":all:", _runs[2].Args);
        Assert.Equal(FridaVersions.Requirements("windows-x64"), File.ReadAllText(_runs[2].Args[^1]));
        Assert.True(env.Complete);
        _runs.Clear();
        Assert.Equal(env.Python, env.Create(Base, out _));
        Assert.Empty(_runs);
    }

    [Fact]
    public void A_base_pip_that_takes_python_installs_into_a_venv_made_without_pip()
    {
        var env = Scripted(basePip: "22.3.1");
        Assert.Equal(env.Python, env.Create(Base, out var problem));
        Assert.Null(problem);
        Assert.Equal([Base.Executable, Base.Executable, Base.Executable], _runs.Select(r => r.Exe));
        Assert.Equal(["-I", "-m", "venv", "--without-pip", env.Folder], _runs[1].Args);
        Assert.Equal(["-I", "-m", "pip", "--python", env.Python, "install"], _runs[2].Args[..6]);
        Assert.Contains("--require-hashes", _runs[2].Args);
        Assert.True(env.Complete);
    }

    [Fact]
    public void A_base_pip_older_than_22_3_leaves_the_install_to_the_venv_pip()
    {
        var env = Scripted(basePip: "22.2");
        Assert.Equal(env.Python, env.Create(Base, out _));
        Assert.Equal(["-I", "-m", "venv", env.Folder], _runs[1].Args);
        Assert.Equal(env.Python, _runs[2].Exe);
    }

    private static PythonInterpreter Py(string source) => new("/py/" + source, new Version(3, 12), 64, source);

    [Fact]
    public void Interpreters_are_chosen_in_order()
    {
        var untested = (Py("py -3"), (string?)"16.7.19");
        var tested = (Py("PATH"), (string?)FridaVersions.Pinned);
        var none = (Py("PATH"), (string?)null);
        var variable = (Py(FridaBackend.PythonVariable), (string?)"16.7.19");
        var made = (Py(FridaEnvironment.Source), FridaVersions.Pinned);

        // CORVUS_FRIDA_PYTHON wins, even over the private environment and on an untested Frida
        Assert.Equal(FridaBackend.PythonVariable, FridaBackend.Choose([variable, tested], install: true, made).Python!.Source);
        // the private environment, once made, before a user Python with a tested Frida
        Assert.Equal(FridaEnvironment.Source, FridaBackend.Choose([tested], install: true, made).Python!.Source);
        Assert.Equal(FridaEnvironment.Source, FridaBackend.Choose([], install: true, made).Python!.Source);
        // without the switch the private environment is not used
        Assert.Equal("PATH", FridaBackend.Choose([tested], install: false, made).Python!.Source);
        // a tested Frida after an untested one
        Assert.Equal("PATH", FridaBackend.Choose([untested, none, tested], install: false, null).Python!.Source);
        // no tested Frida: the switch makes the private environment, else the untested Frida is used
        Assert.Equal((null, true), FridaBackend.Choose([untested, none], install: true, null) is var c ? (c.Python, c.CreatePrivate) : default);
        Assert.Equal("py -3", FridaBackend.Choose([untested, none], install: false, null).Python!.Source);
        Assert.Equal((null, false), FridaBackend.Choose([none], install: false, null) is var d ? (d.Python, d.CreatePrivate) : default);
    }
}

/// <summary>Runs where Frida sessions can (see <see cref="FridaFactAttribute"/>) and pypi.org answers, checked when a test runs.</summary>
[Xunit.Sdk.XunitTestCaseDiscoverer(RunTimeSkips.FactDiscoverer, RunTimeSkips.Assembly)]
public sealed class FridaDownloadFactAttribute : FactAttribute, IRunTimeSkip
{
    private static readonly Lazy<string?> Missing = new(() =>
    {
        if (Environment.GetEnvironmentVariable("CORVUS_ALL_TESTS") != "1") return "Downloads Frida (set CORVUS_ALL_TESTS=1).";
        if (FridaEnvironmentRealTests.Host.Missing is { } missing) return missing;
        if (PythonLocator.Find([], []) == null) return "No 64-bit Python 3.";
        try
        {
            using var tcp = new TcpClient();
            if (!tcp.ConnectAsync("pypi.org", 443).Wait(TimeSpan.FromSeconds(5))) return "pypi.org did not answer (offline).";
        }
        catch (Exception e) { return "pypi.org is unreachable (offline): " + e.GetBaseException().Message; }
        return null;
    });

    public string? RunTimeSkip() => Missing.Value;
}

/// <summary>The private environment made from the network in a test folder, and a session opened on its Frida.</summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
public sealed class FridaEnvironmentRealTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    /// <summary>The target of this machine's own operating system and architecture, which builds the fixture.</summary>
    internal static LiveTarget Host { get; } =
        OperatingSystem.IsMacOS() ? LiveTarget.MacArm64
        : RuntimeInformation.OSArchitecture == Architecture.Arm64 ? (OperatingSystem.IsWindows() ? LiveTarget.WinArm64 : LiveTarget.LinuxArm64)
        : OperatingSystem.IsWindows() ? LiveTarget.WinX64 : LiveTarget.LinuxX64;

    public void Dispose() => _dir.Dispose();

    [FridaDownloadFact]
    public async Task The_private_environment_is_made_and_a_session_opens_on_it()
    {
        var phases = new TestPhases(output);
        var env = new FridaEnvironment(_dir.File("frida-env"));
        var watch = Stopwatch.StartNew();
        var python = env.Create(PythonLocator.Find([], []), out var problem);
        // The problem names the failed step (venv or pip) and why, in full.
        Assert.True(problem == null, problem);
        Assert.Equal(env.Python, python);
        phases.Phase("environment made");
        var bytes = new DirectoryInfo(env.Folder).EnumerateFiles("*", SearchOption.AllDirectories).Sum(f => f.Length);
        output.WriteLine($"private environment: {watch.Elapsed.TotalSeconds:0.0} s, {bytes / 1048576.0:0.0} MB on disk");

        // CORVUS_FRIDA_PYTHON wins over the private environment (the live job sets it), so it is not read here.
        var backend = new FridaBackend { InstallPinned = true, PrivateEnvironment = env, ReadsPythonVariable = false };
        Assert.Null(backend.Unavailable());
        Assert.Equal(FridaEnvironment.Source, backend.Python!.Source);
        Assert.Equal(FridaVersions.Pinned, backend.FridaVersion);
        phases.Phase("frida found");

        var exe = Host.Build(_dir, "orders", "int main(void) { return 3; }");
        phases.Phase("program built");
        using var workspace = new AssemblyWorkspace();
        using var service = new LiveSessionService(workspace, new NativeCodeService(workspace, SharedCodeIndex.Options())) { Backend = backend };
        var session = await service.OpenAsync(spawn: true, exe, [], CancellationToken.None);
        Assert.True(session.ProcessId > 0, phases.Summary());
        phases.Phase("spawn");
        await service.CloseAsync(session, "test");
        phases.Phase("close");
    }
}
