using System.Diagnostics;
using Corvus.Core;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>A fresh workspace with the fixture assembly (and optionally the consumer assembly) loaded, plus all services.</summary>
public sealed class Env : IDisposable
{
    public static readonly string FixturePath = typeof(Fixture.Model.Account).Assembly.Location;
    public static readonly string ConsumerPath = typeof(Consumer.Branch).Assembly.Location;

    public ServerOptions Options { get; } = new() { TimeoutSeconds = 120 };
    public AssemblyWorkspace Workspace { get; }
    public OutputPager Pager { get; }
    public DecompilerService Decompiler { get; }
    public SearchService Search { get; } = new();
    public ReferenceService References { get; }
    public Il2CppService Il2Cpp { get; }
    public Il2CppStringService Il2CppStrings { get; }
    public Il2CppNavigator Il2CppNavigator { get; }
    public ResourceService Resources { get; } = new();
    public AssemblyReport Report { get; }
    public EditService Edits { get; }
    public EditHistoryService History { get; }
    public LoadedAssembly Fixture { get; }

    public Env(string? path = null, bool withConsumer = false)
    {
        Workspace = new AssemblyWorkspace(Options);
        Pager = new OutputPager(Options);
        Decompiler = new DecompilerService(Workspace, Options);
        References = new ReferenceService(Workspace);
        Il2Cpp = new Il2CppService(Workspace);
        Il2CppStrings = new Il2CppStringService(Workspace, Il2Cpp);
        Il2CppNavigator = new Il2CppNavigator(Workspace, Il2Cpp, Il2CppStrings);
        Report = new AssemblyReport(Workspace, Il2Cpp);
        Edits = new EditService(Workspace, new IlAssembler(Workspace), new CSharpPatcher(Workspace, Decompiler));
        History = new EditHistoryService(Workspace, Edits, Decompiler, new AssemblyComparer(Workspace));
        Fixture = Workspace.Load(path ?? FixturePath);
        if (withConsumer)
            Workspace.Load(ConsumerPath);
    }

    public ResolvedSymbol One(string symbol, SymbolKind kind = SymbolKind.Any) => SymbolResolver.ResolveOne(Workspace, null, symbol, kind);

    public T Def<T>(string symbol, SymbolKind kind = SymbolKind.Any) where T : class => (T)One(symbol, kind).Member;

    public string Decompile(string symbol)
    {
        var s = One(symbol);
        return Decompiler.DecompileMembers(s.Assembly, [s.Member], default);
    }

    public string Edit(Func<string> edit) => Workspace.Write(edit);

    /// <summary>What a native address is (see <see cref="Il2CppNavigator.Locate"/>), across all loaded assemblies.</summary>
    public List<Il2CppNavigator.AddressResult> Locate(ulong address, string kind = "auto") =>
        Workspace.Read(() => Il2CppNavigator.Locate(address, kind, Workspace.Assemblies));

    public Corvus.Tools.Il2CppTools Il2CppTools() => new(Workspace, Il2Cpp, new Il2CppExporter(Il2Cpp), Il2CppStrings, Il2CppNavigator);

    public void Dispose() => Workspace.Dispose();
}

/// <summary>Report files that slow tests leave for reading after the run.</summary>
public static class TestReports
{
    /// <summary>%TEMP%\corvus-test-reports\&lt;name&gt;-&lt;time&gt;-&lt;pid&gt;.txt: a name per run, so concurrent runs do not write one file.</summary>
    public static string File(string name)
    {
        var dir = Directory.CreateDirectory(System.IO.Path.Combine(LeakGuard.SharedTemp, "corvus-test-reports")).FullName;
        return System.IO.Path.Combine(dir, $"{name}-{DateTime.Now:yyyyMMdd-HHmmss}-{Environment.ProcessId}.txt");
    }
}

/// <summary>Temporary directory deleted on dispose.</summary>
public sealed class TempDir : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "corvus-test-" + Guid.NewGuid().ToString("N"));

    public TempDir() => Directory.CreateDirectory(Path);

    /// <summary>A directory at <paramref name="path"/> (fixtures written beside the test binaries).</summary>
    public TempDir(string path)
    {
        Path = path;
        Directory.CreateDirectory(path);
    }

    public string File(string name) => System.IO.Path.Combine(Path, name);

    public void Dispose()
    {
        // A server just told to stop may still run in the folder (its working directory on Windows): retry briefly.
        for (var clock = System.Diagnostics.Stopwatch.StartNew(); ; Thread.Sleep(100))
        {
            try
            {
                Directory.Delete(Path, true);
                return;
            }
            catch (DirectoryNotFoundException) { return; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (clock.Elapsed > TimeSpan.FromSeconds(3)) return; // best effort; the leak guard reports what stays
            }
        }
    }
}

/// <summary>A fact that is skipped when the given path does not exist.</summary>
public sealed class RequiresPathFactAttribute : FactAttribute
{
    public RequiresPathFactAttribute(string path)
    {
        if (!System.IO.Path.Exists(path))
            Skip = $"Real-world data not present: {path}";
    }
}

/// <summary>Real-world libraries restored as NuGet packages by the test project.</summary>
public static class RealPackages
{
    /// <summary>Path of a library in the NuGet global packages folder.</summary>
    public static string Lib(string id, string version, string framework, string file) => File(id, version, "lib", framework, file);

    /// <summary>Path of any file of a package in the NuGet global packages folder.</summary>
    public static string File(string id, string version, params string[] parts)
    {
        var root = Environment.GetEnvironmentVariable("NUGET_PACKAGES") is { Length: > 0 } custom
            ? custom
            : System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nuget", "packages");
        var path = System.IO.Path.Combine([root, id.ToLowerInvariant(), version, .. parts]);
        Assert.True(System.IO.File.Exists(path), $"{path} not found: restore the test project");
        return path;
    }
}

/// <summary>Environment variables locating real-world test data; tests needing an unset variable are skipped.</summary>
public static class RealData
{
    /// <summary>A folder of real-world .NET assemblies.</summary>
    public const string AssemblyDir = "CORVUS_ASSEMBLY_DIR";
    /// <summary>An Il2CppDumper / Cpp2IL DummyDll folder.</summary>
    public const string Il2CppDummyDir = "CORVUS_IL2CPP_DUMMY_DIR";
    /// <summary>An Il2CppDumper DummyDll folder with stringliteral.json / script.json (and optionally GameAssembly.dll) beside it.</summary>
    public const string Il2CppStringsDir = "CORVUS_IL2CPP_STRINGS_DIR";
    /// <summary>Two builds of the same application (folders), and the assembly to compare between them.</summary>
    public const string CompareOldDir = "CORVUS_COMPARE_OLD_DIR";
    public const string CompareNewDir = "CORVUS_COMPARE_NEW_DIR";
    public const string CompareAssembly = "CORVUS_COMPARE_ASSEMBLY";
    /// <summary>Optional: known type moves between the two builds, "Old.Name=>New.Name;Old2=>New2".</summary>
    public const string CompareExpect = "CORVUS_COMPARE_EXPECT";
    /// <summary>Optional: a method to search call paths to (default: picked automatically).</summary>
    public const string CallPathTarget = "CORVUS_CALLPATH_TARGET";
    /// <summary>Root of a C/C++ project with a host function table (generate_cpp_binding style=hostapi detection).</summary>
    public const string HostApiProjectDir = "CORVUS_HOSTAPI_PROJECT_DIR";
    /// <summary>A real Android package (.apk, .aab or split set).</summary>
    public const string AndroidPackage = "CORVUS_ANDROID_PACKAGE";
    /// <summary>A large native image (100 MB or more) for speed measurements.</summary>
    public const string LargeNativeImage = "CORVUS_LARGE_NATIVE_IMAGE";

    /// <summary>A folder of installed Electron apps; every .asar below it (six levels) is listed and summarized.</summary>
    public const string ElectronApps = "CORVUS_ELECTRON_APPS";

    /// <summary>A folder of Linux or Android ELF core files (with the program's libraries beside them).</summary>
    public const string ElfCores = "CORVUS_ELF_CORES";

    public static string? Get(string variable) => Environment.GetEnvironmentVariable(variable) is { Length: > 0 } v ? v : null;

    public static string Path(string variable) => Get(variable) ?? throw new InvalidOperationException($"{variable} is not set");

    /// <summary>Assemblies that are not the framework or the engine: the application's own code.</summary>
    public static bool IsAppAssembly(LoadedAssembly a) =>
        !new[] { "System", "Microsoft.", "mscorlib", "netstandard", "Mono.", "UnityEngine", "Unity.", "Newtonsoft." }
            .Any(p => a.AssemblyName.StartsWith(p, StringComparison.OrdinalIgnoreCase));
}

/// <summary>A fact that only runs when every given environment variable names an existing path (see <see cref="RealData"/>).</summary>
public sealed class RequiresRealDataFactAttribute : FactAttribute
{
    public RequiresRealDataFactAttribute(params string[] variables)
    {
        foreach (var v in variables)
        {
            var value = RealData.Get(v);
            if (value == null) { Skip = $"Set {v} to run this real-data test."; return; }
            if (!System.IO.Path.Exists(value)) { Skip = $"{v} points to a missing path: {value}"; return; }
        }
    }
}

/// <summary>Runs external tools (dotnet, clang, python) with a timeout, collecting stdout and stderr.</summary>
internal static class Tools
{
    public static (int ExitCode, string Output) Run(string file, string args) => Run(new ProcessStartInfo(file, args));

    /// <summary>
    /// Runs the dotnet CLI without build servers or reusable MSBuild nodes: those outlive the command and keep its
    /// output pipes open.
    /// </summary>
    public static (int ExitCode, string Output) Dotnet(string? workingDirectory, params string[] args)
    {
        var psi = new ProcessStartInfo("dotnet") { WorkingDirectory = workingDirectory ?? "" };
        foreach (var a in args) psi.ArgumentList.Add(a);
        foreach (var key in psi.Environment.Keys.Where(k => k.StartsWith("MSBuild", StringComparison.OrdinalIgnoreCase)).ToList()) psi.Environment.Remove(key);
        psi.Environment["MSBUILDDISABLENODEREUSE"] = "1";
        psi.Environment["DOTNET_CLI_USE_MSBUILD_SERVER"] = "0";
        psi.Environment["UseSharedCompilation"] = "false";
        psi.Environment["DOTNET_NOLOGO"] = "1";
        psi.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        // Shells such as Git Bash drop ProgramFiles(x86); NativeAOT's linker setup (vcvarsall) runs vswhere from it and from PATH.
        if (OperatingSystem.IsWindows())
        {
            var x86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            if (!psi.Environment.ContainsKey("ProgramFiles(x86)")) psi.Environment["ProgramFiles(x86)"] = x86;
            var installer = Path.Combine(x86, "Microsoft Visual Studio", "Installer");
            if (Directory.Exists(installer)) psi.Environment["PATH"] = psi.Environment["PATH"] + Path.PathSeparator + installer;
        }
        // The SDK leaves folders in its temporary folder: one of its own, deleted after the call.
        var temp = Directory.CreateTempSubdirectory("corvus-dotnet-").FullName;
        foreach (var name in new[] { "TMP", "TEMP", "TMPDIR" }) psi.Environment[name] = temp;
        try { return Run(psi); }
        finally
        {
            try { Directory.Delete(temp, true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    public static (int ExitCode, string Output) Run(ProcessStartInfo psi, int timeoutMs = 900_000)
    {
        psi.RedirectStandardOutput = psi.RedirectStandardError = true;
        psi.UseShellExecute = false;
        var output = new System.Text.StringBuilder();
        using var stdoutDone = new ManualResetEventSlim();
        using var stderrDone = new ManualResetEventSlim();
        using var p = new Process { StartInfo = psi };
        p.OutputDataReceived += (_, e) => { if (e.Data == null) stdoutDone.Set(); else lock (output) output.AppendLine(e.Data); };
        p.ErrorDataReceived += (_, e) => { if (e.Data == null) stderrDone.Set(); else lock (output) output.AppendLine(e.Data); };
        try { p.Start(); }
        catch (System.ComponentModel.Win32Exception) { return (-1, $"{psi.FileName} not found"); }
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        if (!p.WaitForExit(timeoutMs))
        {
            try { p.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            lock (output) return (-2, $"{psi.FileName} timed out after {timeoutMs / 1000} s\n{output}");
        }
        // A child process that inherited the pipes may keep them open; do not wait for it.
        stdoutDone.Wait(10_000);
        stderrDone.Wait(10_000);
        lock (output) return (p.ExitCode, output.ToString());
    }
}
