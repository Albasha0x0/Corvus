using System.Diagnostics;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

/// <summary>A fresh workspace with the fixture assembly (and optionally the consumer assembly) loaded, plus all services.</summary>
public sealed class Env : IDisposable
{
    public static readonly string FixturePath = typeof(Fixture.Game.Player).Assembly.Location;
    public static readonly string ConsumerPath = typeof(Consumer.Arena).Assembly.Location;

    public ServerOptions Options { get; } = new() { TimeoutSeconds = 120 };
    public AssemblyWorkspace Workspace { get; }
    public OutputPager Pager { get; }
    public DecompilerService Decompiler { get; }
    public SearchService Search { get; } = new();
    public ReferenceService References { get; }
    public Il2CppService Il2Cpp { get; }
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
        Report = new AssemblyReport(Workspace, Il2Cpp);
        Edits = new EditService(Workspace, new IlAssembler(Workspace), new CSharpPatcher(Workspace, Decompiler));
        History = new EditHistoryService(Workspace, Edits, Decompiler);
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

    public void Dispose() => Workspace.Dispose();
}

/// <summary>Temporary directory deleted on dispose.</summary>
public sealed class TempDir : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ndm-" + Guid.NewGuid().ToString("N"));

    public TempDir() => Directory.CreateDirectory(Path);

    public string File(string name) => System.IO.Path.Combine(Path, name);

    public void Dispose()
    {
        try { Directory.Delete(Path, true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best effort */ }
    }
}

/// <summary>A fact that only runs when the given path exists on this machine (real-world data).</summary>
public sealed class RequiresPathFactAttribute : FactAttribute
{
    public RequiresPathFactAttribute(string path)
    {
        if (!System.IO.Path.Exists(path))
            Skip = $"Real-world data not present: {path}";
    }
}

/// <summary>
/// Real-world test data, located by environment variables so nothing about one machine lives in the repo.
/// Tests that need a variable are skipped when it is unset or points nowhere.
/// </summary>
public static class RealData
{
    /// <summary>The Managed folder of a Mono game (or any folder of real-world .NET assemblies).</summary>
    public const string MonoGameDir = "NDM_MONO_GAME_DIR";
    /// <summary>An Il2CppDumper / Cpp2IL DummyDll folder.</summary>
    public const string Il2CppDummyDir = "NDM_IL2CPP_DUMMY_DIR";
    /// <summary>Two builds of the same game (folders), and the assembly to compare between them.</summary>
    public const string CompareOldDir = "NDM_COMPARE_OLD_DIR";
    public const string CompareNewDir = "NDM_COMPARE_NEW_DIR";
    public const string CompareAssembly = "NDM_COMPARE_ASSEMBLY";
    /// <summary>Optional: known type moves between the two builds, "Old.Name=>New.Name;Old2=>New2".</summary>
    public const string CompareExpect = "NDM_COMPARE_EXPECT";
    /// <summary>Optional: a method in the Mono game to search call paths to (default: one picked automatically).</summary>
    public const string CallPathTarget = "NDM_CALLPATH_TARGET";
    /// <summary>Root of a C/C++ project with a host function table (generate_cpp_binding style=hostapi detection).</summary>
    public const string HostApiProjectDir = "NDM_HOSTAPI_PROJECT_DIR";

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

/// <summary>Runs external tools (clang, python) used to check generated code.</summary>
internal static class Tools
{
    public static (int ExitCode, string Output) Run(string file, string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(file, args) { RedirectStandardError = true, RedirectStandardOutput = true, UseShellExecute = false })!;
            var stderr = p.StandardError.ReadToEndAsync(); // read both pipes at once, or a full one blocks the process
            var stdout = p.StandardOutput.ReadToEnd();
            p.WaitForExit(600_000);
            return (p.ExitCode, stdout + stderr.Result);
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return (-1, $"{file} not found");
        }
    }
}
