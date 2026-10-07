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
