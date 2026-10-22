using System.ComponentModel;
using System.Text.Json.Serialization;
using Corvus.Core;
using Corvus.Core.Python;
using Corvus.Native.Providers;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=python: a frozen Python program (PyInstaller, py2exe, cx_Freeze, Nuitka), a PYZ archive or a library zip of .pyc
/// files: the freezer, the Python version and where it came from, the entry scripts, the modules, the bundled native
/// modules and runtime, and the data files; unpack_container extracts them with each .pyc's header in place. A .pyc:
/// its disassembly as that version's dis prints it, paged by offset, and its source when CORVUS_PY_DECOMPILER is set.
/// </summary>
internal sealed class PythonFileView : IFileSummaryView
{
    public sealed record Facts(string Freezer, string? PythonVersion, string? VersionSource, IReadOnlyList<string> EntryScripts, int Modules, int Packages,
        int Encrypted, IReadOnlyList<string> NativeModules, IReadOnlyList<string> Runtime, int DataFiles, bool CompiledCode, IReadOnlyList<string> ModuleNames,
        IReadOnlyList<string> Notes)
    {
        /// <summary>The program as its freezer's reader found it, for the dependencies view.</summary>
        [JsonIgnore] public FrozenApp? App { get; init; }
    }

    public sealed record Bytecode(string PythonVersion, int Magic, string Filename, int CodeObjects,
        [property: Description("Qualified names of the functions, classes and comprehensions, to 200.")] IReadOnlyList<string> Functions,
        IReadOnlyList<string> Imports, long Offset, long? Next,
        [property: Description("dis output from offset, as the file's own Python version prints it.")] string Disassembly, bool Complete,
        [property: Description("The source from CORVUS_PY_DECOMPILER, from the same offset.")] string? Source, long? SourceNext,
        [property: Description("The program that wrote the source.")] string? Decompiler, IReadOnlyList<string>? Notes);

    public string Name => "python";

    private const int MaxListed = 200, MaxText = 8 << 20, Window = 24_000, MaxPyc = 32 << 20;

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        var limits = AnalysisLimits.Default;
        var name = Path.GetFileName(file.Path);
        if (file.Kind == "python bytecode") return file.Length <= MaxPyc ? Pyc(file, ct) : null;
        FrozenApp? app = file.Kind switch
        {
            "native PE" or "elf" or "mach-o" when file.Streamed => FrozenPython.LooksStreamable(file.Head) ? Streamed(file, name, limits, ct) : null,
            "native PE" or "elf" or "mach-o" => FrozenPython.Read(file.Bytes, name, file.Path, allFiles: false, limits, ct),
            "pyinstaller pyz" => PyInstallerArchive.ReadPyz(file.Bytes, name, limits, ct),
            "zip" when file.HasZipEntry(e => e.EndsWith(".pyc", StringComparison.OrdinalIgnoreCase)) => FrozenPython.ReadLibraryZip(file.Bytes, limits, ct),
            _ => null,
        };
        if (app == null) return null;
        string[] Paths(Func<string, bool> role) => [.. app.Entries.Where(e => role(e.Role)).Select(e => e.Path).Take(MaxListed)];
        bool Is(string role, string wanted) => role == wanted || role.StartsWith(wanted + " (", StringComparison.Ordinal);
        var modules = app.Entries.Where(e => Is(e.Role, FrozenApp.Module) || Is(e.Role, FrozenApp.Package) || Is(e.Role, FrozenApp.Script) || e.Role == FrozenApp.Encrypted)
            .Select(e => FrozenApp.ModuleOf(e.Path.Split("_extracted/")[^1])?.Name).OfType<string>().Distinct().ToList();
        var notes = new List<string>(app.Notes);
        if (modules.Count > MaxListed) notes.Add($"{MaxListed} of {modules.Count:N0} module names listed; unpack_container lists every file.");
        var facts = new Facts(app.Freezer, app.Version is { } v ? PyVersion.Label(v) : null, app.VersionSource, app.EntryScripts,
            app.Entries.Count(e => Is(e.Role, FrozenApp.Module)), app.Entries.Count(e => Is(e.Role, FrozenApp.Package)), app.Count(FrozenApp.Encrypted),
            Paths(r => Is(r, FrozenApp.Native)), Paths(r => Is(r, FrozenApp.Runtime)), app.Entries.Count(e => e.Role == FrozenApp.Data), app.Compiled,
            [.. modules.Take(MaxListed)], notes) { App = app };
        var highlights = new List<string> { app.Headline() };
        if (app.Compiled) highlights.Add("The program's own Python code was compiled to native code (Nuitka): read it with the native tools.");
        if (facts.Encrypted > 0) highlights.Add($"{facts.Encrypted:N0} modules are encrypted (PyInstaller --key).");
        return new FileView(facts, highlights);
    }

    private static FrozenApp? Streamed(FileInput file, string name, AnalysisLimits limits, CancellationToken ct)
    {
        using var s = file.OpenRead();
        return FrozenPython.Read(s, name, allFiles: false, limits, ct);
    }

    private static FileView? Pyc(FileInput file, CancellationToken ct)
    {
        var data = file.Bytes;
        if (PyVersion.FromMagic(data) is not { } version) return null;
        int header = PyVersion.HeaderLength(version);
        var label = PyVersion.Label(version);
        if (PyMarshal.TryRead(data, version, out var error, header) is not PyCode code)
            return new FileView(new Bytecode(label, PyVersion.Magic(data), "", 0, [], [], 0, null, "", false, null, null, null, [$"The code object does not read: {error}"]),
                [$"Python {label} bytecode whose code object does not read."]);
        var functions = new List<string>();
        int count = 0;
        void Walk(PyCode c, int depth)
        {
            count++;
            if (depth > 0 && functions.Count < MaxListed) functions.Add(c.QualName);
            if (depth < 64)
                foreach (var nested in c.Consts.OfType<PyCode>()) Walk(nested, depth + 1);
        }
        Walk(code, 0);
        var notes = new List<string>();
        bool asked = file.Options.Wants("python");
        string text = "";
        bool complete = true;
        if (!PyDisassembler.Supports(version)) notes.Add($"Python {label} bytecode is not disassembled (2.7 and 3.0 to 3.14 are).");
        else if (asked) text = PyDisassembler.Disassemble(code, version, MaxText, ct, out complete);
        if (!complete) notes.Add($"The disassembly stops after {MaxText:N0} characters.");
        long offset = Math.Clamp(file.Options.Offset, 0, text.Length);
        var window = text.Substring((int)offset, (int)Math.Min(Window, text.Length - offset));
        long? next = offset + window.Length < text.Length ? offset + window.Length : null;
        if (next != null) notes.Add($"{text.Length:N0} characters of disassembly; offset={next} reads on");
        var (source, sourceNext, decompiler) = asked ? Decompile(file, offset, notes, ct) : (null, null, null);
        var facts = new Bytecode(label, PyVersion.Magic(data), code.Filename, count, functions, PyDisassembler.Imports(code, version), offset, next, window, complete,
            source, sourceNext, decompiler, notes.Count > 0 ? notes : null);
        var highlight = $"Python {label} bytecode of {code.Filename}: {count:N0} code objects";
        if (!asked && PyDisassembler.Supports(version)) highlight += "; view=python shows the disassembly";
        return new FileView(facts, [highlight + "."]);
    }

    private static readonly TimeSpan DecompileTimeout = TimeSpan.FromMinutes(1);

    /// <summary>The source from the configured decompiler, from <paramref name="offset"/>, and the decompiler's name; it runs only when CORVUS_PY_DECOMPILER is set.</summary>
    private static (string?, long?, string?) Decompile(FileInput file, long offset, List<string> notes, CancellationToken ct)
    {
        var tool = ExternalTools.PythonDecompiler;
        if (Environment.GetEnvironmentVariable(tool.Variable) is not { Length: > 0 }) return (null, null, null);
        var probe = ExternalTools.Probe(tool);
        if (!probe.Usable)
        {
            notes.Add($"No source: {probe.Problem}.");
            return (null, null, null);
        }
        if (!File.Exists(file.Path))
        {
            notes.Add("No source: the decompiler reads a file on disk; unpack_container saves the .pyc.");
            return (null, null, null);
        }
        var name = Path.GetFileNameWithoutExtension(probe.Path!);
        var run = ExternalTools.Run(probe.Path!, ExternalTools.Arguments(tool, "decompile", ("input", Path.GetFullPath(file.Path))), DecompileTimeout, MaxText, ct);
        if (run.StartError != null || run.TimedOut || run.Output.Length == 0)
        {
            var why = run.StartError ?? (run.TimedOut ? $"no answer within {DecompileTimeout.TotalSeconds:0} s" : $"no output (exit {run.ExitCode}) {run.Stderr.Trim()}");
            notes.Add($"No source: {name} gave {why[..Math.Min(why.Length, 500)]}.");
            return (null, null, null);
        }
        // pycdc exits 1 after a partial listing, and reports on stderr what it does
        // not decompile.
        if (run.ExitCode != 0) notes.Add($"{name} exited with code {run.ExitCode}: the source may be partial.");
        if (run.Stderr.Trim() is { Length: > 0 } stderr)
        {
            var reported = string.Join("; ", stderr.ReplaceLineEndings("\n").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct());
            notes.Add($"{name} reported: {reported[..Math.Min(reported.Length, 500)]}");
        }
        var text = run.Text.ReplaceLineEndings("\n");
        long at = Math.Clamp(offset, 0, text.Length);
        var window = text.Substring((int)at, (int)Math.Min(Window, text.Length - at));
        return (window, at + window.Length < text.Length ? at + window.Length : null, name);
    }
}
