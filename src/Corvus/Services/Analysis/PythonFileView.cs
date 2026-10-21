using Corvus.Core;
using Corvus.Core.Python;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=python: a frozen Python program (PyInstaller, py2exe, cx_Freeze, Nuitka), a PYZ archive or a library zip of .pyc
/// files: the freezer, the Python version and where it came from, the entry scripts, the modules, the bundled native
/// modules and runtime, and the data files; unpack_container extracts them with each .pyc's header in place.
/// </summary>
internal sealed class PythonFileView : IFileSummaryView
{
    public sealed record Facts(string Freezer, string? PythonVersion, string? VersionSource, IReadOnlyList<string> EntryScripts, int Modules, int Packages,
        int Encrypted, IReadOnlyList<string> NativeModules, IReadOnlyList<string> Runtime, int DataFiles, bool CompiledCode, IReadOnlyList<string> ModuleNames,
        IReadOnlyList<string> Notes);

    public string Name => "python";

    private const int MaxListed = 200;

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        var limits = AnalysisLimits.Default;
        var name = Path.GetFileName(file.Path);
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
            [.. modules.Take(MaxListed)], notes);
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
}
