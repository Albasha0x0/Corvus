using System.Text.Json;

namespace Corvus.Core;

/// <summary>corvus.json: CORVUS_ variables read once at startup; environment and options win.</summary>
/// <remarks>Security switches, the file's location variables and the update repository are refused, so they stay visible in the
/// client entry. Program, library, folder and URL locators apply only from a file no other account can write.</remarks>
public static class ConfigFile
{
    public const string Variable = "CORVUS_CONFIG";
    public const string FileName = "corvus.json";
    public const int MaxBytes = 1 << 20;

    /// <summary>What startup read and applied; the reason is null when the file was read or is absent.</summary>
    /// <remarks><paramref name="Writers"/> names who else can write the file when that refused its locators; else null.</remarks>
    public sealed record Report(string Path, string Source, bool Found, IReadOnlyList<string> Applied, IReadOnlyList<string> Overridden,
        IReadOnlyList<string> Refused, string? Problem, string? Writers = null);

    /// <summary>The variables a client entry must set: the security switches, the two that locate this file, and the update repository.</summary>
    public static readonly IReadOnlySet<string> Refused = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        ServerOptions.AllowLiveVariable, ServerOptions.AllowLiveSpawnVariable, ServerOptions.AllowLiveAttachVariable, ServerOptions.LiveAllowVariable,
        ServerOptions.LiveScriptingVariable, ServerOptions.LiveInstallFridaVariable, ServerOptions.IdaScriptingVariable, ServerOptions.GhidraScriptingVariable,
        ServerOptions.AllowReplaceOriginalVariable, ServerOptions.AllowRemotePathsVariable, ServerOptions.AllowDeviceChangesVariable, ServerOptions.TraceArgsVariable,
        ServerOptions.InProcessParsingVariable, Services.LiveSessionService.MaxMinutesVariable,
        Native.Providers.DataFolder.RootVariable, Variable, Setup.Installation.RepositoryVariable, Relay.RelayBuilds.TargetVariable,
    };

    /// <summary>
    /// Variables that name a program, library, engine folder or URL the server
    /// starts, loads or reads from, the audit log it writes, and the call ceiling,
    /// which a file another account can write must not lift.
    /// </summary>
    public static readonly IReadOnlySet<string> Locators = new HashSet<string>(
        Native.Providers.ExternalTools.Table.Select(t => t.Variable).Concat(
        [
            Native.Providers.Worker.Yara.YaraX.LibraryVariable, Native.Providers.Live.Ttd.TtdWorker.FolderVariable,
            Native.Dump.Managed.ClrHelperClient.PathVariable, Native.Dwarf.DwarfLocator.ServersVariable, NetworkPolicy.HttpServersVariable,
            OutputRoots.Variable,
            Native.Providers.Ghidra.GhidraOptions.DirectoryVariable, Native.Providers.Ghidra.GhidraOptions.JavaVariable,
            Native.Providers.Ghidra.GhidraOptions.PythonVariable, Native.Providers.Ghidra.GhidraOptions.ExtensionsVariable,
            Native.Providers.Ghidra.GhidraOptions.WorkerDirectoryVariable, Native.Providers.Ida.IdaInstallation.DirectoryVariable,
            Native.Providers.Ida.IdaProvider.PythonVariable, Native.Providers.Live.FridaBackend.PythonVariable,
            Services.Analysis.BuildSummary.DieVariable, Setup.Installation.HomeVariable, ServerOptions.AuditVariable,
            ServerOptions.MaxCallMinutesVariable,
        ]), StringComparer.OrdinalIgnoreCase);

    /// <summary>The startup report; before <see cref="Apply(TextWriter?)"/> runs, no file was read.</summary>
    public static Report Current { get; private set; } = new("", "default", false, [], [], [], null);

    /// <summary>Reads the file into this process's environment, which worker processes inherit; problems go to <paramref name="warnings"/>.</summary>
    public static Report Apply(TextWriter? warnings)
    {
        var named = Environment.GetEnvironmentVariable(Variable);
        var path = named is { Length: > 0 } ? System.IO.Path.GetFullPath(named) : System.IO.Path.Combine(Native.Providers.DataFolder.Root, FileName);
        Current = Apply(path, named is { Length: > 0 } ? Variable : "default", Environment.GetEnvironmentVariable, Environment.SetEnvironmentVariable);
        if (Current.Problem != null) warnings?.WriteLine($"corvus: {path} not applied: {Current.Problem}");
        foreach (var name in Current.Refused)
            warnings?.WriteLine(Current.Writers != null && Locators.Contains(name)
                ? $"corvus: {path}: {name} is refused: the file {Current.Writers}."
                : $"corvus: {path}: {name} is refused there; set it in the client entry.");
        return Current;
    }

    internal static Report Apply(string path, string source, Func<string, string?> get, Action<string, string> set)
    {
        byte[] bytes;
        string? writers;
        try
        {
            if (!File.Exists(path)) return new(path, source, false, [], [], [], null);
            // Access is checked on the handle the bytes are read from, so a file swapped after the check is not read.
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (file.Length > MaxBytes) return new(path, source, true, [], [], [], $"larger than {MaxBytes >> 20} MB");
            writers = Native.Providers.PrivateFile.OtherWriters(file);
            bytes = new byte[file.Length];
            file.ReadExactly(bytes);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new(path, source, true, [], [], [], ex.Message);
        }

        var values = new List<(string Name, string Value)>();
        var refused = new List<string>();
        try
        {
            using var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return new(path, source, true, [], [], [], "not a JSON object");
            foreach (var p in doc.RootElement.EnumerateObject())
            {
                if (p.Name == "$schema") continue;
                string? value = p.Value.ValueKind switch
                {
                    JsonValueKind.String => p.Value.GetString(),
                    JsonValueKind.Number => p.Value.GetRawText(),
                    JsonValueKind.True => "1",
                    JsonValueKind.False => "0",
                    _ => null,
                };
                if (!p.Name.StartsWith("CORVUS_", StringComparison.Ordinal) || Refused.Contains(p.Name) || value == null
                    || (writers != null && Locators.Contains(p.Name)))
                    refused.Add(p.Name);
                else values.Add((p.Name, value));
            }
        }
        catch (JsonException ex)
        {
            return new(path, source, true, [], [], [], $"not valid JSON: {ex.Message}");
        }

        var applied = new List<string>();
        var overridden = new List<string>();
        foreach (var (name, value) in values)
            if (get(name) is { Length: > 0 }) overridden.Add(name);
            else
            {
                set(name, value);
                applied.Add(name);
            }
        return new(path, source, true, applied, overridden, refused, null, refused.Any(Locators.Contains) ? writers : null);
    }

    /// <summary>A status field's source as shown: "corvus.json" for a variable the file set, else the source unchanged.</summary>
    public static string? Shown(string? source) =>
        source != null && Current.Applied.Contains(source, StringComparer.Ordinal) ? $"{FileName} ({source})" : source;
}
