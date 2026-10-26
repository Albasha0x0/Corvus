using System.Text.Json;

namespace Corvus.Core;

/// <summary>
/// corvus.json: CORVUS_ variables for every server and command of this user, read once at startup from the data folder,
/// or from the file <see cref="Variable"/> names. A variable already set in the environment wins over the file, and an
/// option wins over both. Security switches and the variables that locate the file are refused there: they stay in the
/// client entry, where the client shows them.
/// </summary>
public static class ConfigFile
{
    public const string Variable = "CORVUS_CONFIG";
    public const string FileName = "corvus.json";
    public const int MaxBytes = 1 << 20;

    /// <summary>
    /// What startup read: the file looked at and where its path came from, the variables it set, those the environment
    /// already set, those it refused, and why nothing applied (null when the file was read or is absent).
    /// </summary>
    public sealed record Report(string Path, string Source, bool Found, IReadOnlyList<string> Applied, IReadOnlyList<string> Overridden,
        IReadOnlyList<string> Refused, string? Problem);

    /// <summary>The variables a client entry must set: the security switches, and the two that locate this file.</summary>
    public static readonly IReadOnlySet<string> Refused = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        ServerOptions.AllowLiveVariable, ServerOptions.AllowLiveSpawnVariable, ServerOptions.AllowLiveAttachVariable, ServerOptions.LiveAllowVariable,
        ServerOptions.LiveScriptingVariable, ServerOptions.LiveInstallFridaVariable, ServerOptions.IdaScriptingVariable, ServerOptions.GhidraScriptingVariable,
        ServerOptions.AllowReplaceOriginalVariable, ServerOptions.AllowDeviceChangesVariable, ServerOptions.TraceArgsVariable,
        ServerOptions.InProcessParsingVariable, Services.LiveSessionService.MaxMinutesVariable,
        Native.Providers.DataFolder.RootVariable, Variable,
    };

    /// <summary>The startup report; before <see cref="Apply(TextWriter?)"/> runs, no file was read.</summary>
    public static Report Current { get; private set; } = new("", "default", false, [], [], [], null);

    /// <summary>Reads the file into this process's environment, which worker processes inherit; problems go to <paramref name="warnings"/>.</summary>
    public static Report Apply(TextWriter? warnings)
    {
        var named = Environment.GetEnvironmentVariable(Variable);
        var path = named is { Length: > 0 } ? System.IO.Path.GetFullPath(named) : System.IO.Path.Combine(Native.Providers.DataFolder.Root, FileName);
        Current = Apply(path, named is { Length: > 0 } ? Variable : "default", Environment.GetEnvironmentVariable, Environment.SetEnvironmentVariable);
        if (Current.Problem != null) warnings?.WriteLine($"corvus: {path} not applied: {Current.Problem}");
        foreach (var name in Current.Refused) warnings?.WriteLine($"corvus: {path}: {name} is refused there; set it in the client entry.");
        return Current;
    }

    internal static Report Apply(string path, string source, Func<string, string?> get, Action<string, string> set)
    {
        byte[] bytes;
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists) return new(path, source, false, [], [], [], null);
            if (info.Length > MaxBytes) return new(path, source, true, [], [], [], $"larger than {MaxBytes >> 20} MB");
            bytes = File.ReadAllBytes(path);
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
                if (!p.Name.StartsWith("CORVUS_", StringComparison.Ordinal) || Refused.Contains(p.Name) || value == null) refused.Add(p.Name);
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
        return new(path, source, true, applied, overridden, refused, null);
    }

    /// <summary>A status field's source as shown: "corvus.json" for a variable the file set, else the source unchanged.</summary>
    public static string? Shown(string? source) =>
        source != null && Current.Applied.Contains(source, StringComparer.Ordinal) ? $"{FileName} ({source})" : source;
}
