using System.Text.Json;

namespace Corvus.Core;

/// <summary>What a target parameter accepts.</summary>
public enum TargetKind { Assembly, Native, Any }

/// <summary>A resolved target: the .NET assembly and/or native image, and the notice when this resolution loaded it.</summary>
public sealed record Target(LoadedAssembly? Assembly, LoadedNative? Native, string? Notice);

/// <summary>
/// The one resolver for target parameters (assembly, image, oldImage, newImage, ...): a loaded id or name is that target;
/// an existing file not loaded yet is loaded as load_assembly would (with a notice); a missing path is the same not_found
/// everywhere; a target of the other kind is unsupported naming the family; a name with nothing loaded is not_loaded.
/// Runs outside the workspace lock: loading takes the write lock.
/// </summary>
public static class Targets
{
    public const string FileNotFoundNext = "check the path; list_assemblies shows loaded ids";

    /// <summary>Parameters that name a workspace target, checked before every call.</summary>
    public static readonly IReadOnlyList<string> Parameters = ["assembly", "image", "oldAssembly", "newAssembly", "oldImage", "newImage", "images"];

    /// <summary>Tools whose target parameter is never loaded: unload/reload act on what is loaded; patch_asm's assembly is code.</summary>
    private static readonly HashSet<string> NoPreResolve = new(StringComparer.Ordinal) { "unload_assembly", "reload_assembly", "patch_asm" };

    /// <summary>The not_found every tool reports for an input file that does not exist.</summary>
    public static ToolError FileNotFound(string path) => new(ErrorCode.NotFound, $"File not found: '{path}'", FileNotFoundNext);

    /// <summary>The same for a parameter that names a folder.</summary>
    public static ToolError DirectoryNotFound(string path) => new(ErrorCode.NotFound, $"Directory not found: '{path}'", FileNotFoundNext);

    /// <summary>The not_loaded for a name when nothing of the kind is loaded.</summary>
    internal static ToolError NotLoaded(string message, string value) => new(ErrorCode.NotLoaded, message, $"load_assembly path={value}");

    /// <summary>Resolves <paramref name="value"/> to a target of <paramref name="kind"/>, loading an existing file; the caller shows the notice.</summary>
    public static Target Resolve(AssemblyWorkspace workspace, string? value, TargetKind kind, string parameter = "assembly")
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new ToolError(ErrorCode.InvalidArgument, $"{parameter} is empty.", $"pass {parameter}=<an id from list_assemblies, or a file path>");
        var text = value.Trim();
        if (workspace.Read(() => Find(workspace, text, kind)) is { } found) return found;
        string? notice = Load(workspace, text);
        if (notice != null && workspace.Read(() => Find(workspace, text, kind)) is { } loaded) return loaded with { Notice = notice };
        // nothing of the kind: the workspace's typed error (wrong kind, missing path, not loaded, no match)
        return workspace.Read(() => kind == TargetKind.Native
            ? new Target(null, workspace.GetNative(text), notice)
            : new Target(workspace.Get(text), null, notice));
    }

    /// <summary>A .NET assembly by id, name or path; a load is announced as a workspace notice.</summary>
    public static LoadedAssembly Assembly(AssemblyWorkspace workspace, string? value, string parameter = "assembly") =>
        Announce(workspace, Resolve(workspace, value, TargetKind.Assembly, parameter)).Assembly!;

    /// <summary>A native image by id, name or path; a load is announced as a workspace notice.</summary>
    public static LoadedNative Native(AssemblyWorkspace workspace, string? value, string parameter = "image") =>
        Announce(workspace, Resolve(workspace, value, TargetKind.Native, parameter)).Native!;

    /// <summary>Loads the file a parameter names when it is not loaded yet; a missing path is not_found. Other values are left to the tool.</summary>
    public static void Prepare(AssemblyWorkspace workspace, string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        var text = value.Trim();
        if (workspace.Read(() => Find(workspace, text, TargetKind.Any)) != null) return;
        string? notice;
        try { notice = Load(workspace, text); }
        // a file no image loader reads (an .apk for export_project, a container): the tool decides what it accepts
        catch (ToolError e) when (e.Code is ErrorCode.MalformedInput or ErrorCode.Unsupported) { return; }
        if (notice != null) workspace.Notify(notice);
    }

    /// <summary>The pre-call step: every target parameter of the call is prepared (loaded or not_found) before the tool takes the lock.</summary>
    public static void PreResolve(AssemblyWorkspace workspace, string? tool, IReadOnlyDictionary<string, JsonElement>? arguments)
    {
        if (arguments == null || (tool != null && NoPreResolve.Contains(tool))) return;
        foreach (var name in Parameters)
        {
            if (!arguments.TryGetValue(name, out var value)) continue;
            if (value.ValueKind == JsonValueKind.String && name == "images") // a ';'- or ','-separated list
                foreach (var item in value.GetString()!.Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    Prepare(workspace, item);
            else if (value.ValueKind == JsonValueKind.String) Prepare(workspace, value.GetString());
            else if (value.ValueKind == JsonValueKind.Array)
                foreach (var item in value.EnumerateArray())
                    if (item.ValueKind == JsonValueKind.String) Prepare(workspace, item.GetString());
        }
    }

    /// <summary>True when the text names a file system location rather than an id or name.</summary>
    public static bool LooksLikePath(string text) =>
        text.Contains('/') || text.Contains('\\') || (text.Length >= 2 && text[1] == ':' && char.IsAsciiLetter(text[0]));

    /// <summary>The full path of <paramref name="text"/>, or null when it is not a valid path.</summary>
    internal static string? FullPath(string text)
    {
        try { return Path.GetFullPath(text); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
    }

    private static Target? Find(AssemblyWorkspace workspace, string text, TargetKind kind)
    {
        if (kind != TargetKind.Native && workspace.FindAssemblies(text) is [var asm])
            return new Target(asm, workspace.NativeViewOf(asm), null);
        if (kind != TargetKind.Assembly && workspace.FindNative(text) is { } native)
            return new Target(native.ManagedView, native, null);
        return null;
    }

    /// <summary>
    /// Loads an existing regular file that is not loaded under either kind; the notice text, or null when nothing was
    /// loaded. A missing path is not_found.
    /// </summary>
    private static string? Load(AssemblyWorkspace workspace, string text)
    {
        var full = FullPath(text);
        if (full == null || Directory.Exists(full)) return null;
        if (!File.Exists(full))
        {
            if (LooksLikePath(text)) throw FileNotFound(text);
            return null;
        }
        if (workspace.Read(() => workspace.FindByPath(full) != null || workspace.FindNative(full) != null)) return null;
        if (workspace.LockHeld)
            throw NotLoaded($"'{text}' is not loaded.", text); // a load cannot take the write lock from inside a read
        (LoadedAssembly? Assembly, LoadedNative? Native) loaded;
        try { loaded = workspace.LoadAny(full); }
        catch (ToolError e) when (e.Code == ErrorCode.Unsupported && e.Remediation == null)
        {
            throw new ToolError(ErrorCode.Unsupported, e.Message, $"load_assembly path={text} loads packages, game folders and directories; then pass one of the ids it lists");
        }
        var id = loaded.Assembly?.Id ?? loaded.Native!.Id;
        return $"loaded {id} from {full}";
    }

    private static Target Announce(AssemblyWorkspace workspace, Target target)
    {
        if (target.Notice != null) workspace.Notify(target.Notice);
        return target;
    }
}
