using ModelContextProtocol.Protocol;
using Corvus.Core;

namespace Corvus.Mcp;

/// <summary>Argument completion for prompts and resource templates: assembly, native image and dump ids, type names, file-system paths and guide topics.</summary>
public static class Completions
{
    private const int MaxValues = 100;

    private static readonly string[] ManagedOrNative = [".dll", ".exe", ".sys"];
    private static readonly string[] Dumps = [".dmp", ".mdmp"];
    /// <summary>What a build can be: an install folder, a package or a single binary.</summary>
    private static readonly string[] Builds = [".zip", ".apk", ".aab", ".nupkg", ".ipa", ".msix", ".appx", ".exe", ".dll"];

    /// <param name="dumps">Ids of the open dumps.</param>
    public static CompleteResult Complete(AssemblyWorkspace workspace, CompleteRequestParams request, IReadOnlyCollection<string>? dumps = null)
    {
        var name = request.Argument?.Name ?? "";
        var prefix = request.Argument?.Value ?? "";
        string? assemblyContext = null;
        request.Context?.Arguments?.TryGetValue("assembly", out assemblyContext);

        var values = name switch
        {
            "assembly" or "oldAssembly" or "newAssembly" => workspace.Read(() => workspace.Assemblies.Select(a => a.Id)
                .Where(id => id.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)).ToList()),
            "type" or "symbol" => workspace.Read(() => TypeNames(workspace, assemblyContext, prefix)),
            // An image is a loaded native image id or the path of one.
            "image" or "oldImage" or "newImage" => [.. workspace.Read(() => workspace.Natives.Select(n => n.Id)
                .Where(id => id.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)).ToList()), .. Paths(prefix, ManagedOrNative, drivesWhenEmpty: false)],
            // A dump is an open dump's id or the path of a .dmp (or a folder of them).
            "dump" => [.. (dumps ?? []).Where(id => id.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)).Order(StringComparer.OrdinalIgnoreCase),
                .. Paths(prefix, Dumps, drivesWhenEmpty: false)],
            "oldPath" or "newPath" => Paths(prefix, Builds),
            "path" or "dummyDllFolder" => Paths(prefix, ManagedOrNative),
            "topic" => Guide.Topics.Keys.Where(t => t.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)).ToList(),
            _ => [],
        };
        return new CompleteResult
        {
            Completion = new Completion
            {
                Values = values.Take(MaxValues).ToList(),
                Total = values.Count,
                HasMore = values.Count > MaxValues,
            },
        };
    }

    private static List<string> TypeNames(AssemblyWorkspace workspace, string? assembly, string prefix)
    {
        IEnumerable<LoadedAssembly> scope = workspace.Assemblies;
        if (!string.IsNullOrWhiteSpace(assembly))
        {
            try { scope = [workspace.Get(assembly)]; }
            catch (ToolError) { /* unknown assembly: complete across all */ }
        }
        return scope.SelectMany(a => a.Module.GetTypes())
            .Select(t => t.ReflectionFullName)
            .Where(n => !n.StartsWith('<') && (n.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                                               || n[(n.LastIndexOf('.') + 1)..].StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
            .Distinct()
            .OrderBy(n => n.Length)
            .Take(MaxValues + 1)
            .ToList();
    }

    /// <summary>Folders and files with one of <paramref name="extensions"/> under the prefix's folder.</summary>
    private static List<string> Paths(string prefix, string[] extensions, bool drivesWhenEmpty = true)
    {
        try
        {
            if (string.IsNullOrEmpty(prefix))
                return drivesWhenEmpty ? DriveInfo.GetDrives().Where(d => d.IsReady).Select(d => d.RootDirectory.FullName).ToList() : [];
            var dir = prefix.EndsWith('\\') || prefix.EndsWith('/') ? prefix : Path.GetDirectoryName(prefix);
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return [];
            var start = Path.GetFileName(prefix);
            return Directory.EnumerateFileSystemEntries(dir)
                .Where(p => Path.GetFileName(p).StartsWith(start, StringComparison.OrdinalIgnoreCase))
                .Where(p => Directory.Exists(p) || extensions.Contains(Path.GetExtension(p).ToLowerInvariant()))
                .Take(MaxValues + 1)
                .ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return [];
        }
    }
}
