using ModelContextProtocol.Protocol;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Mcp;

/// <summary>Argument completion for prompts and resource templates: assembly ids, type names and file-system paths.</summary>
public static class Completions
{
    private const int MaxValues = 100;

    public static CompleteResult Complete(AssemblyWorkspace workspace, CompleteRequestParams request)
    {
        var name = request.Argument?.Name ?? "";
        var prefix = request.Argument?.Value ?? "";
        string? assemblyContext = null;
        request.Context?.Arguments?.TryGetValue("assembly", out assemblyContext);

        var values = name switch
        {
            "assembly" => workspace.Read(() => workspace.Assemblies.Select(a => a.Id)
                .Where(id => id.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)).ToList()),
            "type" or "symbol" => workspace.Read(() => TypeNames(workspace, assemblyContext, prefix)),
            "path" or "dummyDllFolder" => Paths(prefix),
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

    private static List<string> Paths(string prefix)
    {
        try
        {
            if (string.IsNullOrEmpty(prefix))
                return DriveInfo.GetDrives().Where(d => d.IsReady).Select(d => d.RootDirectory.FullName).ToList();
            var dir = prefix.EndsWith('\\') || prefix.EndsWith('/') ? prefix : Path.GetDirectoryName(prefix);
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return [];
            var start = Path.GetFileName(prefix);
            return Directory.EnumerateFileSystemEntries(dir)
                .Where(p => Path.GetFileName(p).StartsWith(start, StringComparison.OrdinalIgnoreCase))
                .Where(p => Directory.Exists(p) || p.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                .Take(MaxValues + 1)
                .ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return [];
        }
    }
}
