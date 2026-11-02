using Corvus.Core;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>The file written for one rebuilt module, or null with the reason none was.</summary>
public sealed record WrittenModule(string? File, string? Reason);

/// <summary>Writes rebuilt modules into a folder.</summary>
public static class ModuleWriter
{
    /// <summary>Writes the rebuilt <paramref name="modules"/> into a new or empty <paramref name="folder"/>; one record per module, in order.</summary>
    /// <remarks>A folder that is not empty is refused (Conflict); a module past the total limit is listed without a file; a failed write deletes the files this call created.</remarks>
    public static IReadOnlyList<WrittenModule> WriteAll(IReadOnlyList<RebuiltModule> modules, string folder) =>
        WriteAll(modules, folder, ModuleRebuild.MaxTotalBytes, null);

    internal static IReadOnlyList<WrittenModule> WriteAll(IReadOnlyList<RebuiltModule> modules, string folder, long totalLimit, Action<string>? written)
    {
        var root = Path.GetFullPath(folder);
        if (Directory.Exists(root) && Directory.EnumerateFileSystemEntries(root).Any())
            throw new ToolError(ErrorCode.Conflict, $"{root} is not empty.", "name a new or empty folder");
        Directory.CreateDirectory(root);
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var results = new List<WrittenModule>();
        var created = new List<string>();
        long total = 0;
        try
        {
            foreach (var m in modules)
            {
                if (m.Bytes == null) { results.Add(new WrittenModule(null, m.Refused ?? "not rebuilt")); continue; }
                if (total + m.Bytes.Length > totalLimit)
                {
                    results.Add(new WrittenModule(null, $"past the {totalLimit >> 20} MB total limit"));
                    continue;
                }
                var name = DumpModuleExport.NameFor(m.Target.Name, m.Target.Base, used);
                SafeFile.WriteUnderRoot(root, name, m.Bytes, overwrite: false);
                created.Add(Path.Combine(root, name));
                total += m.Bytes.Length;
                results.Add(new WrittenModule(name, null));
                written?.Invoke(name);
            }
        }
        catch
        {
            foreach (var path in created)
                try { File.Delete(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            throw;
        }
        return results;
    }
}
