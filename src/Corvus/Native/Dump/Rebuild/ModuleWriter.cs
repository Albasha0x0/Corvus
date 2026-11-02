using Corvus.Core;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Writes rebuilt modules into a folder.</summary>
public static class ModuleWriter
{
    /// <summary>Writes the rebuilt <paramref name="modules"/> into a new or empty <paramref name="folder"/>; the file name written for each, null for a refused one.</summary>
    /// <remarks>A failed write deletes the files this call created.</remarks>
    public static IReadOnlyList<string?> WriteAll(IReadOnlyList<RebuiltModule> modules, string folder)
    {
        var root = Path.GetFullPath(folder);
        Directory.CreateDirectory(root);
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var names = new List<string?>();
        var created = new List<string>();
        try
        {
            foreach (var m in modules)
            {
                if (m.Bytes == null) { names.Add(null); continue; }
                var name = DumpModuleExport.NameFor(m.Target.Name, m.Target.Base, used);
                SafeFile.WriteUnderRoot(root, name, m.Bytes, overwrite: false);
                created.Add(Path.Combine(root, name));
                names.Add(name);
            }
        }
        catch
        {
            foreach (var path in created)
                try { File.Delete(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            throw;
        }
        return names;
    }
}
