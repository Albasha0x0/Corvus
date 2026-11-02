using Corvus.Core;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Chooses the file name a rebuilt module gets under an output folder.</summary>
internal static class ModuleFileName
{
    /// <summary>A safe file name for a module under an output folder: its own name, else module.bin; a taken name gets the base address.</summary>
    internal static string NameFor(string fileName, ulong moduleBase, HashSet<string> used)
    {
        var name = fileName;
        if (!InputFiles.IsPlainName(name) || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || name.EndsWith('.') || name.EndsWith(' ') || SafeFile.IsReservedName(name)) name = "module.bin";
        var stem = Path.GetFileNameWithoutExtension(name);
        // A name that already ends in its extension, such as payload.dll, is not given it twice.
        if (Path.GetExtension(name).Length > 0 && Path.GetExtension(stem).Equals(Path.GetExtension(name), StringComparison.OrdinalIgnoreCase)) name = stem;
        if (used.Add(name)) return name;
        var unique = $"{Path.GetFileNameWithoutExtension(name)}-{moduleBase:X}{Path.GetExtension(name)}";
        for (int n = 2; !used.Add(unique); n++) unique = $"{Path.GetFileNameWithoutExtension(name)}-{moduleBase:X}-{n}{Path.GetExtension(name)}";
        return unique;
    }
}
