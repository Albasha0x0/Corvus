using System.Security.Cryptography;
using System.Text;

namespace Corvus.Native.Pe;

/// <summary>The import hash of a PE image, as pefile computes it.</summary>
public static class ImportHash
{
    /// <summary>The lower-case MD5 of the import table as "library.function" terms, or null for an image without regular imports; delay-load imports are not part of it.</summary>
    public static string? Of(PeFile pe)
    {
        var terms = new List<string>();
        foreach (var import in pe.Imports.Where(i => !i.IsDelayLoad))
        {
            var library = import.Module.ToLowerInvariant();
            var dot = library.LastIndexOf('.');
            var stem = dot > 0 && library[(dot + 1)..] is "ocx" or "sys" or "dll" ? library[..dot] : library;
            var function = import.Name ?? (import.Ordinal is { } ordinal ? ImportOrdinals.Name(library, ordinal) : null);
            if (!string.IsNullOrEmpty(function)) terms.Add($"{stem}.{function.ToLowerInvariant()}");
        }
        return terms.Count == 0 ? null : Convert.ToHexStringLower(MD5.HashData(Encoding.UTF8.GetBytes(string.Join(',', terms))));
    }
}
