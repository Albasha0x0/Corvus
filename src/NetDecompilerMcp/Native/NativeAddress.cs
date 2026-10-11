using System.Globalization;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native;

/// <summary>An address a name resolves to, with where the name comes from (user, pdb, il2cpp, ida, export, import, ...).</summary>
public readonly record struct AddressCandidate(uint Rva, string Source);

/// <summary>
/// Parses addresses given to native tools into RVAs. Forms: a number (hex with 0x or a trailing h, or plain hex
/// digits; a value inside [ImageBase, ImageBase + SizeOfImage) is a VA, otherwise an RVA), prefixed "rva:", "va:" or
/// "off:" / "offset:" (file offset), an export name, "module!import" for an IAT slot, a name the caller resolves, or an
/// engine's default name (sub_1800012340, FUN_180001234, DAT_180020000). A name on several addresses is an ambiguous error listing them.
/// </summary>
public static class NativeAddress
{
    public static uint Parse(INativeImage image, string text, Func<string, IReadOnlyList<AddressCandidate>>? names = null)
    {
        if (string.IsNullOrWhiteSpace(text))
            throw new ToolError(ErrorCode.InvalidArgument, "Address is empty.", "pass a hex address (0x180001000), rva:0x1000, off:0x400, or a symbol name");
        var t = text.Trim();
        int colon = t.IndexOf(':');
        if (colon > 0 && t[..colon].ToLowerInvariant() is "rva" or "va" or "off" or "offset")
        {
            var kind = t[..colon].ToLowerInvariant();
            var value = Number(t[(colon + 1)..]) ?? throw Bad(t);
            return kind switch
            {
                "rva" => CheckRva(image, value, t),
                "va" => VaToRva(image, value, t),
                _ => value <= long.MaxValue && image.TryFileOffsetToRva((long)value, out var rva) ? rva
                    : throw new ToolError(ErrorCode.NotFound, $"File offset {t[(colon + 1)..]} is not inside any mapped part of {Path.GetFileName(image.Path)}."),
            };
        }
        // Only 0x and # are numbers outright: "Bach" or "add" (trailing h, bare hex) can be names, so names go first.
        bool explicitNumber = t.StartsWith("0x", StringComparison.OrdinalIgnoreCase) || t.StartsWith('#');
        if (explicitNumber && Number(t) is { } number) return FromNumber(image, number, t);
        var candidates = new List<AddressCandidate>();
        foreach (var c in names?.Invoke(t) ?? []) if (!candidates.Exists(k => k.Rva == c.Rva)) candidates.Add(c);
        foreach (var e in image.Exports)
            if (e.Name == t && e.ForwardedTo == null && !candidates.Exists(k => k.Rva == e.Rva)) candidates.Add(new(e.Rva, "export"));
        int bang = t.IndexOf('!');
        if (candidates.Count == 0 && bang > 0)
        {
            var module = t[..bang];
            var name = t[(bang + 1)..];
            foreach (var i in image.Imports)
                if (SameModule(i.Module, module) && (i.Name == name || name.StartsWith('#') && i.Ordinal?.ToString() == name[1..]) && !candidates.Exists(k => k.Rva == i.SlotRva))
                    candidates.Add(new(i.SlotRva, "import"));
            if (candidates.Count == 0)
                throw new ToolError(ErrorCode.NotFound, $"{Path.GetFileName(image.Path)} does not import {t}.", "list_imports shows what it imports");
        }
        if (candidates.Count == 1) return candidates[0].Rva;
        if (candidates.Count > 1) throw Ambiguous(image, t, candidates);
        if (DefaultName(t) is { } named) return FromNumber(image, named, t);
        if (Number(t) is { } plain) return FromNumber(image, plain, t);
        throw new ToolError(ErrorCode.NotFound, $"'{t}' is neither an address nor a known name in {Path.GetFileName(image.Path)}.",
            "pass a hex address, an export name, module!import, or a function name from list_functions");
    }

    /// <summary>Engines' default names (Ghidra's FUN_, LAB_, DAT_, thunk_FUN_, PTR_..._; IDA's sub_, loc_, off_, unk_, byte_ ...).</summary>
    private static readonly string[] DefaultPrefixes =
        ["thunk_FUN_", "FUN_", "LAB_", "DAT_", "PTR_", "sub_", "j_sub_", "loc_", "locret_", "off_", "unk_", "byte_", "word_", "dword_", "qword_", "stru_", "asc_"];

    /// <summary>The address in an engine's default name: the hex after the prefix (PTR_: the last _ part, as in PTR_DAT_140012000), else null.</summary>
    public static ulong? DefaultName(string name)
    {
        foreach (var p in DefaultPrefixes)
        {
            if (!name.StartsWith(p, StringComparison.Ordinal)) continue;
            var hex = p == "PTR_" ? name[(name.LastIndexOf('_') + 1)..] : name[p.Length..];
            return hex.Length is > 0 and <= 16 && hex.All(Uri.IsHexDigit)
                ? ulong.Parse(hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture) : null;
        }
        return null;
    }

    internal static ToolError Ambiguous(INativeImage image, string name, IEnumerable<AddressCandidate> found)
    {
        var candidates = found.OrderBy(c => c.Rva).ToList();
        return new ToolError(ErrorCode.Ambiguous,
            $"'{name}' names {candidates.Count} addresses in {Path.GetFileName(image.Path)}: {string.Join(", ", candidates.Take(20).Select(c => $"{Va(image, c.Rva)} ({c.Source})"))}" +
            (candidates.Count > 20 ? $", and {candidates.Count - 20} more." : "."),
            "pass one of the addresses")
        {
            Details = new { name, candidates = candidates.Take(100).Select(c => new { address = Va(image, c.Rva), rva = $"0x{c.Rva:X}", source = c.Source }).ToList() },
        };
    }

    private static uint FromNumber(INativeImage image, ulong number, string text) =>
        number >= image.ImageBase && number - image.ImageBase < image.SizeOfImage ? (uint)(number - image.ImageBase) : CheckRva(image, number, text);

    public static string Va(INativeImage image, uint rva) => $"0x{image.ImageBase + rva:X}";

    /// <summary>RVA, VA and file offset of an address, e.g. "rva 0x1000, va 0x180001000, file 0x400".</summary>
    public static string Describe(INativeImage image, uint rva) =>
        $"rva 0x{rva:X}, va {Va(image, rva)}" + (image.TryRvaToFileOffset(rva, out var off) ? $", file 0x{off:X}" : ", not in the file");

    private static bool SameModule(string a, string b) =>
        string.Equals(Path.GetFileNameWithoutExtension(a), Path.GetFileNameWithoutExtension(b), StringComparison.OrdinalIgnoreCase);

    private static uint CheckRva(INativeImage image, ulong value, string text) =>
        value < image.SizeOfImage ? (uint)value
            : throw new ToolError(ErrorCode.NotFound, $"{text} is outside {Path.GetFileName(image.Path)} (image base 0x{image.ImageBase:X}, size 0x{image.SizeOfImage:X}).",
                "addresses are RVAs or VAs within the image; use off:0x... for a file offset");

    private static uint VaToRva(INativeImage image, ulong value, string text) =>
        value >= image.ImageBase && value - image.ImageBase < image.SizeOfImage ? (uint)(value - image.ImageBase)
            : throw new ToolError(ErrorCode.NotFound, $"VA {text} is outside {Path.GetFileName(image.Path)} (0x{image.ImageBase:X}-0x{image.ImageBase + image.SizeOfImage:X}).");

    /// <summary>Hex with 0x prefix or h suffix, plain hex digits, or decimal with a leading '#'.</summary>
    public static ulong? Number(string text)
    {
        var t = text.Trim().Replace("`", "").Replace("_", "");
        if (t.StartsWith('#')) return ulong.TryParse(t[1..], NumberStyles.None, CultureInfo.InvariantCulture, out var d) ? d : null;
        if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) t = t[2..];
        else if (t.EndsWith('h') || t.EndsWith('H')) t = t[..^1];
        if (t.Length == 0) return null;
        var digits = t.TrimStart('0');                  // MASM writes leading-zero hex (0FFFF...h); the value is unchanged
        if (digits.Length == 0) return 0UL;
        return digits.Length <= 16 && ulong.TryParse(digits, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var v) ? v : null;
    }

    private static ToolError Bad(string text) =>
        new(ErrorCode.InvalidArgument, $"'{text}' is not a number.", "use hex such as 0x1000");
}
