using System.Globalization;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native;

/// <summary>
/// Parses addresses given to native tools into RVAs. Forms: a number (hex with 0x or a trailing h, or plain hex
/// digits; a value inside [ImageBase, ImageBase + SizeOfImage) is a VA, otherwise an RVA), prefixed "rva:", "va:" or
/// "off:" / "offset:" (file offset), an export name, "module!import" for an IAT slot, or a name the caller resolves
/// (function names such as sub_1800012340).
/// </summary>
public static class NativeAddress
{
    public static uint Parse(INativeImage image, string text, Func<string, uint?>? names = null)
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
        if (names?.Invoke(t) is { } named) return named;
        int bang = t.IndexOf('!');
        if (bang > 0)
        {
            var module = t[..bang];
            var name = t[(bang + 1)..];
            var slot = image.Imports.FirstOrDefault(i => SameModule(i.Module, module) && (i.Name == name || name.StartsWith('#') && i.Ordinal?.ToString() == name[1..]));
            if (slot != null) return slot.SlotRva;
            throw new ToolError(ErrorCode.NotFound, $"{Path.GetFileName(image.Path)} does not import {t}.", "list_imports shows what it imports");
        }
        var export = image.Exports.FirstOrDefault(e => e.Name == t && e.ForwardedTo == null);
        if (export != null) return export.Rva;
        if (Number(t) is { } plain) return FromNumber(image, plain, t);
        throw new ToolError(ErrorCode.NotFound, $"'{t}' is neither an address nor a known name in {Path.GetFileName(image.Path)}.",
            "pass a hex address, an export name, module!import, or a function name from list_functions");
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
