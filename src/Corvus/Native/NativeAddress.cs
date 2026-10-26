using System.Buffers.Binary;
using System.Globalization;
using Corvus.Core;

namespace Corvus.Native;

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
        // Mach-O symbols carry the C compiler's leading underscore; a C name
        // finds them without it.
        if (candidates.Count == 0 && bang < 0 && image.Format == ImageFormat.MachO && !t.StartsWith('_'))
            try { return Parse(image, "_" + t, names); }
            catch (ToolError e) when (e.Code == ErrorCode.NotFound) { }
        if (candidates.Count == 0 && bang > 0)
        {
            var module = t[..bang];
            var name = t[(bang + 1)..];
            foreach (var i in image.Imports)
                if (ImportMatches(image, i, module, name) && !candidates.Exists(k => k.Rva == i.SlotRva))
                    candidates.Add(new(i.SlotRva, "import"));
            if (candidates.Count == 0)
                throw new ToolError(ErrorCode.NotFound, $"{Path.GetFileName(image.Path)} does not import {t}.", "list_imports shows what it imports");
        }
        candidates = WithoutJumpThunks(image, candidates);
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

    /// <summary>
    /// Drops candidates that are only a direct jump to another candidate: an incremental-link or export thunk and the
    /// body it jumps to carry the same name, and the name means the body.
    /// </summary>
    public static List<AddressCandidate> WithoutJumpThunks(INativeImage image, List<AddressCandidate> candidates)
    {
        if (candidates.Count < 2) return candidates;
        var kept = candidates.Where(c => JumpTarget(image, c.Rva) is not { } to || !candidates.Exists(o => o.Rva == to && o.Rva != c.Rva)).ToList();
        return kept.Count > 0 ? kept : candidates;
    }

    /// <summary>Target of the unconditional direct jump at <paramref name="rva"/> (x86/x64 jmp rel32 or rel8, ARM64 b), else null.</summary>
    private static uint? JumpTarget(INativeImage image, uint rva)
    {
        Span<byte> b = stackalloc byte[5];
        int n = image.Read(rva, b);
        if (image.Arch is NativeArch.X86 or NativeArch.X64)
        {
            if (n >= 5 && b[0] == 0xE9) return unchecked((uint)(rva + 5 + BinaryPrimitives.ReadInt32LittleEndian(b[1..])));
            if (n >= 2 && b[0] == 0xEB) return unchecked((uint)(rva + 2 + (sbyte)b[1]));
        }
        else if (image.Arch == NativeArch.Arm64 && n >= 4 && (BinaryPrimitives.ReadUInt32LittleEndian(b) & 0xFC000000) == 0x14000000)
            return unchecked((uint)(rva + (((int)BinaryPrimitives.ReadUInt32LittleEndian(b) << 6) >> 6) * 4));
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

    /// <summary>
    /// <paramref name="import"/> is module!name: the module by file name with or without its extension (kernel32, KERNEL32.dll,
    /// libc.so.6, libSystem.B.dylib; an unversioned ELF import, module *, matches * or any library it needs), the name exactly, by #ordinal,
    /// or on Mach-O without its leading underscore.
    /// </summary>
    public static bool ImportMatches(INativeImage image, NativeImport import, string module, string name)
    {
        if (import.Module != "*" && !SameModule(import.Module, module)) return false;
        if (import.Module == "*" && module != "*" && image.Dependencies.Count > 0 && !image.Dependencies.Any(d => SameModule(d, module))) return false;
        if (name.StartsWith('#')) return import.Ordinal?.ToString() == name[1..];
        return import.Name == name || (image.Format == ImageFormat.MachO && import.Name == "_" + name);
    }

    private static bool SameModule(string a, string b)
    {
        string x = Path.GetFileName(a), y = Path.GetFileName(b);
        return string.Equals(x, y, StringComparison.OrdinalIgnoreCase)
            || string.Equals(Path.GetFileNameWithoutExtension(x), Path.GetFileNameWithoutExtension(y), StringComparison.OrdinalIgnoreCase)
            || string.Equals(StripSoVersion(x), StripSoVersion(y), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>libc.so.6 -> libc, libSystem.B.dylib -> libSystem.B, kernel32.dll -> kernel32.</summary>
    private static string StripSoVersion(string file)
    {
        int so = file.IndexOf(".so", StringComparison.OrdinalIgnoreCase);
        if (so > 0 && (so + 3 == file.Length || file[so + 3] == '.')) return file[..so];
        return Path.GetFileNameWithoutExtension(file);
    }

    private static uint CheckRva(INativeImage image, ulong value, string text) =>
        value < image.SizeOfImage ? (uint)value
            : throw new ToolError(ErrorCode.NotFound, $"{text} is outside {Path.GetFileName(image.Path)} (image base 0x{image.ImageBase:X}, size 0x{image.SizeOfImage:X}).",
                "addresses are RVAs or VAs within the image; use off:0x... for a file offset");

    private static uint VaToRva(INativeImage image, ulong value, string text) =>
        value >= image.ImageBase && value - image.ImageBase < image.SizeOfImage ? (uint)(value - image.ImageBase)
            : throw new ToolError(ErrorCode.NotFound, $"VA {text} is outside {Path.GetFileName(image.Path)} (0x{image.ImageBase:X}-0x{image.ImageBase + image.SizeOfImage:X}).");

    /// <summary>Whether <see cref="Parse"/> looks <paramref name="text"/> up as a name first: false for the rva:, va:, off: and offset: forms, 0x and #.</summary>
    public static bool IsName(string text)
    {
        var t = text.Trim();
        int colon = t.IndexOf(':');
        if (colon > 0 && t[..colon].ToLowerInvariant() is "rva" or "va" or "off" or "offset") return false;
        return !(t.StartsWith("0x", StringComparison.OrdinalIgnoreCase) || t.StartsWith('#')) || Number(t) == null;
    }

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
