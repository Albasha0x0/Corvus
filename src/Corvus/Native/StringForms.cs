using System.Text.RegularExpressions;

namespace Corvus.Native;

/// <summary>
/// Which string forms besides NUL-terminated text an image's compiler emits: Rust &amp;str (a pointer and a byte length,
/// no terminator) and Swift small strings (held in two 64-bit immediates). PE and ELF only.
/// </summary>
internal static partial class StringForms
{
    /// <summary>Read-only data read for the rustc commit at most.</summary>
    private const int MaxScan = 64 << 20;

    private const int MaxSymbols = 50_000;

    /// <summary>True for a Rust build: Rust-mangled symbols, or the standard library's /rustc/&lt;commit&gt;/ source paths in its data.</summary>
    public static bool HasRustStrings(INativeImage image)
    {
        if (image.Format is not (ImageFormat.Pe or ImageFormat.Elf)) return false;
        var symbols = image.Symbols;
        for (int i = 0; i < symbols.Count && i < MaxSymbols; i++)
            if (RustSymbol().IsMatch(symbols[i].Name)) return true;
        int left = MaxScan;
        foreach (var s in image.Sections)
        {
            if (s.IsExecutable || s.RawSize == 0 || left <= 0) continue;
            var bytes = new byte[Math.Min(s.RawSize, (uint)left)];
            int n = image.Read(s.Rva, bytes);
            left -= n;
            if (RustcCommit(bytes.AsSpan(0, n)) != null) return true;
        }
        return false;
    }

    /// <summary>True for a Swift build: it loads the Swift runtime (swiftCore.dll, libswiftCore.so) or has Swift metadata sections (a static executable).</summary>
    public static bool HasSwiftStrings(INativeImage image) =>
        image.Format is ImageFormat.Pe or ImageFormat.Elf
        && (image.Imports.Any(i => IsSwiftCore(i.Module)) || image.Dependencies.Any(IsSwiftCore)
            || image.Sections.Any(s => s.Name.StartsWith("swift5_", StringComparison.Ordinal) || s.Name.StartsWith(".sw5", StringComparison.Ordinal)));

    private static bool IsSwiftCore(string module) =>
        Path.GetFileName(module) is var name
        && (name.StartsWith("swiftCore.", StringComparison.OrdinalIgnoreCase) || name.StartsWith("libswiftCore.", StringComparison.Ordinal));

    /// <summary>The 40-digit commit after "/rustc/" that most paths name (the standard library's own panic locations); null when none.</summary>
    public static string? RustcCommit(ReadOnlySpan<byte> bytes)
    {
        var counts = new Dictionary<string, int>();
        for (int at = 0, i; (i = bytes[at..].IndexOf("/rustc/"u8)) >= 0 && counts.Count < 16; at += i + 7)
        {
            int start = at + i + 7;
            if (start + 41 > bytes.Length || !IsHex(bytes.Slice(start, 40)) || bytes[start + 40] is not ((byte)'/' or (byte)'\\')) continue;
            var c = System.Text.Encoding.ASCII.GetString(bytes.Slice(start, 40));
            counts[c] = counts.GetValueOrDefault(c) + 1;
        }
        return counts.Count == 0 ? null : counts.MaxBy(kv => kv.Value).Key;
    }

    private static bool IsHex(ReadOnlySpan<byte> s)
    {
        foreach (var c in s)
            if (!char.IsAsciiHexDigitLower((char)c) && !char.IsAsciiDigit((char)c)) return false;
        return true;
    }

    // Legacy mangling ends in a 16-digit hash (17h...E); v0 mangling starts with _R and an uppercase tag.
    [GeneratedRegex(@"^_?_ZN.*17h[0-9a-f]{16}E$|^_?_R[A-Z]", RegexOptions.CultureInvariant)]
    private static partial Regex RustSymbol();
}
