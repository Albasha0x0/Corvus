using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Text;

namespace Corvus.Native.Go;

/// <summary>A Go module: path, version, go.sum hash, and what a replace directive substituted.</summary>
public sealed record GoModule(string Path, string Version, string? Sum, GoModule? Replace = null)
{
    public override string ToString() => $"{Path} {Version}" + (Replace != null ? $" => {Replace.Path} {Replace.Version}" : "");
}

/// <summary>One build setting (-ldflags, GOOS, GOARCH, CGO_ENABLED, vcs.revision, vcs.time, vcs.modified, ...).</summary>
public sealed record GoSetting(string Key, string Value);

/// <summary>Build information the Go linker embeds (Go 1.13+): toolchain version, main package, modules and build settings.</summary>
public sealed record GoBuildInfo(string GoVersion, string? Path, GoModule? Main, IReadOnlyList<GoModule> Dependencies, IReadOnlyList<GoSetting> Settings)
{
    private static ReadOnlySpan<byte> Magic => [0xFF, 0x20, 0x47, 0x6F, 0x20, 0x62, 0x75, 0x69, 0x6C, 0x64, 0x69, 0x6E, 0x66, 0x3A]; // "\xff Go buildinf:"
    private const int MaxString = 1 << 20;
    private const long MaxScan = 64L << 20;
    private static readonly ConditionalWeakTable<INativeImage, StrongBox<GoBuildInfo?>> Cache = new();

    /// <summary>The image's Go build information, or null when it has none (read once per image).</summary>
    public static GoBuildInfo? Of(INativeImage image) => Cache.GetValue(image, i => new StrongBox<GoBuildInfo?>(Find(i))).Value;

    /// <summary>A build setting's value, or null.</summary>
    public string? Setting(string key) => Settings.FirstOrDefault(s => s.Key == key)?.Value;

    private static GoBuildInfo? Find(INativeImage image)
    {
        try
        {
            var named = image.Sections.Where(s => s.Name is ".go.buildinfo" or "__go_buildinfo").ToList();
            foreach (var s in named)
                if (At(image, s.Rva) is { } info) return info;
            if (named.Count > 0) return null;
            long budget = MaxScan;
            var chunk = new byte[1 << 16];
            foreach (var s in image.Sections.Where(s => !s.IsExecutable))
            {
                long backed = image.FileBytesLength(s);
                uint start = (s.Rva + 15) & ~15u;
                for (long offset = start - s.Rva; offset < backed && budget > 0; offset += chunk.Length, budget -= chunk.Length)
                {
                    int n = image.Read(s.Rva + (uint)offset, chunk.AsSpan(0, (int)Math.Min(chunk.Length, backed - offset)));
                    for (int p = 0; p + 32 <= n; p += 16)
                        if (chunk[p] == 0xFF && chunk.AsSpan(p, 14).SequenceEqual(Magic) && At(image, s.Rva + (uint)offset + (uint)p) is { } info) return info;
                    if (n < chunk.Length) break;
                }
            }
        }
        catch (Exception ex) when (ex is ArgumentException or IndexOutOfRangeException or OverflowException) { }
        return null;
    }

    private static GoBuildInfo? At(INativeImage image, uint rva)
    {
        var header = new byte[32];
        if (image.Read(rva, header) < 32 || !header.AsSpan(0, 14).SequenceEqual(Magic)) return null;
        int ptr = header[14];
        bool bigEndian = (header[15] & 1) != 0;
        string? version, modinfo;
        if ((header[15] & 2) != 0)
        {
            // Go 1.18+: two varint-prefixed strings follow the header.
            uint at = rva + 32;
            version = Inline(image, ref at);
            modinfo = version != null ? Inline(image, ref at) : null;
        }
        else
        {
            if (ptr is not (4 or 8)) return null;
            version = Indirect(image, Pointer(header.AsSpan(16), ptr, bigEndian), ptr, bigEndian);
            modinfo = Indirect(image, Pointer(header.AsSpan(16 + ptr), ptr, bigEndian), ptr, bigEndian);
        }
        if (version == null || !version.StartsWith("go", StringComparison.Ordinal) && !version.StartsWith("devel", StringComparison.Ordinal)) return null;
        return Parse(version, modinfo ?? "");
    }

    private static ulong Pointer(ReadOnlySpan<byte> b, int ptr, bool bigEndian) => ptr == 8
        ? bigEndian ? BinaryPrimitives.ReadUInt64BigEndian(b) : BinaryPrimitives.ReadUInt64LittleEndian(b)
        : bigEndian ? BinaryPrimitives.ReadUInt32BigEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b);

    private static string? Inline(INativeImage image, ref uint at)
    {
        var prefix = new byte[10];
        int n = image.Read(at, prefix);
        ulong length = 0;
        int used = 0;
        while (used < n)
        {
            byte b = prefix[used];
            length |= (ulong)(b & 0x7F) << (7 * used++);
            if ((b & 0x80) == 0) break;
        }
        if (used == 0 || (prefix[used - 1] & 0x80) != 0 || length > MaxString) return null;
        var bytes = new byte[length];
        if (image.Read(at + (uint)used, bytes) < bytes.Length) return null;
        at += (uint)used + (uint)length;
        return Encoding.UTF8.GetString(bytes);
    }

    /// <summary>A Go string header (data pointer, length) at virtual address <paramref name="va"/>.</summary>
    private static string? Indirect(INativeImage image, ulong va, int ptr, bool bigEndian)
    {
        if (va < image.ImageBase || va - image.ImageBase >= image.SizeOfImage) return null;
        var head = new byte[2 * ptr];
        if (image.Read((uint)(va - image.ImageBase), head) < head.Length) return null;
        ulong data = Pointer(head, ptr, bigEndian), length = Pointer(head.AsSpan(ptr), ptr, bigEndian);
        if (length == 0) return "";
        if (length > MaxString || data < image.ImageBase || data - image.ImageBase >= image.SizeOfImage) return null;
        var bytes = new byte[length];
        return image.Read((uint)(data - image.ImageBase), bytes) < bytes.Length ? null : Encoding.UTF8.GetString(bytes);
    }

    /// <summary>Parses the module text runtime/debug.BuildInfo.String writes, inside its 16-byte start and end markers.</summary>
    internal static GoBuildInfo Parse(string version, string modinfo)
    {
        // The linker wraps the text in 16 marker bytes on each side.
        if (modinfo.Length >= 33 && modinfo[^17] == '\n') modinfo = modinfo[16..^16];
        string? path = null;
        GoModule? main = null;
        var deps = new List<GoModule>();
        var settings = new List<GoSetting>();
        foreach (var raw in modinfo.Split('\n'))
        {
            var f = raw.Split('\t');
            switch (f[0])
            {
                case "path" when f.Length >= 2: path = f[1]; break;
                case "mod" when f.Length >= 3: main = new GoModule(f[1], f[2], f.Length > 3 && f[3].Length > 0 ? f[3] : null); break;
                case "dep" when f.Length >= 3: deps.Add(new GoModule(f[1], f[2], f.Length > 3 && f[3].Length > 0 ? f[3] : null)); break;
                case "=>" when f.Length >= 3 && deps.Count > 0:
                    deps[^1] = deps[^1] with { Replace = new GoModule(f[1], f[2], f.Length > 3 && f[3].Length > 0 ? f[3] : null) };
                    break;
                case "build" when f.Length >= 2:
                    int eq = f[1].IndexOf('=');
                    if (eq > 0) settings.Add(new GoSetting(Unquote(f[1][..eq]), Unquote(f[1][(eq + 1)..])));
                    break;
            }
        }
        return new GoBuildInfo(version, path, main, deps, settings);
    }

    private static string Unquote(string s)
    {
        if (s.Length < 2 || s[0] != '"' || s[^1] != '"') return s;
        try { return System.Text.Json.JsonSerializer.Deserialize<string>(s) ?? s; }
        catch (System.Text.Json.JsonException) { return s; }
    }
}
