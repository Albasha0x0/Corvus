using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native.Pe;

namespace Corvus.Native;

/// <summary>What a file's first bytes say it is.</summary>
public enum NativeFileKind
{
    Unknown,
    Pe,
    Elf,
    MachO,
    /// <summary>A universal (fat) Mach-O holding several slices.</summary>
    MachOFat,
    /// <summary>A WebAssembly module (not Webcil, which wraps a .NET PE).</summary>
    Wasm,
}

/// <summary>One container format the loader detects by its first bytes and opens.</summary>
public interface INativeFormatProvider
{
    NativeFileKind Kind { get; }
    bool Detect(ReadOnlySpan<byte> head);
    INativeImage Open(string path, string? slice);
    INativeImage FromBytes(ReadOnlySpan<byte> bytes, string path);
}

/// <summary>Opens a native image by its content rather than its name, through the format-provider registry.</summary>
public static class NativeImageLoader
{
    private delegate bool DetectBytes(ReadOnlySpan<byte> head);
    private delegate INativeImage ReadBytes(ReadOnlySpan<byte> bytes, string path);

    private sealed class Provider(NativeFileKind kind, DetectBytes detect, Func<string, string?, INativeImage> open, ReadBytes fromBytes) : INativeFormatProvider
    {
        public NativeFileKind Kind => kind;
        public bool Detect(ReadOnlySpan<byte> head) => detect(head);
        public INativeImage Open(string path, string? slice) => open(path, slice);
        public INativeImage FromBytes(ReadOnlySpan<byte> bytes, string path) => fromBytes(bytes, path);
    }

    /// <summary>The registered formats, in detection order; a new format is one entry here.</summary>
    public static readonly IReadOnlyList<INativeFormatProvider> Providers =
    [
        new Provider(NativeFileKind.Pe, h => h.Length >= 2 && h[0] == 'M' && h[1] == 'Z', (p, _) => PeFile.Open(p), (b, p) => PeFile.FromBytes(b, p)),
        new Provider(NativeFileKind.Elf, h => h.Length >= 4 && h[0] == 0x7F && h[1] == 'E' && h[2] == 'L' && h[3] == 'F', (p, _) => Elf.ElfFile.Open(p), (b, p) => Elf.ElfFile.FromBytes(b, p)),
        new Provider(NativeFileKind.MachO, h => h.Length >= 4 && BinaryPrimitives.ReadUInt32BigEndian(h) is 0xFEEDFACE or 0xFEEDFACF or 0xCEFAEDFE or 0xCFFAEDFE,
            (p, s) => MachO.MachOFile.Open(p, s), (b, p) => MachO.MachOFile.FromBytes(b, p)),
        new Provider(NativeFileKind.MachOFat, IsFat, (p, s) => MachO.MachOFile.Open(p, s), (b, p) => MachO.MachOFile.FromBytes(b, p)),
        new Provider(NativeFileKind.Wasm, h => Core.WebAssembly.WasmBinary.Looks(h), (p, _) => WasmImage.Open(p), (b, p) => new WasmImage(b.ToArray(), p)),
    ];

    /// <summary>0xCAFEBABE is also the Java class magic, so a fat header counts only with fewer than 64 slices whose first CPU type is a Mach-O one.</summary>
    private static bool IsFat(ReadOnlySpan<byte> head)
    {
        if (head.Length < 12 || BinaryPrimitives.ReadUInt32BigEndian(head) is not (0xCAFEBABE or 0xCAFEBABF)) return false;
        uint count = BinaryPrimitives.ReadUInt32BigEndian(head[4..]);
        uint cpu = BinaryPrimitives.ReadUInt32BigEndian(head[8..]);
        return count is > 0 and < 64 && (cpu & 0x00FFFFFF) is 7 or 12 or 18;
    }

    /// <summary>The container format at the start of <paramref name="head"/>.</summary>
    public static NativeFileKind Detect(ReadOnlySpan<byte> head)
    {
        if (head.Length < 4) return NativeFileKind.Unknown;
        foreach (var p in Providers)
            if (p.Detect(head)) return p.Kind;
        return NativeFileKind.Unknown;
    }

    private static INativeFormatProvider? Of(NativeFileKind kind) => Providers.FirstOrDefault(p => p.Kind == kind);

    /// <summary>Opens the image at <paramref name="path"/> by content; anything unrecognized fails as "not a PE file".</summary>
    public static INativeImage Open(string path, string? slice = null)
    {
        var kind = DetectFile(path);
        if (slice != null && kind != NativeFileKind.MachOFat)
            throw new ToolError(ErrorCode.InvalidArgument, $"slice '{slice}' applies to universal Mach-O files only.", "omit slice");
        return (Of(kind) ?? Of(NativeFileKind.Pe)!).Open(path, slice);
    }

    /// <summary>The image in <paramref name="bytes"/>; anything unrecognized fails as "not a PE file".</summary>
    public static INativeImage FromBytes(ReadOnlySpan<byte> bytes, string path = "") => (Of(Detect(bytes)) ?? Of(NativeFileKind.Pe)!).FromBytes(bytes, path);

    /// <summary>The container format of the file at <paramref name="path"/>; Unknown when it cannot be read.</summary>
    public static NativeFileKind DetectFile(string path)
    {
        var full = InputFiles.RequireRegularFile(path, "image file");
        try
        {
            using var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            Span<byte> head = stackalloc byte[16];
            return Detect(head[..stream.ReadAtLeast(head, head.Length, throwOnEndOfStream: false)]);
        }
        // PeFile.Open reports the path problem.
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return NativeFileKind.Unknown;
        }
    }
}
