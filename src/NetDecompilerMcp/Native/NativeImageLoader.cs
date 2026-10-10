using System.Buffers.Binary;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Native;

/// <summary>What a file's first bytes say it is.</summary>
public enum NativeFileKind
{
    Unknown,
    Pe,
    Elf,
    MachO,
    /// <summary>A universal (fat) Mach-O holding several slices.</summary>
    MachOFat,
}

/// <summary>Opens a native image by its content rather than its name.</summary>
public static class NativeImageLoader
{
    /// <summary>
    /// The container format at the start of <paramref name="head"/>. 0xCAFEBABE is also the Java class magic, so a fat
    /// header counts only with fewer than 64 slices whose first CPU type is a Mach-O one.
    /// </summary>
    public static NativeFileKind Detect(ReadOnlySpan<byte> head)
    {
        if (head.Length < 4) return NativeFileKind.Unknown;
        if (head[0] == 'M' && head[1] == 'Z') return NativeFileKind.Pe;
        if (head[0] == 0x7F && head[1] == 'E' && head[2] == 'L' && head[3] == 'F') return NativeFileKind.Elf;
        uint be = BinaryPrimitives.ReadUInt32BigEndian(head);
        if (be is 0xFEEDFACE or 0xFEEDFACF or 0xCEFAEDFE or 0xCFFAEDFE) return NativeFileKind.MachO;
        if (be is 0xCAFEBABE or 0xCAFEBABF && head.Length >= 12)
        {
            uint count = BinaryPrimitives.ReadUInt32BigEndian(head[4..]);
            uint cpu = BinaryPrimitives.ReadUInt32BigEndian(head[8..]);
            if (count is > 0 and < 64 && (cpu & 0x00FFFFFF) is 7 or 12 or 18) return NativeFileKind.MachOFat;
        }
        return NativeFileKind.Unknown;
    }

    /// <summary>
    /// Opens the image at <paramref name="path"/>. PE images (and anything unrecognized, which fails as "not a PE file")
    /// are read; ELF and Mach-O images are recognized and refused until their load path is enabled.
    /// </summary>
    public static INativeImage Open(string path, string? slice = null)
    {
        var kind = DetectFile(path);
        if (slice != null && kind != NativeFileKind.MachOFat)
            throw new ToolError(ErrorCode.InvalidArgument, $"slice '{slice}' applies to universal Mach-O files only.", "omit slice");
        return kind switch
        {
            NativeFileKind.Elf or NativeFileKind.MachO or NativeFileKind.MachOFat => throw NotLoaded(path, kind),
            _ => PeFile.Open(path),
        };
    }

    private static NativeFileKind DetectFile(string path)
    {
        var full = InputFiles.RequireRegularFile(path, "image file");
        try
        {
            using var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            Span<byte> head = stackalloc byte[16];
            return Detect(head[..stream.ReadAtLeast(head, head.Length, throwOnEndOfStream: false)]);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return NativeFileKind.Unknown; // PeFile.Open reports the path problem
        }
    }

    private static ToolError NotLoaded(string path, NativeFileKind kind)
    {
        var format = kind == NativeFileKind.Elf ? "ELF" : "Mach-O";
        return new ToolError(ErrorCode.Unsupported, $"{System.IO.Path.GetFileName(path)} is a {format} image; only PE images are loaded as native images so far.",
            "load a Windows PE image, or open the file in an analysis engine")
        { Details = new { reason = "format_not_loaded", format = kind.ToString() } };
    }
}
