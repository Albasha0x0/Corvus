using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump;

/// <summary>Whether the managed metadata of an image rebuilt from a dump can be read: readable, partial or unreadable, with the reason.</summary>
public sealed record ManagedMetadataState(string State, string? Reason);

/// <summary>Checks the compiled metadata of a module image rebuilt from dump memory.</summary>
public static class DumpManagedMetadata
{
    private const uint RootSignature = 0x424A5342;
    private const int ClrHeaderSize = 72;

    /// <summary>Returns the metadata state of a .NET image, or null for a native image.</summary>
    /// <remarks>The image must be in mapped layout, as <see cref="DumpImages.FromMemory"/> builds it, so an RVA is an offset. A malformed image is reported unreadable, never thrown.</remarks>
    public static ManagedMetadataState? Inspect(PeFile image)
    {
        if (!image.IsDotNet) return null;
        try { return InspectCore(image); }
        catch (Exception ex) when (ex is not OperationCanceledException) { return Unreadable($"the metadata is not valid: {ex.Message}"); }
    }

    /// <summary>Returns the metadata state of the module's image rebuilt from <paramref name="memory"/>; null for a native module, unknown when the header or image is not in the dump.</summary>
    /// <remarks>With <paramref name="notRebuilt"/>, a .NET module is reported unknown with that reason instead of being rebuilt.</remarks>
    public static ManagedMetadataState? Inspect(IProcessMemory memory, DumpModule module, string? notRebuilt = null)
    {
        var head = new byte[0x1000];
        if (memory.ReadMemory(module.Base, head) < 0x200) return Unknown("the dump does not hold the module header");
        if (!DumpImages.TryHeader(head, out _, out _, out bool dotNet)) return Unknown("the module header is not a PE header");
        if (!dotNet) return null;
        if (notRebuilt != null) return Unknown(notRebuilt);
        if (module.Size > DumpModuleExport.MaxImageBytes) return Unknown($"the image is larger than {DumpModuleExport.MaxImageBytes >> 20} MB: not rebuilt");
        var image = DumpImages.FromMemory(memory, module, out _);
        return image == null ? Unknown("the dump does not hold the image headers") : Inspect(image);
    }

    private static ManagedMetadataState Unknown(string reason) => new("unknown", reason);

    private static ManagedMetadataState InspectCore(PeFile image)
    {
        var bytes = image.FileBytes.Span;
        var clr = image.Directory(PeDirectory.ClrRuntimeHeader);
        if (clr.Rva > bytes.Length || bytes.Length - clr.Rva < ClrHeaderSize)
            return Unreadable("the CLR header lies outside the captured image");
        var header = bytes.Slice((int)clr.Rva, ClrHeaderSize);
        if (header.IndexOfAnyExcept((byte)0) < 0) return Unreadable("the CLR header is zero-filled: its page was not captured");
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(header);
        if (size != ClrHeaderSize) return Unreadable($"the CLR header size is {size}, not {ClrHeaderSize}");
        uint rva = BinaryPrimitives.ReadUInt32LittleEndian(header[8..]);
        uint length = BinaryPrimitives.ReadUInt32LittleEndian(header[12..]);
        if (rva == 0 || length == 0) return Unreadable("the CLR header has no metadata directory");
        if (rva >= bytes.Length) return Unreadable("the metadata block lies outside the captured image");
        int held = (int)Math.Min(length, (uint)(bytes.Length - rva));
        var block = bytes.Slice((int)rva, held);
        if (block.Length < 16)
            return Unreadable(held == length ? $"the metadata directory length is {length}, below the 16-byte root" : $"only {held} bytes of the metadata block were captured");
        if (block[..16].IndexOfAnyExcept((byte)0) < 0) return Unreadable("the metadata root is zero-filled");
        uint signature = BinaryPrimitives.ReadUInt32LittleEndian(block);
        if (signature != RootSignature) return Unreadable($"the metadata root signature is 0x{signature:X8}, not BSJB");
        if (!TryStreams(block, out var streams)) return Unreadable("the metadata stream headers are cut or not valid");
        int tables = streams.FindIndex(s => s.Name is "#~" or "#-");
        if (tables < 0) return Unreadable("the metadata has no tables stream");
        string Where(Stream s) => $"{s.Name} cut at {Math.Clamp(held - s.Offset, 0, s.Size)} of {s.Size} bytes";
        if (streams[tables].Offset + streams[tables].Size > held)
            return Unreadable(held < length ? $"{held} of {length} metadata bytes were captured; {Where(streams[tables])}" : $"the metadata directory length {length} ends inside {Where(streams[tables])}");
        var cut = streams.Where(s => s.Offset + s.Size > held).OrderBy(s => s.Offset).Cast<Stream?>().FirstOrDefault();
        if (cut is { } first)
            return new ManagedMetadataState("partial", held < length
                ? $"{held} of {length} metadata bytes were captured; the tables read, {Where(first)}"
                : $"the metadata directory length {length} ends inside {Where(first)}; the tables read");
        using var provider = MetadataReaderProvider.FromMetadataImage(System.Runtime.InteropServices.ImmutableCollectionsMarshal.AsImmutableArray(block.ToArray()));
        _ = provider.GetMetadataReader().GetTableRowCount(TableIndex.TypeDef);
        return new ManagedMetadataState("readable", null);
    }

    private readonly record struct Stream(string Name, long Offset, long Size);

    private static bool TryStreams(ReadOnlySpan<byte> block, out List<Stream> streams)
    {
        streams = [];
        uint versionLength = BinaryPrimitives.ReadUInt32LittleEndian(block[12..]);
        long at = 16L + versionLength;
        if (at + 4 > block.Length) return false;
        int count = BinaryPrimitives.ReadUInt16LittleEndian(block[(int)(at + 2)..]);
        at += 4;
        for (int i = 0; i < count; i++)
        {
            if (at + 9 > block.Length) return false;
            var entry = block[(int)at..];
            int end = entry[8..].IndexOf((byte)0);
            if (end < 0) return false;
            streams.Add(new Stream(System.Text.Encoding.ASCII.GetString(entry.Slice(8, end)), BinaryPrimitives.ReadUInt32LittleEndian(entry), BinaryPrimitives.ReadUInt32LittleEndian(entry[4..])));
            at += 8 + ((end + 1 + 3) & ~3);
        }
        return true;
    }

    private static ManagedMetadataState Unreadable(string reason) => new("unreadable", reason);
}
