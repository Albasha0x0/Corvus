using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Reopens a rebuilt PE file with the PE and metadata readers.</summary>
public static class PeVerify
{
    private const int ClrHeaderSize = 72;
    private const uint MetadataSignature = 0x424A5342;

    /// <summary>Adds the parse check, failed when the PE or the CLR header cannot be read; the managed metadata state of a .NET image, else null.</summary>
    public static ManagedMetadataState? Check(byte[] bytes, RebuildTarget target, List<RebuildCheck> checks)
    {
        try
        {
            var pe = PeFile.FromBytes(bytes, target.Name);
            string? problem = ClrHeaderProblem(pe);
            checks.Add(problem == null
                ? RebuildCheck.Ok("parse", $"{pe.Sections.Count} sections read back")
                : RebuildCheck.Failed("parse", problem));
            return DumpManagedMetadata.Inspect(pe);
        }
        catch (ToolError e)
        {
            checks.Add(RebuildCheck.Failed("parse", e.Message));
            return null;
        }
    }

    /// <summary>Names why the CLR header of a .NET image is invalid; null for a valid header or a native image.</summary>
    public static string? ClrHeaderProblem(PeFile pe)
    {
        var clr = pe.Directory(PeDirectory.ClrRuntimeHeader);
        if (clr.Rva == 0) return null;
        var bytes = pe.FileBytes.Span;
        if (!pe.TryRvaToFileOffset(clr.Rva, out long at) || bytes.Length - at < ClrHeaderSize)
            return $"the CLR header at RVA 0x{clr.Rva:X} lies outside the image";
        var header = bytes.Slice((int)at, ClrHeaderSize);
        uint cb = BinaryPrimitives.ReadUInt32LittleEndian(header);
        if (cb != ClrHeaderSize) return $"the CLR header size is {cb}, not {ClrHeaderSize}";
        uint rva = BinaryPrimitives.ReadUInt32LittleEndian(header[8..]);
        if (rva == 0) return "the CLR header has no metadata directory";
        if (rva >= pe.SizeOfImage || !pe.TryRvaToFileOffset(rva, out long root))
            return $"the metadata RVA 0x{rva:X} lies outside the image";
        if (bytes.Length - root < 4) return $"the metadata at RVA 0x{rva:X} is cut";
        uint signature = BinaryPrimitives.ReadUInt32LittleEndian(bytes[(int)root..]);
        return signature == MetadataSignature ? null : $"the metadata signature is 0x{signature:X8}, not BSJB";
    }
}
