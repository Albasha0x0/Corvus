using System.Buffers.Binary;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using dnlib.DotNet;
using dnlib.DotNet.Writer;

namespace Corvus.Core;

/// <summary>Writes a generated module deterministically: MVID and timestamp come from a hash, as a deterministic build sets them.</summary>
/// <remarks>Edited assemblies keep the original's MVID and timestamp instead, so they stay bound to their build.</remarks>
public static class DeterministicModule
{
    public static byte[] Write(ModuleDef module, ILogger logger)
    {
        module.Mvid = Guid.Empty;
        var options = new ModuleWriterOptions(module) { Logger = logger };
        options.PEHeadersOptions.TimeDateStamp = 0;
        byte[] image;
        using (var stream = new MemoryStream())
        {
            module.Write(stream, options);
            image = stream.ToArray();
        }
        var hash = SHA256.HashData(image);
        var mvid = new Guid(hash.AsSpan(0, 16));
        // High bit set, as Roslyn marks a deterministic timestamp that is not a time.
        uint stamp = BinaryPrimitives.ReadUInt32LittleEndian(hash.AsSpan(16)) | 0x8000_0000;
        int mvidOffset, stampOffset;
        using (var pe = new PEReader(new MemoryStream(image)))
        {
            var md = pe.GetMetadataReader();
            int index = MetadataTokens.GetHeapOffset(md.GetModuleDefinition().Mvid);
            mvidOffset = pe.PEHeaders.MetadataStartOffset + md.GetHeapMetadataOffset(HeapIndex.Guid) + (index - 1) * 16;
            stampOffset = pe.PEHeaders.CoffHeaderStartOffset + 4;
        }
        mvid.TryWriteBytes(image.AsSpan(mvidOffset, 16));
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(stampOffset), stamp);
        module.Mvid = mvid;
        return image;
    }
}
