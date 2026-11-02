using System.Reflection.Metadata;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>Assemblies loaded from a byte array listed and rebuilt from a minidump.</summary>
public sealed class InMemoryAssemblyTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>A fact skipped, with the reason, where the dump cannot be written.</summary>
    [Xunit.Sdk.XunitTestCaseDiscoverer(RunTimeSkips.FactDiscoverer, RunTimeSkips.Assembly)]
    private sealed class DumpFactAttribute : FactAttribute, IRunTimeSkip
    {
        public string? RunTimeSkip() => InMemoryAssemblyProgram.Unavailable;
    }

    [DumpFact]
    public void An_assembly_loaded_from_bytes_is_listed_as_managed()
    {
        using var dump = MinidumpFile.Open(InMemoryAssemblyProgram.WriteDump(_dir));
        var target = Assert.Single(ModuleRebuild.Select(dump, "Loaded.dll", default));
        Assert.Equal(ModuleOrigin.Managed, target.Origin);
        Assert.NotEqual(0UL, target.Base);
    }

    [DumpFact]
    public void The_rebuilt_assembly_opens_with_its_type()
    {
        using var dump = MinidumpFile.Open(InMemoryAssemblyProgram.WriteDump(_dir));
        var target = Assert.Single(ModuleRebuild.Select(dump, "Loaded.dll", default));
        var rebuilt = ModuleRebuild.Rebuild(dump, target, RebuildOptions.Default, default);
        Assert.NotNull(rebuilt.Bytes);
        var pe = PeFile.FromBytes(rebuilt.Bytes);
        Assert.True(pe.IsDotNet);
        using var provider = MetadataReaderProvider.FromMetadataImage(System.Runtime.InteropServices.ImmutableCollectionsMarshal.AsImmutableArray(MetadataBytes(pe)));
        var reader = provider.GetMetadataReader();
        Assert.Contains(reader.TypeDefinitions, h =>
        {
            var t = reader.GetTypeDefinition(h);
            return reader.GetString(t.Namespace) + "." + reader.GetString(t.Name) == InMemoryAssemblyProgram.LoadedType;
        });
    }

    private static byte[] MetadataBytes(PeFile pe)
    {
        var clr = pe.Directory(PeDirectory.ClrRuntimeHeader);
        Assert.True(pe.TryRvaToFileOffset(clr.Rva, out long at));
        var bytes = pe.FileBytes.Span;
        uint rva = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(bytes[((int)at + 8)..]);
        uint length = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(bytes[((int)at + 12)..]);
        Assert.True(pe.TryRvaToFileOffset(rva, out long md));
        return bytes.Slice((int)md, (int)length).ToArray();
    }
}
