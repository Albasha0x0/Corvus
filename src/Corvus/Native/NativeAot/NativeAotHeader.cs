namespace Corvus.Native.NativeAot;

/// <summary>One row of a NativeAOT ReadyToRun header: a module section [Start, End) by RVA.</summary>
public sealed record NativeAotSection(int Id, uint Flags, uint StartRva, uint EndRva)
{
    /// <summary>Row flag bit 0: the row has an end (TypeManagerIndirection has none).</summary>
    public bool HasEnd => (Flags & 1) != 0;
    public uint Length => HasEnd ? EndRva - StartRva : 0;
    public string Name => NativeAotFormats.SectionName(Id);
    public bool IsBlob => Id is >= SectionId.BlobBase and <= SectionId.BlobLast;
}

/// <summary>A NativeAOT module header ("RTR\0") with its section rows.</summary>
public sealed class NativeAotHeader(uint rva, ushort major, ushort minor, uint flags, IReadOnlyList<NativeAotSection> sections, bool relocated)
{
    public uint Rva { get; } = rva;
    public ushort MajorVersion { get; } = major;
    public ushort MinorVersion { get; } = minor;
    public uint Flags { get; } = flags;
    public IReadOnlyList<NativeAotSection> Sections { get; } = sections;
    /// <summary>Every row start carries a base relocation (false for images without relocations).</summary>
    public bool Relocated { get; } = relocated;
    public NativeAotFormat Format { get; } = NativeAotFormats.For(major);

    public NativeAotSection? Section(int id) => Sections.FirstOrDefault(s => s.Id == id);

    /// <summary>The ReflectionMapBlob <paramref name="blobId"/> (section 300 + id), or null when absent or empty.</summary>
    public NativeAotSection? Blob(int blobId) => Section(SectionId.BlobBase + blobId) is { HasEnd: true, Length: > 0 } s ? s : null;

    public bool IsDehydrated => Section(SectionId.DehydratedData) is { Length: > 0 };
}
