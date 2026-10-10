namespace NetDecompilerMcp.Native.NativeAot;

/// <summary>Record layouts and handle encodings of the NativeFormat metadata (Internal.Metadata.NativeFormat).</summary>
public enum MetadataDialect
{
    /// <summary>.NET 7 and 8: ConstantBoxedEnumValue, tokens type &lt;&lt; 24, record handles type in the low byte.</summary>
    Net7,
    /// <summary>.NET 9: ConstantEnumValue replaces ConstantBoxedEnumValue (handle types renumbered).</summary>
    Net9,
    /// <summary>.NET 10: tokens type &lt;&lt; 25, record handles type in the low 7 bits.</summary>
    Net10,
    /// <summary>.NET 11 development: TypeDefinition and TypeReference carry one namespace-or-enclosing-type handle.</summary>
    Net11,
}

/// <summary>MethodTable (EEType) layout generation.</summary>
public enum MethodTableLayout
{
    /// <summary>u16 component size + u16 flags; optional fields; interface map entries are pointers.</summary>
    Net7,
    /// <summary>u32 flags; optional fields pointer in the tail.</summary>
    Net8,
    /// <summary>u32 flags; no optional fields (padding, nullable offset and align8 in the extended flags).</summary>
    Net9,
}

/// <summary>Header of the DehydratedData section (207).</summary>
public enum RehydrationFormat
{
    /// <summary>i32 relptr to the destination, commands up to the section end, fixups after it (.NET 8–10).</summary>
    EndBounded,
    /// <summary>i32 relptr, i32 length of header and commands, fixups after them (.NET 11).</summary>
    LengthPrefixed,
}

/// <summary>Layout of the StackTraceMethodRvaToTokenMapping blob (27).</summary>
public enum StackTraceFormat
{
    /// <summary>{i32 relptr to code; i32 metadata token} pairs (.NET 7).</summary>
    Pairs,
    /// <summary>i32 count, then command byte, operands, i32 relptr per method (.NET 8+).</summary>
    Commands,
}

/// <summary>
/// The format facts of one NativeAOT compiler generation, keyed by the ReadyToRun header major version
/// (ModuleHeaders.cs CurrentMajorVersion at each dotnet/runtime release tag).
/// </summary>
public sealed record NativeAotFormat(ushort RtrMajor, string Runtime, MetadataDialect Metadata, MethodTableLayout Layout,
    RehydrationFormat Rehydration, StackTraceFormat StackTrace, bool InvokeMapAlwaysHasMethodHandle)
{
    /// <summary>False when the header major is not one of the known releases and the nearest lower one is assumed.</summary>
    public bool Exact { get; init; } = true;

    /// <summary>Token shift of a full metadata handle (type &lt;&lt; shift | offset).</summary>
    public int TokenShift => Metadata >= MetadataDialect.Net10 ? 25 : 24;

    /// <summary>Bits of the handle type in a handle stored inside a record.</summary>
    public int RecordHandleTypeBits => Metadata >= MetadataDialect.Net10 ? 7 : 8;
}

/// <summary>Version-specific NativeAOT facts in one place.</summary>
public static class NativeAotFormats
{
    private static readonly NativeAotFormat[] Known =
    [
        new(8, ".NET 7", MetadataDialect.Net7, MethodTableLayout.Net7, RehydrationFormat.EndBounded, StackTraceFormat.Pairs, false),
        new(9, ".NET 8", MetadataDialect.Net7, MethodTableLayout.Net8, RehydrationFormat.EndBounded, StackTraceFormat.Commands, false),
        new(10, ".NET 9", MetadataDialect.Net9, MethodTableLayout.Net9, RehydrationFormat.EndBounded, StackTraceFormat.Commands, false),
        new(16, ".NET 10", MetadataDialect.Net10, MethodTableLayout.Net9, RehydrationFormat.EndBounded, StackTraceFormat.Commands, true),
        new(31, ".NET 11 (development)", MetadataDialect.Net11, MethodTableLayout.Net9, RehydrationFormat.LengthPrefixed, StackTraceFormat.Commands, true),
    ];

    /// <summary>The format of <paramref name="rtrMajor"/>; an unknown major gets the nearest known one with <see cref="NativeAotFormat.Exact"/> false.</summary>
    public static NativeAotFormat For(ushort rtrMajor)
    {
        var lower = Known.LastOrDefault(f => f.RtrMajor <= rtrMajor) ?? Known[0];
        return lower.RtrMajor == rtrMajor ? lower : lower with { Exact = false };
    }

    /// <summary>The release that writes DotNetRuntimeDebugHeader major <paramref name="major"/>, or null.</summary>
    public static string? RuntimeOfDebugHeader(int major) => major switch
    {
        1 => ".NET 7",
        3 => ".NET 8",
        4 => ".NET 9",
        5 => ".NET 10",
        _ => null,
    };

    /// <summary>ReadyToRunSectionType values of NativeAOT modules (ModuleHeaders.cs).</summary>
    public static string SectionName(int id) => id switch
    {
        200 => "StringTable",
        201 => "GCStaticRegion",
        202 => "ThreadStaticRegion",
        203 => "InterfaceDispatchTable",
        204 => "TypeManagerIndirection",
        205 => "EagerCctor",
        206 => "FrozenObjectRegion",
        207 => "DehydratedData",
        208 => "ThreadStaticOffsetRegion",
        209 => "InterfaceDispatchCellInfoRegion",
        210 => "InterfaceDispatchCellRegion",
        212 => "ImportAddressTables",
        213 => "ModuleInitializerList",
        214 => "GvmDispatchCellInfoRegion",
        215 => "GvmDispatchCellRegion",
        >= SectionId.BlobBase and <= SectionId.BlobLast => BlobName(id - SectionId.BlobBase),
        _ => $"section {id}",
    };

    /// <summary>ReflectionMapBlob values (MetadataBlob.cs); a blob is section 300 + id.</summary>
    public static string BlobName(int blob) => blob switch
    {
        BlobId.TypeMap => "TypeMap",
        2 => "ArrayMap",
        3 => "PointerTypeMap",
        4 => "FunctionPointerTypeMap",
        BlobId.InvokeMap => "InvokeMap",
        7 => "VirtualInvokeMap",
        BlobId.CommonFixupsTable => "CommonFixupsTable",
        9 => "FieldAccessMap",
        10 => "CCtorContextMap",
        11 => "ByRefTypeMap",
        BlobId.EmbeddedMetadata => "EmbeddedMetadata",
        16 => "StructMarshallingStubMap",
        17 => "DelegateMarshallingStubMap",
        18 => "GenericVirtualMethodTable",
        19 => "InterfaceGenericVirtualMethodTable",
        21 => "TypeTemplateMap",
        22 => "GenericMethodsTemplateMap",
        24 => "BlobIdResourceIndex",
        25 => "BlobIdResourceData",
        26 => "BlobIdStackTraceEmbeddedMetadata",
        BlobId.StackTraceMethodRvaToTokenMapping => "StackTraceMethodRvaToTokenMapping",
        28 => "StackTraceLineNumbers",
        29 => "StackTraceDocuments",
        30 => "NativeLayoutInfo",
        31 => "NativeReferences",
        32 => "GenericsHashtable",
        33 => "NativeStatics",
        34 => "StaticsInfoHashtable",
        35 => "GenericMethodsHashtable",
        36 => "ExactMethodInstantiationsHashtable",
        _ => $"blob {blob}",
    };
}

/// <summary>Section ids of the NativeAOT ReadyToRun header used by the reader.</summary>
public static class SectionId
{
    public const int FrozenObjectRegion = 206;
    public const int DehydratedData = 207;
    public const int BlobBase = 300;
    public const int BlobLast = 399;
}

/// <summary>ReflectionMapBlob ids used by the reader.</summary>
public static class BlobId
{
    public const int TypeMap = 1;
    public const int InvokeMap = 6;
    public const int CommonFixupsTable = 8;
    public const int EmbeddedMetadata = 13;
    public const int StackTraceMethodRvaToTokenMapping = 27;
}
