namespace NetDecompilerMcp.Native.NativeAot;

/// <summary>Outcome of one recovery stage: complete, partial, absent or unsupported, with the reason.</summary>
public sealed record NativeAotStage(string Name, string Status, string? Detail = null)
{
    public const string Complete = "complete";
    public const string Partial = "partial";
    public const string Absent = "absent";
    public const string Unsupported = "unsupported";
}

public sealed record NativeAotSectionInfo(int Id, string Name, uint Rva, uint Size);

/// <summary>What a NativeAOT image reveals: runtime version, header, sections and the outcome of each recovery stage.</summary>
public sealed record NativeAotSummary(string Runtime, string ReadyToRunVersion, int? DebugHeaderVersion, bool Dehydrated, uint HeaderRva,
    int Modules, IReadOnlyList<NativeAotSectionInfo> Sections, IReadOnlyList<NativeAotStage> Stages, IReadOnlyDictionary<string, int> Counts);

/// <summary>
/// The NativeAOT view of a native image. <see cref="Open"/> only locates the module header; the recovery stages run on
/// first use and are cached. Reads only mapped bytes; never executes or patches the image.
/// </summary>
public sealed class NativeAotImage
{
    private NativeAotImage(INativeImage image, IReadOnlyList<NativeAotHeader> headers, int? debugHeaderMajor)
    {
        Image = image;
        Headers = headers;
        Header = headers[0];
        DebugHeaderMajor = debugHeaderMajor;
        metadata = new(ReadMetadata);
        hydrated = new(() => HydratedImage.Create(image, Header));
        names = new(() => NativeAotNameMaps.Read(this));
        types = new(() => NativeAotTypes.Read(this));
    }

    /// <summary>Largest blob read into memory.</summary>
    private const int MaxBlobBytes = 256 << 20;
    private readonly Lazy<(NativeAotMetadata? Metadata, NativeAotStage Stage)> metadata;
    private readonly Lazy<HydratedImage> hydrated;
    private readonly Lazy<NativeAotNameMaps> names;
    private readonly Lazy<NativeAotTypes> types;

    public INativeImage Image { get; }
    /// <summary>The module analyzed (the first header found); <see cref="Headers"/> lists every module of a multi-module image.</summary>
    public NativeAotHeader Header { get; }
    public IReadOnlyList<NativeAotHeader> Headers { get; }
    public int? DebugHeaderMajor { get; }
    public NativeAotFormat Format => Header.Format;

    /// <summary>The NativeAOT view of <paramref name="image"/>, or null when it has no NativeAOT module header.</summary>
    public static NativeAotImage? Open(INativeImage image, CancellationToken ct = default)
    {
        var headers = NativeAotLocator.Find(image, ct);
        return headers.Count == 0 ? null : new NativeAotImage(image, headers, NativeAotLocator.DebugHeaderMajor(image));
    }

    /// <summary>The runtime release: from the header version, else from the debug header, else the nearest known layout.</summary>
    public string Runtime
    {
        get
        {
            if (Format.Exact) return Format.Runtime;
            if (DebugHeaderMajor is { } d && NativeAotFormats.RuntimeOfDebugHeader(d) is { } fromDebug) return fromDebug;
            return $"unknown (read with the {Format.Runtime} layout)";
        }
    }

    /// <summary>The EmbeddedMetadata reader, or null when the blob is absent or unreadable (see the "metadata" stage).</summary>
    public NativeAotMetadata? Metadata => metadata.Value.Metadata;

    /// <summary>The image with dehydrated data expanded and its pointer slots (see the "rehydration" stage).</summary>
    public HydratedImage Hydrated => hydrated.Value;

    /// <summary>Method and type names from the stack-trace, type and invoke maps.</summary>
    public NativeAotNameMaps Names => names.Value;

    /// <summary>The MethodTables found and their names (see the "method tables" stage).</summary>
    public NativeAotTypes Types => types.Value;

    /// <summary>The bytes of a module section, or null when it is empty, too large or not fully mapped.</summary>
    public byte[]? ReadSection(NativeAotSection? section)
    {
        if (section is not { HasEnd: true, Length: > 0 and <= MaxBlobBytes }) return null;
        var bytes = new byte[section.Length];
        return Image.Read(section.StartRva, bytes) == bytes.Length ? bytes : null;
    }

    private (NativeAotMetadata?, NativeAotStage) ReadMetadata()
    {
        const string name = "metadata";
        var blob = Header.Blob(BlobId.EmbeddedMetadata);
        if (blob == null) return (null, new(name, NativeAotStage.Absent, "no EmbeddedMetadata blob"));
        if (ReadSection(blob) is not { } bytes) return (null, new(name, NativeAotStage.Partial, $"the {blob.Length}-byte EmbeddedMetadata blob is not mapped or too large"));
        try
        {
            var md = new NativeAotMetadata(bytes, Format);
            int types = md.TypeDefinitions().Count;
            return (md, new(name, Format.Exact ? NativeAotStage.Complete : NativeAotStage.Partial,
                $"{md.ScopeDefinitions.Count} scope(s), {types} type definitions, {bytes.Length} bytes ({Format.Metadata} dialect)"));
        }
        catch (NativeAotFormatException ex)
        {
            return (null, new(name, NativeAotStage.Partial, ex.Message));
        }
    }

    public string ReadyToRunVersion => $"{Header.MajorVersion}.{Header.MinorVersion}";

    public NativeAotSummary Summary()
    {
        var stages = new List<NativeAotStage>
        {
            new("header", Format.Exact ? NativeAotStage.Complete : NativeAotStage.Partial,
                (Headers.Count > 1 ? $"{Headers.Count} modules, the first is analyzed; " : "") +
                (Format.Exact ? $"ReadyToRun {ReadyToRunVersion}" : $"ReadyToRun {ReadyToRunVersion} is not a known release; best effort with the {Format.Runtime} layout")
                + (Header.Relocated ? "" : "; no base relocations confirm the header")),
        };
        stages.Add(metadata.Value.Stage);
        stages.Add(Hydrated.Stage);
        stages.AddRange(Names.Stages);
        stages.Add(Types.Stage);
        var sections = Header.Sections.Select(s => new NativeAotSectionInfo(s.Id, s.Name, s.StartRva, s.Length)).ToList();
        var counts = new Dictionary<string, int>
        {
            ["namedMethods"] = Names.Methods.Count,
            ["namedCodeAddresses"] = Names.MethodAt.Count,
            ["typeMapMethodTables"] = Names.TypeNames.Count,
            ["methodTables"] = Types.ByRva.Count,
            ["namedMethodTables"] = Types.ByRva.Values.Count(t => t.NameOrigin != "generated"),
        };
        return new NativeAotSummary(Runtime, ReadyToRunVersion, DebugHeaderMajor, Header.IsDehydrated, Header.Rva, Headers.Count, sections, stages, counts);
    }

    /// <summary>One line for container listings and notes.</summary>
    public string Describe() =>
        $"{Runtime}, ReadyToRun {ReadyToRunVersion}{(Header.IsDehydrated ? ", dehydrated" : "")}" +
        (Header.Blob(BlobId.StackTraceMethodRvaToTokenMapping) is { Length: > 4 } ? ", method names present" : "") +
        (Header.Blob(BlobId.EmbeddedMetadata) != null ? ", reflection metadata present" : "");
}
