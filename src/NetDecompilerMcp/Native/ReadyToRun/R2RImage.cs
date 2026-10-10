using System.Collections.Immutable;
using System.Reflection.Metadata;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Native.ReadyToRun;

/// <summary>READYTORUN_SECTION_* values.</summary>
public enum R2RSectionType
{
    CompilerIdentifier = 100, ImportSections = 101, RuntimeFunctions = 102, MethodDefEntryPoints = 103, ExceptionInfo = 104,
    DebugInfo = 105, DelayLoadMethodCallThunks = 106, AvailableTypesOld = 107, AvailableTypes = 108, InstanceMethodEntryPoints = 109,
    InliningInfo = 110, ProfileDataInfo = 111, ManifestMetadata = 112, AttributePresence = 113, InliningInfo2 = 114,
    ComponentAssemblies = 115, OwnerCompositeExecutable = 116, PgoInstrumentationData = 117, ManifestAssemblyMvids = 118,
    CrossModuleInlineInfo = 119, HotColdMap = 120, MethodIsGenericMap = 121, EnclosingTypeMap = 122, TypeGenericInfoMap = 123,
}

public sealed record R2RSection(int Type, uint Rva, uint Size)
{
    public string Name => Enum.IsDefined(typeof(R2RSectionType), Type) ? ((R2RSectionType)Type).ToString() : $"section {Type}";
}

/// <summary>A READYTORUN_IMPORT_SECTION: <see cref="Count"/> cells of <see cref="EntrySize"/> bytes, each with a signature RVA.</summary>
public sealed record R2RImportSection(int Index, uint Rva, uint Size, ushort Flags, byte Type, byte EntrySize, uint SignaturesRva)
{
    public int Count => EntrySize == 0 ? 0 : (int)(Size / EntrySize);
    public bool IsEager => (Flags & 1) != 0;
    public bool Contains(uint rva) => rva >= Rva && rva - Rva < (ulong)Count * EntrySize;
}

/// <summary>One RUNTIME_FUNCTION of the ReadyToRun table (code range [Begin, End)).</summary>
public sealed record R2RRuntimeFunction(int Index, uint Begin, uint End, uint UnwindRva);

/// <summary>
/// A method with precompiled code: a MethodDef row (<see cref="MethodDefRid"/>) or an instantiation named by a
/// signature (<see cref="Signature"/>, from InstanceMethodEntryPoints). <see cref="Component"/> is the component
/// index in a composite image, else -1.
/// </summary>
public sealed record R2REntry(int Component, uint MethodDefRid, uint SignatureRva, R2RMethodSig? Signature, int RuntimeFunction, uint FixupsRva)
{
    public bool IsInstance => SignatureRva != 0;
}

/// <summary>A component assembly of a composite image and the sections of its READYTORUN_CORE_HEADER.</summary>
public sealed record R2RComponent(int Index, string? Name, uint CoreHeaderRva, IReadOnlyList<R2RSection> Sections);

/// <summary>
/// A ReadyToRun image parsed from its READYTORUN_HEADER (readytorun.h): version, flags, sections, the runtime
/// function table, import sections and every method entry point. A component assembly of a composite image has
/// no code of its own; <see cref="OwnerComposite"/> names the file that has it.
/// </summary>
public sealed class R2RImage
{
    public const uint Signature = 0x00525452; // "RTR"
    public const uint FlagComponent = 0x20;
    private const int MaxEntries = 4_000_000;

    private R2RImage(INativeImage image) => View = new ImageView(image);

    public ImageView View { get; }
    public INativeImage Image => View.Image;
    public uint HeaderRva { get; private set; }
    public ushort MajorVersion { get; private set; }
    public ushort MinorVersion { get; private set; }
    public uint Flags { get; private set; }
    public IReadOnlyList<R2RSection> Sections { get; private set; } = [];
    public NativeArch Arch { get; private set; }
    /// <summary>Target OS from the machine field's XOR mask (Windows, Linux, Apple, FreeBSD, NetBSD, SunOS).</summary>
    public string TargetOs { get; private set; } = "Windows";
    public string MachineName { get; private set; } = "";
    public bool IsComponent => (Flags & FlagComponent) != 0;
    public bool IsComposite => Section(R2RSectionType.ComponentAssemblies) != null;
    /// <summary>For a component assembly: the composite image file holding its code.</summary>
    public string? OwnerComposite { get; private set; }
    public string? CompilerIdentifier { get; private set; }
    public IReadOnlyList<R2RComponent> Components { get; private set; } = [];
    public IReadOnlyList<string> ManifestAssemblyRefs { get; private set; } = [];
    public IReadOnlyList<R2RRuntimeFunction> RuntimeFunctions { get; private set; } = [];
    public IReadOnlyList<R2RImportSection> ImportSections { get; private set; } = [];
    public IReadOnlyList<R2REntry> Entries { get; private set; } = [];
    /// <summary>Cold runtime function index -> hot runtime function index of the same method (HotColdMap).</summary>
    public IReadOnlyDictionary<int, int> ColdToHot { get; private set; } = new Dictionary<int, int>();

    public R2RSection? Section(R2RSectionType type, IReadOnlyList<R2RSection>? sections = null) =>
        (sections ?? Sections).FirstOrDefault(s => s.Type == (int)type);

    /// <summary>
    /// The READYTORUN_HEADER of an IL image (COR header ManagedNativeHeader) or of a composite image (RTR_HEADER
    /// export); 0 when there is none.
    /// </summary>
    public static uint FindHeader(PeFile pe)
    {
        var v = new ImageView(pe);
        var cor = pe.Directory(PeDirectory.ClrRuntimeHeader);
        try
        {
            if (cor.Rva != 0 && cor.Size >= 72)
            {
                uint rva = v.U32(cor.Rva + 64);
                if (rva != 0 && v.U32(rva) == Signature) return rva;
                return 0;
            }
            var export = pe.Exports.FirstOrDefault(e => e.Name == "RTR_HEADER");
            if (export != null && v.U32(export.Rva) == Signature) return export.Rva;
        }
        catch (R2RFormatException) { }
        return 0;
    }

    /// <summary>Parses the image's ReadyToRun data; null when it has none.</summary>
    /// <exception cref="R2RFormatException">The ReadyToRun data is malformed.</exception>
    public static R2RImage? Open(PeFile pe, CancellationToken ct = default)
    {
        uint header = FindHeader(pe);
        if (header == 0) return null;
        var r2r = new R2RImage(pe) { HeaderRva = header };
        r2r.Parse(pe, ct);
        return r2r;
    }

    private static readonly (ushort Mask, string Os)[] OsMasks =
        [(0, "Windows"), (0x7B79, "Linux"), (0x4644, "Apple"), (0xADC4, "FreeBSD"), (0x1993, "NetBSD"), (0x1992, "SunOS")];

    private void Parse(PeFile pe, CancellationToken ct)
    {
        var v = View;
        MajorVersion = v.U16(HeaderRva + 4);
        MinorVersion = v.U16(HeaderRva + 6);
        Flags = v.U32(HeaderRva + 8);
        Sections = ReadSections(HeaderRva + 12);

        foreach (var (mask, os) in OsMasks)
        {
            var arch = PeNames.Arch((ushort)(pe.Coff.Machine ^ mask));
            if (arch == NativeArch.Unknown) continue;
            Arch = arch;
            TargetOs = os;
            MachineName = PeNames.Machine((ushort)(pe.Coff.Machine ^ mask));
            break;
        }
        if (Arch == NativeArch.Unknown) MachineName = pe.MachineName;

        if (Section(R2RSectionType.CompilerIdentifier) is { } id) CompilerIdentifier = v.Utf8(id.Rva, (int)Math.Min(id.Size, 512));
        if (Section(R2RSectionType.OwnerCompositeExecutable) is { } owner) OwnerComposite = v.Utf8(owner.Rva, (int)Math.Min(owner.Size, 1024));
        if (Section(R2RSectionType.ManifestMetadata) is { } manifest) ManifestAssemblyRefs = ReadManifest(manifest);
        if (IsComponent) return;

        RuntimeFunctions = ReadRuntimeFunctions();
        ImportSections = ReadImportSections();
        ColdToHot = ReadHotColdMap();
        var entries = new List<R2REntry>();
        if (Section(R2RSectionType.ComponentAssemblies) is { } components)
        {
            var list = new List<R2RComponent>();
            uint count = components.Size / 16;
            for (uint i = 0; i < count; i++)
            {
                uint core = v.U32(components.Rva + i * 16 + 8);
                var sections = ReadSections(core + 4);
                // The manifest lists the component assemblies first, in component order.
                list.Add(new R2RComponent((int)i, i < ManifestAssemblyRefs.Count ? ManifestAssemblyRefs[(int)i] : null, core, sections));
                ReadMethodDefEntries(Section(R2RSectionType.MethodDefEntryPoints, sections), (int)i, entries, ct);
            }
            Components = list;
        }
        else ReadMethodDefEntries(Section(R2RSectionType.MethodDefEntryPoints), -1, entries, ct);
        ReadInstanceEntries(entries, ct);
        foreach (var e in entries)
            if (e.RuntimeFunction < 0 || e.RuntimeFunction >= RuntimeFunctions.Count)
                throw new R2RFormatException($"method entry names runtime function {e.RuntimeFunction}; the table has {RuntimeFunctions.Count}");
        Entries = entries;
    }

    private List<R2RSection> ReadSections(uint countRva)
    {
        uint count = View.U32(countRva);
        if (count > 1000) throw new R2RFormatException($"ReadyToRun header at RVA 0x{countRva:X} claims {count} sections");
        var list = new List<R2RSection>((int)count);
        for (uint i = 0; i < count; i++)
        {
            uint at = countRva + 4 + i * 12;
            list.Add(new R2RSection((int)View.U32(at), View.U32(at + 4), View.U32(at + 8)));
        }
        return list;
    }

    /// <summary>The assembly names of the manifest metadata's AssemblyRef rows (references beyond the IL metadata's own).</summary>
    private List<string> ReadManifest(R2RSection manifest)
    {
        if (manifest.Size > 64 << 20) throw new R2RFormatException($"manifest metadata claims {manifest.Size} bytes");
        var bytes = View.Bytes(manifest.Rva, (int)manifest.Size);
        try
        {
            using var provider = MetadataReaderProvider.FromMetadataImage(ImmutableArray.Create(bytes));
            var reader = provider.GetMetadataReader();
            return reader.AssemblyReferences.Select(h => reader.GetString(reader.GetAssemblyReference(h).Name)).ToList();
        }
        catch (Exception ex) when (ex is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            throw new R2RFormatException($"manifest metadata is unreadable: {ex.Message}");
        }
    }

    private List<R2RRuntimeFunction> ReadRuntimeFunctions()
    {
        var section = Section(R2RSectionType.RuntimeFunctions);
        if (section == null) return [];
        var v = View;
        bool hasEnd = Arch == NativeArch.X64;
        uint size = hasEnd ? 12u : 8u;
        uint count = section.Size / size;
        if (count > MaxEntries) throw new R2RFormatException($"runtime function table claims {count} entries");
        var raw = v.Bytes(section.Rva, (int)(count * size));
        var list = new List<R2RRuntimeFunction>((int)count);
        for (int i = 0; i < count; i++)
        {
            int at = (int)(i * size);
            uint begin = BitConverter.ToUInt32(raw, at);
            if (Arch == NativeArch.Arm) begin &= ~1u; // Thumb bit
            uint end = hasEnd ? BitConverter.ToUInt32(raw, at + 4) : 0;
            uint unwind = BitConverter.ToUInt32(raw, at + (hasEnd ? 8 : 4));
            list.Add(new R2RRuntimeFunction(i, begin, end, unwind));
        }
        if (!hasEnd)
            for (int i = 0; i < list.Count; i++)
                list[i] = list[i] with { End = ImpliedEnd(list, i) };
        foreach (var rf in list)
            if (rf.End <= rf.Begin || rf.End > Image.SizeOfImage)
                throw new R2RFormatException($"runtime function {rf.Index} has a bad range 0x{rf.Begin:X}-0x{rf.End:X}");
        return list;
    }

    /// <summary>End of a function without one in the table: the ARM64 unwind data's length, else the next function's start.</summary>
    private uint ImpliedEnd(List<R2RRuntimeFunction> list, int i)
    {
        var rf = list[i];
        if (Arch == NativeArch.Arm64 && (rf.UnwindRva & 3) == 0)
        {
            uint xdata = View.U32(rf.UnwindRva);
            uint length = (xdata & 0x3FFFF) * 4;
            if (length > 0) return rf.Begin + length;
        }
        uint next = i + 1 < list.Count && list[i + 1].Begin > rf.Begin ? list[i + 1].Begin : 0;
        if (next != 0) return next;
        var section = Image.SectionAt(rf.Begin);
        return section != null ? section.Rva + section.MappedSize : rf.Begin + 1;
    }

    private List<R2RImportSection> ReadImportSections()
    {
        var section = Section(R2RSectionType.ImportSections);
        if (section == null) return [];
        uint count = section.Size / 20;
        if (count > 10_000) throw new R2RFormatException($"import section table claims {count} entries");
        var list = new List<R2RImportSection>((int)count);
        for (uint i = 0; i < count; i++)
        {
            uint at = section.Rva + i * 20;
            list.Add(new R2RImportSection((int)i, View.U32(at), View.U32(at + 4), View.U16(at + 8), View.U8(at + 10), View.U8(at + 11), View.U32(at + 12)));
        }
        return list;
    }

    private Dictionary<int, int> ReadHotColdMap()
    {
        var map = new Dictionary<int, int>();
        if (Section(R2RSectionType.HotColdMap) is not { } section) return map;
        uint pairs = section.Size / 8;
        if (pairs > MaxEntries) throw new R2RFormatException($"hot/cold map claims {pairs} entries");
        for (uint i = 0; i < pairs; i++)
            map[(int)View.U32(section.Rva + i * 8)] = (int)View.U32(section.Rva + i * 8 + 4);
        return map;
    }

    /// <summary>MethodDefEntryPoints: a native array indexed by MethodDef rid - 1.</summary>
    private void ReadMethodDefEntries(R2RSection? section, int component, List<R2REntry> entries, CancellationToken ct)
    {
        if (section == null) return;
        var array = new NativeFormat.NativeArray(View, section.Rva);
        // Each block of 16 elements needs at least one byte of block index.
        if (array.Count > 0x00FFFFFF || array.Count > (ulong)section.Size * 16)
            throw new R2RFormatException($"method entry point array claims {array.Count} entries in {section.Size} bytes");
        for (uint i = 0; i < array.Count; i++)
        {
            if ((i & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            if (!array.TryGetAt(i, out uint at)) continue;
            int rf = EntryPoint(at, out uint fixups);
            entries.Add(new R2REntry(component, i + 1, 0, null, rf, fixups));
        }
    }

    /// <summary>InstanceMethodEntryPoints: a hash table of (method signature, entry point) for generic instantiations.</summary>
    private void ReadInstanceEntries(List<R2REntry> entries, CancellationToken ct)
    {
        if (Section(R2RSectionType.InstanceMethodEntryPoints) is not { } section) return;
        var sigs = new R2RSignatures(View, null);
        int n = 0;
        foreach (uint at in NativeFormat.HashtableEntries(View, section.Rva, section.Rva + section.Size, MaxEntries))
        {
            if ((++n & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            var reader = new SigReader(View, at);
            var sig = sigs.Method(reader, -1);
            int rf = EntryPoint(reader.Position, out uint fixups);
            entries.Add(new R2REntry(-1, 0, at, sig, rf, fixups));
        }
    }

    /// <summary>An entry point: runtime function index, then optionally the fixup list (inline or at a backward offset).</summary>
    private int EntryPoint(uint at, out uint fixups)
    {
        fixups = 0;
        at = NativeFormat.DecodeUnsigned(View, at, out uint id);
        if ((id & 1) != 0)
        {
            if ((id & 2) != 0)
            {
                NativeFormat.DecodeUnsigned(View, at, out uint back);
                fixups = ImageView.Add(at, -(long)back);
            }
            else fixups = at;
            id >>= 2;
        }
        else id >>= 1;
        return (int)id;
    }

    /// <summary>The import cells an entry point's fixup list names: (import section index, cell index) pairs.</summary>
    public List<(int Section, int Cell)> Fixups(uint rva)
    {
        var list = new List<(int, int)>();
        if (rva == 0) return list;
        var nibbles = new NibbleReader(View, rva);
        uint table = nibbles.ReadUInt();
        while (true)
        {
            uint cell = nibbles.ReadUInt();
            while (true)
            {
                if (table >= ImportSections.Count || cell >= ImportSections[(int)table].Count)
                    throw new R2RFormatException($"fixup list at RVA 0x{rva:X} names cell {cell} of import section {table}, which does not exist");
                list.Add(((int)table, (int)cell));
                if (list.Count > 100_000) throw new R2RFormatException($"fixup list at RVA 0x{rva:X} is too long");
                uint delta = nibbles.ReadUInt();
                if (delta == 0) break;
                cell += delta;
            }
            uint tableDelta = nibbles.ReadUInt();
            if (tableDelta == 0) break;
            table += tableDelta;
        }
        return list;
    }

    /// <summary>The import section and cell index of an import cell address, or null.</summary>
    public (R2RImportSection Section, int Cell)? CellAt(uint rva)
    {
        foreach (var s in ImportSections)
            if (s.Contains(rva) && (rva - s.Rva) % s.EntrySize == 0)
                return (s, (int)((rva - s.Rva) / s.EntrySize));
        return null;
    }

    /// <summary>The signature RVA of a cell, or 0 when its section has no signatures.</summary>
    public uint CellSignature(R2RImportSection section, int cell) =>
        section.SignaturesRva == 0 ? 0 : View.U32(section.SignaturesRva + (uint)cell * 4);
}
