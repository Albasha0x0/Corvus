namespace Corvus.Tests.NativeFormats;

/// <summary>Lays out Objective-C and Swift metadata in extra sections of a <see cref="MachOWriter"/> image, with pointers as chained fixups.</summary>
internal sealed class AppleMetadataBuilder(MachOWriter writer)
{
    private readonly List<Region> regions = [];
    private readonly Dictionary<string, uint> labels = [];
    private readonly List<(Region Region, int At, string Label, bool Relative, int Addend)> patches = [];
    private readonly Dictionary<string, int> imports = [];
    private Region? strings;

    public sealed class Region(string seg, string name, uint start, uint flags)
    {
        public string Seg { get; } = seg;
        public string Name { get; } = name;
        public uint Start { get; } = start;
        public uint Flags { get; } = flags;
        public ByteWriter W { get; } = new();
        public uint Here => Start + (uint)W.Length;
    }

    public Region Section(string seg, string name, uint start, uint flags = 0)
    {
        var r = new Region(seg, name, start, flags);
        regions.Add(r);
        return r;
    }

    /// <summary>Marks the current position of <paramref name="r"/> as <paramref name="label"/> (aligned to <paramref name="align"/>).</summary>
    public uint Label(Region r, string label, int align = 8)
    {
        r.W.Align(align);
        labels[label] = r.Here;
        return r.Here;
    }

    public uint this[string label] => labels[label];

    /// <summary>Names an offset outside the regions (code in __text, for instance).</summary>
    public void Define(string label, uint offset) => labels[label] = offset;

    /// <summary>A pointer slot rebased to a label (resolved at <see cref="Build"/>); null writes a zero slot.</summary>
    public void Ptr(Region r, string? label, int addend = 0)
    {
        if (label != null) patches.Add((r, r.W.Length, label, false, addend));
        r.W.U64(0);
    }

    /// <summary>A pointer slot bound to <paramref name="symbol"/> of the first dependent library.</summary>
    public void Bind(Region r, string symbol)
    {
        if (!imports.TryGetValue(symbol, out int index))
        {
            index = writer.Imports.Count;
            writer.Imports.Add(new MachOWriter.ChainedImport(1, symbol));
            imports[symbol] = index;
        }
        writer.Fixups.Add(new MachOWriter.Fixup(r.Here, Import: index));
        r.W.U64(0);
    }

    /// <summary>A 32-bit offset from this field to a label (plus <paramref name="addend"/>, e.g. 1 for an indirect reference).</summary>
    public void Rel(Region r, string? label, int addend = 0)
    {
        if (label != null) patches.Add((r, r.W.Length, label, true, addend));
        r.W.U32(0);
    }

    /// <summary>A NUL-terminated string in the shared string section, labelled "str:" + text.</summary>
    public string Str(string text)
    {
        strings ??= Section("__TEXT", "__objc_methname", 0x2000, 2);
        string label = "str:" + text;
        if (!labels.ContainsKey(label))
        {
            labels[label] = strings.Here;
            strings.W.CString(text);
        }
        return label;
    }

    /// <summary>Raw mangled-name bytes in the string section (symbolic references written with <see cref="SymbolicRef"/>).</summary>
    public string Mangled(string label, params object[] parts)
    {
        strings ??= Section("__TEXT", "__objc_methname", 0x2000, 2);
        labels[label] = strings.Here;
        foreach (var part in parts)
        {
            if (part is string text) foreach (char c in text) strings.W.U8((byte)c);
            else if (part is (byte kind, string target))
            {
                strings.W.U8(kind);
                patches.Add((strings, strings.W.Length, target, true, 0));
                strings.W.U32(0);
            }
        }
        strings.W.U8(0);
        return label;
    }

    /// <summary>A symbolic reference part for <see cref="Mangled"/>: kind 1 direct context, 2 indirect.</summary>
    public static (byte, string) SymbolicRef(byte kind, string label) => (kind, label);

    /// <summary>Writes the sections and fixups into the writer (chained format <paramref name="format"/>).</summary>
    public void Build(ushort format = 6)
    {
        foreach (var (r, at, label, relative, addend) in patches)
        {
            uint target = labels[label];
            if (relative) r.W.U32At(at, unchecked((uint)((int)target + addend - (int)(r.Start + (uint)at))));
            else writer.Fixups.Add(new MachOWriter.Fixup(r.Start + (uint)at, Target: (uint)(target + addend)));
        }
        writer.ChainedFormat = format;
        foreach (var r in regions) writer.ExtraSections.Add((r.Seg, r.Name, r.Start, r.W.ToArray(), r.Flags));
        if (writer.Dylibs.Count == 0) writer.Dylibs.Add(("/usr/lib/libobjc.A.dylib", 0xC));
    }
}
