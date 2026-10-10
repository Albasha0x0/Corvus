using System.Text;

namespace NetDecompilerMcp.Tests.NativeFormats;

/// <summary>
/// Builds small ELF shared objects and executables for reader tests: an R-X segment (headers, .text at
/// <see cref="TextRva"/>, then the tables) and an RW segment at <see cref="DynamicRva"/> holding .dynamic, .got,
/// .got.plt and .data. Addresses below are RVAs; the file maps them at <see cref="Base"/>.
/// </summary>
internal sealed class ElfWriter
{
    public const uint TextRva = 0x1000;
    private const uint TablesRva = 0x8000;
    public const uint DynamicRva = 0x20000;
    public const uint GotRva = 0x20400;
    public const uint GotPltRva = 0x20600;
    public const uint DataRva = 0x20800;

    public const ushort EmX86 = 3, EmArm = 40, EmX64 = 62, EmAarch64 = 183, EmMips = 8;

    public sealed record Symbol(string Name, uint Value = 0, uint Size = 0, byte Type = 2, byte Bind = 1, bool Defined = true);
    public sealed record Reloc(uint Offset, uint Type, string? Symbol = null, long Addend = 0);
    public enum HashKind { None, Sysv, Gnu, Both }

    public bool Is64 { get; set; } = true;
    public bool BigEndian { get; set; }
    public ushort Machine { get; set; } = EmAarch64;
    public ushort Type { get; set; } = 3;
    public ulong Base { get; set; }
    public uint Entry { get; set; }
    public string? Interpreter { get; set; }
    public bool SectionHeaders { get; set; } = true;
    public bool BindNow { get; set; }
    public byte[] Text { get; set; } = [0x1F, 0x20, 0x03, 0xD5, 0xC0, 0x03, 0x5F, 0xD6];
    public byte[] Data { get; set; } = new byte[0x100];
    public HashKind Hash { get; set; } = HashKind.Both;
    /// <summary>Dynamic symbols; undefined ones are imports.</summary>
    public List<Symbol> Symbols { get; set; } = [];
    public List<string> Needed { get; set; } = [];
    public string? SoName { get; set; }
    /// <summary>.rela.dyn (or .rel.dyn when <see cref="UseRel"/>); a REL addend is written into the slot.</summary>
    public List<Reloc> Relocations { get; set; } = [];
    public bool UseRel { get; set; }
    /// <summary>Imports called through the PLT (AArch64 stubs, JUMP_SLOT relocations in .rela.plt).</summary>
    public List<string> PltImports { get; set; } = [];
    /// <summary>Locations relocated by DT_RELR (relative, implicit addend in the slot).</summary>
    public List<uint> Relr { get; set; } = [];
    /// <summary>Android packed relocations (APS2) instead of plain RELA/REL tables for <see cref="Relocations"/>.</summary>
    public bool PackAndroid { get; set; }
    public byte[]? BuildId { get; set; }
    public (uint Api, string Ndk)? AndroidIdent { get; set; }
    /// <summary>Unwind ranges written as .eh_frame FDEs and indexed by .eh_frame_hdr (when <see cref="EhFrameHdr"/>).</summary>
    public List<(uint Start, uint Size)> Fdes { get; set; } = [];
    public bool EhFrameHdr { get; set; } = true;
    /// <summary>ARM exception index entries (PT_ARM_EXIDX); <c>Thumb</c> sets bit 0 of the start.</summary>
    public List<(uint Start, bool CantUnwind)> Exidx { get; set; } = [];
    public List<uint> InitArray { get; set; } = [];
    /// <summary>Symbol versions of imports: name → (library, version).</summary>
    public Dictionary<string, (string Library, string Version)> Versions { get; set; } = [];
    /// <summary>Static symbols (.symtab, not loaded).</summary>
    public List<Symbol> StaticSymbols { get; set; } = [];

    private int WordSize => Is64 ? 8 : 4;
    private int SymSize => Is64 ? 24 : 16;
    private int RelSize => (Is64 ? 16 : 8) + (UseRel ? 0 : WordSize);

    public uint PltRva { get; private set; }
    /// <summary>RVA of the GOT slot a PLT import goes through.</summary>
    public uint PltSlotRva(int index) => GotPltRva + (uint)(3 + index) * (uint)WordSize;

    private sealed class Sec(string name, uint type, ulong flags)
    {
        public string Name = name;
        public uint Type = type;
        public ulong Flags = flags;
        public uint Rva, Offset, Size, Link, Info, EntSize, Align = 1;
        public bool Alloc = true;
    }

    public byte[] Build()
    {
        if (Text.Length > TablesRva - TextRva) throw new InvalidOperationException("text too large");
        var w = new ByteWriter(BigEndian);
        var sections = new List<Sec>();
        Sec Add(string name, uint type, ulong flags) { var s = new Sec(name, type, flags); sections.Add(s); return s; }

        // Dynamic symbol order: imports, then defined symbols grouped by GNU hash bucket.
        var undefined = Symbols.Where(s => !s.Defined).ToList();
        foreach (var name in PltImports.Where(n => undefined.All(u => u.Name != n))) undefined.Add(new Symbol(name, Defined: false));
        var defined = Symbols.Where(s => s.Defined).ToList();
        uint gnuBuckets = (uint)Math.Max(1, defined.Count / 2);
        defined = [.. defined.OrderBy(s => GnuHash(s.Name) % gnuBuckets)];
        var dynsym = new List<Symbol> { new("", Defined: false) };
        dynsym.AddRange(undefined);
        int symOffset = dynsym.Count;
        dynsym.AddRange(defined);
        int SymIndex(string? name) => name == null ? 0 : dynsym.FindIndex(s => s.Name == name) is var i and >= 0 ? i : throw new ArgumentException("unknown symbol " + name);

        var dynstr = new StringTable();
        dynstr.Add("");
        foreach (var n in Needed) dynstr.Add(n);
        if (SoName != null) dynstr.Add(SoName);

        // Text: user code, then a PLT when there are PLT imports.
        var text = Add(".text", 1, 6);
        text.Rva = TextRva;
        w.PadTo((int)TextRva);
        w.Bytes(Text);
        text.Size = (uint)Text.Length;
        if (PltImports.Count > 0)
        {
            w.Align(16);
            var plt = Add(".plt", 1, 6);
            plt.Rva = PltRva = (uint)w.Length;
            WritePlt(w);
            plt.Size = (uint)w.Length - plt.Rva;
        }
        if (w.Length > TablesRva) throw new InvalidOperationException("text and PLT too large");
        w.PadTo((int)TablesRva);

        Sec Table(string name, uint type, ulong flags, Action body, int align = 8)
        {
            w.Align(align);
            var s = Add(name, type, flags);
            s.Rva = (uint)w.Length;
            s.Align = (uint)align;
            body();
            s.Size = (uint)w.Length - s.Rva;
            return s;
        }

        if (Interpreter != null) Table(".interp", 1, 2, () => w.CString(Interpreter), 1);

        // Names first so .dynstr is complete before it is written.
        foreach (var s in dynsym.Skip(1)) dynstr.Add(s.Name);
        foreach (var (lib, ver) in Versions.Values) { dynstr.Add(lib); dynstr.Add(ver); }

        var dynsymSec = Table(".dynsym", 11, 2, () => { foreach (var s in dynsym) WriteSym(w, s, dynstr, s.Defined ? (ushort)1 : (ushort)0); });
        dynsymSec.EntSize = (uint)SymSize;
        dynsymSec.Info = (uint)symOffset;
        var dynstrSec = Table(".dynstr", 3, 2, () => w.Bytes(dynstr.Bytes), 1);
        dynsymSec.Link = (uint)sections.IndexOf(dynstrSec) + 1;

        Sec? hash = null, gnuHash = null, versym = null, verneed = null;
        if (Hash is HashKind.Sysv or HashKind.Both)
            hash = Table(".hash", 5, 2, () => WriteSysvHash(w, dynsym), 4);
        if (Hash is HashKind.Gnu or HashKind.Both)
            gnuHash = Table(".gnu.hash", 0x6FFFFFF6, 2, () => WriteGnuHash(w, dynsym, symOffset, gnuBuckets));
        var libs = Versions.Values.Select(v => v.Library).Distinct().ToList();
        var versionIndex = Versions.Values.Distinct().Select((v, i) => (v, i)).ToDictionary(p => p.v, p => (ushort)(2 + p.i));
        if (Versions.Count > 0)
        {
            versym = Table(".gnu.version", 0x6FFFFFFF, 2, () =>
            {
                foreach (var s in dynsym)
                    w.U16(s.Name.Length == 0 ? (ushort)0 : Versions.TryGetValue(s.Name, out var v) ? versionIndex[v] : (ushort)1);
            }, 2);
            versym.EntSize = 2;
            verneed = Table(".gnu.version_r", 0x6FFFFFFE, 2, () =>
            {
                for (int li = 0; li < libs.Count; li++)
                {
                    var auxes = versionIndex.Where(p => p.Key.Library == libs[li]).ToList();
                    w.U16(1);
                    w.U16((ushort)auxes.Count);
                    w.U32(dynstr.Offset(libs[li]));
                    w.U32(16);
                    w.U32(li + 1 < libs.Count ? 16u + 16u * (uint)auxes.Count : 0);
                    for (int ai = 0; ai < auxes.Count; ai++)
                    {
                        w.U32(ElfHash(auxes[ai].Key.Version));
                        w.U16(0);
                        w.U16(auxes[ai].Value);
                        w.U32(dynstr.Offset(auxes[ai].Key.Version));
                        w.U32(ai + 1 < auxes.Count ? 16u : 0);
                    }
                }
            }, 4);
            verneed.Info = (uint)libs.Count;
        }

        Sec? relDyn = null, relPlt = null, relr = null, android = null;
        if (Relocations.Count > 0 && !PackAndroid)
        {
            relDyn = Table(UseRel ? ".rel.dyn" : ".rela.dyn", UseRel ? 9u : 4u, 2, () => { foreach (var r in Relocations) WriteRel(w, r.Offset, r.Type, SymIndex(r.Symbol), r.Addend); });
            relDyn.EntSize = (uint)RelSize;
        }
        if (Relocations.Count > 0 && PackAndroid)
            android = Table(UseRel ? ".rel.dyn" : ".rela.dyn", UseRel ? 0x60000001u : 0x60000002u, 2, () => WriteAps2(w, Relocations, SymIndex));
        if (PltImports.Count > 0)
        {
            relPlt = Table(UseRel ? ".rel.plt" : ".rela.plt", UseRel ? 9u : 4u, 0x42, () =>
            {
                for (int i = 0; i < PltImports.Count; i++) WriteRel(w, PltSlotRva(i), JumpSlotType, SymIndex(PltImports[i]), 0);
            });
            relPlt.EntSize = (uint)RelSize;
        }
        if (Relr.Count > 0)
        {
            relr = Table(".relr.dyn", 19, 2, () => { foreach (var e in EncodeRelr(Relr.Select(r => Base + r).Order().ToList())) w.Word(e, Is64); });
            relr.EntSize = (uint)WordSize;
        }

        Sec? buildId = null, ident = null;
        if (BuildId != null) buildId = Table(".note.gnu.build-id", 7, 2, () => WriteNote(w, "GNU", 3, BuildId), 4);
        if (AndroidIdent is { } ai2)
            ident = Table(".note.android.ident", 7, 2, () =>
            {
                var desc = new byte[132];
                BitConverter.TryWriteBytes(desc, ai2.Api);
                if (BigEndian) Array.Reverse(desc, 0, 4);
                Encoding.ASCII.GetBytes(ai2.Ndk).CopyTo(desc, 4);
                WriteNote(w, "Android", 1, desc);
            }, 4);

        Sec? ehHdr = null, eh = null, exidx = null;
        if (Fdes.Count > 0)
        {
            var fdeAt = new List<uint>();
            eh = Table(".eh_frame", 1, 2, () => WriteEhFrame(w, fdeAt));
            if (EhFrameHdr)
                ehHdr = Table(".eh_frame_hdr", 1, 2, () =>
                {
                    uint at = (uint)w.Length;
                    w.U8(1); w.U8(0x1B); w.U8(0x03); w.U8(0x3B);
                    w.U32(eh.Rva - (at + 4));
                    w.U32((uint)Fdes.Count);
                    foreach (var (start, fde) in Fdes.Zip(fdeAt).OrderBy(p => p.First.Start))
                    {
                        w.U32(start.Start - at);
                        w.U32(fde - at);
                    }
                }, 4);
        }
        if (Exidx.Count > 0)
            exidx = Table(".ARM.exidx", 0x70000001, 0x82, () =>
            {
                foreach (var (start, cant) in Exidx.OrderBy(e => e.Start & ~1u))
                {
                    uint at = (uint)w.Length;
                    w.U32((start - at) & 0x7FFFFFFF);
                    w.U32(cant ? 1u : 0x80B0B0B0);
                }
            }, 4);

        int rxEnd = w.Length;

        // RW segment: .dynamic, .got, .got.plt, .data, .init_array at fixed RVAs.
        int rwOffset = (rxEnd + 0xFFF) & ~0xFFF;
        int RwAt(uint rva) => rwOffset + (int)(rva - DynamicRva);
        var dyn = new List<(long Tag, ulong Value)>();
        foreach (var n in Needed) dyn.Add((1, dynstr.Offset(n)));
        if (SoName != null) dyn.Add((14, dynstr.Offset(SoName)));
        if (hash != null) dyn.Add((4, Base + hash.Rva));
        if (gnuHash != null) dyn.Add((0x6FFFFEF5, Base + gnuHash.Rva));
        dyn.Add((5, Base + dynstrSec.Rva));
        dyn.Add((6, Base + dynsymSec.Rva));
        dyn.Add((10, dynstrSec.Size));
        dyn.Add((11, (ulong)SymSize));
        if (relDyn != null)
        {
            dyn.Add((UseRel ? 17 : 7, Base + relDyn.Rva));
            dyn.Add((UseRel ? 18 : 8, relDyn.Size));
            dyn.Add((UseRel ? 19 : 9, (ulong)RelSize));
        }
        if (android != null)
        {
            dyn.Add((UseRel ? 0x6000000F : 0x60000011, Base + android.Rva));
            dyn.Add((UseRel ? 0x60000010 : 0x60000012, android.Size));
        }
        if (relPlt != null)
        {
            dyn.Add((23, Base + relPlt.Rva));
            dyn.Add((2, relPlt.Size));
            dyn.Add((20, UseRel ? 17ul : 7ul));
            dyn.Add((3, Base + GotPltRva));
        }
        if (relr != null)
        {
            dyn.Add((36, Base + relr.Rva));
            dyn.Add((35, relr.Size));
            dyn.Add((37, (ulong)WordSize));
        }
        if (versym != null && verneed != null)
        {
            dyn.Add((0x6FFFFFF0, Base + versym.Rva));
            dyn.Add((0x6FFFFFFE, Base + verneed.Rva));
            dyn.Add((0x6FFFFFFF, (ulong)libs.Count));
        }
        uint initRva = DataRva + (uint)((Data.Length + 7) & ~7);
        if (InitArray.Count > 0)
        {
            dyn.Add((25, Base + initRva));
            dyn.Add((27, (ulong)(InitArray.Count * WordSize)));
        }
        if (BindNow) dyn.Add((30, 8));
        dyn.Add((0, 0));
        if (dyn.Count * 2 * WordSize > GotRva - DynamicRva) throw new InvalidOperationException("dynamic table too large");

        var dynamicSec = Add(".dynamic", 6, 3);
        dynamicSec.Rva = DynamicRva;
        dynamicSec.Size = (uint)(dyn.Count * 2 * WordSize);
        dynamicSec.EntSize = (uint)(2 * WordSize);
        dynamicSec.Link = (uint)sections.IndexOf(dynstrSec) + 1;
        int p = RwAt(DynamicRva);
        foreach (var (tag, value) in dyn) { w.WordAt(p, (ulong)tag, Is64); w.WordAt(p + WordSize, value, Is64); p += 2 * WordSize; }
        var got = Add(".got", 1, 3);
        got.Rva = GotRva;
        got.Size = GotPltRva - GotRva;
        w.PadTo(RwAt(GotPltRva));
        if (PltImports.Count > 0)
        {
            var gotPlt = Add(".got.plt", 1, 3);
            gotPlt.Rva = GotPltRva;
            gotPlt.Size = (uint)((3 + PltImports.Count) * WordSize);
            w.WordAt(RwAt(GotPltRva), Base + DynamicRva, Is64);
            for (int i = 0; i < PltImports.Count; i++) w.WordAt(RwAt(PltSlotRva(i)), Base + PltRva, Is64);
        }
        if ((3 + PltImports.Count) * WordSize > DataRva - GotPltRva) throw new InvalidOperationException("too many PLT imports");
        var data = Add(".data", 1, 3);
        data.Rva = DataRva;
        data.Size = (uint)Data.Length;
        w.BytesAt(RwAt(DataRva), Data);
        foreach (var r in Relocations.Where(r => UseRel))
            w.WordAt(RwAt(r.Offset), (ulong)r.Addend, Is64);
        if (InitArray.Count > 0)
        {
            var init = Add(".init_array", 14, 3);
            init.Rva = initRva;
            init.Size = (uint)(InitArray.Count * WordSize);
            for (int i = 0; i < InitArray.Count; i++) w.WordAt(RwAt(initRva) + i * WordSize, Base + InitArray[i], Is64);
        }
        w.PadTo(RwAt(initRva) + InitArray.Count * WordSize);
        int rwEnd = w.Length;
        foreach (var s in sections) s.Offset = s.Rva >= DynamicRva ? (uint)RwAt(s.Rva) : s.Rva;

        // Non-allocated: .symtab/.strtab, .shstrtab, section headers.
        if (SectionHeaders && StaticSymbols.Count > 0)
        {
            var strtab = new StringTable();
            strtab.Add("");
            foreach (var s in StaticSymbols) strtab.Add(s.Name);
            w.Align(8);
            var symtab = Add(".symtab", 2, 0);
            symtab.Alloc = false;
            symtab.Offset = (uint)w.Length;
            WriteSym(w, new Symbol("", Defined: false), strtab, 0);
            foreach (var s in StaticSymbols.OrderBy(s => s.Bind == 0 ? 0 : 1)) WriteSym(w, s, strtab, s.Defined ? (ushort)1 : (ushort)0);
            symtab.Size = (uint)w.Length - symtab.Offset;
            symtab.EntSize = (uint)SymSize;
            symtab.Info = 1 + (uint)StaticSymbols.Count(s => s.Bind == 0);
            var strSec = Add(".strtab", 3, 0);
            strSec.Alloc = false;
            strSec.Offset = (uint)w.Length;
            w.Bytes(strtab.Bytes);
            strSec.Size = (uint)strtab.Bytes.Length;
            symtab.Link = (uint)sections.IndexOf(strSec) + 1;
        }

        int shoff = 0, shnum = 0, shstrndx = 0;
        if (SectionHeaders)
        {
            var shstr = new StringTable();
            shstr.Add("");
            foreach (var s in sections) shstr.Add(s.Name);
            shstr.Add(".shstrtab");
            var shstrSec = Add(".shstrtab", 3, 0);
            shstrSec.Alloc = false;
            shstrSec.Offset = (uint)w.Length;
            w.Bytes(shstr.Bytes);
            shstrSec.Size = (uint)shstr.Bytes.Length;
            if (hash != null) hash.Link = (uint)sections.IndexOf(dynsymSec) + 1;
            if (gnuHash != null) gnuHash.Link = (uint)sections.IndexOf(dynsymSec) + 1;
            if (versym != null) versym.Link = (uint)sections.IndexOf(dynsymSec) + 1;
            if (verneed != null) verneed.Link = (uint)sections.IndexOf(dynstrSec) + 1;
            foreach (var r in new[] { relDyn, relPlt, android }) if (r != null) r.Link = (uint)sections.IndexOf(dynsymSec) + 1;
            if (relPlt != null) relPlt.Info = (uint)sections.FindIndex(s => s.Name == ".got.plt") + 1;
            if (exidx != null) exidx.Link = (uint)sections.IndexOf(text) + 1;
            w.Align(8);
            shoff = w.Length;
            shnum = sections.Count + 1;
            shstrndx = sections.Count;
            WriteShdr(w, 0, new Sec("", 0, 0) { Alloc = false, Align = 0 });
            foreach (var s in sections) WriteShdr(w, shstr.Offset(s.Name), s);
        }

        // Program headers and the file header.
        var phdrs = new List<(uint Type, uint Flags, ulong Offset, ulong Vaddr, ulong FileSize, ulong MemSize, ulong Align)>();
        if (Interpreter != null) { var s = sections.First(x => x.Name == ".interp"); phdrs.Add((3, 4, s.Offset, Base + s.Rva, s.Size, s.Size, 1)); }
        phdrs.Add((1, 5, 0, Base, (ulong)rxEnd, (ulong)rxEnd, 0x1000));
        phdrs.Add((1, 6, (ulong)rwOffset, Base + DynamicRva, (ulong)(rwEnd - rwOffset), (ulong)(rwEnd - rwOffset), 0x1000));
        phdrs.Add((2, 6, (ulong)RwAt(DynamicRva), Base + DynamicRva, dynamicSec.Size, dynamicSec.Size, (ulong)WordSize));
        foreach (var note in new[] { buildId, ident }) if (note != null) phdrs.Add((4, 4, note.Offset, Base + note.Rva, note.Size, note.Size, 4));
        if (ehHdr != null) phdrs.Add((0x6474E550, 4, ehHdr.Offset, Base + ehHdr.Rva, ehHdr.Size, ehHdr.Size, 4));
        if (exidx != null) phdrs.Add((0x70000001, 4, exidx.Offset, Base + exidx.Rva, exidx.Size, exidx.Size, 4));

        int ehsize = Is64 ? 64 : 52, phentsize = Is64 ? 56 : 32;
        var h = new ByteWriter(BigEndian);
        h.Bytes([0x7F, (byte)'E', (byte)'L', (byte)'F', (byte)(Is64 ? 2 : 1), (byte)(BigEndian ? 2 : 1), 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        h.U16(Type);
        h.U16(Machine);
        h.U32(1);
        h.Word(Entry == 0 ? 0 : Base + Entry, Is64);
        h.Word((ulong)ehsize, Is64);
        h.Word((ulong)shoff, Is64);
        h.U32(Machine == EmArm ? 0x05000000u : 0);
        h.U16((ushort)ehsize);
        h.U16((ushort)phentsize);
        h.U16((ushort)phdrs.Count);
        h.U16((ushort)(Is64 ? 64 : 40));
        h.U16((ushort)shnum);
        h.U16((ushort)shstrndx);
        foreach (var ph in phdrs)
        {
            if (Is64)
            {
                h.U32(ph.Type); h.U32(ph.Flags); h.U64(ph.Offset); h.U64(ph.Vaddr); h.U64(ph.Vaddr); h.U64(ph.FileSize); h.U64(ph.MemSize); h.U64(ph.Align);
            }
            else
            {
                h.U32(ph.Type); h.U32((uint)ph.Offset); h.U32((uint)ph.Vaddr); h.U32((uint)ph.Vaddr); h.U32((uint)ph.FileSize); h.U32((uint)ph.MemSize); h.U32(ph.Flags); h.U32((uint)ph.Align);
            }
        }
        if (h.Length > TextRva) throw new InvalidOperationException("headers too large");
        w.BytesAt(0, h.ToArray());
        return w.ToArray();
    }

    private uint JumpSlotType => Machine switch { EmAarch64 => 1026, EmArm => 22, _ => 7 };

    private void WriteSym(ByteWriter w, Symbol s, StringTable strings, ushort shndx)
    {
        uint name = s.Name.Length == 0 ? 0 : strings.Offset(s.Name);
        byte info = s.Name.Length == 0 ? (byte)0 : (byte)((s.Bind << 4) | s.Type);
        ulong value = s.Defined && s.Name.Length > 0 && s.Type != 6 ? Base + s.Value : s.Value;
        if (Is64) { w.U32(name); w.U8(info); w.U8(0); w.U16(shndx); w.U64(value); w.U64(s.Size); }
        else { w.U32(name); w.U32((uint)value); w.U32(s.Size); w.U8(info); w.U8(0); w.U16(shndx); }
    }

    private void WriteRel(ByteWriter w, uint offset, uint type, int sym, long addend)
    {
        w.Word(Base + offset, Is64);
        w.Word(Is64 ? ((ulong)(uint)sym << 32) | type : ((uint)sym << 8) | (type & 0xFF), Is64);
        if (!UseRel) w.Word((ulong)addend, Is64);
    }

    /// <summary>APS2: groups of equal info and offset delta are packed (exercising the grouped forms); others go one by one.</summary>
    private void WriteAps2(ByteWriter w, List<Reloc> relocs, Func<string?, int> symIndex)
    {
        w.Bytes("APS2"u8);
        var sorted = relocs.OrderBy(r => r.Offset).ToList();
        w.Sleb(sorted.Count);
        w.Sleb(0);
        ulong offset = 0;
        long addend = 0;
        int i = 0;
        ulong Info(Reloc r) => Is64 ? ((ulong)(uint)symIndex(r.Symbol) << 32) | r.Type : ((uint)symIndex(r.Symbol) << 8) | (r.Type & 0xFF);
        while (i < sorted.Count)
        {
            ulong delta = Base + sorted[i].Offset - offset;
            int run = 1;
            if (delta == (ulong)WordSize)
                while (i + run < sorted.Count && Info(sorted[i + run]) == Info(sorted[i]) && sorted[i + run].Offset - sorted[i + run - 1].Offset == (uint)WordSize) run++;
            if (run >= 3)
            {
                // Grouped by info and offset delta; addends (RELA) per relocation.
                w.Sleb(run);
                w.Sleb(UseRel ? 3 : 3 | 8);
                w.Sleb(WordSize);
                w.Sleb((long)Info(sorted[i]));
                for (int k = 0; k < run; k++)
                    if (!UseRel) { w.Sleb(sorted[i + k].Addend - addend); addend = sorted[i + k].Addend; }
                offset += (ulong)(run * WordSize);
                i += run;
            }
            else
            {
                w.Sleb(1);
                w.Sleb(UseRel ? 1 : 1 | 8);
                w.Sleb((long)Info(sorted[i]));
                w.Sleb((long)delta);
                if (!UseRel) { w.Sleb(sorted[i].Addend - addend); addend = sorted[i].Addend; }
                offset += delta;
                i++;
            }
        }
    }

    private List<ulong> EncodeRelr(List<ulong> addresses)
    {
        int bits = WordSize * 8 - 1;
        var result = new List<ulong>();
        int i = 0;
        while (i < addresses.Count)
        {
            result.Add(addresses[i]);
            ulong where = addresses[i] + (ulong)WordSize;
            i++;
            while (true)
            {
                ulong bitmap = 0;
                while (i < addresses.Count)
                {
                    ulong d = addresses[i] - where;
                    if (d >= (ulong)(bits * WordSize) || d % (ulong)WordSize != 0) break;
                    bitmap |= 1UL << (int)(d / (ulong)WordSize);
                    i++;
                }
                if (bitmap == 0) break;
                result.Add((bitmap << 1) | 1);
                where += (ulong)(bits * WordSize);
            }
        }
        return result;
    }

    private void WritePlt(ByteWriter w)
    {
        uint Adrp(uint at, uint target)
        {
            long pages = ((long)(Base + target) >> 12) - ((long)(Base + at) >> 12);
            return 0x90000010u | ((uint)(pages & 3) << 29) | (((uint)(pages >> 2) & 0x7FFFF) << 5);
        }
        uint Ldr(uint target) => 0xF9400211u | ((uint)((Base + target) & 0xFFF) / 8 << 10);
        uint AddX16(uint target) => 0x91000210u | ((uint)((Base + target) & 0xFFF) << 10);
        uint plt0 = (uint)w.Length;
        w.U32(0xA9BF7BF0);
        w.U32(Adrp(plt0 + 4, GotPltRva + 16)); w.U32(Ldr(GotPltRva + 16)); w.U32(AddX16(GotPltRva + 16)); w.U32(0xD61F0220);
        w.U32(0xD503201F); w.U32(0xD503201F); w.U32(0xD503201F);
        for (int i = 0; i < PltImports.Count; i++)
        {
            uint at = (uint)w.Length;
            uint slot = PltSlotRva(i);
            w.U32(Adrp(at, slot)); w.U32(Ldr(slot)); w.U32(AddX16(slot)); w.U32(0xD61F0220);
        }
    }

    private void WriteEhFrame(ByteWriter w, List<uint> fdeAt)
    {
        uint cie = (uint)w.Length;
        var c = new ByteWriter(BigEndian);
        c.U32(0); c.U8(1); c.CString("zR"); c.Uleb(4); c.Sleb(-8); c.U8(30); c.Uleb(1); c.U8(0x1B);
        c.U8(0x0C); c.Uleb(31); c.Uleb(0);
        c.Align(4);
        w.U32((uint)c.Length);
        w.Bytes(c.ToArray());
        foreach (var (start, size) in Fdes)
        {
            uint at = (uint)w.Length;
            fdeAt.Add(at);
            w.U32(16);
            w.U32(at + 4 - cie);
            w.U32(start - (at + 8));
            w.U32(size);
            w.U8(0);
            w.U8(0); w.U8(0); w.U8(0);
        }
        w.U32(0);
    }

    private static void WriteNote(ByteWriter w, string name, uint type, byte[] desc)
    {
        w.U32((uint)name.Length + 1);
        w.U32((uint)desc.Length);
        w.U32(type);
        w.CString(name);
        w.Align(4);
        w.Bytes(desc);
        w.Align(4);
    }

    private void WriteShdr(ByteWriter w, uint name, Sec s)
    {
        ulong addr = s.Alloc ? Base + s.Rva : 0;
        ulong flags = s.Flags;
        if (Is64)
        {
            w.U32(name); w.U32(s.Type); w.U64(flags); w.U64(addr); w.U64(s.Offset); w.U64(s.Size); w.U32(s.Link); w.U32(s.Info); w.U64(s.Align); w.U64(s.EntSize);
        }
        else
        {
            w.U32(name); w.U32(s.Type); w.U32((uint)flags); w.U32((uint)addr); w.U32(s.Offset); w.U32(s.Size); w.U32(s.Link); w.U32(s.Info); w.U32(s.Align); w.U32(s.EntSize);
        }
    }

    private static void WriteSysvHash(ByteWriter w, List<Symbol> dynsym)
    {
        uint nbucket = (uint)Math.Max(1, dynsym.Count / 2);
        var buckets = new uint[nbucket];
        var chains = new uint[dynsym.Count];
        for (int i = 1; i < dynsym.Count; i++)
        {
            uint b = ElfHash(dynsym[i].Name) % nbucket;
            chains[i] = buckets[b];
            buckets[b] = (uint)i;
        }
        w.U32(nbucket);
        w.U32((uint)dynsym.Count);
        foreach (var b in buckets) w.U32(b);
        foreach (var c in chains) w.U32(c);
    }

    private void WriteGnuHash(ByteWriter w, List<Symbol> dynsym, int symOffset, uint nbuckets)
    {
        const int shift = 6;
        int bits = WordSize * 8;
        ulong bloom = 0;
        for (int i = symOffset; i < dynsym.Count; i++)
        {
            uint hh = GnuHash(dynsym[i].Name);
            bloom |= 1UL << (int)(hh % (uint)bits);
            bloom |= 1UL << (int)((hh >> shift) % (uint)bits);
        }
        w.U32(nbuckets);
        w.U32((uint)symOffset);
        w.U32(1);
        w.U32(shift);
        w.Word(bloom, Is64);
        var buckets = new uint[nbuckets];
        for (int i = dynsym.Count - 1; i >= symOffset; i--) buckets[GnuHash(dynsym[i].Name) % nbuckets] = (uint)i;
        foreach (var b in buckets) w.U32(b);
        for (int i = symOffset; i < dynsym.Count; i++)
        {
            uint hh = GnuHash(dynsym[i].Name);
            bool last = i + 1 == dynsym.Count || GnuHash(dynsym[i + 1].Name) % nbuckets != hh % nbuckets;
            w.U32(last ? hh | 1 : hh & ~1u);
        }
    }

    public static uint ElfHash(string name)
    {
        uint h = 0;
        foreach (byte c in Encoding.UTF8.GetBytes(name))
        {
            h = (h << 4) + c;
            uint g = h & 0xF0000000;
            if (g != 0) h ^= g >> 24;
            h &= ~g;
        }
        return h;
    }

    public static uint GnuHash(string name)
    {
        uint h = 5381;
        foreach (byte c in Encoding.UTF8.GetBytes(name)) h = h * 33 + c;
        return h;
    }

    /// <summary>A string table that deduplicates names.</summary>
    internal sealed class StringTable
    {
        private readonly ByteWriter w = new();
        private readonly Dictionary<string, uint> offsets = [];

        public uint Add(string s)
        {
            if (offsets.TryGetValue(s, out var o)) return o;
            o = (uint)w.Length;
            w.CString(s);
            offsets[s] = o;
            return o;
        }

        public uint Offset(string s) => offsets[s];
        public byte[] Bytes => w.ToArray();
    }
}
