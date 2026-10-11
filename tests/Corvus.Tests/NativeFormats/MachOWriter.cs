using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace Corvus.Tests.NativeFormats;

/// <summary>
/// Builds small Mach-O images for reader tests. Offsets are from the Mach header (file offset == VM offset):
/// __TEXT holds the header, __text, __stubs, __unwind_info and __eh_frame; __DATA_CONST holds __got and __const;
/// __DATA holds __data, __la_symbol_ptr and __bss; __LINKEDIT the link-edit blobs. Executables get __PAGEZERO.
/// </summary>
internal sealed class MachOWriter
{
    public const uint TextOffset = 0x1000;
    public const uint StubsOffset = 0x3000;
    public const uint UnwindOffset = 0x3400;
    public const uint EhFrameOffset = 0x3800;
    public const uint GotOffset = 0x4000;
    public const uint ConstOffset = 0x4800;
    public const uint DataOffset = 0x8000;
    public const uint LazyPointersOffset = 0x9000;
    private const uint BssOffset = 0xA000;
    private const uint LinkEditOffset = 0xC000;

    public const uint CpuArm64 = 0x0100000C, CpuX64 = 0x01000007, CpuArm = 12, CpuArm64_32 = 0x0200000C, CpuX86 = 7, CpuPpc = 18;

    public sealed record NList(string Name, ulong Value, byte Type = 0x0F, byte Sect = 1, ushort Desc = 0);
    public sealed record Export(string Name, ulong Offset, ulong Flags = 0, ulong Resolver = 0, int ReexportOrdinal = 0, string? ImportName = null);
    public sealed record ChainedImport(int LibOrdinal, string Name, bool Weak = false, long Addend = 0);
    /// <summary>A chained fixup at <paramref name="Offset"/>: a rebase to <paramref name="Target"/> (offset from the header) or a bind to import <paramref name="Import"/>.</summary>
    public sealed record Fixup(uint Offset, ulong Target = 0, int Import = -1, long Addend = 0, bool Auth = false, ushort Diversity = 0, bool AddrDiv = false, byte Key = 0, byte High8 = 0);
    public sealed record Signature(string Identifier, string? TeamId = null, string? Entitlements = null, byte[]? DerEntitlements = null, byte HashType = 2, byte[]? Cms = null);

    public uint CpuType { get; set; } = CpuArm64;
    public uint CpuSubType { get; set; }
    public bool Is64 { get; set; } = true;
    public bool BigEndian { get; set; }
    public uint FileType { get; set; } = 6;
    public byte[] Text { get; set; } = [0x1F, 0x20, 0x03, 0xD5, 0xC0, 0x03, 0x5F, 0xD6];
    public byte[] Const { get; set; } = new byte[0x100];
    public byte[] Data { get; set; } = new byte[0x100];
    public string? InstallName { get; set; } = "@rpath/libtest.dylib";
    /// <summary>Dependent libraries with their load command (LC_LOAD_DYLIB 0xC, LC_LOAD_WEAK_DYLIB 0x80000018, LC_REEXPORT_DYLIB 0x8000001F).</summary>
    public List<(string Path, uint Command)> Dylibs { get; set; } = [];
    public List<string> Rpaths { get; set; } = [];
    public byte[]? Uuid { get; set; }
    public (uint Platform, uint MinOs, uint Sdk)? BuildVersion { get; set; }
    public uint? MainOffset { get; set; }
    public List<NList> Symbols { get; set; } = [];
    /// <summary>Undefined symbols (by name) whose pointers live in __got, indexed through the indirect symbol table.</summary>
    public List<string> GotSymbols { get; set; } = [];
    /// <summary>Undefined symbols reached through __stubs and __la_symbol_ptr.</summary>
    public List<string> StubSymbols { get; set; } = [];
    public List<Export> Exports { get; set; } = [];
    public bool ExportsInDyldInfo { get; set; }
    public List<uint> FunctionStarts { get; set; } = [];
    public List<(uint Offset, ushort Length, ushort Kind)> DataInCode { get; set; } = [];
    public (uint Offset, uint Size, uint Id)? Encryption { get; set; }
    public Signature? CodeSignature { get; set; }
    public ushort? ChainedFormat { get; set; }
    public List<ChainedImport> Imports { get; set; } = [];
    public uint ImportsFormat { get; set; } = 1;
    public bool CompressSymbols { get; set; }
    public List<Fixup> Fixups { get; set; } = [];
    public uint ChainPageSize { get; set; } = 0x1000;
    /// <summary>Raw LC_DYLD_INFO_ONLY opcode streams.</summary>
    public byte[]? RebaseOpcodes { get; set; }
    public byte[]? BindOpcodes { get; set; }
    public byte[]? WeakBindOpcodes { get; set; }
    public byte[]? LazyBindOpcodes { get; set; }
    public List<(uint FunctionOffset, uint Encoding)> CompactUnwind { get; set; } = [];
    public bool CompactCompressed { get; set; }
    public List<(uint Start, uint Size)> EhFdes { get; set; } = [];
    /// <summary>Extra load commands, written as given (cmd and cmdsize included).</summary>
    public List<byte[]> ExtraCommands { get; set; } = [];

    private bool IsExecute => FileType == 2;
    public ulong TextVm => IsExecute ? 0x1_0000_0000UL : 0;
    private int Ptr => Is64 ? 8 : 4;

    private sealed record Section(string Seg, string Name, uint Offset, uint Size, uint Flags, uint Reserved1 = 0, uint Reserved2 = 0, bool ZeroFill = false);

    public byte[] Build()
    {
        if (!Is64 && IsExecute) throw new NotSupportedException("32-bit executables are not built");
        var w = new ByteWriter(BigEndian);
        w.PadTo((int)LinkEditOffset);
        var sections = new List<Section>();

        void Put(uint at, byte[] bytes, uint max) { if (bytes.Length > max) throw new InvalidOperationException("content too large"); w.BytesAt((int)at, bytes); }
        Put(TextOffset, Text, StubsOffset - TextOffset);
        sections.Add(new("__TEXT", "__text", TextOffset, (uint)Text.Length, 0x80000400));

        // Symbols: locals, external definitions, undefined (the order LC_DYSYMTAB describes).
        var undefinedNames = GotSymbols.Concat(StubSymbols).Distinct().Where(n => Symbols.All(s => s.Name != n)).ToList();
        var all = Symbols.Concat(undefinedNames.Select(n => new NList(n, 0, 0x01, 0, 0x0100))).ToList();
        var locals = all.Where(s => (s.Type & 0x0E) != 0 && (s.Type & 0x01) == 0).ToList();
        var extdef = all.Where(s => (s.Type & 0x0E) != 0 && (s.Type & 0x01) != 0).ToList();
        var undef = all.Where(s => (s.Type & 0x0E) == 0).ToList();
        var symbols = locals.Concat(extdef).Concat(undef).ToList();
        int SymbolIndex(string name) => symbols.FindIndex(s => s.Name == name);
        var indirect = new List<uint>();

        if (StubSymbols.Count > 0)
        {
            var stubs = new ByteWriter(BigEndian);
            for (int i = 0; i < StubSymbols.Count; i++)
            {
                ulong at = TextVm + StubsOffset + (ulong)(i * 12);
                ulong slot = TextVm + LazyPointersOffset + (ulong)(i * Ptr);
                long pages = (long)(slot >> 12) - (long)(at >> 12);
                stubs.U32(0x90000010u | ((uint)(pages & 3) << 29) | (((uint)(pages >> 2) & 0x7FFFF) << 5));
                stubs.U32(0xF9400210u | ((uint)(slot & 0xFFF) / 8 << 10));
                stubs.U32(0xD61F0200);
            }
            Put(StubsOffset, stubs.ToArray(), UnwindOffset - StubsOffset);
        }
        if (CompactUnwind.Count > 0)
        {
            var u = BuildUnwindInfo();
            Put(UnwindOffset, u, EhFrameOffset - UnwindOffset);
            sections.Add(new("__TEXT", "__unwind_info", UnwindOffset, (uint)u.Length, 0));
        }
        if (EhFdes.Count > 0)
        {
            var e = BuildEhFrame();
            Put(EhFrameOffset, e, GotOffset - EhFrameOffset);
            sections.Add(new("__TEXT", "__eh_frame", EhFrameOffset, (uint)e.Length, 0x6800000B));
        }
        if (GotSymbols.Count > 0)
        {
            sections.Add(new("__DATA_CONST", "__got", GotOffset, (uint)(GotSymbols.Count * Ptr), 6, (uint)indirect.Count));
            indirect.AddRange(GotSymbols.Select(n => (uint)SymbolIndex(n)));
        }
        Put(ConstOffset, Const, DataOffset - ConstOffset);
        sections.Add(new("__DATA_CONST", "__const", ConstOffset, (uint)Const.Length, 0));
        Put(DataOffset, Data, LazyPointersOffset - DataOffset);
        sections.Add(new("__DATA", "__data", DataOffset, (uint)Data.Length, 0));
        if (StubSymbols.Count > 0)
        {
            sections.Insert(1, new("__TEXT", "__stubs", StubsOffset, (uint)(StubSymbols.Count * 12), 0x80000408, (uint)indirect.Count, 12));
            indirect.AddRange(StubSymbols.Select(n => (uint)SymbolIndex(n)));
            sections.Add(new("__DATA", "__la_symbol_ptr", LazyPointersOffset, (uint)(StubSymbols.Count * Ptr), 7, (uint)indirect.Count));
            indirect.AddRange(StubSymbols.Select(n => (uint)SymbolIndex(n)));
        }
        sections.Add(new("__DATA", "__bss", BssOffset, 0x100, 1, ZeroFill: true));

        // Chained fixups are written into the data before __LINKEDIT is laid out.
        byte[]? chained = ChainedFormat is { } format ? BuildChainedFixups(w, format) : null;

        // __LINKEDIT
        var le = new ByteWriter(BigEndian);
        (uint Off, uint Size) Blob(byte[]? bytes)
        {
            if (bytes == null) return (0, 0);
            le.Align(8);
            uint off = LinkEditOffset + (uint)le.Length;
            le.Bytes(bytes);
            return (off, (uint)bytes.Length);
        }
        var chainedBlob = Blob(chained);
        var trie = Exports.Count > 0 ? BuildTrie() : null;
        var trieBlob = ExportsInDyldInfo ? default : Blob(trie);
        var startsBlob = Blob(FunctionStarts.Count > 0 ? FunctionStartsBytes() : null);
        var dicBlob = Blob(DataInCode.Count > 0 ? DataInCodeBytes() : null);
        var rebase = Blob(RebaseOpcodes);
        var bind = Blob(BindOpcodes);
        var weak = Blob(WeakBindOpcodes);
        var lazy = Blob(LazyBindOpcodes);
        var dyldExport = ExportsInDyldInfo ? Blob(trie) : default;
        var strings = new ElfWriter.StringTable();
        strings.Add(" ");
        foreach (var s in symbols) strings.Add(s.Name);
        var symBytes = new ByteWriter(BigEndian);
        foreach (var s in symbols)
        {
            symBytes.U32(strings.Offset(s.Name));
            symBytes.U8(s.Type);
            symBytes.U8(s.Sect);
            symBytes.U16(s.Desc);
            ulong value = (s.Type & 0x0E) == 0x0E ? TextVm + s.Value : s.Value;
            symBytes.Word(value, Is64);
        }
        var symtab = Blob(symbols.Count > 0 ? symBytes.ToArray() : null);
        var indirectBytes = new ByteWriter(BigEndian);
        foreach (var i in indirect) indirectBytes.U32(i);
        var indirectBlob = Blob(indirect.Count > 0 ? indirectBytes.ToArray() : null);
        var strBlob = Blob(symbols.Count > 0 ? strings.Bytes : null);
        le.Align(16);
        uint signatureOffset = LinkEditOffset + (uint)le.Length;
        w.BytesAt((int)LinkEditOffset, le.ToArray());

        // Load commands
        var lc = new ByteWriter(BigEndian);
        int ncmds = 0;
        void Cmd(uint cmd, Action<ByteWriter> body, int align)
        {
            var c = new ByteWriter(BigEndian);
            body(c);
            c.Align(align);
            lc.U32(cmd);
            lc.U32((uint)c.Length + 8);
            lc.Bytes(c.ToArray());
            ncmds++;
        }
        int lcAlign = Is64 ? 8 : 4;
        void Segment(string name, ulong vm, ulong vmSize, ulong fileOff, ulong fileSize, uint prot)
        {
            var secs = sections.Where(s => s.Seg == name).ToList();
            Cmd(Is64 ? 0x19u : 0x1u, c =>
            {
                c.FixedString(name, 16);
                c.Word(vm, Is64); c.Word(vmSize, Is64); c.Word(fileOff, Is64); c.Word(fileSize, Is64);
                c.U32(prot); c.U32(prot); c.U32((uint)secs.Count); c.U32(0);
                foreach (var s in secs)
                {
                    c.FixedString(s.Name, 16);
                    c.FixedString(s.Seg, 16);
                    c.Word(TextVm + s.Offset, Is64);
                    c.Word(s.Size, Is64);
                    c.U32(s.ZeroFill ? 0 : s.Offset);
                    c.U32(Is64 ? 3u : 2u);
                    c.U32(0); c.U32(0);
                    c.U32(s.Flags); c.U32(s.Reserved1); c.U32(s.Reserved2);
                    if (Is64) c.U32(0);
                }
            }, lcAlign);
        }
        uint signatureSize = CodeSignature != null ? (uint)BuildSignature(new byte[signatureOffset], signatureOffset).Length : 0;
        uint linkEditSize = signatureOffset - LinkEditOffset + signatureSize;
        if (IsExecute) Segment("__PAGEZERO", 0, 0x1_0000_0000UL, 0, 0, 0);
        Segment("__TEXT", TextVm, GotOffset, 0, GotOffset, 5);
        Segment("__DATA_CONST", TextVm + GotOffset, DataOffset - GotOffset, GotOffset, DataOffset - GotOffset, 3);
        Segment("__DATA", TextVm + DataOffset, LinkEditOffset - DataOffset, DataOffset, LinkEditOffset - DataOffset, 3);
        Segment("__LINKEDIT", TextVm + LinkEditOffset, (linkEditSize + 0xFFF) & ~0xFFFu, LinkEditOffset, linkEditSize, 1);
        void Dylib(uint cmd, string path) => Cmd(cmd, c => { c.U32(24); c.U32(2); c.U32(0x10000); c.U32(0x10000); c.CString(path); }, lcAlign);
        if (InstallName != null && FileType == 6) Dylib(0xD, InstallName);
        foreach (var (path, command) in Dylibs) Dylib(command, path);
        foreach (var r in Rpaths) Cmd(0x8000001C, c => { c.U32(12); c.CString(r); }, lcAlign);
        if (Uuid != null) Cmd(0x1B, c => c.Bytes(Uuid), 1);
        if (BuildVersion is { } bv) Cmd(0x32, c => { c.U32(bv.Platform); c.U32(bv.MinOs); c.U32(bv.Sdk); c.U32(0); }, 1);
        if (MainOffset is { } main) Cmd(0x80000028, c => { c.U64(main); c.U64(0); }, 1);
        void LinkEdit(uint cmd, (uint Off, uint Size) blob) { if (blob.Size != 0) Cmd(cmd, c => { c.U32(blob.Off); c.U32(blob.Size); }, 1); }
        LinkEdit(0x80000034, chainedBlob);
        LinkEdit(0x80000033, trieBlob);
        if (RebaseOpcodes != null || BindOpcodes != null || WeakBindOpcodes != null || LazyBindOpcodes != null || ExportsInDyldInfo)
            Cmd(0x80000022, c =>
            {
                foreach (var b in new[] { rebase, bind, weak, lazy, dyldExport }) { c.U32(b.Off); c.U32(b.Size); }
            }, 1);
        if (symbols.Count > 0)
        {
            Cmd(0x2, c => { c.U32(symtab.Off); c.U32((uint)symbols.Count); c.U32(strBlob.Off); c.U32(strBlob.Size); }, 1);
            Cmd(0xB, c =>
            {
                c.U32(0); c.U32((uint)locals.Count); c.U32((uint)locals.Count); c.U32((uint)extdef.Count); c.U32((uint)(locals.Count + extdef.Count)); c.U32((uint)undef.Count);
                for (int i = 0; i < 6; i++) c.U32(0);
                c.U32(indirectBlob.Off); c.U32((uint)indirect.Count);
                for (int i = 0; i < 4; i++) c.U32(0);
            }, 1);
        }
        LinkEdit(0x26, startsBlob);
        LinkEdit(0x29, dicBlob);
        if (Encryption is { } enc)
            Cmd(Is64 ? 0x2Cu : 0x21u, c => { c.U32(enc.Offset); c.U32(enc.Size); c.U32(enc.Id); if (Is64) c.U32(0); }, 1);
        foreach (var extra in ExtraCommands) { lc.Bytes(extra); ncmds++; }
        int signatureCommandAt = -1;
        if (CodeSignature != null)
        {
            signatureCommandAt = lc.Length;
            Cmd(0x1D, c => { c.U32(signatureOffset); c.U32(0); }, 1);
        }

        var h = new ByteWriter(BigEndian);
        h.U32(Is64 ? 0xFEEDFACFu : 0xFEEDFACEu);
        h.U32(CpuType); h.U32(CpuSubType); h.U32(FileType);
        h.U32((uint)ncmds); h.U32((uint)lc.Length);
        h.U32(IsExecute ? 0x00200085u : 0x00100085u);
        if (Is64) h.U32(0);
        if (h.Length + lc.Length > TextOffset) throw new InvalidOperationException("load commands too large");
        w.BytesAt(0, h.ToArray());
        w.BytesAt(h.Length, lc.ToArray());

        if (CodeSignature != null)
        {
            w.PadTo((int)signatureOffset);
            var sig = BuildSignature(w.ToArray().AsSpan(0, (int)signatureOffset), signatureOffset);
            w.U32At(h.Length + signatureCommandAt + 12, (uint)sig.Length);
            w.BytesAt((int)signatureOffset, sig);
            // The code directory hashes the load commands, so hash again now that the size is final.
            sig = BuildSignature(w.ToArray().AsSpan(0, (int)signatureOffset), signatureOffset);
            w.BytesAt((int)signatureOffset, sig);
        }
        return w.ToArray();
    }

    /// <summary>A universal file of the given slices (aligned to 2^14), FAT_MAGIC or FAT_MAGIC_64.</summary>
    public static byte[] Fat(IReadOnlyList<(uint CpuType, uint CpuSubType, byte[] Bytes)> slices, bool fat64 = false)
    {
        var w = new ByteWriter(bigEndian: true);
        w.U32(fat64 ? 0xCAFEBABFu : 0xCAFEBABEu);
        w.U32((uint)slices.Count);
        long offset = 0x4000;
        var placed = new List<long>();
        foreach (var (cpu, sub, bytes) in slices)
        {
            placed.Add(offset);
            w.U32(cpu); w.U32(sub);
            if (fat64) { w.U64((ulong)offset); w.U64((ulong)bytes.Length); w.U32(14); w.U32(0); }
            else { w.U32((uint)offset); w.U32((uint)bytes.Length); w.U32(14); }
            offset = (offset + bytes.Length + 0x3FFF) & ~0x3FFFL;
        }
        for (int i = 0; i < slices.Count; i++) w.BytesAt((int)placed[i], slices[i].Bytes);
        return w.ToArray();
    }

    private byte[] FunctionStartsBytes()
    {
        var b = new ByteWriter();
        ulong prev = 0;
        foreach (var s in FunctionStarts.Order()) { b.Uleb(s - prev); prev = s; }
        b.U8(0);
        b.Align(Ptr);
        return b.ToArray();
    }

    private byte[] DataInCodeBytes()
    {
        var b = new ByteWriter(BigEndian);
        foreach (var (off, len, kind) in DataInCode) { b.U32(off); b.U16(len); b.U16(kind); }
        return b.ToArray();
    }

    private sealed class TrieNode
    {
        public byte[]? Terminal;
        public List<(string Edge, TrieNode Child)> Children = [];
        public int Offset;
    }

    private byte[] BuildTrie()
    {
        var root = new TrieNode();
        foreach (var e in Exports)
        {
            var t = new ByteWriter();
            t.Uleb(e.Flags);
            if ((e.Flags & 0x08) != 0) { t.Uleb((ulong)e.ReexportOrdinal); t.CString(e.ImportName ?? ""); }
            else if ((e.Flags & 0x10) != 0) { t.Uleb(e.Offset); t.Uleb(e.Resolver); }
            else t.Uleb(e.Offset);
            Insert(root, e.Name, t.ToArray());
        }
        var order = new List<TrieNode>();
        void Walk(TrieNode n) { order.Add(n); foreach (var (_, c) in n.Children) Walk(c); }
        Walk(root);
        bool changed = true;
        while (changed)
        {
            changed = false;
            int at = 0;
            foreach (var n in order)
            {
                if (n.Offset != at) { n.Offset = at; changed = true; }
                at += NodeSize(n);
            }
        }
        var w = new ByteWriter();
        foreach (var n in order)
        {
            if (n.Terminal is { } term) { w.Uleb((ulong)term.Length); w.Bytes(term); }
            else w.U8(0);
            w.U8((byte)n.Children.Count);
            foreach (var (edge, child) in n.Children) { w.CString(edge); w.Uleb((ulong)child.Offset); }
        }
        w.Align(8);
        return w.ToArray();
    }

    private static int NodeSize(TrieNode n)
    {
        int size = n.Terminal is { } t ? ByteWriter.UlebSize((ulong)t.Length) + t.Length : 1;
        size += 1;
        foreach (var (edge, child) in n.Children) size += Encoding.UTF8.GetByteCount(edge) + 1 + ByteWriter.UlebSize((ulong)child.Offset);
        return size;
    }

    private static void Insert(TrieNode node, string rest, byte[] terminal)
    {
        if (rest.Length == 0) { node.Terminal = terminal; return; }
        for (int i = 0; i < node.Children.Count; i++)
        {
            var (edge, child) = node.Children[i];
            int k = 0;
            while (k < edge.Length && k < rest.Length && edge[k] == rest[k]) k++;
            if (k == 0) continue;
            if (k == edge.Length) { Insert(child, rest[k..], terminal); return; }
            var mid = new TrieNode();
            mid.Children.Add((edge[k..], child));
            node.Children[i] = (edge[..k], mid);
            Insert(mid, rest[k..], terminal);
            return;
        }
        var leaf = new TrieNode();
        node.Children.Add((rest, leaf));
        Insert(leaf, "", terminal);
    }

    private static int Stride(ushort format) => format switch { 1 or 9 or 12 or 13 => 8, 11 => 1, _ => 4 };

    /// <summary>Encodes every fixup into the segment bytes as a chain and returns the LC_DYLD_CHAINED_FIXUPS payload.</summary>
    private byte[] BuildChainedFixups(ByteWriter image, ushort format)
    {
        int stride = Stride(format);
        bool wide = format is not (3 or 4 or 5);
        int nextBits = format switch { 2 or 6 or 8 or 11 => 12, 1 or 7 or 9 or 10 or 12 => 11, 3 => 5, 4 => 2, 5 => 6, _ => 11 };
        var segments = IsExecute
            ? new[] { ("__PAGEZERO", 0u, 0u), ("__TEXT", 0u, GotOffset), ("__DATA_CONST", GotOffset, DataOffset), ("__DATA", DataOffset, LinkEditOffset), ("__LINKEDIT", LinkEditOffset, LinkEditOffset) }
            : new[] { ("__TEXT", 0u, GotOffset), ("__DATA_CONST", GotOffset, DataOffset), ("__DATA", DataOffset, LinkEditOffset), ("__LINKEDIT", LinkEditOffset, LinkEditOffset) };

        var starts = new ByteWriter(BigEndian);
        starts.U32((uint)segments.Length);
        int infoTable = starts.Length;
        foreach (var _ in segments) starts.U32(0);
        for (int si = 0; si < segments.Length; si++)
        {
            var (_, from, to) = segments[si];
            var inSeg = Fixups.Where(f => f.Offset >= from && f.Offset < to).OrderBy(f => f.Offset).ToList();
            if (inSeg.Count == 0) continue;
            starts.Align(8);
            starts.U32At(infoTable + si * 4, (uint)starts.Length);
            int pageCount = (int)((to - from + ChainPageSize - 1) / ChainPageSize);
            var pageStarts = new List<ushort>();
            var overflow = new List<ushort>();
            for (int p = 0; p < pageCount; p++)
            {
                uint pageAt = from + (uint)p * ChainPageSize;
                var onPage = inSeg.Where(f => f.Offset >= pageAt && f.Offset < pageAt + ChainPageSize).ToList();
                if (onPage.Count == 0) { pageStarts.Add(0xFFFF); continue; }
                // Split into chains wherever the gap does not fit the next field.
                var chainStarts = new List<ushort> { (ushort)(onPage[0].Offset - pageAt) };
                for (int i = 0; i < onPage.Count; i++)
                {
                    uint next = 0;
                    if (i + 1 < onPage.Count)
                    {
                        uint gap = onPage[i + 1].Offset - onPage[i].Offset;
                        if (gap % stride == 0 && gap / stride < (1u << nextBits)) next = gap / (uint)stride;
                        else chainStarts.Add((ushort)(onPage[i + 1].Offset - pageAt));
                    }
                    var value = Encode(format, onPage[i], next);
                    if (wide) image.U64At((int)onPage[i].Offset, value);
                    else image.U32At((int)onPage[i].Offset, (uint)value);
                }
                if (chainStarts.Count == 1) pageStarts.Add(chainStarts[0]);
                else
                {
                    // DYLD_CHAINED_PTR_START_MULTI indexes page_start past page_count, where the chain starts are listed.
                    pageStarts.Add((ushort)(0x8000 | (pageCount + overflow.Count)));
                    for (int c = 0; c < chainStarts.Count; c++) overflow.Add((ushort)(chainStarts[c] | (c + 1 == chainStarts.Count ? 0x8000 : 0)));
                }
            }
            int size = 22 + 2 * (pageStarts.Count + overflow.Count);
            starts.U32((uint)size);
            starts.U16((ushort)ChainPageSize);
            starts.U16(format);
            starts.U64(from);
            starts.U32(0);
            starts.U16((ushort)pageStarts.Count);
            foreach (var ps in pageStarts) starts.U16(ps);
            foreach (var o in overflow) starts.U16(o);
        }

        var pool = new ByteWriter();
        pool.U8(0);
        var nameOffsets = Imports.Select(i => { uint o = (uint)pool.Length; pool.CString(i.Name); return o; }).ToList();
        var imports = new ByteWriter(BigEndian);
        for (int i = 0; i < Imports.Count; i++)
        {
            var imp = Imports[i];
            switch (ImportsFormat)
            {
                case 1: imports.U32((uint)(imp.LibOrdinal & 0xFF) | (imp.Weak ? 1u << 8 : 0) | (nameOffsets[i] << 9)); break;
                case 2: imports.U32((uint)(imp.LibOrdinal & 0xFF) | (imp.Weak ? 1u << 8 : 0) | (nameOffsets[i] << 9)); imports.U32((uint)(int)imp.Addend); break;
                default: imports.U64((ulong)(uint)(imp.LibOrdinal & 0xFFFF) | (imp.Weak ? 1UL << 16 : 0) | ((ulong)nameOffsets[i] << 32)); imports.U64((ulong)imp.Addend); break;
            }
        }
        byte[] symbolBytes = pool.ToArray();
        if (CompressSymbols)
        {
            using var ms = new MemoryStream();
            using (var z = new ZLibStream(ms, CompressionLevel.Optimal)) z.Write(symbolBytes);
            symbolBytes = ms.ToArray();
        }
        var b = new ByteWriter(BigEndian);
        int startsOffset = 32;
        int importsOffset = (startsOffset + starts.Length + 7) & ~7;
        int symbolsOffset = importsOffset + imports.Length;
        b.U32(0); b.U32((uint)startsOffset); b.U32((uint)importsOffset); b.U32((uint)symbolsOffset);
        b.U32((uint)Imports.Count); b.U32(ImportsFormat); b.U32(CompressSymbols ? 1u : 0);
        b.PadTo(startsOffset);
        b.Bytes(starts.ToArray());
        b.PadTo(importsOffset);
        b.Bytes(imports.ToArray());
        b.Bytes(symbolBytes);
        b.Align(8);
        return b.ToArray();
    }

    private ulong Encode(ushort format, Fixup f, uint next)
    {
        ulong n = next;
        bool bind = f.Import >= 0;
        ulong vm = TextVm + f.Target;
        ulong auth = ((ulong)f.Diversity << 32) | ((f.AddrDiv ? 1UL : 0) << 48) | ((ulong)(f.Key & 3) << 49);
        switch (format)
        {
            case 1 or 7 or 9 or 10 or 12:
            {
                bool vmTargets = format is 1 or 10;
                bool ord24 = format == 12;
                if (f.Auth)
                    return bind
                        ? ((ulong)(uint)f.Import & (ord24 ? 0xFFFFFFu : 0xFFFFu)) | auth | (n << 51) | (1UL << 62) | (1UL << 63)
                        : (f.Target & 0xFFFFFFFF) | auth | (n << 51) | (1UL << 63);
                if (bind)
                    return ((ulong)(uint)f.Import & (ord24 ? 0xFFFFFFu : 0xFFFFu)) | (((ulong)f.Addend & 0x7FFFF) << 32) | (n << 51) | (1UL << 62);
                return ((vmTargets ? vm : f.Target) & 0x7FFFFFFFFFF) | ((ulong)f.High8 << 43) | (n << 51);
            }
            case 2 or 6:
                if (bind) return ((ulong)(uint)f.Import & 0xFFFFFF) | (((ulong)f.Addend & 0xFF) << 24) | (n << 51) | (1UL << 63);
                return ((format == 2 ? vm : f.Target) & 0xFFFFFFFFF) | ((ulong)f.High8 << 36) | (n << 51);
            case 3:
                if (bind) return ((ulong)(uint)f.Import & 0xFFFFF) | (((ulong)f.Addend & 0x3F) << 20) | (n << 26) | (1UL << 31);
                return (vm & 0x3FFFFFF) | (n << 26);
            case 4: return (f.Target & 0x3FFFFFFF) | (n << 30);
            case 5: return (vm & 0x3FFFFFF) | (n << 26);
            case 8 or 11: return (f.Target & 0x3FFFFFFF) | (f.Auth ? auth | (1UL << 63) : 0) | (n << 51);
            default: throw new NotSupportedException($"pointer format {format}");
        }
    }

    private byte[] BuildUnwindInfo()
    {
        var entries = CompactUnwind.OrderBy(e => e.FunctionOffset).ToList();
        var w = new ByteWriter(BigEndian);
        const uint indexAt = 28;
        uint lsdaAt = indexAt + 24;
        uint pageAt = lsdaAt;
        w.U32(1); w.U32(28); w.U32(0); w.U32(28); w.U32(0); w.U32(indexAt); w.U32(2);
        w.U32(entries[0].FunctionOffset); w.U32(pageAt); w.U32(lsdaAt);
        w.U32(entries[^1].FunctionOffset + 4); w.U32(0); w.U32(lsdaAt);
        if (!CompactCompressed)
        {
            w.U32(2); w.U16(8); w.U16((ushort)entries.Count);
            foreach (var (f, e) in entries) { w.U32(f); w.U32(e); }
        }
        else
        {
            var encodings = entries.Select(e => e.Encoding).Distinct().ToList();
            ushort entriesAt = 12;
            ushort encodingsAt = (ushort)(entriesAt + 4 * entries.Count);
            w.U32(3); w.U16(entriesAt); w.U16((ushort)entries.Count); w.U16(encodingsAt); w.U16((ushort)encodings.Count);
            foreach (var (f, e) in entries) w.U32(((f - entries[0].FunctionOffset) & 0xFFFFFF) | ((uint)encodings.IndexOf(e) << 24));
            foreach (var e in encodings) w.U32(e);
        }
        return w.ToArray();
    }

    private byte[] BuildEhFrame()
    {
        var w = new ByteWriter(BigEndian);
        var c = new ByteWriter(BigEndian);
        c.U32(0); c.U8(1); c.CString("zR"); c.Uleb(1); c.Sleb(-8); c.U8(30); c.Uleb(1); c.U8(0x10);
        c.Align(4);
        w.U32((uint)c.Length);
        w.Bytes(c.ToArray());
        foreach (var (start, size) in EhFdes)
        {
            uint at = EhFrameOffset + (uint)w.Length;
            w.U32(Is64 ? 24u : 16u);
            w.U32((uint)w.Length);
            ulong field = TextVm + at + 8;
            if (Is64) { w.U64(TextVm + start - field); w.U64(size); } else { w.U32((uint)(start - (at + 8))); w.U32(size); }
            w.U8(0);
            w.Align(4);
        }
        w.U32(0);
        return w.ToArray();
    }

    private byte[] BuildSignature(ReadOnlySpan<byte> code, uint codeLimit)
    {
        var sig = CodeSignature!;
        var blobs = new List<(uint Slot, byte[] Blob)>();
        static byte[] Wrap(uint magic, byte[] payload)
        {
            var b = new ByteWriter(true);
            b.U32(magic); b.U32((uint)payload.Length + 8); b.Bytes(payload);
            return b.ToArray();
        }
        var requirements = Wrap(0xFADE0C01, [0, 0, 0, 0]);
        byte[]? ent = sig.Entitlements != null ? Wrap(0xFADE7171, Encoding.UTF8.GetBytes(sig.Entitlements)) : null;
        byte[]? der = sig.DerEntitlements != null ? Wrap(0xFADE7172, sig.DerEntitlements) : null;
        int special = der != null ? 7 : ent != null ? 5 : 2;
        int hashSize = sig.HashType == 1 ? 20 : sig.HashType == 4 ? 48 : 32;
        byte[] Hash(ReadOnlySpan<byte> data)
        {
            byte[] full = sig.HashType switch { 1 => SHA1.HashData(data), 4 => SHA384.HashData(data), _ => SHA256.HashData(data) };
            return full.AsSpan(0, hashSize).ToArray();
        }
        var specialHashes = new byte[special][];
        for (int i = 0; i < special; i++) specialHashes[i] = new byte[hashSize];
        specialHashes[2 - 1] = Hash(requirements);
        if (ent != null) specialHashes[5 - 1] = Hash(ent);
        if (der != null) specialHashes[7 - 1] = Hash(der);
        int pages = (int)((codeLimit + 0xFFF) / 0x1000);

        var cd = new ByteWriter(true);
        const int fixedSize = 88;
        byte[] ident = Encoding.UTF8.GetBytes(sig.Identifier + "\0");
        byte[] team = sig.TeamId != null ? Encoding.UTF8.GetBytes(sig.TeamId + "\0") : [];
        uint identOffset = fixedSize;
        uint teamOffset = sig.TeamId != null ? identOffset + (uint)ident.Length : 0;
        uint hashOffset = identOffset + (uint)ident.Length + (uint)team.Length + (uint)(special * hashSize);
        uint length = hashOffset + (uint)(pages * hashSize);
        cd.U32(0xFADE0C02); cd.U32(length); cd.U32(0x20400); cd.U32(0x2);
        cd.U32(hashOffset); cd.U32(identOffset); cd.U32((uint)special); cd.U32((uint)pages); cd.U32(codeLimit);
        cd.U8((byte)hashSize); cd.U8(sig.HashType); cd.U8(0); cd.U8(12); cd.U32(0);
        cd.U32(0); cd.U32(teamOffset); cd.U32(0); cd.U64(0);
        cd.U64(0); cd.U64(GotOffset); cd.U64(IsExecute ? 1UL : 0);
        cd.Bytes(ident);
        cd.Bytes(team);
        for (int i = special - 1; i >= 0; i--) cd.Bytes(specialHashes[i]);
        for (int p = 0; p < pages; p++)
        {
            int start = p * 0x1000;
            cd.Bytes(Hash(code.Slice(start, Math.Min(0x1000, code.Length - start))));
        }
        blobs.Add((0, cd.ToArray()));
        blobs.Add((2, requirements));
        if (ent != null) blobs.Add((5, ent));
        if (der != null) blobs.Add((7, der));
        blobs.Add((0x10000, Wrap(0xFADE0B01, sig.Cms ?? [])));

        var sb = new ByteWriter(true);
        uint offset = 12 + 8 * (uint)blobs.Count;
        uint total = offset + (uint)blobs.Sum(b => b.Blob.Length);
        sb.U32(0xFADE0CC0); sb.U32(total); sb.U32((uint)blobs.Count);
        foreach (var (slot, blob) in blobs) { sb.U32(slot); sb.U32(offset); offset += (uint)blob.Length; }
        foreach (var (_, blob) in blobs) sb.Bytes(blob);
        return sb.ToArray();
    }
}
