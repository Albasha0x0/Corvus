using System.Buffers.Binary;
using System.Text;
using Corvus.Native.Dump;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>One section of a <see cref="PeSpec"/>; the virtual size is the length of <paramref name="Raw"/>.</summary>
internal sealed record SectionSpec(string Name, uint Characteristics, byte[] Raw);

/// <summary>An absolute pointer at <paramref name="Offset"/> in a section, written as image base plus <paramref name="TargetRva"/>.</summary>
internal sealed record PointerSite(string Section, int Offset, uint TargetRva);

/// <summary>A named export at <paramref name="Rva"/>.</summary>
internal sealed record ExportSpec(string Name, uint Rva);

/// <summary>A module imported by name, with the functions imported from it.</summary>
internal sealed record ImportSpec(string Module, IReadOnlyList<string> Functions);

/// <summary>A built PE file and the RVA of each import address table slot, keyed by <c>module!name</c>.</summary>
internal sealed record PeBuilt(byte[] Bytes, IReadOnlyDictionary<string, uint> IatSlots);

/// <summary>Layout of a synthetic PE; a null <paramref name="ImageBase"/> picks the usual base of the width.</summary>
internal sealed record PeSpec(
    bool Is64Bit,
    IReadOnlyList<SectionSpec> Sections,
    IReadOnlyList<PointerSite>? Pointers = null,
    ulong? ImageBase = null,
    uint FileAlignment = 0x200,
    uint SectionAlignment = 0x1000,
    IReadOnlyList<ExportSpec>? Exports = null,
    IReadOnlyList<ImportSpec>? Imports = null)
{
    /// <summary>The image base written to the optional header.</summary>
    public ulong Base => ImageBase ?? (Is64Bit ? 0x140000000UL : 0x10000000UL);
}

/// <summary>How a loader leaves an image in memory: sections at virtual addresses, or the file bytes unchanged.</summary>
internal enum ImageLayout { Mapped, Flat }

/// <summary>
/// An image placed at <paramref name="Base"/> in a dump; <paramref name="Listed"/> adds it to the module list,
/// <paramref name="OmittedPages"/> are RVAs of pages left out, and <paramref name="IatValues"/> overrides slot values
/// keyed by <c>module!name</c> (by default the address of the named export in another placed image).
/// </summary>
internal sealed record Placed(
    string Name,
    PeBuilt Image,
    ulong Base,
    ImageLayout Layout = ImageLayout.Mapped,
    bool Listed = true,
    IReadOnlyList<uint>? OmittedPages = null,
    IReadOnlyDictionary<string, ulong>? IatValues = null);
/// <summary>Builds synthetic PE files and their mapped form for rebuild tests.</summary>
internal static class RebuildFixtures
{
    private const int Dos = 0x40;
    private const ushort Dir64 = 10;
    private const ushort HighLow = 3;

    /// <summary>Returns a PE file in file layout; pointer sites get a .reloc section. Throws on a site outside its section.</summary>
    public static byte[] Pe(PeSpec spec) => Build(spec).Bytes;

    /// <summary>Returns the PE file and its IAT slot RVAs; exports go in .edata, imports in .idata. Throws on a bad site.</summary>
    public static PeBuilt Build(PeSpec spec)
    {
        var sections = spec.Sections.Select(s => (s.Name, s.Characteristics, Raw: (byte[])s.Raw.Clone())).ToList();
        var rva = new List<uint>();
        uint next = spec.SectionAlignment;
        foreach (var s in sections)
        {
            rva.Add(next);
            next = Align(next + (uint)Math.Max(s.Raw.Length, 1), spec.SectionAlignment);
        }

        uint exportRva = 0, exportSize = 0, importRva = 0, importSize = 0;
        var slots = new Dictionary<string, uint>();
        if (spec.Exports is { Count: > 0 })
        {
            var edata = ExportDirectory(spec.Exports, next);
            exportRva = next;
            exportSize = (uint)edata.Length;
            sections.Add((".edata", 0x40000040, edata));
            rva.Add(next);
            next = Align(next + exportSize, spec.SectionAlignment);
        }
        if (spec.Imports is { Count: > 0 })
        {
            var idata = ImportDirectory(spec.Imports, next, spec.Is64Bit, slots);
            importRva = next;
            importSize = (uint)((spec.Imports.Count + 1) * 20);
            sections.Add((".idata", 0xC0000040, idata));
            rva.Add(next);
            next = Align(next + (uint)idata.Length, spec.SectionAlignment);
        }

        var sites = new List<uint>();
        foreach (var p in spec.Pointers ?? [])
        {
            int i = sections.FindIndex(s => s.Name == p.Section);
            int width = spec.Is64Bit ? 8 : 4;
            if (i < 0 || p.Offset < 0 || p.Offset + width > sections[i].Raw.Length)
                throw new ArgumentException($"Pointer site {p.Section}+{p.Offset:X} is outside its section.");
            ulong value = spec.Base + p.TargetRva;
            if (spec.Is64Bit) BinaryPrimitives.WriteUInt64LittleEndian(sections[i].Raw.AsSpan(p.Offset), value);
            else BinaryPrimitives.WriteUInt32LittleEndian(sections[i].Raw.AsSpan(p.Offset), (uint)value);
            sites.Add(rva[i] + (uint)p.Offset);
        }

        uint relocRva = 0, relocSize = 0;
        if (sites.Count > 0)
        {
            var table = RelocationTable(sites, spec.Is64Bit);
            relocRva = next;
            relocSize = (uint)table.Length;
            sections.Add((".reloc", 0x42000040, table));
            rva.Add(relocRva);
            next = Align(next + relocSize, spec.SectionAlignment);
        }

        int optional = spec.Is64Bit ? 240 : 224;
        uint headers = Align((uint)(Dos + 4 + 20 + optional + 40 * sections.Count), spec.FileAlignment);
        var rawOffsets = new List<uint>();
        uint file = headers;
        foreach (var s in sections)
        {
            rawOffsets.Add(file);
            file += Align((uint)s.Raw.Length, spec.FileAlignment);
        }

        var pe = new byte[file];
        pe[0] = (byte)'M';
        pe[1] = (byte)'Z';
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(0x3C), Dos);
        int at = Dos;
        Encoding.ASCII.GetBytes("PE\0\0").CopyTo(pe, at);
        at += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(at), spec.Is64Bit ? (ushort)0x8664 : (ushort)0x14C);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(at + 2), (ushort)sections.Count);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(at + 16), (ushort)optional);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(at + 18), spec.Is64Bit ? (ushort)0x2022 : (ushort)0x2102);
        at += 20;
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(at), spec.Is64Bit ? (ushort)0x20B : (ushort)0x10B);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 32), spec.SectionAlignment);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 36), spec.FileAlignment);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(at + 40), 6);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(at + 48), 6);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 56), next);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 60), headers);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(at + 68), 3);
        int dirs;
        if (spec.Is64Bit)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(pe.AsSpan(at + 24), spec.Base);
            BinaryPrimitives.WriteUInt64LittleEndian(pe.AsSpan(at + 72), 0x100000);
            BinaryPrimitives.WriteUInt64LittleEndian(pe.AsSpan(at + 80), 0x1000);
            BinaryPrimitives.WriteUInt64LittleEndian(pe.AsSpan(at + 88), 0x100000);
            BinaryPrimitives.WriteUInt64LittleEndian(pe.AsSpan(at + 96), 0x1000);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 108), 16);
            dirs = at + 112;
        }
        else
        {
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 28), (uint)spec.Base);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 72), 0x100000);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 76), 0x1000);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 80), 0x100000);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 84), 0x1000);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 92), 16);
            dirs = at + 96;
        }
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(dirs), exportRva);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(dirs + 4), exportSize);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(dirs + 8), importRva);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(dirs + 12), importSize);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(dirs + 5 * 8), relocRva);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(dirs + 5 * 8 + 4), relocSize);

        int headerTable = at + optional;
        for (int i = 0; i < sections.Count; i++)
        {
            int h = headerTable + 40 * i;
            var name = Encoding.ASCII.GetBytes(sections[i].Name);
            name.AsSpan(0, Math.Min(8, name.Length)).CopyTo(pe.AsSpan(h));
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(h + 8), (uint)sections[i].Raw.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(h + 12), rva[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(h + 16), Align((uint)sections[i].Raw.Length, spec.FileAlignment));
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(h + 20), rawOffsets[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(h + 36), sections[i].Characteristics);
            sections[i].Raw.CopyTo(pe, (int)rawOffsets[i]);
        }
        return new PeBuilt(pe, slots);
    }

    /// <summary>Returns the image in mapped layout, each section at its virtual address; a malformed file throws.</summary>
    public static byte[] Mapped(byte[] file)
    {
        int nt = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C));
        int count = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(nt + 6));
        int optional = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(nt + 20));
        int opt = nt + 24;
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(opt + 56));
        uint headers = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(opt + 60));
        var mapped = new byte[size];
        file.AsSpan(0, (int)Math.Min(headers, (uint)file.Length)).CopyTo(mapped);
        for (int i = 0; i < count; i++)
        {
            int h = opt + optional + 40 * i;
            uint virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(h + 8));
            uint va = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(h + 12));
            uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(h + 16));
            uint rawAt = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(h + 20));
            file.AsSpan((int)rawAt, (int)Math.Min(rawSize, virtualSize)).CopyTo(mapped.AsSpan((int)va));
        }
        return mapped;
    }

    /// <summary>
    /// Writes a minidump holding the images as a loader leaves them and opens it. A mapped image gets the
    /// relocation delta applied at each pointer site and its import slots filled; a flat image keeps its file bytes.
    /// </summary>
    public static MinidumpFile Dump(TempDir dir, params Placed[] images)
    {
        const int page = 0x1000;
        var first = PeFile.FromBytes(images[0].Image.Bytes);
        var builder = new MinidumpBuilder { ProcessorArchitecture = first.Is64Bit ? (ushort)9 : (ushort)0 };
        foreach (var p in images)
        {
            var pe = PeFile.FromBytes(p.Image.Bytes);
            byte[] data = p.Layout == ImageLayout.Flat ? p.Image.Bytes : Loaded(p, pe, images);
            uint stamp = BinaryPrimitives.ReadUInt32LittleEndian(p.Image.Bytes.AsSpan(BinaryPrimitives.ReadInt32LittleEndian(p.Image.Bytes.AsSpan(0x3C)) + 8));
            if (p.Listed) builder.Modules.Add(new MinidumpBuilder.Module(p.Base, (uint)data.Length, stamp, p.Name));
            int padded = (data.Length + page - 1) / page * page;
            // The last page is zero-filled past the data, as a loader maps it.
            var captured = new byte[padded];
            data.CopyTo(captured, 0);
            var omitted = (p.OmittedPages ?? []).Select(r => r / page).ToHashSet();
            int start = -1;
            for (int offset = 0; offset <= padded; offset += page)
            {
                bool present = offset < padded && !omitted.Contains((uint)(offset / page));
                if (present && start < 0) start = offset;
                if (!present && start >= 0)
                {
                    builder.Memory.Add((p.Base + (ulong)start, captured[start..offset]));
                    start = -1;
                }
            }
        }
        builder.Memory.Sort((a, b) => a.Start.CompareTo(b.Start));
        string path = dir.File($"placed-{Guid.NewGuid():N}.dmp");
        File.WriteAllBytes(path, builder.Build());
        return MinidumpFile.Open(path);
    }

    private static byte[] Loaded(Placed p, PeFile pe, Placed[] all)
    {
        var data = Mapped(p.Image.Bytes);
        int width = pe.Is64Bit ? 8 : 4;
        ulong delta = p.Base - pe.ImageBase;
        foreach (uint site in pe.RelocationRvas)
        {
            if (pe.Is64Bit)
                BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan((int)site), BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan((int)site)) + delta);
            else
                BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan((int)site), BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan((int)site)) + (uint)delta);
        }
        foreach (var (key, slot) in p.Image.IatSlots)
        {
            ulong value;
            if (p.IatValues is { } given && given.TryGetValue(key, out var chosen)) value = chosen;
            else if (!TryExportAddress(all, key, out value)) continue;
            if (width == 8) BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan((int)slot), value);
            else BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan((int)slot), (uint)value);
        }
        return data;
    }

    private static bool TryExportAddress(Placed[] all, string key, out ulong address)
    {
        address = 0;
        int bang = key.IndexOf('!');
        string module = key[..bang], name = key[(bang + 1)..];
        var target = all.FirstOrDefault(x => string.Equals(x.Name, module, StringComparison.OrdinalIgnoreCase));
        if (target is null) return false;
        var export = PeFile.FromBytes(target.Image.Bytes).Exports.FirstOrDefault(e => e.Name == name);
        if (export is null) return false;
        address = target.Base + export.Rva;
        return true;
    }

    private static byte[] ExportDirectory(IReadOnlyList<ExportSpec> exports, uint rva)
    {
        var sorted = exports.OrderBy(e => e.Name, StringComparer.Ordinal).ToList();
        int n = sorted.Count;
        uint address = rva + 40, names = address + (uint)(4 * n), ordinals = names + (uint)(4 * n);
        uint text = ordinals + (uint)(2 * n);
        var strings = new List<byte>();
        uint Add(string value)
        {
            uint at = text + (uint)strings.Count;
            strings.AddRange(Encoding.ASCII.GetBytes(value));
            strings.Add(0);
            return at;
        }

        var buffer = new byte[40 + 10 * n];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(12), Add("fixture.dll"));
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(16), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(20), (uint)n);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(24), (uint)n);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(28), address);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(32), names);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(36), ordinals);
        for (int i = 0; i < n; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(40 + 4 * i), sorted[i].Rva);
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(40 + 4 * n + 4 * i), Add(sorted[i].Name));
            BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(40 + 8 * n + 2 * i), (ushort)i);
        }
        return [.. buffer, .. strings];
    }

    private static byte[] ImportDirectory(IReadOnlyList<ImportSpec> imports, uint rva, bool is64, Dictionary<string, uint> slots)
    {
        int width = is64 ? 8 : 4;
        int count = imports.Count;
        uint cursor = (uint)((count + 1) * 20);
        var lookups = new uint[count];
        var addresses = new uint[count];
        for (int i = 0; i < count; i++)
        {
            uint table = (uint)((imports[i].Functions.Count + 1) * width);
            lookups[i] = cursor;
            addresses[i] = cursor + table;
            cursor += 2 * table;
        }

        var buffer = new byte[cursor];
        var text = new List<byte>();
        uint Add(byte[] bytes)
        {
            uint at = rva + cursor + (uint)text.Count;
            text.AddRange(bytes);
            return at;
        }

        for (int i = 0; i < count; i++)
        {
            var m = imports[i];
            for (int k = 0; k < m.Functions.Count; k++)
            {
                string f = m.Functions[k];
                byte[] entry = [0, 0, .. Encoding.ASCII.GetBytes(f), 0];
                if (entry.Length % 2 != 0) entry = [.. entry, 0];
                uint hintName = Add(entry);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan((int)lookups[i] + k * width), hintName);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan((int)addresses[i] + k * width), hintName);
                slots[$"{m.Module}!{f}"] = rva + addresses[i] + (uint)(k * width);
            }
            uint module = Add([.. Encoding.ASCII.GetBytes(m.Module), 0]);
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(i * 20), rva + lookups[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(i * 20 + 12), module);
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(i * 20 + 16), rva + addresses[i]);
        }
        return [.. buffer, .. text];
    }

    private static byte[] RelocationTable(List<uint> sites, bool is64)
    {
        var table = new List<byte>();
        foreach (var page in sites.GroupBy(s => s & ~0xFFFu).OrderBy(g => g.Key))
        {
            var entries = page.Order().Select(s => (ushort)(((uint)(is64 ? Dir64 : HighLow) << 12) | (s & 0xFFF))).ToList();
            if (entries.Count % 2 != 0) entries.Add(0);
            var block = new byte[8 + entries.Count * 2];
            BinaryPrimitives.WriteUInt32LittleEndian(block, page.Key);
            BinaryPrimitives.WriteUInt32LittleEndian(block.AsSpan(4), (uint)block.Length);
            for (int i = 0; i < entries.Count; i++)
                BinaryPrimitives.WriteUInt16LittleEndian(block.AsSpan(8 + i * 2), entries[i]);
            table.AddRange(block);
        }
        return [.. table];
    }

    private static uint Align(uint value, uint alignment) => (value + alignment - 1) / alignment * alignment;
}
