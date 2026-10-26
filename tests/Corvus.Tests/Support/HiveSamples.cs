using System.Buffers.Binary;
using System.Text;

namespace Corvus.Tests;

/// <summary>
/// Builds registry hive files (regf) for reader tests: one hive bin holding a security cell, nk, vk, lh (or ri over lh),
/// db and class cells, then free cells holding deleted keys and values, and a free cell to the end of the bin.
/// </summary>
internal sealed class HiveSamples
{
    public sealed record Value(string Name, int Type, byte[] Data);

    public sealed class Node(string name)
    {
        public string Name { get; } = name;
        public string? Class { get; init; }
        public DateTime Written { get; init; } = new(2024, 5, 6, 7, 8, 9, DateTimeKind.Utc);
        public List<Node> Children { get; } = [];
        public List<Value> Values { get; } = [];
    }

    private readonly List<byte> _cells = [];
    private int _security;

    public int Minor { get; init; } = 5;
    public uint Sequence2 { get; init; } = 1;
    /// <summary>Subkey lists of more entries than this become an ri list over lh lists of this many entries.</summary>
    public int SplitAbove { get; init; } = int.MaxValue;
    /// <summary>Keys written as free cells under the root: the deleted keys a reader can recover.</summary>
    public List<Node> Deleted { get; } = [];

    public static byte[] Utf16(string s) => Encoding.Unicode.GetBytes(s);

    public static byte[] U32(uint v) => BitConverter.GetBytes(v);

    /// <summary>The hive file of <paramref name="root"/>.</summary>
    public byte[] Build(Node root)
    {
        _security = Cell(Security(), free: false);
        int rootCell = Key(root, -1, isRoot: true);
        foreach (var d in Deleted) Key(d, rootCell, isRoot: false, free: true);
        // The rest of the bin is one free cell.
        int used = 32 + _cells.Count;
        int bin = (used + 8 + 4095) & ~4095;
        Cell(new byte[bin - used - 4], free: true);
        var file = new byte[4096 + bin];
        var b = file.AsSpan();
        "regf"u8.CopyTo(b);
        BinaryPrimitives.WriteUInt32LittleEndian(b[4..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(b[8..], Sequence2);
        BinaryPrimitives.WriteInt64LittleEndian(b[12..], root.Written.ToFileTimeUtc());
        BinaryPrimitives.WriteUInt32LittleEndian(b[20..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(b[24..], (uint)Minor);
        BinaryPrimitives.WriteUInt32LittleEndian(b[32..], 1);
        BinaryPrimitives.WriteInt32LittleEndian(b[36..], rootCell);
        BinaryPrimitives.WriteInt32LittleEndian(b[40..], bin);
        BinaryPrimitives.WriteUInt32LittleEndian(b[44..], 1);
        Utf16("\\??\\C:\\work\\sample.dat").CopyTo(b[48..]);
        uint sum = 0;
        for (int i = 0; i < 508; i += 4) sum ^= BinaryPrimitives.ReadUInt32LittleEndian(b[i..]);
        BinaryPrimitives.WriteUInt32LittleEndian(b[508..], sum switch { 0 => 1, 0xFFFFFFFF => 0xFFFFFFFE, _ => sum });
        "hbin"u8.CopyTo(b[4096..]);
        BinaryPrimitives.WriteInt32LittleEndian(b[(4096 + 8)..], bin);
        _cells.ToArray().CopyTo(b[(4096 + 32)..]);
        return file;
    }

    /// <summary>Appends a cell (size rounded up to 8, negative while allocated) and returns its offset from the first bin.</summary>
    private int Cell(byte[] data, bool free)
    {
        int offset = 32 + _cells.Count;
        int size = (data.Length + 4 + 7) & ~7;
        _cells.AddRange(BitConverter.GetBytes(free ? size : -size));
        _cells.AddRange(data);
        _cells.AddRange(new byte[size - 4 - data.Length]);
        return offset;
    }

    private void Patch(int cell, byte[] data) { for (int i = 0; i < data.Length; i++) _cells[cell - 32 + 4 + i] = data[i]; }

    /// <summary>An sk cell of a self-relative descriptor whose DACL allows Everyone KEY_ALL_ACCESS.</summary>
    private static byte[] Security()
    {
        byte[] sd = [1, 0, 0x04, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0,
            2, 0, 28, 0, 1, 0, 0, 0,
            0, 0, 20, 0, 0x3F, 0, 0x0F, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        // The list of security cells is circular: this one links to itself (offset 32, the first cell).
        return [.. "sk"u8, 0, 0, .. U32(32), .. U32(32), .. U32(0x10000), .. U32((uint)sd.Length), .. sd];
    }

    private static bool Ascii(string s) => s.All(c => c is >= ' ' and < (char)0x7F);

    private int Key(Node node, int parent, bool isRoot, bool free = false)
    {
        var name = Ascii(node.Name) ? Encoding.Latin1.GetBytes(node.Name) : Utf16(node.Name);
        int cell = Cell(new byte[76 + name.Length], free);
        var children = node.Children.Select(c => (Name: c.Name, Cell: Key(c, cell, false, free))).OrderBy(c => c.Name.ToUpperInvariant(), StringComparer.Ordinal).ToList();
        int list = children.Count == 0 ? -1 : SubkeyList(children.Select(c => (c.Name, c.Cell)).ToList(), free);
        var values = node.Values.Select(v => ValueCell(v, free)).ToList();
        int valueList = values.Count == 0 ? -1 : Cell([.. values.SelectMany(v => BitConverter.GetBytes(v))], free);
        int classCell = node.Class == null ? -1 : Cell(Utf16(node.Class), free);
        var nk = new byte[76 + name.Length];
        var k = nk.AsSpan();
        "nk"u8.CopyTo(k);
        BinaryPrimitives.WriteUInt16LittleEndian(k[2..], (ushort)((isRoot ? 0x0C : 0) | (Ascii(node.Name) ? 0x20 : 0)));
        BinaryPrimitives.WriteInt64LittleEndian(k[4..], node.Written.ToFileTimeUtc());
        BinaryPrimitives.WriteInt32LittleEndian(k[16..], parent);
        BinaryPrimitives.WriteInt32LittleEndian(k[20..], children.Count);
        BinaryPrimitives.WriteInt32LittleEndian(k[28..], list);
        BinaryPrimitives.WriteInt32LittleEndian(k[32..], -1);
        BinaryPrimitives.WriteInt32LittleEndian(k[36..], values.Count);
        BinaryPrimitives.WriteInt32LittleEndian(k[40..], valueList);
        BinaryPrimitives.WriteInt32LittleEndian(k[44..], _security);
        BinaryPrimitives.WriteInt32LittleEndian(k[48..], classCell);
        BinaryPrimitives.WriteInt32LittleEndian(k[52..], node.Children.Select(c => c.Name.Length * 2).DefaultIfEmpty().Max());
        BinaryPrimitives.WriteInt32LittleEndian(k[56..], node.Children.Select(c => (c.Class?.Length ?? 0) * 2).DefaultIfEmpty().Max());
        BinaryPrimitives.WriteInt32LittleEndian(k[60..], node.Values.Select(v => v.Name.Length * 2).DefaultIfEmpty().Max());
        BinaryPrimitives.WriteInt32LittleEndian(k[64..], node.Values.Select(v => v.Data.Length).DefaultIfEmpty().Max());
        BinaryPrimitives.WriteUInt16LittleEndian(k[72..], (ushort)name.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(k[74..], (ushort)((node.Class?.Length ?? 0) * 2));
        name.CopyTo(k[76..]);
        Patch(cell, nk);
        return cell;
    }

    private int SubkeyList(List<(string Name, int Cell)> children, bool free)
    {
        if (children.Count <= SplitAbove) return Lh(children, free);
        var lists = children.Chunk(SplitAbove).Select(c => Lh([.. c], free)).ToList();
        return Cell([.. "ri"u8, .. BitConverter.GetBytes((ushort)lists.Count), .. lists.SelectMany(x => BitConverter.GetBytes(x))], free);
    }

    /// <summary>An lh list: each key cell with the hash of its upper-case name (h = h * 37 + c).</summary>
    private int Lh(List<(string Name, int Cell)> children, bool free)
    {
        var s = new List<byte>([.. "lh"u8, .. BitConverter.GetBytes((ushort)children.Count)]);
        foreach (var (name, cell) in children)
        {
            uint h = 0;
            foreach (char c in name.ToUpperInvariant()) h = h * 37 + c;
            s.AddRange(BitConverter.GetBytes(cell));
            s.AddRange(BitConverter.GetBytes(h));
        }
        return Cell([.. s], free);
    }

    private int ValueCell(Value v, bool free)
    {
        var name = Ascii(v.Name) ? Encoding.Latin1.GetBytes(v.Name) : Utf16(v.Name);
        uint size = (uint)v.Data.Length;
        int data;
        if (v.Data.Length <= 4)
        {
            // Data of at most 4 bytes sits in the offset field; the top bit of the size says so.
            var inline = new byte[4];
            v.Data.CopyTo(inline, 0);
            data = BitConverter.ToInt32(inline);
            size |= 0x80000000;
        }
        else if (v.Data.Length > 16344 && Minor >= 4)
        {
            // Each segment cell holds 16,344 bytes, the last one padded, as the registry allocates them.
            var segments = v.Data.Chunk(16344).Select(c => Cell([.. c, .. new byte[16344 - c.Length]], free)).ToList();
            int list = Cell([.. segments.SelectMany(x => BitConverter.GetBytes(x))], free);
            data = Cell([.. "db"u8, .. BitConverter.GetBytes((ushort)segments.Count), .. BitConverter.GetBytes(list)], free);
        }
        else data = Cell(v.Data, free);
        return Cell([.. "vk"u8, .. BitConverter.GetBytes((ushort)name.Length), .. BitConverter.GetBytes(size), .. BitConverter.GetBytes(data),
            .. BitConverter.GetBytes(v.Type), .. BitConverter.GetBytes((ushort)(Ascii(v.Name) ? 1 : 0)), 0, 0, .. name], free);
    }
}
