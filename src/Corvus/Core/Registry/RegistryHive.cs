using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Registry;

/// <summary>A registry hive file (regf) read without the registry API; deleted keys and values in free cells are recovered.</summary>
internal sealed class RegistryHive
{
    /// <summary>The base block: stored file name, last write, format version, hive type, the two sequence numbers and whether its checksum holds.</summary>
    public sealed record BaseBlock(string FileName, DateTime? LastWritten, int Major, int Minor, int Type, uint Sequence1, uint Sequence2, bool ChecksumValid, int RootCell, int BinsSize)
    {
        /// <summary>The sequence numbers differ when a write did not complete; the transaction logs may hold newer data.</summary>
        public bool Dirty => Sequence1 != Sequence2;
    }

    /// <summary>A key: its cell, name, last write, class name (null for none), parent cell, counts and list cells, and whether it came from a free cell.</summary>
    public sealed record Key(int Cell, string Name, DateTime? LastWritten, string? Class, int Parent, int SubkeyCount, int ValueCount, int SubkeyList, int ValueList, bool Recovered);

    /// <summary>A value: its cell, name (empty for the default value), type, data, the size its cell declares, and whether it came from a free cell.</summary>
    public sealed record Value(int Cell, string Name, int Type, byte[] Data, long DeclaredSize, bool Recovered);

    private const int BinsStart = 4096, MaxSegment = 16344, MaxListDepth = 4, MaxNotes = 20;

    private readonly byte[] _b;
    private readonly int _end;
    private int _noted;

    public BaseBlock Header { get; }
    public List<string> Notes { get; } = [];
    public Key Root { get; }

    private RegistryHive(byte[] b, BaseBlock header)
    {
        _b = b;
        Header = header;
        _end = (int)Math.Min(b.Length, (long)BinsStart + header.BinsSize);
        Root = KeyAt(header.RootCell, recovered: false) ?? throw new InvalidDataException($"the root key cell 0x{header.RootCell:X} does not read");
    }

    /// <summary>"regf" at offset 0.</summary>
    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= 4 && b[..4].SequenceEqual("regf"u8);

    /// <summary>Reads the base block and root key; throws <see cref="InvalidDataException"/> when either does not read.</summary>
    public static RegistryHive Read(byte[] data)
    {
        if (!Looks(data) || data.Length < BinsStart + 32) throw new InvalidDataException("no regf base block");
        var b = data.AsSpan();
        uint sum = 0;
        for (int i = 0; i < 508; i += 4) sum ^= BinaryPrimitives.ReadUInt32LittleEndian(b[i..]);
        sum = sum switch { 0 => 1, 0xFFFFFFFF => 0xFFFFFFFE, _ => sum };
        int bins = (int)Math.Min(int.MaxValue - BinsStart, BinaryPrimitives.ReadUInt32LittleEndian(b[40..]));
        var header = new BaseBlock(Utf16(b.Slice(48, 64)).Split('\0')[0], Time(b[12..]), (int)BinaryPrimitives.ReadUInt32LittleEndian(b[20..]),
            (int)BinaryPrimitives.ReadUInt32LittleEndian(b[24..]), (int)BinaryPrimitives.ReadUInt32LittleEndian(b[28..]),
            BinaryPrimitives.ReadUInt32LittleEndian(b[4..]), BinaryPrimitives.ReadUInt32LittleEndian(b[8..]),
            sum == BinaryPrimitives.ReadUInt32LittleEndian(b[508..]), BinaryPrimitives.ReadInt32LittleEndian(b[36..]), bins);
        var hive = new RegistryHive(data, header);
        if (header.Dirty)
            hive.Notes.Add($"the sequence numbers differ ({header.Sequence1}, {header.Sequence2}): a write did not complete; the transaction logs (.LOG1, .LOG2) may hold newer keys and values, not applied");
        if (!header.ChecksumValid) hive.Notes.Add("the base block checksum does not hold");
        if ((long)BinsStart + header.BinsSize > data.Length) hive.Notes.Add($"the hive bins declare {header.BinsSize:N0} bytes; the file holds {data.Length - BinsStart:N0}");
        return hive;
    }

    /// <summary>The data of the cell at <paramref name="offset"/>, allocated or not; empty when the cell runs outside the bins.</summary>
    private ReadOnlySpan<byte> Cell(int offset, bool allocated = true)
    {
        long at = (long)BinsStart + offset;
        if (offset < 0 || at + 4 > _end) return [];
        int size = BinaryPrimitives.ReadInt32LittleEndian(_b.AsSpan((int)at));
        if (allocated && size >= 0 || size == int.MinValue) return [];
        long length = Math.Abs((long)size);
        if (length < 8 || at + length > _end) return [];
        return _b.AsSpan((int)at + 4, (int)length - 4);
    }

    private void Note(string text)
    {
        if (_noted++ < MaxNotes) Notes.Add(text);
        else if (_noted == MaxNotes + 1) Notes.Add("more cells do not read; further notes are not kept");
    }

    /// <summary>The key in the nk cell at <paramref name="offset"/>; null when the cell is no key.</summary>
    public Key? KeyAt(int offset, bool recovered) => ParseKey(recovered ? FreeCell(offset) : Cell(offset), offset, recovered);

    private ReadOnlySpan<byte> FreeCell(int offset)
    {
        long at = (long)BinsStart + offset;
        if (offset < 0 || at + 4 > _end) return [];
        long length = Math.Abs((long)BinaryPrimitives.ReadInt32LittleEndian(_b.AsSpan((int)at)));
        return length >= 8 && at + length <= _end ? _b.AsSpan((int)at + 4, (int)length - 4) : [];
    }

    private Key? ParseKey(ReadOnlySpan<byte> c, int offset, bool recovered)
    {
        if (c.Length < 76 || c[0] != 'n' || c[1] != 'k') return null;
        int flags = BinaryPrimitives.ReadUInt16LittleEndian(c[2..]);
        int nameLength = BinaryPrimitives.ReadUInt16LittleEndian(c[72..]), classLength = BinaryPrimitives.ReadUInt16LittleEndian(c[74..]);
        if (76 + nameLength > c.Length) return null;
        // KEY_COMP_NAME: the name is stored one byte per character.
        string name = (flags & 0x20) != 0 ? Encoding.Latin1.GetString(c.Slice(76, nameLength)) : Utf16(c.Slice(76, nameLength));
        string? className = null;
        int classCell = BinaryPrimitives.ReadInt32LittleEndian(c[48..]);
        if (classCell != -1 && classLength > 0)
        {
            var cc = recovered ? FreeCell(classCell) : Cell(classCell);
            className = cc.Length >= classLength ? Utf16(cc[..classLength]) : null;
        }
        return new Key(offset, name, Time(c[4..]), className, BinaryPrimitives.ReadInt32LittleEndian(c[16..]),
            (int)BinaryPrimitives.ReadUInt32LittleEndian(c[20..]), (int)BinaryPrimitives.ReadUInt32LittleEndian(c[36..]),
            BinaryPrimitives.ReadInt32LittleEndian(c[28..]), BinaryPrimitives.ReadInt32LittleEndian(c[40..]), recovered);
    }

    /// <summary>The subkeys of <paramref name="key"/> in list order; a list cell that does not read is a note.</summary>
    public List<Key> Subkeys(Key key)
    {
        var keys = new List<Key>();
        if (key.SubkeyCount == 0 || key.SubkeyList == -1) return keys;
        var cells = new List<int>();
        List(key.SubkeyList, cells, 0, key.Recovered);
        foreach (int cell in cells)
        {
            if (KeyAt(cell, key.Recovered) is { } k) keys.Add(k);
            else Note($"{key.Name}: subkey cell 0x{cell:X} is no key");
            if (keys.Count >= key.SubkeyCount && !key.Recovered) break;
        }
        if (keys.Count < key.SubkeyCount && !key.Recovered) Note($"{key.Name}: {keys.Count:N0} of {key.SubkeyCount:N0} subkeys read");
        return keys;
    }

    private void List(int offset, List<int> cells, int depth, bool recovered)
    {
        var c = recovered ? FreeCell(offset) : Cell(offset);
        if (c.Length < 4 || depth > MaxListDepth) { Note($"subkey list cell 0x{offset:X} does not read"); return; }
        int count = BinaryPrimitives.ReadUInt16LittleEndian(c[2..]);
        // li and ri hold 4-byte offsets; lf and lh pair each offset with a 4-byte name hint or hash.
        int width = c[0] == 'l' && c[1] is (byte)'f' or (byte)'h' ? 8 : 4;
        if (!(c[0] == 'l' && c[1] is (byte)'i' or (byte)'f' or (byte)'h' || c[0] == 'r' && c[1] == 'i')) { Note($"subkey list cell 0x{offset:X}: unknown signature"); return; }
        if (4 + (long)count * width > c.Length) { Note($"subkey list cell 0x{offset:X}: {count:N0} entries run past the cell"); count = (c.Length - 4) / width; }
        for (int i = 0; i < count; i++)
        {
            int cell = BinaryPrimitives.ReadInt32LittleEndian(c[(4 + i * width)..]);
            if (c[0] == 'r') List(cell, cells, depth + 1, recovered);
            else cells.Add(cell);
        }
    }

    /// <summary>The values of <paramref name="key"/> in list order; a value cell that does not read is a note.</summary>
    public List<Value> Values(Key key)
    {
        var values = new List<Value>();
        if (key.ValueCount == 0 || key.ValueList == -1) return values;
        var list = key.Recovered ? FreeCell(key.ValueList) : Cell(key.ValueList);
        int count = Math.Min(key.ValueCount, list.Length / 4);
        if (count < key.ValueCount) Note($"{key.Name}: the value list holds {count:N0} of {key.ValueCount:N0} values");
        for (int i = 0; i < count; i++)
        {
            int cell = BinaryPrimitives.ReadInt32LittleEndian(list[(i * 4)..]);
            if (ValueAt(cell, key.Recovered) is { } v) values.Add(v);
            else Note($"{key.Name}: value cell 0x{cell:X} does not read");
        }
        return values;
    }

    /// <summary>The value in the vk cell at <paramref name="offset"/>; null when the cell is no value.</summary>
    public Value? ValueAt(int offset, bool recovered)
    {
        var c = recovered ? FreeCell(offset) : Cell(offset);
        if (c.Length < 20 || c[0] != 'v' || c[1] != 'k') return null;
        int nameLength = BinaryPrimitives.ReadUInt16LittleEndian(c[2..]);
        if (20 + nameLength > c.Length) return null;
        // VALUE_COMP_NAME: the name is stored one byte per character.
        string name = (BinaryPrimitives.ReadUInt16LittleEndian(c[16..]) & 1) != 0 ? Encoding.Latin1.GetString(c.Slice(20, nameLength)) : Utf16(c.Slice(20, nameLength));
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(c[4..]);
        int type = (int)BinaryPrimitives.ReadUInt32LittleEndian(c[12..]);
        long length = size & 0x7FFFFFFF;
        byte[] data;
        // The top bit marks data of at most 4 bytes kept in the offset field itself.
        if ((size & 0x80000000) != 0) data = c.Slice(8, (int)Math.Min(4, length)).ToArray();
        else data = Data(BinaryPrimitives.ReadInt32LittleEndian(c[8..]), length, recovered, name);
        return new Value(offset, name, type, data, length, recovered);
    }

    private byte[] Data(int offset, long length, bool recovered, string name)
    {
        if (length == 0) return [];
        var cell = recovered ? FreeCell(offset) : Cell(offset);
        // Data past one segment is a db cell (format 1.4 and later): a list of segment cells of 16,344 bytes each.
        if (length > MaxSegment && Header.Minor >= 4 && cell.Length >= 8 && cell[0] == 'd' && cell[1] == 'b')
        {
            int count = BinaryPrimitives.ReadUInt16LittleEndian(cell[2..]);
            var list = recovered ? FreeCell(BinaryPrimitives.ReadInt32LittleEndian(cell[4..])) : Cell(BinaryPrimitives.ReadInt32LittleEndian(cell[4..]));
            var data = new byte[length];
            int got = 0;
            for (int i = 0; i < count && i * 4 + 4 <= list.Length && got < length; i++)
            {
                var segment = recovered ? FreeCell(BinaryPrimitives.ReadInt32LittleEndian(list[(i * 4)..])) : Cell(BinaryPrimitives.ReadInt32LittleEndian(list[(i * 4)..]));
                int take = (int)Math.Min(Math.Min(MaxSegment, segment.Length), length - got);
                segment[..take].CopyTo(data.AsSpan(got));
                got += take;
            }
            if (got < length && !recovered) Note($"value {Shown(name)}: its segments hold {got:N0} of {length:N0} bytes");
            return got < length ? data[..got] : data;
        }
        if (cell.Length < length)
        {
            if (!recovered) Note($"value {Shown(name)}: its data cell 0x{offset:X} holds {cell.Length:N0} of {length:N0} bytes");
            return cell.ToArray();
        }
        return cell[..(int)length].ToArray();
    }

    private static string Shown(string name) => name.Length == 0 ? "(Default)" : name;

    /// <summary>The key at a case-insensitive '\'-separated <paramref name="path"/>, root name optional; null when not found.</summary>
    public Key? Find(string path)
    {
        var key = Root;
        var parts = path.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        int i = parts.Length > 0 && string.Equals(parts[0], Root.Name, StringComparison.OrdinalIgnoreCase) && Subkeys(Root).All(k => !string.Equals(k.Name, parts[0], StringComparison.OrdinalIgnoreCase)) ? 1 : 0;
        for (; i < parts.Length; i++)
        {
            var next = Subkeys(key).FirstOrDefault(k => string.Equals(k.Name, parts[i], StringComparison.OrdinalIgnoreCase));
            if (next == null) return null;
            key = next;
        }
        return key;
    }

    /// <summary>Every key from the root, depth first, with its path below the root; a key reached twice is a note and is not walked again.</summary>
    public IEnumerable<(string Path, Key Key)> Walk(CancellationToken ct)
    {
        var seen = new HashSet<int>();
        var stack = new Stack<(string, Key)>();
        stack.Push(("", Root));
        seen.Add(Root.Cell);
        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (path, key) = stack.Pop();
            yield return (path, key);
            var subkeys = Subkeys(key);
            for (int i = subkeys.Count - 1; i >= 0; i--)
            {
                if (!seen.Add(subkeys[i].Cell)) { Note($"{path}\\{subkeys[i].Name}: reached twice; not walked again"); continue; }
                stack.Push((path.Length == 0 ? subkeys[i].Name : path + "\\" + subkeys[i].Name, subkeys[i]));
            }
        }
    }

    /// <summary>Keys and values left in free cells, found by signature at 8-byte alignment.</summary>
    public (List<Key> Keys, List<Value> Values) Recover(CancellationToken ct)
    {
        var keys = new List<Key>();
        var values = new List<Value>();
        for (long bin = BinsStart; bin + 32 <= _end;)
        {
            ct.ThrowIfCancellationRequested();
            if (!_b.AsSpan((int)bin, 4).SequenceEqual("hbin"u8)) { Note($"no hbin signature at 0x{bin:X}; recovery stops"); break; }
            long binSize = BinaryPrimitives.ReadUInt32LittleEndian(_b.AsSpan((int)bin + 8));
            if (binSize < 4096 || binSize % 4096 != 0 || bin + binSize > _end) binSize = Math.Max(0, _end - bin);
            for (long at = bin + 32; at + 8 <= bin + binSize;)
            {
                int size = BinaryPrimitives.ReadInt32LittleEndian(_b.AsSpan((int)at));
                long length = Math.Abs((long)size);
                if (length < 8 || length % 8 != 0 || at + length > bin + binSize) break;
                if (size > 0)
                    for (long p = at; p + 8 <= at + length; p += 8)
                    {
                        if (p != at && BinaryPrimitives.ReadInt32LittleEndian(_b.AsSpan((int)p)) >= 0) continue;
                        int offset = (int)(p - BinsStart);
                        if (_b[p + 4] == 'n' && _b[p + 5] == 'k' && ParseKey(FreeCell(offset), offset, true) is { } k) keys.Add(k);
                        else if (_b[p + 4] == 'v' && _b[p + 5] == 'k' && ValueAt(offset, true) is { } v) values.Add(v);
                    }
                at += length;
            }
            if (binSize == 0) break;
            bin += binSize;
        }
        return (keys, values);
    }

    /// <summary>The registry type name (REG_SZ ...), or "type 0x..." for a type the registry does not define.</summary>
    public static string TypeName(int type) => type switch
    {
        0 => "REG_NONE", 1 => "REG_SZ", 2 => "REG_EXPAND_SZ", 3 => "REG_BINARY", 4 => "REG_DWORD", 5 => "REG_DWORD_BIG_ENDIAN", 6 => "REG_LINK",
        7 => "REG_MULTI_SZ", 8 => "REG_RESOURCE_LIST", 9 => "REG_FULL_RESOURCE_DESCRIPTOR", 10 => "REG_RESOURCE_REQUIREMENTS_LIST", 11 => "REG_QWORD",
        _ => $"type 0x{type:X}",
    };

    /// <summary>Value data as its type reads, else hex of the first <paramref name="maxBytes"/> bytes.</summary>
    public static object Render(int type, byte[] data, int maxBytes = 256)
    {
        switch (type)
        {
            case 1 or 2 or 6:
                string s = Utf16(data);
                int nul = s.IndexOf('\0');
                return nul >= 0 ? s[..nul] : s;
            case 7:
                return Utf16(data).Split('\0').Reverse().SkipWhile(x => x.Length == 0).Reverse().ToArray();
            case 4 when data.Length == 4:
                return BinaryPrimitives.ReadUInt32LittleEndian(data);
            case 5 when data.Length == 4:
                return BinaryPrimitives.ReadUInt32BigEndian(data);
            case 11 when data.Length == 8:
                return BinaryPrimitives.ReadUInt64LittleEndian(data);
            default:
                return Convert.ToHexString(data, 0, Math.Min(data.Length, maxBytes)) + (data.Length > maxBytes ? "..." : "");
        }
    }

    private static string Utf16(ReadOnlySpan<byte> b) => Encoding.Unicode.GetString(b[..(b.Length & ~1)]).TrimEnd('\0');

    private static DateTime? Time(ReadOnlySpan<byte> b)
    {
        long ft = BinaryPrimitives.ReadInt64LittleEndian(b);
        return ft > 0 && ft < DateTime.MaxValue.Ticks - 504911232000000000L ? DateTime.FromFileTimeUtc(ft) : null;
    }
}
