using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Mobile;

/// <summary>
/// BOM store files (bill of materials, big-endian): the block index, named variables and B+ trees whose leaves list
/// key and value blocks. Damaged ranges, cycles and unknown tree forms throw <see cref="InvalidDataException"/>.
/// </summary>
internal sealed class BomStore
{
    private readonly byte[] _data;
    private readonly (uint At, uint Length)[] _blocks;
    private readonly Dictionary<string, uint> _variables = new(StringComparer.Ordinal);

    public static bool Looks(ReadOnlySpan<byte> data) => data.Length >= 32 && data.StartsWith("BOMStore"u8);

    /// <summary>Whether the variables table of a BOM store names <paramref name="name"/>; false for anything else.</summary>
    public static bool Names(ReadOnlySpan<byte> data, ReadOnlySpan<byte> name)
    {
        if (!Looks(data)) return false;
        ulong at = BinaryPrimitives.ReadUInt32BigEndian(data[24..]), length = BinaryPrimitives.ReadUInt32BigEndian(data[28..]);
        if (at + length > (ulong)data.Length || length < 4) return false;
        var vars = data.Slice((int)at, (int)length);
        for (int p = 4; p + 5 <= vars.Length && p + 5 + vars[p + 4] <= vars.Length; p += 5 + vars[p + 4])
            if (vars.Slice(p + 5, vars[p + 4]).SequenceEqual(name)) return true;
        return false;
    }

    public BomStore(byte[] data)
    {
        _data = data;
        if (!Looks(data) || BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(8)) != 1) throw new InvalidDataException("no BOMStore header of version 1");
        var index = Range(BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(16)), BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(20)), "the block index");
        if (index.Length < 4) throw new InvalidDataException("an empty block index");
        long count = BinaryPrimitives.ReadUInt32BigEndian(index);
        if (count > (index.Length - 4) / 8) throw new InvalidDataException($"a block index of {count:N0} entries in {index.Length:N0} bytes");
        _blocks = new (uint, uint)[count];
        for (int i = 0; i < count; i++)
            _blocks[i] = (BinaryPrimitives.ReadUInt32BigEndian(index[(4 + 8 * i)..]), BinaryPrimitives.ReadUInt32BigEndian(index[(8 + 8 * i)..]));
        var vars = Range(BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(24)), BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(28)), "the variables table");
        if (vars.Length < 4) throw new InvalidDataException("an empty variables table");
        long names = BinaryPrimitives.ReadUInt32BigEndian(vars);
        int p = 4;
        for (long i = 0; i < names; i++)
        {
            if (p + 5 > vars.Length || p + 5 + vars[p + 4] > vars.Length) throw new InvalidDataException("the variables table is cut short");
            _variables[Encoding.ASCII.GetString(vars.Slice(p + 5, vars[p + 4]))] = BinaryPrimitives.ReadUInt32BigEndian(vars[p..]);
            p += 5 + vars[p + 4];
        }
    }

    public bool Has(string name) => _variables.ContainsKey(name);

    /// <summary>The block a variable names; null when the store has no such variable.</summary>
    public byte[]? Variable(string name) => _variables.TryGetValue(name, out var id) ? Block(id) : null;

    public byte[] Block(uint id)
    {
        // Block 0 is the null block; an index entry of all ones is unused.
        if (id == 0 || id >= _blocks.Length || _blocks[id] is (uint.MaxValue, uint.MaxValue)) throw new InvalidDataException($"block {id} is not in the index");
        return Range(_blocks[id].At, _blocks[id].Length, $"block {id}").ToArray();
    }

    /// <summary>
    /// The (key, value) blocks of a named tree in key order: down the first child of each branch, then along the leaves'
    /// forward links. Null when the store has no such variable.
    /// </summary>
    public List<(byte[] Key, byte[] Value)>? Tree(string name)
    {
        if (Variable(name) is not { } header) return null;
        if (header.Length < 21 || !header.AsSpan().StartsWith("tree"u8) || BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(4)) != 1)
            throw new InvalidDataException($"tree {name} has no tree header of version 1");
        if ((header[20] & 4) != 0) throw new InvalidDataException($"tree {name} keeps its keys in its nodes, a form not read");
        var entries = new List<(byte[], byte[])>();
        var seen = new HashSet<uint>();
        uint id = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(8));
        while (id != 0)
        {
            if (!seen.Add(id)) throw new InvalidDataException($"tree {name} visits node {id} twice");
            var node = Block(id);
            if (node.Length < 12) throw new InvalidDataException($"tree {name} node {id} is cut short");
            bool leaf = BinaryPrimitives.ReadUInt16BigEndian(node) != 0;
            int count = BinaryPrimitives.ReadUInt16BigEndian(node.AsSpan(2));
            if (12 + 8L * count > node.Length) throw new InvalidDataException($"tree {name} node {id} lists {count} entries in {node.Length} bytes");
            if (!leaf)
            {
                if (count == 0) throw new InvalidDataException($"tree {name} branch {id} has no children");
                id = BinaryPrimitives.ReadUInt32BigEndian(node.AsSpan(12));
                continue;
            }
            for (int i = 0; i < count; i++)
                entries.Add((Block(BinaryPrimitives.ReadUInt32BigEndian(node.AsSpan(16 + 8 * i))), Block(BinaryPrimitives.ReadUInt32BigEndian(node.AsSpan(12 + 8 * i)))));
            id = BinaryPrimitives.ReadUInt32BigEndian(node.AsSpan(4));
        }
        return entries;
    }

    private ReadOnlySpan<byte> Range(uint at, uint length, string what) =>
        (ulong)at + length <= (ulong)_data.Length ? _data.AsSpan((int)at, (int)length) : throw new InvalidDataException($"{what} ({length:N0} bytes at 0x{at:X}) runs past the end of the file");
}
