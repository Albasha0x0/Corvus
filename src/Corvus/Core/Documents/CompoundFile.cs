using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Documents;

/// <summary>One storage or stream of a compound file; <see cref="Path"/> joins the storage names with '/'.</summary>
internal sealed record CompoundEntry(int Id, string Path, string Name, bool IsStorage, long Size, Guid Clsid, DateTime? Modified)
{
    internal uint Start { get; init; }
}

/// <summary>
/// Compound File Binary (MS-CFB, the OLE container of .doc, .xls, .ppt, .msi, .msg and vbaProject.bin), version 3 and 4:
/// the FAT and DIFAT, the mini stream, and the directory tree walked from the root. Chains and the tree are bounded, so a
/// cycle in damaged tables ends the walk with a note.
/// </summary>
internal sealed class CompoundFile
{
    private const uint EndOfChain = 0xFFFFFFFE, FreeSect = 0xFFFFFFFF, MaxRegSect = 0xFFFFFFFA;
    private const int MaxEntries = 1 << 20;

    private static ReadOnlySpan<byte> Magic => [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    private readonly byte[] _data;
    private readonly int _sectorSize, _miniSectorSize;
    private readonly uint _miniCutoff;
    private readonly uint[] _fat;
    private uint[] _miniFat = [];
    private byte[] _miniStream = [];
    private readonly List<CompoundEntry> _entries = [];

    public string Name { get; }
    public IReadOnlyList<CompoundEntry> Entries => _entries;
    public List<string> Notes { get; } = [];
    /// <summary>The root storage's class id (an MSI database, a Word document and others name themselves here).</summary>
    public Guid RootClsid { get; private set; }

    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= 512 && b.StartsWith(Magic) && BinaryPrimitives.ReadUInt16LittleEndian(b[28..]) == 0xFFFE;

    private CompoundFile(byte[] data, string name)
    {
        _data = data;
        Name = name;
        var h = data.AsSpan(0, 512);
        int major = BinaryPrimitives.ReadUInt16LittleEndian(h[26..]);
        int shift = BinaryPrimitives.ReadUInt16LittleEndian(h[30..]);
        int miniShift = BinaryPrimitives.ReadUInt16LittleEndian(h[32..]);
        if (major is not (3 or 4) || shift is not (9 or 12) || miniShift != 6) throw Malformed($"unsupported header (version {major}, sector shift {shift}, mini shift {miniShift})");
        _sectorSize = 1 << shift;
        _miniSectorSize = 1 << miniShift;
        uint fatSectors = BinaryPrimitives.ReadUInt32LittleEndian(h[44..]);
        uint dirStart = BinaryPrimitives.ReadUInt32LittleEndian(h[48..]);
        _miniCutoff = BinaryPrimitives.ReadUInt32LittleEndian(h[56..]);
        uint miniFatStart = BinaryPrimitives.ReadUInt32LittleEndian(h[60..]);
        uint difatStart = BinaryPrimitives.ReadUInt32LittleEndian(h[68..]);
        uint difatCount = BinaryPrimitives.ReadUInt32LittleEndian(h[72..]);

        long sectors = SectorCount;
        if (fatSectors > sectors + 1) throw Malformed($"the header names {fatSectors:N0} FAT sectors in a file of {sectors:N0}");
        var fatList = new List<uint>();
        for (int i = 0; i < 109 && fatList.Count < fatSectors; i++)
        {
            uint s = BinaryPrimitives.ReadUInt32LittleEndian(h[(76 + i * 4)..]);
            if (s <= MaxRegSect) fatList.Add(s);
        }
        // DIFAT sectors: each holds sector numbers and, last, the next DIFAT sector
        uint d = difatStart;
        int perSector = _sectorSize / 4 - 1;
        for (uint n = 0; n < difatCount && d <= MaxRegSect && fatList.Count < fatSectors; n++)
        {
            if (!InFile(d)) { Notes.Add($"DIFAT sector {d} lies past the end of the file"); break; }
            var sec = Sector(d);
            for (int i = 0; i < perSector && fatList.Count < fatSectors; i++)
            {
                uint s = BinaryPrimitives.ReadUInt32LittleEndian(sec[(i * 4)..]);
                if (s <= MaxRegSect) fatList.Add(s);
            }
            d = BinaryPrimitives.ReadUInt32LittleEndian(sec[(perSector * 4)..]);
        }
        if (fatList.Count < fatSectors) Notes.Add($"{fatSectors - fatList.Count} of {fatSectors} FAT sectors are not listed");
        _fat = new uint[fatList.Count * (_sectorSize / 4)];
        for (int i = 0; i < fatList.Count; i++)
        {
            if (!InFile(fatList[i])) { _fat.AsSpan(i * (_sectorSize / 4), _sectorSize / 4).Fill(FreeSect); continue; }
            var sec = Sector(fatList[i]);
            for (int j = 0; j < _sectorSize / 4; j++) _fat[i * (_sectorSize / 4) + j] = BinaryPrimitives.ReadUInt32LittleEndian(sec[(j * 4)..]);
        }

        var dir = ReadChain(dirStart, long.MaxValue, "the directory");
        if (dir.Length < 128) throw Malformed("the directory is empty");
        var miniFat = miniFatStart <= MaxRegSect ? ReadChain(miniFatStart, long.MaxValue, "the mini FAT") : [];
        _miniFat = new uint[miniFat.Length / 4];
        for (int i = 0; i < _miniFat.Length; i++) _miniFat[i] = BinaryPrimitives.ReadUInt32LittleEndian(miniFat.AsSpan(i * 4));
        ReadDirectory(dir, major);
    }

    /// <summary>Reads the file; damaged headers or tables are malformed input.</summary>
    public static CompoundFile Read(byte[] data, string name)
    {
        if (!Looks(data)) throw new ToolError(ErrorCode.MalformedInput, $"{name} is not a compound file (no D0 CF 11 E0 signature).");
        return new CompoundFile(data, name);
    }

    private long SectorCount => (_data.Length - 512L + _sectorSize - 1) / _sectorSize;

    private bool InFile(uint sector) => sector <= MaxRegSect && 512L + (long)sector * _sectorSize < _data.Length;

    /// <summary>One sector; the last sector of a truncated file is padded with zeros.</summary>
    private ReadOnlySpan<byte> Sector(uint s)
    {
        long at = 512L + (long)s * _sectorSize;
        if (at + _sectorSize <= _data.Length) return _data.AsSpan((int)at, _sectorSize);
        var pad = new byte[_sectorSize];
        _data.AsSpan((int)at).CopyTo(pad);
        return pad;
    }

    private ToolError Malformed(string what) => new(ErrorCode.MalformedInput, $"{Name}: {what}.");

    /// <summary>A FAT chain's bytes up to <paramref name="max"/>; a chain that loops or leaves the file stops there.</summary>
    private byte[] ReadChain(uint start, long max, string what)
    {
        using var ms = new MemoryStream();
        uint s = start;
        long steps = 0, limit = Math.Min(_fat.Length, SectorCount) + 1;
        while (s != EndOfChain && ms.Length < max)
        {
            if (s >= _fat.Length || !InFile(s)) { Notes.Add($"{what}: chain leaves the file at sector {s}"); break; }
            if (++steps > limit) { Notes.Add($"{what}: the sector chain loops"); break; }
            ms.Write(Sector(s));
            s = _fat[s];
        }
        var bytes = ms.ToArray();
        return bytes.Length > max ? bytes[..(int)max] : bytes;
    }

    private byte[] ReadMiniChain(uint start, long size, string what)
    {
        var result = new byte[size];
        int done = 0;
        uint s = start;
        long steps = 0;
        while (done < size && s != EndOfChain)
        {
            long at = (long)s * _miniSectorSize;
            if (s >= _miniFat.Length || at + _miniSectorSize > _miniStream.Length) { Notes.Add($"{what}: mini chain leaves the mini stream at {s}"); break; }
            if (++steps > _miniFat.Length) { Notes.Add($"{what}: the mini sector chain loops"); break; }
            int n = (int)Math.Min(_miniSectorSize, size - done);
            _miniStream.AsSpan((int)at, n).CopyTo(result.AsSpan(done));
            done += n;
            s = _miniFat[s];
        }
        return done == size ? result : result[..done];
    }

    private sealed record RawEntry(string Name, int Type, uint Left, uint Right, uint Child, Guid Clsid, DateTime? Modified, uint Start, long Size);

    private void ReadDirectory(byte[] dir, int major)
    {
        int count = Math.Min(dir.Length / 128, MaxEntries);
        var raw = new RawEntry?[count];
        for (int i = 0; i < count; i++)
        {
            var e = dir.AsSpan(i * 128, 128);
            int type = e[66];
            if (type is not (1 or 2 or 5)) continue;
            int nameLen = BinaryPrimitives.ReadUInt16LittleEndian(e[64..]);
            nameLen = Math.Clamp(nameLen, 0, 64) / 2;
            if (nameLen > 0) nameLen--; // terminating NUL
            var name = Encoding.Unicode.GetString(e[..(nameLen * 2)]);
            long mtime = BinaryPrimitives.ReadInt64LittleEndian(e[108..]);
            long size = major == 3 ? BinaryPrimitives.ReadUInt32LittleEndian(e[120..]) : BinaryPrimitives.ReadInt64LittleEndian(e[120..]);
            raw[i] = new RawEntry(name, type, BinaryPrimitives.ReadUInt32LittleEndian(e[68..]), BinaryPrimitives.ReadUInt32LittleEndian(e[72..]),
                BinaryPrimitives.ReadUInt32LittleEndian(e[76..]), new Guid(e.Slice(80, 16)),
                mtime > 0 && mtime < DateTime.MaxValue.ToFileTime() ? DateTime.FromFileTimeUtc(mtime) : null, BinaryPrimitives.ReadUInt32LittleEndian(e[116..]), size);
        }
        if (raw[0] is not { Type: 5 } root) throw Malformed("the first directory entry is not the root storage");
        RootClsid = root.Clsid;
        if (root.Size > 0 && root.Start <= MaxRegSect) _miniStream = ReadChain(root.Start, root.Size, "the mini stream");

        var seen = new HashSet<uint> { 0 };
        var stack = new Stack<(uint Id, string Prefix, int Depth)>();
        void Siblings(uint child, string prefix, int depth)
        {
            // in-order walk of one storage's red-black tree, iterative so a deep or looping tree cannot overflow
            var pending = new Stack<uint>();
            if (child < count) pending.Push(child);
            var found = new List<uint>();
            while (pending.Count > 0)
            {
                uint id = pending.Pop();
                if (id >= count || raw[id] is not { } r || !seen.Add(id)) continue;
                found.Add(id);
                if (r.Left < count) pending.Push(r.Left);
                if (r.Right < count) pending.Push(r.Right);
            }
            // pushed in reverse so names pop in order
            foreach (var id in found.OrderByDescending(i => raw[i]!.Name, StringComparer.OrdinalIgnoreCase)) stack.Push((id, prefix, depth));
        }
        Siblings(root.Child, "", 0);
        var ordered = new List<(uint Id, string Path)>();
        while (stack.Count > 0)
        {
            var (id, prefix, depth) = stack.Pop();
            var r = raw[id]!;
            var path = prefix + r.Name;
            ordered.Add((id, path));
            if (r.Type == 1)
            {
                if (depth >= 64) { Notes.Add($"{path}: storages nested deeper than 64 are not read"); continue; }
                Siblings(r.Child, path + "/", depth + 1);
            }
        }
        foreach (var (id, path) in ordered)
        {
            var r = raw[id]!;
            _entries.Add(new CompoundEntry((int)id, path, r.Name, r.Type == 1, r.Type == 2 ? Math.Max(0, r.Size) : 0, r.Clsid, r.Modified) { Start = r.Start });
        }
        int unreached = raw.Count(r => r != null) - 1 - _entries.Count;
        if (unreached > 0) Notes.Add($"{unreached} directory entries are not reachable from the root");
    }

    /// <summary>The stream at <paramref name="path"/> (case-insensitive, as the format compares names), or null.</summary>
    public CompoundEntry? Find(string path) => _entries.FirstOrDefault(e => !e.IsStorage && string.Equals(e.Path, path, StringComparison.OrdinalIgnoreCase));

    /// <summary>A stream's bytes, at most <paramref name="max"/>; a stream over it is a limit error.</summary>
    public byte[] Read(CompoundEntry entry, long max)
    {
        if (entry.IsStorage) return [];
        if (entry.Size > max) throw new ToolError(ErrorCode.LimitExceeded, $"{Name}: stream {entry.Path} is {entry.Size:N0} bytes, over the {max:N0}-byte item limit.");
        var bytes = entry.Size < _miniCutoff ? ReadMiniChain(entry.Start, entry.Size, entry.Path) : ReadChain(entry.Start, entry.Size, entry.Path);
        if (bytes.Length < entry.Size) Notes.Add($"{entry.Path}: {bytes.Length:N0} of {entry.Size:N0} bytes read");
        return bytes;
    }
}
