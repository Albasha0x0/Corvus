using System.Buffers.Binary;
using System.Text;
using Corvus.Core.Firmware;

namespace Corvus.Core.Disks;

/// <summary>ISO 9660 and UDF disc images: UDF when present, else Joliet, else the primary tree with Rock Ridge names.</summary>
internal sealed class Iso9660Reader : IContainerReader
{
    private const int Sector = 2048;

    public string Kind => "iso9660";

    /// <summary>A volume descriptor ("CD001") at sector 16, or a UDF anchor at sector 256.</summary>
    public static bool Looks(ReadOnlySpan<byte> b) =>
        b.Length >= 16 * Sector + 6 && b.Slice(16 * Sector + 1, 5).SequenceEqual("CD001"u8)
        || b.Length >= 256 * Sector + 16 && UdfReader.IsAnchor(b.Slice(256 * Sector, 16));

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(FsSource.Of(data, name), allFiles, limits, ct);

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(new FsSource(stream, 0, stream.Length, name), allFiles, limits, ct);

    public static ContainerContents Read(FsSource src, bool allFiles, AnalysisLimits limits, CancellationToken ct) => FsTree.Guard(src, () =>
    {
        if (UdfReader.Open(src, allFiles, limits, ct) is { } udf) return udf;
        return new Volume(src, allFiles, limits, ct).Walk();
    });

    private sealed class Volume
    {
        private readonly FsSource _src;
        private readonly FsTree _tree;
        private readonly uint _rootExtent, _rootSize;
        private readonly bool _joliet;
        private readonly HashSet<uint> _dirs = [];
        private int _blockSize = Sector;
        private uint _bootCatalog;

        public Volume(FsSource src, bool allFiles, AnalysisLimits limits, CancellationToken ct)
        {
            _src = src;
            byte[]? primary = null, joliet = null;
            for (int s = 16; s < 64; s++)
            {
                var vd = src.ReadUpTo((long)s * Sector, Sector);
                if (vd.Length < Sector || !vd.AsSpan(1, 5).SequenceEqual("CD001"u8)) break;
                if (vd[0] == 255) break;
                if (vd[0] == 0 && vd.AsSpan(7).StartsWith("EL TORITO SPECIFICATION"u8)) _bootCatalog = BinaryPrimitives.ReadUInt32LittleEndian(vd.AsSpan(0x47));
                if (vd[0] == 1) primary ??= vd;
                if (vd[0] == 2 && vd[88] == 0x25 && vd[89] == 0x2F && vd[90] is 0x40 or 0x43 or 0x45) joliet ??= vd;
            }
            var chosen = joliet ?? primary ?? throw src.Malformed("no primary volume descriptor");
            _joliet = joliet != null;
            _blockSize = BinaryPrimitives.ReadUInt16LittleEndian(chosen.AsSpan(128)) is var bs and (512 or 1024 or 2048 or 4096) ? bs : Sector;
            _rootExtent = BinaryPrimitives.ReadUInt32LittleEndian(chosen.AsSpan(156 + 2));
            _rootSize = BinaryPrimitives.ReadUInt32LittleEndian(chosen.AsSpan(156 + 10));
            var label = (_joliet ? Encoding.BigEndianUnicode.GetString(chosen, 40, 32) : Encoding.ASCII.GetString(chosen, 40, 32)).TrimEnd(' ', '\0');
            _tree = new FsTree("ISO 9660", allFiles, limits, ct);
            _tree.Notes.Add($"ISO 9660{(_joliet ? " with Joliet names" : "")}, volume '{label}'");
        }

        public ContainerContents Walk()
        {
            Directory(_rootExtent, _rootSize, "", 0);
            if (_bootCatalog != 0) BootImage();
            return _tree.Done();
        }

        /// <summary>The El Torito default boot entry, as [BOOT]/Boot-&lt;media&gt;.img (7-Zip's name); its size from the media type, else the sector count.</summary>
        private void BootImage()
        {
            var catalog = _src.ReadUpTo((long)_bootCatalog * Sector, 64);
            if (catalog.Length < 64 || catalog[0] != 1 || catalog[30] != 0x55 || catalog[31] != 0xAA) return;
            var entry = catalog.AsSpan(32, 32);
            if (entry[0] != 0x88) return;
            int media = entry[1] & 0x0F;
            long sectors = BinaryPrimitives.ReadUInt16LittleEndian(entry[6..]);
            uint rba = BinaryPrimitives.ReadUInt32LittleEndian(entry[8..]);
            var (name, size) = media switch
            {
                1 => ("Boot-1.2M.img", 1_228_800L), 2 => ("Boot-1.44M.img", 1_474_560L), 3 => ("Boot-2.88M.img", 2_949_120L),
                4 => ("Boot-HardDisk.img", sectors * 512), _ => ("Boot-NoEmul.img", sectors * 512),
            };
            long at = (long)rba * Sector;
            _tree.File("[BOOT]/" + name, size, n => _src.ReadUpTo(at, (int)Math.Min(n, size)), "El Torito boot image");
        }

        private void Directory(uint extent, uint size, string prefix, int depth)
        {
            if (depth >= FsTree.MaxDepth) { _tree.Notes.Add($"{prefix}: deeper than {FsTree.MaxDepth} levels; not read"); return; }
            if (!_dirs.Add(extent)) return;
            if (size > 64u << 20) { _tree.Notes.Add($"{prefix}: a {size:N0}-byte directory; not read"); return; }
            var data = _src.ReadUpTo((long)extent * _blockSize, (int)size);
            var pending = new List<(string Name, uint Extent, long Size, bool Dir)>();
            var links = new List<(string Name, string Target)>();
            int pos = 0;
            while (pos < data.Length)
            {
                _tree.Token.ThrowIfCancellationRequested();
                int len = data[pos];
                // Records do not cross a sector.
                if (len == 0) { pos = (pos / Sector + 1) * Sector; continue; }
                if (len < 34 || pos + len > data.Length) break;
                var r = data.AsSpan(pos, len);
                pos += len;
                int nameLen = r[32];
                if (33 + nameLen > len) continue;
                var raw = r.Slice(33, nameLen);
                // The . and .. entries.
                if (nameLen == 1 && raw[0] is 0 or 1) continue;
                bool dir = (r[25] & 0x02) != 0;
                string name = _joliet ? Encoding.BigEndianUnicode.GetString(raw) : Encoding.ASCII.GetString(raw);
                var systemUse = r[(33 + nameLen + ((nameLen & 1) == 0 ? 1 : 0))..];
                string? link = null;
                if (!_joliet && RockRidge(systemUse, out link) is { } rr) name = rr;
                else
                {
                    int semi = name.IndexOf(';');
                    if (semi >= 0) name = name[..semi];
                    if (!dir && name.EndsWith('.')) name = name[..^1];
                }
                uint ext = BinaryPrimitives.ReadUInt32LittleEndian(r[2..]);
                long fileSize = BinaryPrimitives.ReadUInt32LittleEndian(r[10..]);
                // A file of several extents: records with the multi-extent flag, then the last.
                if (pending.Count > 0 && pending[^1].Name == name && !dir && (r[25] & 0x80) == 0 && pending[^1].Size < 0)
                {
                    pending[^1] = (name, pending[^1].Extent, -pending[^1].Size + fileSize, false);
                    continue;
                }
                if (link != null) { links.Add((name, link)); continue; }
                pending.Add((name, ext, (r[25] & 0x80) != 0 ? -fileSize : fileSize, dir));
            }
            foreach (var (name, target) in links)
                if (FsTree.UsableName(name)) _tree.Link(prefix.Length == 0 ? name : prefix + "/" + name, target);
            foreach (var (name, ext, length, dir) in pending)
            {
                if (!FsTree.UsableName(name)) continue;
                var path = prefix.Length == 0 ? name : prefix + "/" + name;
                if (dir) Directory(ext, (uint)length, path, depth + 1);
                else
                {
                    long at = (long)ext * _blockSize, n = Math.Abs(length);
                    _tree.File(path, n, k => _src.Read(at, (int)Math.Min(k, n)));
                }
            }
        }

        /// <summary>The Rock Ridge name (NM) of a record's system use area, if any, and its symbolic link target (SL).</summary>
        private static string? RockRidge(ReadOnlySpan<byte> su, out string? link)
        {
            var name = new StringBuilder();
            var target = new StringBuilder();
            bool isLink = false;
            int pos = 0;
            while (pos + 4 <= su.Length)
            {
                int len = su[pos + 2];
                if (len < 4 || pos + len > su.Length) break;
                if (su[pos] == 'N' && su[pos + 1] == 'M' && len >= 5 && (su[pos + 4] & 0x06) == 0) name.Append(Encoding.UTF8.GetString(su.Slice(pos + 5, len - 5)));
                if (su[pos] == 'S' && su[pos + 1] == 'L' && len >= 5)
                {
                    isLink = true;
                    for (int c = pos + 5; c + 2 <= pos + len;)
                    {
                        int flags = su[c], n = su[c + 1];
                        if (c + 2 + n > pos + len) break;
                        if (target.Length > 0 && target[^1] != '/') target.Append('/');
                        target.Append((flags & 0x08) != 0 ? "/" : (flags & 0x04) != 0 ? ".." : (flags & 0x02) != 0 ? "." : Encoding.UTF8.GetString(su.Slice(c + 2, n)));
                        c += 2 + n;
                    }
                }
                pos += len;
            }
            link = isLink ? target.ToString() : null;
            return name.Length > 0 ? name.ToString() : null;
        }
    }
}
