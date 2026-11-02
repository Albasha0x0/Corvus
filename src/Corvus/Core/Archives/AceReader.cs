using System.Buffers.Binary;
using System.IO.Hashing;
using System.Text;

namespace Corvus.Core.Archives;

/// <summary>ACE archives listed from their block headers; entry data is not decompressed, so no file is extracted.</summary>
internal sealed class AceReader : IContainerReader
{
    private const int Signature = 7;

    private const ushort AddSize = 0x0001, SplitBefore = 0x1000, SplitAfter = 0x2000, Password = 0x4000;
    private const uint DirectoryAttribute = 0x10;

    public string Kind => "ace";

    // The main header is block type 0 and fits the file.
    public bool Accepts(ReadOnlySpan<byte> data, string name) =>
        data.Length >= Signature + 7 && data.Slice(Signature, 7).SequenceEqual("**ACE**"u8)
        && BinaryPrimitives.ReadUInt16LittleEndian(data[2..]) is var size && size >= 10 && 4 + size <= data.Length && data[4] == 0;

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var entries = new List<ContainerEntry>();
        var notes = new List<string>();
        long p = 0;
        int damaged = 0, directories = 0;
        bool wideNames = false;
        bool main = true;
        // A tail shorter than a block header is checked after the loop.
        while (p + 4 <= data.Length)
        {
            ct.ThrowIfCancellationRequested();
            int bodySize = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan((int)p + 2));
            if (bodySize < 1 || p + 4 + bodySize > data.Length)
            {
                if (main) throw new ToolError(ErrorCode.MalformedInput, $"{name}: not a readable ace archive: the main header runs past the end.", "summarize_file reports what the file is and its size");
                notes.Add($"ace: stopped at 0x{p:X}: a block header runs past the end; later entries are unknown");
                break;
            }
            var body = data.AsSpan((int)p + 4, bodySize);
            bool crcHolds = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan((int)p)) == (ushort)Crc32.HashToUInt32(body);
            byte type = body[0];
            ushort flags = body.Length >= 3 ? BinaryPrimitives.ReadUInt16LittleEndian(body[1..]) : (ushort)0;
            long add = (flags & AddSize) != 0 && body.Length >= 7 ? BinaryPrimitives.ReadUInt32LittleEndian(body[3..]) : 0;
            if (type == 0)
            {
                if (!crcHolds) notes.Add("ace: the main header checksum does not hold");
                if ((flags & 0x8000) != 0) notes.Add("ace: solid archive; entries are listed from headers only");
            }
            else if (type == 1 && body.Length < 31)
            {
                damaged++;
                notes.Add($"ace: the entry at 0x{p:X} has a header shorter than a file header; not listed");
            }
            else if (type == 1)
            {
                long size = BinaryPrimitives.ReadUInt32LittleEndian(body[7..]);
                uint attr = BinaryPrimitives.ReadUInt32LittleEndian(body[15..]);
                int nameSize = BinaryPrimitives.ReadUInt16LittleEndian(body[29..]);
                if (31 + nameSize > body.Length) { damaged++; notes.Add($"ace: the entry at 0x{p:X} has a name past its header; not listed"); }
                else if ((attr & DirectoryAttribute) != 0) directories++;
                else if (entries.Count >= limits.MaxItems)
                {
                    notes.Add($"ace: {AnalysisLimits.Reached("item count", $"{limits.MaxItems:N0}-file", null)} Stopped at 0x{p:X}; later entries are unknown.");
                    break;
                }
                else
                {
                    var raw = body.Slice(31, nameSize);
                    wideNames |= raw.IndexOfAnyInRange((byte)0x80, (byte)0xFF) >= 0;
                    string path = Encoding.Latin1.GetString(raw).Replace('\\', '/');
                    var detail = new List<string> { body[23] == 0 ? "stored" : "compressed", "data not read" };
                    if ((flags & Password) != 0) detail.Add("encrypted");
                    if ((flags & SplitBefore) != 0) detail.Add("continues from the previous volume");
                    if ((flags & SplitAfter) != 0) detail.Add("continues in the next volume");
                    if (!crcHolds) detail.Add("header checksum does not hold");
                    entries.Add(new ContainerEntry(path, size, string.Join("; ", detail)));
                }
            }
            main = false;
            p += 4 + bodySize + add;
        }
        // The last block's packed size, or a short tail, can end past the data.
        if (p > data.Length) notes.Add($"ace: the data ends inside the last packed size (block ends at 0x{p:X}); later entries are unknown");
        else if (p < data.Length && p + 4 > data.Length) notes.Add($"ace: {data.Length - p} trailing bytes at 0x{p:X} are not a block header; later entries are unknown");
        if (wideNames) notes.Add("ace: names with bytes above 0x7F use an unrecorded code page; shown as Latin-1");
        if (entries.Count == 0 && damaged == 0) notes.Add("ace: no file entries in the headers read");
        if (directories > 0) notes.Add($"ace: {directories} folder entries not listed");
        notes.Add($"ace: {entries.Count} entries listed from headers; list_assemblies pages them with offset and limit; unpack_container does not extract their data");
        string[] paths = [.. entries.Select(e => e.Path)];
        notes.AddRange(MemberNames.Notes(paths));
        return new ContainerContents(Kind, [], notes) { Entries = entries, Names = MemberNames.Issues(paths) };
    }
}
