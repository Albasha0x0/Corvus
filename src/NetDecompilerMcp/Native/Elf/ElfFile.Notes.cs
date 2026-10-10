using System.Text;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Native.Elf;

/// <summary>An ELF note: owner name, type and descriptor bytes.</summary>
public sealed record ElfNote(string Name, uint Type, byte[] Description);

/// <summary>.note.android.ident: the API level the library targets and the NDK that built it (newer NDKs only).</summary>
public sealed record AndroidIdent(uint ApiLevel, string? NdkVersion, string? NdkBuild);

public sealed partial class ElfFile
{
    private const int MaxNotes = 1024;
    private const int MaxNoteSize = 1 << 16;

    private ImageArea<List<ElfNote>> notes = null!;

    /// <summary>Notes of the PT_NOTE segments (or SHT_NOTE sections when there are none).</summary>
    public IReadOnlyList<ElfNote> Notes => notes.Value;

    /// <summary>NT_GNU_BUILD_ID as lowercase hex.</summary>
    public string? BuildId => notes.Value.FirstOrDefault(n => n.Name == "GNU" && n.Type == 3) is { } n ? Convert.ToHexStringLower(n.Description) : null;

    public AndroidIdent? AndroidIdent
    {
        get
        {
            if (notes.Value.FirstOrDefault(n => n.Name == "Android" && n.Type == 1 && n.Description.Length >= 4) is not { } n) return null;
            var d = new ByteView(n.Description, BigEndian);
            string? Text(int at) => n.Description.Length >= at + 64 ? d.CString(at, 64) : null;
            return new AndroidIdent(d.U32(0), Text(4), Text(68));
        }
    }

    private List<ElfNote> ParseNotes(IssueLog log)
    {
        var result = new List<ElfNote>();
        var ranges = segments.Where(s => s.Type == 4).Select(s => (Offset: IsMappedDump ? s.VirtualAddress - ImageBase : s.Offset, s.FileSize, s.Align)).ToList();
        if (ranges.Count == 0) ranges = [.. sectionHeaders.Where(s => s.Type == 7).Select(s => (s.Offset, s.Size, s.Align))];
        foreach (var (offset, size, align) in ranges)
        {
            if (offset > (ulong)data.Length) { log.Add($"note at 0x{offset:X} lies past the end of the file", (long)Math.Min(offset, long.MaxValue)); continue; }
            var t = new ByteView(data, (long)offset, (long)Math.Min(size, (ulong)data.Length - offset), BigEndian);
            long pad = align == 8 ? 8 : 4;
            long at = 0;
            while (at + 12 <= t.Length && result.Count < MaxNotes)
            {
                uint nameSize = t.U32(at), descSize = t.U32(at + 4), type = t.U32(at + 8);
                if (nameSize > MaxNoteSize || descSize > MaxNoteSize)
                {
                    log.Add($"note at file offset 0x{(long)offset + at:X} declares sizes {nameSize}/{descSize}; the rest of this note area is not read");
                    break;
                }
                long name = at + 12, desc = name + Align(nameSize, pad), next = desc + Align(descSize, pad);
                if (desc + descSize > t.Length)
                {
                    log.Add($"note at file offset 0x{(long)offset + at:X} extends past its area");
                    break;
                }
                var nameBytes = t.Span(name, nameSize);
                int nul = nameBytes.IndexOf((byte)0);
                result.Add(new ElfNote(Encoding.UTF8.GetString(nul < 0 ? nameBytes : nameBytes[..nul]), type, t.Span(desc, descSize).ToArray()));
                at = next;
            }
        }
        return result;

        static long Align(long v, long a) => (v + a - 1) & ~(a - 1);
    }
}
