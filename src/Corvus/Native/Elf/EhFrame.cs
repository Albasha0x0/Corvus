using Corvus.Native.Pe;

namespace Corvus.Native.Elf;

/// <summary>FDE address ranges from DWARF call frame information (.eh_frame / __eh_frame records and the .eh_frame_hdr table).</summary>
internal static partial class EhFrame
{
    public const byte Omit = 0xFF;

    /// <summary>One FDE: the code range [Start, Start + Range) as virtual addresses.</summary>
    public readonly record struct Fde(ulong Start, ulong Range);

    /// <summary>What an FDE needs from its CIE.</summary>
    public readonly record struct Cie(byte FdeEncoding, bool HasAugmentationData);

    /// <summary>Decodes a DW_EH_PE pointer at <paramref name="pos"/>, the data starting at <paramref name="dataVa"/>; indirect and unknown formats fail.</summary>
    public static bool TryReadPointer(ByteView data, ref long pos, byte encoding, ulong dataVa, ulong dataRelBase, bool is64, out ulong value)
    {
        value = 0;
        if (encoding == Omit) return false;
        long at = pos;
        ulong raw;
        switch (encoding & 0x0F)
        {
            case 0x00: raw = data.Word(pos, is64); pos += is64 ? 8 : 4; break;
            case 0x01:
            case 0x09:
            {
                var r = new LebReader(data.Span(pos, Math.Min(16, data.Length - pos)));
                raw = (encoding & 0x0F) == 0x01 ? r.Uleb() : (ulong)r.Sleb();
                if (r.Failed) return false;
                pos += r.Position;
                break;
            }
            case 0x02: raw = data.U16(pos); pos += 2; break;
            case 0x03: raw = data.U32(pos); pos += 4; break;
            case 0x04: raw = data.U64(pos); pos += 8; break;
            case 0x0A: raw = (ulong)(short)data.U16(pos); pos += 2; break;
            case 0x0B: raw = (ulong)(int)data.U32(pos); pos += 4; break;
            case 0x0C: raw = data.U64(pos); pos += 8; break;
            default: return false;
        }
        if (pos > data.Length) return false;
        switch (encoding & 0x70)
        {
            case 0x00: value = raw; break;
            case 0x10: value = dataVa + (ulong)at + raw; break;
            case 0x30: value = dataRelBase + raw; break;
            default: return false; // textrel, funcrel, aligned: not used for FDE locations
        }
        if (!is64) value &= 0xFFFFFFFF;
        return (encoding & 0x80) == 0;
    }

    /// <summary>Every FDE in order until the terminator or the end; a problem stops the walk with an issue and keeps what was read.</summary>
    public static List<Fde> Walk(ByteView data, ulong dataVa, bool is64, IssueLog log, int max)
    {
        var fdes = new List<Fde>();
        var cies = new Dictionary<long, Cie?>();
        var budget = new WorkBudget(log);
        long at = 0;
        while (at + 4 <= data.Length && budget.Step())
        {
            long length = data.U32(at);
            long body = at + 4;
            if (length == 0) break;
            if (length == 0xFFFFFFFF)
            {
                length = (long)Math.Min(data.U64(body), long.MaxValue / 2);
                body += 8;
            }
            long next = body + length;
            if (length < 4 || next > data.Length)
            {
                log.Add($"CFI record at +0x{at:X} has length 0x{length:X} past the end of the section");
                break;
            }
            uint id = data.U32(body);
            if (id != 0)
            {
                long cieAt = body - id;
                if (!cies.TryGetValue(cieAt, out var cie)) cies[cieAt] = cie = ParseCie(data, cieAt, is64);
                if (cie is { } c && ReadFde(data, body + 4, next, c, dataVa, is64) is { } fde)
                {
                    if (fdes.Count >= max)
                    {
                        log.Add($"more than {max} FDEs; the rest are not read");
                        break;
                    }
                    fdes.Add(fde);
                }
                else if (cie == null) log.Add($"FDE at +0x{at:X} refers to an unreadable CIE at +0x{cieAt:X}");
            }
            at = next;
        }
        return fdes;
    }

    /// <summary>The FDE at <paramref name="at"/> (its length field) of an .eh_frame image, or null.</summary>
    public static Fde? ReadFdeAt(ByteView data, long at, ulong dataVa, bool is64, Dictionary<long, Cie?>? cache = null)
    {
        long length = data.U32(at);
        long body = at + 4;
        if (length == 0xFFFFFFFF)
        {
            length = (long)Math.Min(data.U64(body), long.MaxValue / 2);
            body += 8;
        }
        long next = body + length;
        if (length < 8 || next > data.Length) return null;
        uint id = data.U32(body);
        if (id == 0) return null;
        long cieAt = body - id;
        Cie? cie;
        if (cache == null) cie = ParseCie(data, cieAt, is64);
        else if (!cache.TryGetValue(cieAt, out cie)) cache[cieAt] = cie = ParseCie(data, cieAt, is64);
        return cie is { } c ? ReadFde(data, body + 4, next, c, dataVa, is64) : null;
    }

    /// <summary>A CIE cache for <see cref="ReadFdeAt"/>.</summary>
    public static Dictionary<long, Cie?> NewCache() => [];

    private static Fde? ReadFde(ByteView data, long pos, long end, Cie cie, ulong dataVa, bool is64)
    {
        if (!TryReadPointer(data, ref pos, cie.FdeEncoding, dataVa, 0, is64, out var start)) return null;
        if (!TryReadPointer(data, ref pos, (byte)(cie.FdeEncoding & 0x0F), dataVa, 0, is64, out var range)) return null;
        return pos <= end ? new Fde(start, range) : null;
    }

    private static Cie? ParseCie(ByteView data, long at, bool is64)
    {
        if (at < 0 || at + 8 > data.Length) return null;
        long length = data.U32(at);
        long body = at + 4;
        if (length == 0xFFFFFFFF)
        {
            length = (long)Math.Min(data.U64(body), long.MaxValue / 2);
            body += 8;
        }
        long end = body + length;
        if (length < 4 || end > data.Length || data.U32(body) != 0) return null;
        var r = new LebReader(data.Span(body + 4, end - body - 4));
        byte version = r.Byte();
        var augmentation = r.CString();
        if (augmentation == null || version is not (1 or 3 or 4)) return null;
        if (augmentation.Contains("eh", StringComparison.Ordinal)) r.Position += is64 ? 8 : 4;
        if (version == 4) r.Position += 2; // address size, segment selector size
        r.Uleb(); // code alignment
        r.Sleb(); // data alignment
        if (version == 1) r.Byte(); else r.Uleb(); // return address register
        byte fdeEncoding = 0; // absptr
        bool hasData = augmentation.StartsWith('z');
        if (hasData)
        {
            ulong augLength = r.Uleb();
            int augEnd = r.Position + (int)Math.Min(augLength, int.MaxValue / 2);
            for (int i = 1; i < augmentation.Length && !r.Failed && r.Position < augEnd; i++)
            {
                switch (augmentation[i])
                {
                    case 'R': fdeEncoding = r.Byte(); break;
                    case 'L': r.Byte(); break;
                    case 'P':
                    {
                        byte enc = r.Byte();
                        long p = body + 4 + r.Position, before = p;
                        TryReadPointer(data, ref p, (byte)(enc & 0x0F), 0, 0, is64, out _); // the personality routine itself is not needed
                        if (p == before) return null;
                        r.Position = (int)(p - body - 4);
                        break;
                    }
                    case 'S' or 'B' or 'G': break;
                    default: i = augmentation.Length; break; // unknown: the length still bounds the data
                }
            }
            r.Position = augEnd;
        }
        return r.Failed ? null : new Cie(fdeEncoding, hasData);
    }
}
