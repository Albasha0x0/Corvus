namespace Corvus.Native.Elf;

/// <summary>A CIE in full: alignment factors, the return address column, augmentation pointers and its initial instructions.</summary>
internal sealed record CfiCie(long At, ulong CodeAlign, long DataAlign, int ReturnColumn, byte FdeEncoding, byte LsdaEncoding, byte PersonalityEncoding,
    ulong? Personality, long Instructions, long InstructionsEnd);

/// <summary>An FDE in full: its code range, LSDA pointer (as encoded: the indirect flag is the encoding's 0x80 bit) and instructions.</summary>
internal sealed record CfiFde(long At, ulong Start, ulong Range, CfiCie Cie, ulong? Lsda, long Instructions, long InstructionsEnd);

internal static partial class EhFrame
{
    /// <summary>Every FDE with its CIE, LSDA and instruction ranges, in order; unreadable records are skipped, at most <paramref name="max"/>.</summary>
    public static List<CfiFde> WalkFull(ByteView data, ulong dataVa, bool is64, int max)
    {
        var result = new List<CfiFde>();
        var cies = new Dictionary<long, CfiCie?>();
        long at = 0;
        int steps = 0;
        while (at + 4 <= data.Length && result.Count < max && ++steps < 4 * max)
        {
            long length = data.U32(at), body = at + 4;
            if (length == 0) break;
            if (length == 0xFFFFFFFF) { length = (long)Math.Min(data.U64(body), long.MaxValue / 2); body += 8; }
            long next = body + length;
            if (length < 4 || next > data.Length) break;
            uint id = data.U32(body);
            if (id != 0)
            {
                long cieAt = body - id;
                if (!cies.TryGetValue(cieAt, out var cie)) cies[cieAt] = cie = ParseCieFull(data, cieAt, dataVa, is64);
                if (cie != null && ParseFde(data, at, body + 4, next, cie, dataVa, is64) is { } fde) result.Add(fde);
            }
            at = next;
        }
        return result;
    }

    /// <summary>The FDE at <paramref name="at"/> (its length field) with its CIE in full, or null; CIEs are cached in <paramref name="cache"/>.</summary>
    public static CfiFde? ReadFullFdeAt(ByteView data, long at, ulong dataVa, bool is64, Dictionary<long, CfiCie?> cache)
    {
        if (at < 0 || at + 8 > data.Length) return null;
        long length = data.U32(at), body = at + 4;
        if (length == 0xFFFFFFFF) { length = (long)Math.Min(data.U64(body), long.MaxValue / 2); body += 8; }
        long next = body + length;
        if (length < 8 || next > data.Length) return null;
        uint id = data.U32(body);
        if (id == 0) return null;
        long cieAt = body - id;
        if (!cache.TryGetValue(cieAt, out var cie)) cache[cieAt] = cie = ParseCieFull(data, cieAt, dataVa, is64);
        return cie != null ? ParseFde(data, at, body + 4, next, cie, dataVa, is64) : null;
    }

    private static CfiFde? ParseFde(ByteView data, long at, long pos, long end, CfiCie cie, ulong dataVa, bool is64)
    {
        if (!TryReadPointer(data, ref pos, cie.FdeEncoding, dataVa, 0, is64, out var start)) return null;
        if (!TryReadPointer(data, ref pos, (byte)(cie.FdeEncoding & 0x0F), dataVa, 0, is64, out var range)) return null;
        ulong? lsda = null;
        if (cie.LsdaEncoding != NoAugmentation)
        {
            var r = new LebReader(data.Span(pos, Math.Min(16, end - pos)));
            ulong length = r.Uleb();
            if (r.Failed) return null;
            long augEnd = pos + r.Position + (long)Math.Min(length, (ulong)(end - pos));
            long p = pos + r.Position;
            if (cie.LsdaEncoding != Omit && length > 0 && TryReadPointer(data, ref p, (byte)(cie.LsdaEncoding & 0x7F), dataVa, 0, is64, out var l) && l != 0) lsda = l;
            pos = augEnd;
        }
        return pos <= end ? new CfiFde(at, start, range, cie, lsda, pos, end) : null;
    }

    /// <summary>The CIE has no 'z' augmentation: its FDEs carry no augmentation data.</summary>
    private const byte NoAugmentation = 0xFE;

    private static CfiCie? ParseCieFull(ByteView data, long at, ulong dataVa, bool is64)
    {
        if (at < 0 || at + 8 > data.Length) return null;
        long length = data.U32(at), body = at + 4;
        if (length == 0xFFFFFFFF) { length = (long)Math.Min(data.U64(body), long.MaxValue / 2); body += 8; }
        long end = body + length;
        if (length < 4 || end > data.Length || data.U32(body) != 0) return null;
        long start = body + 4;
        var r = new LebReader(data.Span(start, end - start));
        byte version = r.Byte();
        var aug = r.CString();
        if (aug == null || version is not (1 or 3 or 4)) return null;
        if (aug.Contains("eh", StringComparison.Ordinal)) r.Position += is64 ? 8 : 4;
        if (version == 4) r.Position += 2;
        ulong codeAlign = r.Uleb();
        long dataAlign = r.Sleb();
        int ra = version == 1 ? r.Byte() : (int)Math.Min(r.Uleb(), int.MaxValue);
        byte fde = 0, lsda = Omit, personalityEncoding = Omit;
        ulong? personality = null;
        bool z = aug.StartsWith('z');
        if (z)
        {
            ulong augLength = r.Uleb();
            int augEnd = r.Position + (int)Math.Min(augLength, int.MaxValue / 2);
            for (int i = 1; i < aug.Length && !r.Failed && r.Position < augEnd; i++)
            {
                switch (aug[i])
                {
                    case 'R': fde = r.Byte(); break;
                    case 'L': lsda = r.Byte(); break;
                    case 'P':
                    {
                        personalityEncoding = r.Byte();
                        long p = start + r.Position;
                        if (TryReadPointer(data, ref p, (byte)(personalityEncoding & 0x7F), dataVa, 0, is64, out var value)) personality = value;
                        r.Position = (int)(p - start);
                        break;
                    }
                    case 'S' or 'B' or 'G': break;
                    default: i = aug.Length; break;
                }
            }
            r.Position = augEnd;
        }
        if (r.Failed) return null;
        return new CfiCie(at, codeAlign, dataAlign, ra, fde, z ? lsda : NoAugmentation, personalityEncoding, personality, start + r.Position, end);
    }
}
