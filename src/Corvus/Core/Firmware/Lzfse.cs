// Ported from lzfse 1.0, Copyright (c) 2015-2016, Apple Inc. All rights reserved. BSD 3-Clause License; the notice
// and license text are in THIRD-PARTY-NOTICES.md.
using System.Buffers.Binary;

namespace Corvus.Core.Firmware;

/// <summary>LZFSE and LZVN decoding from lzfse 1.0; damaged input throws <see cref="InvalidDataException"/>, nothing reads outside the spans.</summary>
internal static class Lzfse
{
    private const uint EndOfStream = 0x24787662, Raw = 0x2d787662, V1 = 0x31787662, V2 = 0x32787662, Lzvn = 0x6e787662;
    private const int LSymbols = 20, MSymbols = 20, DSymbols = 64, LiteralSymbols = 256;
    private const int LStates = 64, MStates = 64, DStates = 256, LiteralStates = 1024;
    private const int MatchesPerBlock = 10_000, LiteralsPerBlock = 4 * MatchesPerBlock, V1HeaderSize = 772;

    private static readonly byte[] LExtra = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8];
    private static readonly int[] LBase = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60];
    private static readonly byte[] MExtra = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11];
    private static readonly int[] MBase = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312];
    private static readonly byte[] DExtra =
    [
        0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
        8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11, 12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15,
    ];
    private static readonly int[] DBase =
    [
        0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 28, 36, 44, 52, 60, 76, 92, 108, 124, 156, 188, 220, 252, 316, 380, 444, 508, 636,
        764, 892, 1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580, 4092, 5116, 6140, 7164, 8188, 10236, 12284, 14332, 16380, 20476,
        24572, 28668, 32764, 40956, 49148, 57340, 65532, 81916, 98300, 114684, 131068, 163836, 196604, 229372,
    ];

    /// <summary>True when <paramref name="data"/> starts with an LZFSE block magic.</summary>
    public static bool Looks(ReadOnlySpan<byte> data) =>
        data.Length >= 4 && BinaryPrimitives.ReadUInt32LittleEndian(data) is EndOfStream or Raw or V1 or V2 or Lzvn;

    /// <summary>Decodes an LZFSE stream into <paramref name="dst"/>; returns the bytes written, all of dst when the stream fills it first.</summary>
    public static int Decode(ReadOnlySpan<byte> src, Span<byte> dst)
    {
        int s = 0, o = 0;
        byte[]? literals = null;
        while (true)
        {
            if (s > src.Length - 4) throw new InvalidDataException("an LZFSE stream ends without its end-of-stream block");
            uint magic = BinaryPrimitives.ReadUInt32LittleEndian(src[s..]);
            switch (magic)
            {
                case EndOfStream:
                    return o;
                case Raw:
                {
                    if (s > src.Length - 8) throw Truncated();
                    long n = BinaryPrimitives.ReadUInt32LittleEndian(src[(s + 4)..]);
                    s += 8;
                    if (n > src.Length - s) throw Truncated();
                    int fit = (int)Math.Min(n, dst.Length - o);
                    src.Slice(s, fit).CopyTo(dst[o..]);
                    if (fit < n) return dst.Length;
                    s += fit;
                    o += fit;
                    break;
                }
                case Lzvn:
                {
                    if (s > src.Length - 12) throw Truncated();
                    long raw = BinaryPrimitives.ReadUInt32LittleEndian(src[(s + 4)..]), payload = BinaryPrimitives.ReadUInt32LittleEndian(src[(s + 8)..]);
                    s += 12;
                    if (payload > src.Length - s) throw Truncated();
                    int end = (int)Math.Min(dst.Length, o + raw);
                    int dPrev = 0;
                    int start = o;
                    bool eos = LzvnBlock(src.Slice(s, (int)payload), dst, ref o, end, ref dPrev, out int used);
                    if (!eos && o == dst.Length && end == dst.Length && start + raw > dst.Length) return dst.Length;
                    if (!eos || o != start + raw || used != payload) throw new InvalidDataException("an LZVN block does not decode to its declared size");
                    s += (int)payload;
                    break;
                }
                case V1 or V2:
                    literals ??= new byte[LiteralsPerBlock + 64];
                    if (FseBlock(src, ref s, magic, dst, ref o, literals)) return dst.Length;
                    break;
                default:
                    throw new InvalidDataException($"an unknown LZFSE block magic 0x{magic:X8} at offset {s:N0}");
            }
        }
    }

    /// <summary>The decoded size the block headers declare; null on a damaged header, unknown magic or missing end block.</summary>
    public static long? DecodedSize(ReadOnlySpan<byte> src)
    {
        long total = 0;
        for (int s = 0; s <= src.Length - 4;)
        {
            uint magic = BinaryPrimitives.ReadUInt32LittleEndian(src[s..]);
            if (magic == EndOfStream) return total;
            long raw, size;
            switch (magic)
            {
                case Raw when s <= src.Length - 8:
                    raw = BinaryPrimitives.ReadUInt32LittleEndian(src[(s + 4)..]);
                    size = 8 + raw;
                    break;
                case Lzvn when s <= src.Length - 12:
                    raw = BinaryPrimitives.ReadUInt32LittleEndian(src[(s + 4)..]);
                    size = 12L + BinaryPrimitives.ReadUInt32LittleEndian(src[(s + 8)..]);
                    break;
                case V2 when s <= src.Length - 32:
                {
                    ulong v0 = BinaryPrimitives.ReadUInt64LittleEndian(src[(s + 8)..]), v1 = BinaryPrimitives.ReadUInt64LittleEndian(src[(s + 16)..]);
                    raw = BinaryPrimitives.ReadUInt32LittleEndian(src[(s + 4)..]);
                    size = (long)(uint)BinaryPrimitives.ReadUInt64LittleEndian(src[(s + 24)..]) + Field(v0, 20, 20) + Field(v1, 40, 20);
                    break;
                }
                case V1 when s <= src.Length - V1HeaderSize:
                    raw = BinaryPrimitives.ReadUInt32LittleEndian(src[(s + 4)..]);
                    size = V1HeaderSize + (long)BinaryPrimitives.ReadUInt32LittleEndian(src[(s + 20)..]) + BinaryPrimitives.ReadUInt32LittleEndian(src[(s + 24)..]);
                    break;
                default:
                    return null;
            }
            if (size > src.Length - s) return null;
            total += raw;
            s += (int)size;
        }
        return null;
    }

    /// <summary>Decodes a raw LZVN stream (no block header) into <paramref name="dst"/>; returns the bytes written.</summary>
    public static int DecodeLzvn(ReadOnlySpan<byte> src, Span<byte> dst)
    {
        int o = 0, d = 0;
        LzvnBlock(src, dst, ref o, dst.Length, ref d, out _);
        return o;
    }

    private static InvalidDataException Truncated() => new("a truncated LZFSE block");

    private struct Header
    {
        public uint Literals, Matches, LiteralPayload, LmdPayload;
        public int LiteralBits, LmdBits;
        public ushort L, M, D;
        public ushort[] LiteralState, Freq;
    }

    // Returns true when the output filled before the block ended.
    private static bool FseBlock(ReadOnlySpan<byte> src, ref int s, uint magic, Span<byte> dst, ref int o, byte[] literals)
    {
        var h = new Header { LiteralState = new ushort[4], Freq = new ushort[LSymbols + MSymbols + DSymbols + LiteralSymbols] };
        int headerSize;
        if (magic == V2)
        {
            if (s > src.Length - 32) throw Truncated();
            ulong v0 = BinaryPrimitives.ReadUInt64LittleEndian(src[(s + 8)..]), v1 = BinaryPrimitives.ReadUInt64LittleEndian(src[(s + 16)..]), v2 = BinaryPrimitives.ReadUInt64LittleEndian(src[(s + 24)..]);
            headerSize = (int)Math.Min(int.MaxValue, (uint)v2);
            if (headerSize < 32 || headerSize > src.Length - s) throw Truncated();
            h.Literals = Field(v0, 0, 20);
            h.LiteralPayload = Field(v0, 20, 20);
            h.Matches = Field(v0, 40, 20);
            h.LiteralBits = (int)Field(v0, 60, 3) - 7;
            for (int i = 0; i < 4; i++) h.LiteralState[i] = (ushort)Field(v1, 10 * i, 10);
            h.LmdPayload = Field(v1, 40, 20);
            h.LmdBits = (int)Field(v1, 60, 3) - 7;
            h.L = (ushort)Field(v2, 32, 10);
            h.M = (ushort)Field(v2, 42, 10);
            h.D = (ushort)Field(v2, 52, 10);
            ReadFrequencies(src.Slice(s + 32, headerSize - 32), h.Freq);
        }
        else
        {
            headerSize = V1HeaderSize;
            if (s > src.Length - headerSize) throw Truncated();
            var b = src[s..];
            h.Literals = BinaryPrimitives.ReadUInt32LittleEndian(b[12..]);
            h.Matches = BinaryPrimitives.ReadUInt32LittleEndian(b[16..]);
            h.LiteralPayload = BinaryPrimitives.ReadUInt32LittleEndian(b[20..]);
            h.LmdPayload = BinaryPrimitives.ReadUInt32LittleEndian(b[24..]);
            h.LiteralBits = BinaryPrimitives.ReadInt32LittleEndian(b[28..]);
            for (int i = 0; i < 4; i++) h.LiteralState[i] = BinaryPrimitives.ReadUInt16LittleEndian(b[(32 + 2 * i)..]);
            h.LmdBits = BinaryPrimitives.ReadInt32LittleEndian(b[40..]);
            h.L = BinaryPrimitives.ReadUInt16LittleEndian(b[44..]);
            h.M = BinaryPrimitives.ReadUInt16LittleEndian(b[46..]);
            h.D = BinaryPrimitives.ReadUInt16LittleEndian(b[48..]);
            for (int i = 0; i < h.Freq.Length; i++) h.Freq[i] = BinaryPrimitives.ReadUInt16LittleEndian(b[(50 + 2 * i)..]);
        }
        if ((long)headerSize + h.LiteralPayload + h.LmdPayload > src.Length - s) throw Truncated();
        var freq = h.Freq.AsSpan();
        var lFreq = freq[..LSymbols];
        var mFreq = freq.Slice(LSymbols, MSymbols);
        var dFreq = freq.Slice(LSymbols + MSymbols, DSymbols);
        var litFreq = freq.Slice(LSymbols + MSymbols + DSymbols, LiteralSymbols);
        if (h.Literals > LiteralsPerBlock || h.Matches > MatchesPerBlock || h.LiteralState.Any(x => x >= LiteralStates)
            || h.L >= LStates || h.M >= MStates || h.D >= DStates
            || Sum(lFreq) > LStates || Sum(mFreq) > MStates || Sum(dFreq) > DStates || Sum(litFreq) > LiteralStates)
            throw new InvalidDataException("an LZFSE block header out of range");
        s += headerSize;

        var literalTable = LiteralTable(litFreq);
        var lTable = ValueTable(LStates, lFreq, LExtra, LBase);
        var mTable = ValueTable(MStates, mFreq, MExtra, MBase);
        var dTable = ValueTable(DStates, dFreq, DExtra, DBase);

        // Both bit streams are read backwards from their end; the literal stream may start in bytes before its payload.
        s += (int)h.LiteralPayload;
        var bits = new BitReader(src, s, 0, h.LiteralBits);
        ushort s0 = h.LiteralState[0], s1 = h.LiteralState[1], s2 = h.LiteralState[2], s3 = h.LiteralState[3];
        for (int i = 0; i < h.Literals; i += 4)
        {
            bits.Flush(src);
            literals[i] = Symbol(ref s0, literalTable, ref bits);
            literals[i + 1] = Symbol(ref s1, literalTable, ref bits);
            literals[i + 2] = Symbol(ref s2, literalTable, ref bits);
            literals[i + 3] = Symbol(ref s3, literalTable, ref bits);
        }

        int lmdStart = s;
        var lmd = new BitReader(src, lmdStart + (int)h.LmdPayload, lmdStart, h.LmdBits);
        ushort ls = h.L, ms = h.M, ds = h.D;
        int lit = 0, d = -1;
        for (uint symbols = h.Matches; symbols > 0; symbols--)
        {
            lmd.Flush(src);
            int l = Value(ref ls, lTable, ref lmd);
            if (lit + l >= literals.Length) throw new InvalidDataException("an LZFSE literal run past the block's literals");
            int m = Value(ref ms, mTable, ref lmd);
            int newD = Value(ref ds, dTable, ref lmd);
            if (newD != 0) d = newD;
            if ((uint)d > (uint)(o + l)) throw new InvalidDataException("an LZFSE match before the start of the output");
            int fit = Math.Min(l, dst.Length - o);
            literals.AsSpan(lit, fit).CopyTo(dst[o..]);
            o += fit;
            lit += fit;
            if (fit < l) return true;
            fit = Math.Min(m, dst.Length - o);
            Match(dst, o, d, fit);
            o += fit;
            if (fit < m) return true;
        }
        s = lmdStart + (int)h.LmdPayload;
        return false;
    }

    private static uint Field(ulong v, int offset, int n) => (uint)((v >> offset) & ((1UL << n) - 1));

    private static int Sum(ReadOnlySpan<ushort> f)
    {
        int sum = 0;
        foreach (var x in f) sum += x;
        return sum;
    }

    // The v2 header's frequencies: a prefix code of 2 to 14 bits per value, least significant bit first.
    private static void ReadFrequencies(ReadOnlySpan<byte> table, ushort[] freq)
    {
        if (table.Length == 0) return;
        ReadOnlySpan<sbyte> nbitsTable = [2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14, 2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14];
        ReadOnlySpan<sbyte> valueTable = [0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1, 0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1];
        uint accum = 0;
        int accumBits = 0, at = 0;
        for (int i = 0; i < freq.Length; i++)
        {
            while (at < table.Length && accumBits + 8 <= 32)
            {
                accum |= (uint)table[at++] << accumBits;
                accumBits += 8;
            }
            int b = (int)(accum & 31), n = nbitsTable[b];
            freq[i] = (ushort)(n == 8 ? 8 + (int)((accum >> 4) & 0xF) : n == 14 ? 24 + (int)((accum >> 4) & 0x3FF) : valueTable[b]);
            if (n > accumBits) throw new InvalidDataException("a truncated LZFSE frequency table");
            accum >>= n;
            accumBits -= n;
        }
        if (accumBits >= 8 || at != table.Length) throw new InvalidDataException("an LZFSE frequency table that does not end at its header's end");
    }

    private struct LiteralEntry
    {
        public sbyte K;
        public byte Symbol;
        public short Delta;
    }

    private struct ValueEntry
    {
        public byte TotalBits, ValueBits;
        public short Delta;
        public int Base;
    }

    private static LiteralEntry[] LiteralTable(ReadOnlySpan<ushort> freq)
    {
        var t = new LiteralEntry[LiteralStates];
        int clzStates = System.Numerics.BitOperations.LeadingZeroCount((uint)LiteralStates), at = 0;
        for (int i = 0; i < freq.Length; i++)
        {
            int f = freq[i];
            if (f == 0) continue;
            int k = System.Numerics.BitOperations.LeadingZeroCount((uint)f) - clzStates;
            int j0 = ((2 * LiteralStates) >> k) - f;
            for (int j = 0; j < f; j++)
                t[at++] = j < j0
                    ? new LiteralEntry { K = (sbyte)k, Symbol = (byte)i, Delta = (short)(((f + j) << k) - LiteralStates) }
                    : new LiteralEntry { K = (sbyte)(k - 1), Symbol = (byte)i, Delta = (short)((j - j0) << (k - 1)) };
        }
        return t;
    }

    private static ValueEntry[] ValueTable(int states, ReadOnlySpan<ushort> freq, byte[] extra, int[] bases)
    {
        var t = new ValueEntry[states];
        int clzStates = System.Numerics.BitOperations.LeadingZeroCount((uint)states), at = 0;
        for (int i = 0; i < freq.Length; i++)
        {
            int f = freq[i];
            if (f == 0) continue;
            int k = System.Numerics.BitOperations.LeadingZeroCount((uint)f) - clzStates;
            int j0 = ((2 * states) >> k) - f;
            for (int j = 0; j < f; j++)
                t[at++] = j < j0
                    ? new ValueEntry { TotalBits = (byte)(k + extra[i]), ValueBits = extra[i], Delta = (short)(((f + j) << k) - states), Base = bases[i] }
                    : new ValueEntry { TotalBits = (byte)(k - 1 + extra[i]), ValueBits = extra[i], Delta = (short)((j - j0) << (k - 1)), Base = bases[i] };
        }
        return t;
    }

    private static byte Symbol(ref ushort state, LiteralEntry[] table, ref BitReader bits)
    {
        var e = table[state];
        state = (ushort)(e.Delta + (int)bits.Pull(e.K));
        if (state >= table.Length) throw new InvalidDataException("an LZFSE literal state out of range");
        return e.Symbol;
    }

    private static int Value(ref ushort state, ValueEntry[] table, ref BitReader bits)
    {
        var e = table[state];
        uint v = (uint)bits.Pull(e.TotalBits);
        state = (ushort)(e.Delta + (int)(v >> e.ValueBits));
        if (state >= table.Length) throw new InvalidDataException("an LZFSE value state out of range");
        return e.Base + (int)(v & ((1u << e.ValueBits) - 1));
    }

    /// <summary>A bit stream read backwards from <c>at</c>, holding 56 to 63 bits after each flush, never reading below <c>floor</c>.</summary>
    private struct BitReader
    {
        private ulong _accum;
        private int _bits, _at;
        private readonly int _floor;

        public BitReader(ReadOnlySpan<byte> src, int at, int floor, int n)
        {
            _floor = floor;
            int take = n != 0 ? 8 : 7;
            if (at - take < floor || at > src.Length) throw new InvalidDataException("an LZFSE bit stream shorter than its first word");
            _at = at - take;
            _accum = 0;
            for (int i = 0; i < take; i++) _accum |= (ulong)src[_at + i] << (8 * i);
            _bits = n + (n != 0 ? 64 : 56);
            if (_bits < 56 || _bits >= 64 || _accum >> _bits != 0) throw new InvalidDataException("an LZFSE bit stream with a bad first word");
        }

        public void Flush(ReadOnlySpan<byte> src)
        {
            int n = (63 - _bits) & -8, bytes = n >> 3;
            if (_at - bytes < _floor) throw new InvalidDataException("an LZFSE bit stream read past its start");
            _at -= bytes;
            ulong incoming = 0;
            for (int i = 0; i < bytes; i++) incoming |= (ulong)src[_at + i] << (8 * i);
            _accum = n == 0 ? _accum : (_accum << n) | incoming;
            _bits += n;
        }

        public ulong Pull(int n)
        {
            if (n < 0 || n > _bits) throw new InvalidDataException("an LZFSE bit stream read past its flushed bits");
            _bits -= n;
            ulong result = _accum >> _bits;
            _accum &= _bits == 0 ? 0 : ulong.MaxValue >> (64 - _bits);
            return result;
        }
    }

    // A match may overlap its own output: copied forward one byte at a time unless the distance clears it.
    private static void Match(Span<byte> dst, int o, int d, int m)
    {
        if (d >= m) dst.Slice(o - d, m).CopyTo(dst[o..]);
        else for (int i = 0; i < m; i++) dst[o + i] = dst[o + i - d];
    }

    /// <summary>Decodes one LZVN stream; true at its end opcode, false when output reaches <paramref name="end"/> first.</summary>
    private static bool LzvnBlock(ReadOnlySpan<byte> src, Span<byte> dst, ref int o, int end, ref int dPrev, out int used)
    {
        int p = 0, d = dPrev;
        try
        {
            while (true)
            {
                if (p >= src.Length) throw new InvalidDataException("an LZVN stream ends without its end-of-stream opcode");
                int opc = src[p], l = 0, m = 0, len;
                if (opc >= 0xF0)
                {
                    len = opc == 0xF0 ? 2 : 1;
                    if (p + len > src.Length) throw Truncated();
                    m = opc == 0xF0 ? src[p + 1] + 16 : opc & 0xF;
                }
                else if (opc >= 0xE0)
                {
                    len = opc == 0xE0 ? 2 : 1;
                    if (p + len > src.Length) throw Truncated();
                    l = opc == 0xE0 ? src[p + 1] + 16 : opc & 0xF;
                }
                else if (opc >= 0xD0 || opc is >= 0x70 and < 0x80) throw new InvalidDataException($"an undefined LZVN opcode 0x{opc:X2}");
                else if (opc is >= 0xA0 and < 0xC0)
                {
                    len = 3;
                    if (p + 3 > src.Length) throw Truncated();
                    int opc23 = BinaryPrimitives.ReadUInt16LittleEndian(src[(p + 1)..]);
                    l = (opc >> 3) & 3;
                    m = ((opc & 7) << 2 | (opc23 & 3)) + 3;
                    d = opc23 >> 2;
                }
                else
                {
                    l = opc >> 6;
                    m = ((opc >> 3) & 7) + 3;
                    switch (opc & 7)
                    {
                        case 7:
                            len = 3;
                            if (p + 3 > src.Length) throw Truncated();
                            d = BinaryPrimitives.ReadUInt16LittleEndian(src[(p + 1)..]);
                            break;
                        case 6 when opc == 6:
                            if (p + 8 > src.Length) throw Truncated();
                            p += 8;
                            return true;
                        case 6 when opc is 14 or 22:
                            p += 1;
                            continue;
                        case 6 when opc < 0x40:
                            throw new InvalidDataException($"an undefined LZVN opcode 0x{opc:X2}");
                        case 6:
                            len = 1;
                            break;
                        default:
                            len = 2;
                            if (p + 2 > src.Length) throw Truncated();
                            d = (opc & 7) << 8 | src[p + 1];
                            break;
                    }
                }
                p += len;
                if (l > 0)
                {
                    if (p + l > src.Length) throw Truncated();
                    int fit = Math.Min(l, end - o);
                    src.Slice(p, fit).CopyTo(dst[o..]);
                    o += fit;
                    p += fit;
                    if (fit < l) return false;
                }
                if (m > 0)
                {
                    if (d == 0 || d > o) throw new InvalidDataException("an LZVN match before the start of the output");
                    int fit = Math.Min(m, end - o);
                    Match(dst, o, d, fit);
                    o += fit;
                    if (fit < m) return false;
                }
            }
        }
        finally
        {
            used = p;
            dPrev = d;
        }
    }
}
