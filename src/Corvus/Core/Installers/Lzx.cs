using System.Buffers.Binary;

namespace Corvus.Core.Installers;

/// <summary>
/// LZX as cabinet files use it (window 2^15 to 2^21): verbatim, aligned-offset and uncompressed blocks, main / length /
/// aligned Huffman trees delta-coded through pretrees against the previous block's lengths, the three recent match
/// offsets, frames (one per cabinet data block) with the bitstream realigned to 16 bits after each, and E8 call translation.
/// </summary>
internal sealed class Lzx
{
    private const int MainLiterals = 256, LengthElements = 249, AlignedElements = 8, PretreeElements = 20, MinMatch = 2, Frame = 32768;

    private static readonly int[] ExtraBits = new int[51];
    private static readonly int[] PositionBase = new int[51];

    static Lzx()
    {
        for (int i = 0, j = 0; i < 51; i += 2)
        {
            ExtraBits[i] = j;
            if (i + 1 < 51) ExtraBits[i + 1] = j;
            if (i != 0 && j < 17) j++;
        }
        for (int i = 0, j = 0; i < 51; i++)
        {
            PositionBase[i] = j;
            j += 1 << ExtraBits[i];
        }
    }

    private readonly int _positionSlots, _mainElements;
    private readonly byte[] _window;
    private int _windowPos;
    private uint _r0 = 1, _r1 = 1, _r2 = 1;
    private readonly byte[] _mainLengths, _lengthLengths;
    private int _translationSize;
    private int _blockType, _blockRemaining, _blockLength;
    private Huffman? _main, _length, _aligned;

    // the folder's compressed bytes as 16-bit little-endian words, read most significant bit first
    private readonly byte[] _in;
    private int _inPos;
    private uint _bits;
    private int _bitCount;

    private Lzx(int windowBits, byte[] input)
    {
        if (windowBits is < 15 or > 21) throw new InvalidDataException($"LZX window 2^{windowBits} is out of range");
        _positionSlots = windowBits switch { 20 => 42, 21 => 50, _ => windowBits * 2 };
        _mainElements = MainLiterals + _positionSlots * 8;
        _window = new byte[1 << windowBits];
        _mainLengths = new byte[_mainElements];
        _lengthLengths = new byte[LengthElements];
        _in = input;
    }

    /// <summary>A folder's data: <paramref name="frames"/> are the uncompressed sizes of its data blocks, each at most 32 KiB.</summary>
    public static byte[] DecodeFolder(byte[] compressed, IReadOnlyList<int> frames, int windowBits, long max)
    {
        var lzx = new Lzx(windowBits, compressed);
        long total = frames.Sum(f => (long)f);
        if (total > max) throw new ToolError(ErrorCode.LimitExceeded, $"an LZX folder decompresses to {total:N0} bytes, over the {max:N0}-byte item limit.");
        var output = new byte[total];
        if (lzx.Bit() == 1) lzx._translationSize = (lzx.Bits(16) << 16) | lzx.Bits(16);
        long at = 0;
        for (int f = 0; f < frames.Count; f++)
        {
            int size = frames[f];
            if (size is <= 0 or > Frame) throw new InvalidDataException($"LZX frame of {size} bytes");
            lzx.DecodeFrame(output.AsSpan((int)at, size));
            if (lzx._translationSize != 0 && size > 10 && at < 0x40000000) lzx.Translate(output.AsSpan((int)at, size), (int)at);
            at += size;
        }
        return output;
    }

    private void Need(int n)
    {
        while (_bitCount < n)
        {
            uint word = _inPos + 1 < _in.Length ? BinaryPrimitives.ReadUInt16LittleEndian(_in.AsSpan(_inPos)) : _inPos < _in.Length ? _in[_inPos] : 0u;
            if (_inPos >= _in.Length + 4) throw new InvalidDataException("LZX data ends inside a block");
            _inPos += 2;
            _bits |= word << (16 - _bitCount);
            _bitCount += 16;
        }
    }

    private int Bits(int n)
    {
        if (n == 0) return 0;
        Need(n);
        int v = (int)(_bits >> (32 - n));
        _bits <<= n;
        _bitCount -= n;
        return v;
    }

    private int Bit() => Bits(1);

    // bytes decoded into the window and bytes handed out; a match may run up to 257 bytes into the next frame
    private long _decoded, _emitted;

    private void DecodeFrame(Span<byte> output)
    {
        int mask = _window.Length - 1;
        while (_decoded < _emitted + output.Length)
        {
            if (_blockRemaining == 0)
            {
                if (_blockType == 3 && (_blockLength & 1) == 1) _inPos++; // the pad byte after an odd uncompressed block
                ReadBlockHeader();
            }
            int n = (int)Math.Min(_emitted + output.Length - _decoded, _blockRemaining);
            if (_blockType == 3)
            {
                if (_inPos + n > _in.Length) throw new InvalidDataException("an uncompressed LZX block runs past its data");
                for (int i = 0; i < n; i++) { _window[_windowPos] = _in[_inPos++]; _windowPos = (_windowPos + 1) & mask; }
            }
            else
            {
                n = DecodeSymbols(n);
                if (n > _blockRemaining) throw new InvalidDataException("an LZX match runs past its block");
            }
            _decoded += n;
            _blockRemaining -= n;
        }
        // realign to 16 bits after each frame
        int drop = _bitCount % 16;
        _bits <<= drop;
        _bitCount -= drop;
        for (int i = 0; i < output.Length; i++) output[i] = _window[(int)((_emitted + i) & mask)];
        _emitted += output.Length;
    }

    private void Translate(Span<byte> data, int offset)
    {
        for (int i = 0; i < data.Length - 10; i++)
        {
            if (data[i] != 0xE8) continue;
            int pos = offset + i;
            int abs = BinaryPrimitives.ReadInt32LittleEndian(data[(i + 1)..]);
            if (abs >= -pos && abs < _translationSize)
                BinaryPrimitives.WriteInt32LittleEndian(data[(i + 1)..], abs >= 0 ? abs - pos : abs + _translationSize);
            i += 4;
        }
    }

    private void ReadBlockHeader()
    {
        _blockType = Bits(3);
        _blockLength = _blockRemaining = (Bits(8) << 16) | Bits(16);
        switch (_blockType)
        {
            case 1 or 2:
                if (_blockType == 2)
                {
                    var lengths = new byte[AlignedElements];
                    for (int i = 0; i < AlignedElements; i++) lengths[i] = (byte)Bits(3);
                    _aligned = new Huffman(lengths);
                }
                ReadLengths(_mainLengths, 0, MainLiterals);
                ReadLengths(_mainLengths, MainLiterals, _mainElements);
                _main = new Huffman(_mainLengths);
                ReadLengths(_lengthLengths, 0, LengthElements);
                _length = new Huffman(_lengthLengths);
                break;
            case 3:
                // 1 to 16 bits of padding to the next 16-bit boundary, then R0, R1, R2 as 32-bit little-endian values
                if (_bitCount == 0) _inPos += 2;
                _bits = 0;
                _bitCount = 0;
                if (_inPos + 12 > _in.Length) throw new InvalidDataException("an uncompressed LZX block header runs past its data");
                _r0 = BinaryPrimitives.ReadUInt32LittleEndian(_in.AsSpan(_inPos));
                _r1 = BinaryPrimitives.ReadUInt32LittleEndian(_in.AsSpan(_inPos + 4));
                _r2 = BinaryPrimitives.ReadUInt32LittleEndian(_in.AsSpan(_inPos + 8));
                _inPos += 12;
                break;
            default:
                throw new InvalidDataException($"LZX block type {_blockType}");
        }
        if (_blockRemaining == 0) throw new InvalidDataException("an empty LZX block");
    }

    /// <summary>Tree lengths [from, to) through a pretree, each a delta against the previous block's length.</summary>
    private void ReadLengths(byte[] lengths, int from, int to)
    {
        var pre = new byte[PretreeElements];
        for (int i = 0; i < PretreeElements; i++) pre[i] = (byte)Bits(4);
        var tree = new Huffman(pre);
        for (int i = from; i < to;)
        {
            int code = tree.Decode(this);
            if (code == 17)
            {
                for (int run = Bits(4) + 4; run > 0 && i < to; run--) lengths[i++] = 0;
            }
            else if (code == 18)
            {
                for (int run = Bits(5) + 20; run > 0 && i < to; run--) lengths[i++] = 0;
            }
            else if (code == 19)
            {
                int run = Bit() + 4;
                code = tree.Decode(this);
                if (code > 16) throw new InvalidDataException("LZX pretree run of a run");
                byte len = (byte)((lengths[i] - code + 17) % 17);
                for (; run > 0 && i < to; run--) lengths[i++] = len;
            }
            else
            {
                lengths[i] = (byte)((lengths[i] - code + 17) % 17);
                i++;
            }
        }
    }

    /// <summary>Literals and matches until at least <paramref name="want"/> bytes are produced; returns how many (the last match may run past).</summary>
    private int DecodeSymbols(int want)
    {
        int produced = 0;
        int mask = _window.Length - 1;
        while (produced < want)
        {
            int element = _main!.Decode(this);
            if (element < MainLiterals)
            {
                _window[_windowPos] = (byte)element;
                _windowPos = (_windowPos + 1) & mask;
                produced++;
                continue;
            }
            element -= MainLiterals;
            int length = element & 7;
            if (length == 7) length += _length!.Decode(this);
            length += MinMatch;
            int slot = element >> 3;
            uint offset;
            if (slot == 0) offset = _r0;
            else if (slot == 1) { offset = _r1; _r1 = _r0; _r0 = offset; }
            else if (slot == 2) { offset = _r2; _r2 = _r0; _r0 = offset; }
            else
            {
                if (slot >= _positionSlots) throw new InvalidDataException("LZX position slot past the window");
                int extra = ExtraBits[slot];
                uint baseOffset = (uint)PositionBase[slot] - 2;
                offset = _blockType == 2 && extra >= 3
                    ? baseOffset + ((uint)Bits(extra - 3) << 3) + (uint)_aligned!.Decode(this)
                    : baseOffset + (uint)Bits(extra);
                _r2 = _r1; _r1 = _r0; _r0 = offset;
            }
            if (offset == 0 || offset > (uint)_window.Length) throw new InvalidDataException("LZX match offset outside the window");
            for (int k = 0; k < length; k++)
            {
                _window[_windowPos] = _window[(_windowPos - (int)offset) & mask];
                _windowPos = (_windowPos + 1) & mask;
            }
            produced += length;
        }
        return produced;
    }

    /// <summary>A canonical Huffman code decoded bit by bit, most significant first (codes up to 16 bits).</summary>
    private sealed class Huffman
    {
        private readonly int[] _count = new int[17], _first = new int[17], _offset = new int[17];
        private readonly int[] _symbols;

        public Huffman(byte[] lengths)
        {
            foreach (var l in lengths) if (l > 16) throw new InvalidDataException("LZX code length over 16");
            foreach (var l in lengths) if (l > 0) _count[l]++;
            _symbols = new int[lengths.Length];
            int code = 0, index = 0;
            for (int len = 1; len <= 16; len++)
            {
                _first[len] = code;
                _offset[len] = index;
                index += _count[len];
                code = (code + _count[len]) << 1;
            }
            var next = (int[])_offset.Clone();
            for (int s = 0; s < lengths.Length; s++) if (lengths[s] > 0) _symbols[next[lengths[s]]++] = s;
        }

        public int Decode(Lzx r)
        {
            int code = 0;
            for (int len = 1; len <= 16; len++)
            {
                code = (code << 1) | r.Bit();
                int idx = code - _first[len];
                if (idx >= 0 && idx < _count[len]) return _symbols[_offset[len] + idx];
            }
            throw new InvalidDataException("an LZX code matches no symbol");
        }
    }
}
