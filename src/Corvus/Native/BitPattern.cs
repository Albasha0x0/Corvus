namespace Corvus.Native;

/// <summary>
/// A byte pattern with a bit mask per byte (0xFF fixed, 0x00 any, else only the set bits must match). Candidates come
/// from a vectorized search for the longest run of fixed bytes, else for a byte whose fixed bits are its high bits (a value
/// range), else every position is tried.
/// </summary>
public sealed class BitPattern
{
    private readonly byte[] _bytes, _mask;
    private readonly int _anchorAt, _anchorLength, _rangeAt;

    public BitPattern(byte[] bytes, byte[] mask, string label)
    {
        if (bytes.Length != mask.Length) throw new ArgumentException("bytes and mask differ in length");
        _bytes = bytes.Select((b, i) => (byte)(b & mask[i])).ToArray();
        _mask = mask;
        Label = label;
        for (int i = 0, run = 0; i < mask.Length; i++)
        {
            run = mask[i] == 0xFF ? run + 1 : 0;
            if (run > _anchorLength) (_anchorAt, _anchorLength) = (i - run + 1, run);
        }
        _rangeAt = -1;
        if (_anchorLength > 0) return;
        for (int i = 0, best = 0; i < mask.Length; i++)
        {
            int fixedBits = byte.PopCount(mask[i]);
            // high bits only: the matching values are one range
            if (fixedBits > best && (byte)(0xFF << (8 - fixedBits)) == mask[i]) (_rangeAt, best) = (i, fixedBits);
        }
    }

    public static BitPattern Exact(byte[] bytes, string label) => new(bytes, bytes.Select(_ => (byte)0xFF).ToArray(), label);

    public string Label { get; }
    public int Length => _bytes.Length;
    public ReadOnlySpan<byte> Bytes => _bytes;
    public ReadOnlySpan<byte> Mask => _mask;

    /// <summary>Whether zero fill matches.</summary>
    public bool MatchesZero => _bytes.All(b => b == 0);

    public bool Matches(ReadOnlySpan<byte> data, int at)
    {
        for (int j = 0; j < _bytes.Length; j++)
            if ((data[at + j] & _mask[j]) != _bytes[j]) return false;
        return true;
    }

    /// <summary>Calls <paramref name="hit"/> with every match start below <paramref name="starts"/> that fits in <paramref name="data"/>, in order.</summary>
    public void Scan(ReadOnlySpan<byte> data, int starts, Action<int> hit)
    {
        int limit = Math.Min(starts, data.Length - _bytes.Length + 1);
        if (limit <= 0) return;
        if (_anchorLength > 0)
        {
            var anchor = _bytes.AsSpan(_anchorAt, _anchorLength);
            for (int i = 0; i < limit; i++)
            {
                int k = data.Slice(i + _anchorAt, limit - i + _anchorLength - 1).IndexOf(anchor);
                if (k < 0) return;
                i += k;
                if (Matches(data, i)) hit(i);
            }
        }
        else if (_rangeAt >= 0)
        {
            byte low = _bytes[_rangeAt], high = (byte)(low | (byte)~_mask[_rangeAt]);
            for (int i = 0; i < limit; i++)
            {
                int k = data.Slice(i + _rangeAt, limit - i).IndexOfAnyInRange(low, high);
                if (k < 0) return;
                i += k;
                if (Matches(data, i)) hit(i);
            }
        }
        else
        {
            for (int i = 0; i < limit; i++)
                if (Matches(data, i)) hit(i);
        }
    }
}
