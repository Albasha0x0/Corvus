using System.Buffers.Binary;

namespace Corvus.Core.Documents;

/// <summary>Reads the "Equation Native" stream of an Equation Editor object: the header lengths and the MTEF font records; nothing is run.</summary>
internal static class EquationNative
{
    // The MTEF 3 font record keeps its name in a fixed buffer of this many bytes.
    private const int NameBuffer = 32;
    private const int HeaderSize = 28;

    /// <summary>Adds notes for length mismatches, oversized font names and unread records; a stream that cannot be walked is noted as partial.</summary>
    public static void Read(byte[] s, string where, List<string> notes)
    {
        if (s.Length < HeaderSize) { notes.Add($"{where}: {s.Length} bytes, shorter than the {HeaderSize}-byte equation header; its content is unknown"); return; }
        int header = BinaryPrimitives.ReadUInt16LittleEndian(s);
        long declared = BinaryPrimitives.ReadUInt32LittleEndian(s.AsSpan(8));
        if (header != HeaderSize) notes.Add($"{where}: header length is {header}, not {HeaderSize}");
        long actual = s.Length - Math.Min(header, s.Length);
        if (declared > actual) notes.Add($"{where}: the header declares {declared:N0} bytes of equation data and the stream holds {actual:N0}");
        else if (declared < actual) notes.Add($"{where}: {actual - declared:N0} bytes follow the {declared:N0} declared bytes of equation data");
        int at = Math.Min(header, s.Length) + 5;
        if (at > s.Length) { notes.Add($"{where}: no MTEF header; its content is unknown"); return; }
        if (s[at - 5] is not (2 or 3)) { notes.Add($"{where}: MTEF version {s[at - 5]}; records are not read"); return; }
        while (at < s.Length)
        {
            int tag = s[at++];
            if (tag == 0 || tag is >= 10 and <= 14) continue;
            if (tag == 1)
            {
                if (at >= s.Length) { Truncated(); return; }
                int attr = s[at++];
                if ((attr & 2) != 0) { Stopped(tag); return; }
                if ((attr & 8) != 0)
                {
                    if (at + 2 > s.Length) { Truncated(); return; }
                    bool wide = s[at] == 0x80 && s[at + 1] == 0x80;
                    at += wide ? 6 : 2;
                }
                if ((attr & 4) != 0) at += 2;
                if (at > s.Length) { Truncated(); return; }
                continue;
            }
            if (tag != 8) { Stopped(tag); return; }
            at += 2;
            int end = at <= s.Length ? Array.IndexOf(s, (byte)0, at) : -1;
            if (end < 0) { notes.Add($"{where}: font name at 0x{at:X} runs to the end of the stream without a terminator"); return; }
            if (end - at > NameBuffer) notes.Add($"{where}: font name at 0x{at:X} is {end - at} bytes, past its {NameBuffer}-byte buffer");
            at = end + 1;
        }

        void Truncated() => notes.Add($"{where}: MTEF record truncated at 0x{Math.Min(at, s.Length):X}; the rest is not read");

        void Stopped(int tag) => notes.Add($"{where}: MTEF records read up to 0x{at - 1:X} (tag {tag}); the other {s.Length - at + 1:N0} bytes are not read");
    }
}
