using Iced.Intel;

namespace Corvus.Native.Code;

/// <summary>Decoded instructions of an x64 function.</summary>
internal static class FunctionInstructions
{
    /// <summary>
    /// The function's instructions in address order; a range stops at its first
    /// invalid instruction, and a range over 1 MiB is skipped.
    /// </summary>
    internal static List<Instruction> Decode(INativeImage image, IEnumerable<(uint Start, uint End)> ranges, CancellationToken ct)
    {
        var result = new List<Instruction>();
        foreach (var (start, end) in ranges.OrderBy(r => r.Start))
        {
            ct.ThrowIfCancellationRequested();
            if (end <= start || end - start > 1 << 20) continue;
            var bytes = new byte[end - start];
            int n = image.Read(start, bytes);
            var decoder = Decoder.Create(64, new ByteArrayCodeReader(bytes, 0, n));
            decoder.IP = image.ImageBase + start;
            while (decoder.IP < image.ImageBase + start + (ulong)n)
            {
                decoder.Decode(out var ins);
                if (ins.IsInvalid) break;
                result.Add(ins);
            }
        }
        return result;
    }
}
