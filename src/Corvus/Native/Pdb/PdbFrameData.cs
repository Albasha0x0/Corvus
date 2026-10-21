using System.Buffers.Binary;
using System.Text;

namespace Corvus.Native.Pdb;

/// <summary>
/// x86 frame data of one code block, from a PDB's FRAMEDATA (new FPO) or FPO_DATA records: sizes in bytes, and the
/// postfix program that recovers the caller's registers (null for FPO_DATA, which has none). FPO_DATA only:
/// <paramref name="SavesFramePointer"/>, EBP is the first saved register; <paramref name="StandardFrame"/>, the block
/// keeps a standard EBP frame.
/// </summary>
public sealed record PdbFrameRecord(uint Rva, uint Size, uint Locals, uint Params, uint SavedRegs, ushort Prolog, string? Program,
    bool SavesFramePointer, bool StandardFrame, bool HasSeh);

/// <summary>The x86 frame data of a PDB, sorted by RVA. <see cref="Find"/> returns the record whose block holds an RVA, or null.</summary>
public sealed class PdbFrameTable
{
    /// <summary>Most records read from each frame data stream.</summary>
    public const int MaxRecords = 1 << 20;

    private const int FrameDataSize = 32;
    private const int FpoDataSize = 16;
    // Records are sorted by start; a block nested in another lies within this many records after the outer one's start.
    private const int MaxNesting = 8;

    private readonly PdbFrameRecord[] _records;
    private readonly uint[] _starts;

    private PdbFrameTable(List<PdbFrameRecord> records)
    {
        records.Sort((a, b) => a.Rva.CompareTo(b.Rva));
        _records = [.. records];
        _starts = _records.Select(r => r.Rva).ToArray();
    }

    public int Count => _records.Length;

    /// <summary>The innermost record whose block holds <paramref name="rva"/>, or null.</summary>
    public PdbFrameRecord? Find(uint rva)
    {
        int i = Array.BinarySearch(_starts, rva);
        if (i < 0) i = ~i - 1;
        else while (i + 1 < _starts.Length && _starts[i + 1] == rva) i++;
        for (int k = i; k >= 0 && k > i - MaxNesting; k--)
            if (rva - _records[k].Rva < Math.Max(1, _records[k].Size)) return _records[k];
        return null;
    }

    /// <summary>
    /// Reads the FRAMEDATA stream (programs from the /names table) and the FPO_DATA stream; a block both describe keeps its
    /// FRAMEDATA record. <paramref name="map"/> maps an RVA of the original layout (OMAP); null drops the record.
    /// Null when the PDB has neither stream.
    /// </summary>
    internal static PdbFrameTable? Read(MsfFile msf, int frameDataStream, int fpoStream, byte[] names, Func<uint, uint?> map)
    {
        bool hasNames = names.Length >= 12 && BinaryPrimitives.ReadUInt32LittleEndian(names) == 0xEFFEEFFE;
        var records = new List<PdbFrameRecord>();
        var covered = new Dictionary<uint, int>();
        if (frameDataStream != 0xFFFF && msf.HasStream(frameDataStream))
        {
            var bytes = msf.ReadStream(frameDataStream, MaxRecords * FrameDataSize);
            for (int at = 0; at + FrameDataSize <= bytes.Length; at += FrameDataSize)
            {
                var r = bytes.AsSpan(at, FrameDataSize);
                if (map(Le32(r, 0)) is not { } rva) continue;
                uint flags = Le32(r, 28);
                records.Add(new PdbFrameRecord(rva, Le32(r, 4), Le32(r, 8), Le32(r, 12), BinaryPrimitives.ReadUInt16LittleEndian(r[26..]),
                    BinaryPrimitives.ReadUInt16LittleEndian(r[24..]), hasNames ? StringAt(names, Le32(r, 20)) : null, false, false, (flags & 1) != 0));
                covered.TryAdd(rva, records.Count - 1);
            }
        }
        if (fpoStream != 0xFFFF && msf.HasStream(fpoStream))
        {
            var bytes = msf.ReadStream(fpoStream, MaxRecords * FpoDataSize);
            for (int at = 0; at + FpoDataSize <= bytes.Length; at += FpoDataSize)
            {
                var r = bytes.AsSpan(at, FpoDataSize);
                if (map(Le32(r, 0)) is not { } rva) continue;
                ushort bits = BinaryPrimitives.ReadUInt16LittleEndian(r[14..]);
                // cbFrame: 0 FPO, 1 trap, 2 TSS, 3 standard EBP frame; trap and TSS frames are not unwound from these fields.
                int frameType = bits >> 14;
                uint locals = Le32(r, 8) * 4, saved = (uint)((bits >> 8) & 7) * 4;
                if (covered.TryGetValue(rva, out int known))
                {
                    // The return address search is sized from FPO_DATA, as the debuggers do: the FRAMEDATA of an exception
                    // filter block carries its enclosing function's locals, while the filter runs on a stack of its own.
                    if (frameType == 0) records[known] = records[known] with { Locals = locals, SavedRegs = saved };
                    continue;
                }
                if (frameType is 1 or 2) continue;
                records.Add(new PdbFrameRecord(rva, Le32(r, 4), locals, BinaryPrimitives.ReadUInt16LittleEndian(r[12..]) * 4u,
                    saved, (ushort)(bits & 0xFF), null, (bits & 0x1000) != 0, frameType == 3, (bits & 0x0800) != 0));
            }
        }
        return records.Count > 0 ? new PdbFrameTable(records) : null;
    }

    private static string? StringAt(byte[] names, uint offset)
    {
        long at = 12 + (long)offset;
        if (offset == 0 || at >= names.Length) return null;
        int end = names.AsSpan((int)at).IndexOf((byte)0);
        return Encoding.ASCII.GetString(names, (int)at, end < 0 ? names.Length - (int)at : end);
    }

    private static uint Le32(ReadOnlySpan<byte> b, int at) => BinaryPrimitives.ReadUInt32LittleEndian(b[at..]);
}
