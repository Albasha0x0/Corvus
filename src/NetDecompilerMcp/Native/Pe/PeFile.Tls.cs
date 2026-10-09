namespace NetDecompilerMcp.Native.Pe;

/// <summary>IMAGE_TLS_DIRECTORY32 / 64; addresses are VAs as stored.</summary>
public sealed record PeTlsDirectory(
    ulong StartAddressOfRawData,
    ulong EndAddressOfRawData,
    ulong AddressOfIndex,
    ulong AddressOfCallBacks,
    uint SizeOfZeroFill,
    uint Characteristics);

public sealed partial class PeFile
{
    private sealed record TlsInfo(PeTlsDirectory? Directory, IReadOnlyList<uint> CallbackRvas)
    {
        public static readonly TlsInfo Empty = new(null, []);
    }

    /// <summary>
    /// The TLS directory and its callback array: VAs up to a zero entry, converted to RVAs against the preferred image
    /// base. In a relocatable image a callback slot without a base relocation keeps its on-disk value after rebasing,
    /// so it no longer points into the image; that is recorded.
    /// </summary>
    private TlsInfo ParseTls(IssueLog log)
    {
        var dir = Directory(PeDirectory.Tls);
        if (dir.Rva == 0) return TlsInfo.Empty;
        int size = Is64Bit ? 40 : 24;
        var d = ReadBlock(dir.Rva, size);
        if (d == null)
        {
            log.Add($"TLS directory at RVA 0x{dir.Rva:X} is outside the mapped image");
            return TlsInfo.Empty;
        }
        var tlsDir = Is64Bit
            ? new PeTlsDirectory(Le64(d, 0), Le64(d, 8), Le64(d, 16), Le64(d, 24), Le32(d, 32), Le32(d, 36))
            : new PeTlsDirectory(Le32(d, 0), Le32(d, 4), Le32(d, 8), Le32(d, 12), Le32(d, 16), Le32(d, 20));
        var callbacks = new List<uint>();
        if (tlsDir.AddressOfCallBacks == 0) return new TlsInfo(tlsDir, callbacks);
        if (!TryVaToRva(tlsDir.AddressOfCallBacks, out uint array))
        {
            log.Add($"TLS callback array VA 0x{tlsDir.AddressOfCallBacks:X} is below the image base");
            return new TlsInfo(tlsDir, callbacks);
        }
        var relocated = relocations.Value.PointerRvas;
        bool relocatable = relocated.Count > 0;
        bool slotReported = false;
        for (int i = 0; ; i++)
        {
            if (i >= PeLimits.MaxTlsCallbacks)
            {
                log.Add($"more than {PeLimits.MaxTlsCallbacks} TLS callbacks; the rest are not read");
                break;
            }
            long slot = array + (long)i * PointerSize;
            if (!TryPointer(slot, out ulong va))
            {
                log.Add($"TLS callback array at RVA 0x{array:X} runs out of the mapped image without a terminator", RvaToOffsetOrNull(array));
                break;
            }
            if (va == 0) break;
            if (relocatable && !slotReported && slot <= uint.MaxValue && !Contains(relocated, (uint)slot))
            {
                slotReported = true;
                log.Add($"TLS callback slot at RVA 0x{slot:X} has no base relocation; it does not follow the image when rebased", RvaToOffsetOrNull(slot));
            }
            if (!TryVaToRva(va, out uint rva) || Locate(rva) < 0)
            {
                log.Add($"TLS callback VA 0x{va:X} is outside the image", RvaToOffsetOrNull(slot));
                continue;
            }
            if (SectionAt(rva) is { IsExecutable: false } section)
                log.Add($"TLS callback at RVA 0x{rva:X} is in non-executable section '{section.Name}'", RvaToOffsetOrNull(slot));
            callbacks.Add(rva);
        }
        return new TlsInfo(tlsDir, callbacks);
    }

    private static bool Contains(IReadOnlyList<uint> sorted, uint value)
    {
        int lo = 0, hi = sorted.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (sorted[mid] < value) lo = mid + 1;
            else if (sorted[mid] > value) hi = mid - 1;
            else return true;
        }
        return false;
    }
}
