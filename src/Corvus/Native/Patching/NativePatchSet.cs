using System.Buffers.Binary;
using Corvus.Native.Pe;

namespace Corvus.Native.Patching;

/// <summary>Ordered byte patches over a snapshot of the original file; not thread-safe, callers hold the workspace write lock.</summary>
/// <remarks>Every read path sees the patched bytes because the image built from <see cref="ApplyTo"/> replaces the one
/// the workspace holds.</remarks>
public sealed class NativePatchSet
{
    private readonly byte[] _original;
    private readonly List<NativePatch> _patches = new();

    /// <summary>The unmodified file bytes the first image was built from.</summary>
    public NativePatchSet(ReadOnlySpan<byte> originalBytes) => _original = originalBytes.ToArray();

    public IReadOnlyList<NativePatch> Patches => _patches;
    public bool IsDirty => _patches.Count > 0;

    /// <summary>Incremented by every add and removal.</summary>
    public int Version { get; private set; }

    /// <summary>The unmodified file bytes (a fresh copy).</summary>
    public byte[] OriginalBytes() => (byte[])_original.Clone();

    /// <summary>Every byte range a patch writes: its site region and, for an extension, its stub region.</summary>
    private static IEnumerable<(uint Rva, uint End)> Regions(NativePatch p)
    {
        yield return (p.Rva, p.EndRva);
        if (p.Stub is { } s) yield return (s.Rva, s.EndRva);
    }

    /// <summary>The patch whose written ranges (site or stub) overlap [rva, rva+length), or null.</summary>
    public NativePatch? Overlapping(uint rva, int length)
    {
        uint end = rva + (uint)length;
        foreach (var p in _patches)
            foreach (var (s, e) in Regions(p))
                if (rva < e && s < end) return p;
        return null;
    }

    /// <summary>The patch whose bytes or relocation rewrites <paramref name="candidate"/> overlaps; shared relocation slots are allowed, and undo order keeps them consistent.</summary>
    public NativePatch? Conflicting(NativePatch candidate)
    {
        foreach (var p in _patches)
        {
            foreach (var (cs, ce) in Regions(candidate))
                foreach (var (ps, pe) in Regions(p))
                    if (cs < pe && ps < ce) return p;
            if (p.RelocationEdits.Any(e => Regions(candidate).Any(r => e.SlotRva + 2 > r.Rva && e.SlotRva < r.End))) return p;
            if (candidate.RelocationEdits.Any(e => Regions(p).Any(r => e.SlotRva + 2 > r.Rva && e.SlotRva < r.End))) return p;
        }
        return null;
    }

    public void Add(NativePatch patch)
    {
        _patches.Add(patch);
        Version++;
    }

    /// <summary>A later patch sharing a relocation slot with patch <paramref name="number"/> (1-based, last when null), which blocks its undo.</summary>
    public (int Number, NativePatch Patch)? LaterSlotUser(int? number)
    {
        int index = number is { } n ? n - 1 : _patches.Count - 1;
        if (index < 0 || index >= _patches.Count) return null;
        var slots = _patches[index].RelocationEdits.Select(e => e.SlotRva).ToHashSet();
        if (slots.Count == 0) return null;
        for (int i = index + 1; i < _patches.Count; i++)
            if (_patches[i].RelocationEdits.Any(e => slots.Contains(e.SlotRva))) return (i + 1, _patches[i]);
        return null;
    }

    /// <summary>Removes the patch at 1-based <paramref name="number"/> (the last when null); returns it, or null.</summary>
    public NativePatch? Remove(int? number)
    {
        if (_patches.Count == 0) return null;
        int index = number is { } n ? n - 1 : _patches.Count - 1;
        if (index < 0 || index >= _patches.Count) return null;
        var patch = _patches[index];
        _patches.RemoveAt(index);
        Version++;
        return patch;
    }

    /// <summary>A new array of the original bytes with every patch overlaid, longer when a patch added a section.</summary>
    public byte[] PatchedBytes()
    {
        long target = _original.Length;
        foreach (var p in _patches) target = Math.Max(target, p.OutputEnd);
        var bytes = new byte[target];
        _original.CopyTo(bytes, 0);
        foreach (var p in _patches)
        {
            p.Replacement.CopyTo(bytes.AsSpan((int)p.FileOffset));
            // A grown patch writes its stub inside the appended section data; a cave stub overlays existing file bytes.
            if (p.Stub is { } s && p.Growth is null) s.Replacement.CopyTo(bytes.AsSpan((int)s.FileOffset));
            foreach (var e in p.RelocationEdits)
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan((int)e.FileOffset), e.Replacement);
            if (p.Growth is { } g)
            {
                foreach (var h in g.HeaderEdits) h.Replacement.CopyTo(bytes.AsSpan((int)h.FileOffset));
                g.AppendedData.CopyTo(bytes.AsSpan((int)g.AppendFileOffset));
            }
        }
        return bytes;
    }

    /// <summary>The image parsed from the patched bytes in the format of <paramref name="like"/>, carrying the original path.</summary>
    public INativeImage ApplyTo(INativeImage like, string path) => Open(PatchedBytes(), like, path);

    /// <summary>The image parsed from the original bytes, in the format of <paramref name="like"/>.</summary>
    public INativeImage OriginalImage(INativeImage like, string path) => Open(_original, like, path);

    /// <summary>Parses <paramref name="bytes"/> (an image's own bytes: the slice of a universal Mach-O) as <paramref name="like"/> is.</summary>
    public static INativeImage Open(byte[] bytes, INativeImage like, string path) => like switch
    {
        Elf.ElfFile => Elf.ElfFile.FromBytes(bytes, path),
        MachO.MachOFile { Slice: { } slice } macho => MachO.MachOFile.FromSlice(bytes, path, macho.Slices, slice),
        MachO.MachOFile => MachO.MachOFile.FromBytes(bytes, path),
        _ => PeFile.FromBytes(bytes, path),
    };

    /// <summary>The bytes of a file in its own format: a PE, ELF or Mach-O image's own bytes (a universal Mach-O's slice).</summary>
    public static ReadOnlySpan<byte> FileBytesOf(INativeImage image) => image switch
    {
        PeFile pe => pe.FileBytes.Span,
        Elf.ElfFile elf => elf.FileBytes.Span,
        MachO.MachOFile macho => macho.FileBytes.Span,
        _ => throw new Core.ToolError(Core.ErrorCode.Unsupported, $"Byte patching is not supported for {System.IO.Path.GetFileName(image.Path)}."),
    };
}
