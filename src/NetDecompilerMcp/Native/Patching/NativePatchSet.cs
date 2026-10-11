using System.Buffers.Binary;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Native.Patching;

/// <summary>
/// The ordered byte patches applied to one image in memory, over a snapshot of the original file bytes. The patched
/// image is produced by overlaying every patch's replacement bytes (and its relocation entry rewrites) onto that
/// snapshot; every read path (disassembly, strings, search_bytes, read_bytes, the code index) sees the patched bytes
/// because the <see cref="PeFile"/> built from <see cref="ApplyTo"/> replaces the one the workspace holds. Not
/// thread-safe; callers serialize through the workspace write lock.
/// </summary>
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

    /// <summary>
    /// The recorded patch <paramref name="candidate"/> collides with: its bytes overlap another patch's bytes, or one's
    /// bytes overlap the other's relocation entry rewrites. Two patches may rewrite the same relocation slot (a later
    /// patch reusing a slot an earlier one neutralized); undo order keeps that consistent.
    /// </summary>
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

    /// <summary>
    /// A later patch that rewrote one of the relocation slots patch <paramref name="number"/> (1-based; the last when
    /// null) rewrote: undoing it first would leave that later patch's entry on top of a stale original.
    /// </summary>
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

    /// <summary>
    /// The original file bytes with every patch overlaid (a fresh array each call). A patch that grows the file (a stub
    /// placed in a new section) makes the result longer: its appended section data is written past the original end and
    /// its header edits admit the section. Removing that patch shrinks the result back to the original length.
    /// </summary>
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

    /// <summary>A <see cref="PeFile"/> parsed from the patched bytes, carrying the original path.</summary>
    public PeFile ApplyTo(string path) => PeFile.FromBytes(PatchedBytes(), path);
}
