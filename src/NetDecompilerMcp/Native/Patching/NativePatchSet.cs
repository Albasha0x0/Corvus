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

    /// <summary>The unmodified file bytes (a fresh copy).</summary>
    public byte[] OriginalBytes() => (byte[])_original.Clone();

    /// <summary>The patch whose replaced range overlaps [rva, rva+length), or null.</summary>
    public NativePatch? Overlapping(uint rva, int length)
    {
        uint end = rva + (uint)length;
        foreach (var p in _patches)
            if (rva < p.EndRva && p.Rva < end) return p;
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
            if (candidate.Rva < p.EndRva && p.Rva < candidate.EndRva) return p;
            if (p.RelocationEdits.Any(e => e.SlotRva + 2 > candidate.Rva && e.SlotRva < candidate.EndRva)) return p;
            if (candidate.RelocationEdits.Any(e => e.SlotRva + 2 > p.Rva && e.SlotRva < p.EndRva)) return p;
        }
        return null;
    }

    public void Add(NativePatch patch) => _patches.Add(patch);

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
        return patch;
    }

    /// <summary>The original file bytes with every patch overlaid (a fresh array each call).</summary>
    public byte[] PatchedBytes()
    {
        var bytes = (byte[])_original.Clone();
        foreach (var p in _patches)
        {
            p.Replacement.CopyTo(bytes.AsSpan((int)p.FileOffset));
            foreach (var e in p.RelocationEdits)
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan((int)e.FileOffset), e.Replacement);
        }
        return bytes;
    }

    /// <summary>A <see cref="PeFile"/> parsed from the patched bytes, carrying the original path.</summary>
    public PeFile ApplyTo(string path) => PeFile.FromBytes(PatchedBytes(), path);
}
