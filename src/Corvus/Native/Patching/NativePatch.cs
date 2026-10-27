namespace Corvus.Native.Patching;

/// <summary>One byte patch at <see cref="Rva"/>, with equal-length original and replacement and its relocation rewrites, applied and undone with it.</summary>
public sealed record NativePatch(uint Rva, long FileOffset, byte[] Original, byte[] Replacement, string Description, RelocationPlan? Relocations = null)
{
    public int Length => Replacement.Length;
    public uint EndRva => Rva + (uint)Replacement.Length;
    public IReadOnlyList<RelocationEdit> RelocationEdits => Relocations?.Edits ?? [];

    /// <summary>The assembly text a patch_asm patch was assembled from (null for raw bytes); migration re-assembles it at the new address.</summary>
    public string? Assembly { get; init; }

    /// <summary>The stub the site jumps to, applied and undone with the site bytes; null for an in-place patch.</summary>
    public NativeStub? Stub { get; init; }

    /// <summary>The new section holding the stub, applied and undone with the site bytes; null unless the stub grew the file.</summary>
    public SectionGrowth? Growth { get; init; }

    /// <summary>The file offset one past the last byte this patch writes (the appended section's end when it grows the file).</summary>
    public long OutputEnd => Growth?.OutputEnd ?? Math.Max(FileOffset + Length, Stub?.FileOffset + Stub?.Length ?? 0);
}

/// <summary>A byte rewrite inside the PE headers for a grown section: NumberOfSections, the new section header, SizeOfImage, SizeOfCode.</summary>
public readonly record struct HeaderEdit(long FileOffset, byte[] Original, byte[] Replacement)
{
    public int Length => Replacement.Length;
}

/// <summary>A new section appended at <see cref="AppendFileOffset"/> with its header edits; undo restores the original file exactly.</summary>
public sealed record SectionGrowth(
    string SectionName,
    uint SectionRva,
    uint SectionVirtualSize,
    long AppendFileOffset,
    byte[] AppendedData,
    IReadOnlyList<HeaderEdit> HeaderEdits)
{
    /// <summary>The file offset one past the appended data: the grown file's length.</summary>
    public long OutputEnd => AppendFileOffset + AppendedData.Length;
}

/// <summary>A stub in a code cave that runs the new and displaced code, then jumps to <see cref="ReturnRva"/>; its equal-length cave bytes are applied and undone with the site patch.</summary>
public sealed record NativeStub(
    uint Rva, long FileOffset, byte[] Original, byte[] Replacement, uint ReturnRva, string Mode, string Placement)
{
    public int Length => Replacement.Length;
    public uint EndRva => Rva + (uint)Replacement.Length;

    /// <summary>The new code the stub runs, as given (raw bytes, or assembled at the site for patch_asm); a migration re-creates the stub from it.</summary>
    public byte[]? NewCode { get; init; }

    /// <summary>The patch_asm text of the new code (null for raw bytes); re-assembled at the stub address when the stub is re-created.</summary>
    public string? NewAssembly { get; init; }
}
