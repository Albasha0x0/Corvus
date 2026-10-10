namespace NetDecompilerMcp.Native.Patching;

/// <summary>
/// One recorded byte patch: the bytes at <see cref="Rva"/> (file offset <see cref="FileOffset"/>) were changed from
/// <see cref="Original"/> to <see cref="Replacement"/>. Both arrays have the same length. <see cref="Relocations"/> holds
/// the base-relocation entry rewrites that belong to the patch (applied and undone with it).
/// </summary>
public sealed record NativePatch(uint Rva, long FileOffset, byte[] Original, byte[] Replacement, string Description, RelocationPlan? Relocations = null)
{
    public int Length => Replacement.Length;
    public uint EndRva => Rva + (uint)Replacement.Length;
    public IReadOnlyList<RelocationEdit> RelocationEdits => Relocations?.Edits ?? [];

    /// <summary>The assembly text a patch_asm patch was assembled from (null for raw bytes); migration re-assembles it at the new address.</summary>
    public string? Assembly { get; init; }

    /// <summary>
    /// The relocation stub of a patch-site extension (null for a plain in-place patch). When set, <see cref="Rva"/>'s
    /// region is a jmp to the stub (the rest int3-padded), and the stub holds the new code and the re-encoded displaced
    /// instructions, returning to the instruction after the site. Applied and undone together with the site bytes.
    /// </summary>
    public NativeStub? Stub { get; init; }

    /// <summary>
    /// The file-growth side of a patch-site extension whose stub went into a new section rather than a reusable cave
    /// (null otherwise). When set, the stub bytes live in <see cref="SectionGrowth.AppendedData"/> at the end of the
    /// file and the header edits add the section; applied and undone with the site bytes.
    /// </summary>
    public SectionGrowth? Growth { get; init; }

    /// <summary>The file offset one past the last byte this patch writes (the appended section's end when it grows the file).</summary>
    public long OutputEnd => Growth?.OutputEnd ?? Math.Max(FileOffset + Length, Stub?.FileOffset + Stub?.Length ?? 0);
}

/// <summary>A byte rewrite inside the PE headers for a grown section: NumberOfSections, the new section header, SizeOfImage, SizeOfCode.</summary>
public readonly record struct HeaderEdit(long FileOffset, byte[] Original, byte[] Replacement)
{
    public int Length => Replacement.Length;
}

/// <summary>
/// The file-growth side of a patch-site extension placed in a new section. The new section's raw data (the stub plus
/// file-alignment zero padding) is appended at <see cref="AppendFileOffset"/> (the original end of file rounded up to
/// the file alignment); the header rewrites in <see cref="HeaderEdits"/> admit it (the section count, the new section
/// header slot, SizeOfImage and SizeOfCode). Appended bytes have no original (the file grew); the header edits record
/// the bytes they overwrite so undo and save-verify treat them like any other patched range. Removing the patch drops
/// the appended data and reverts the header, returning the file to its original length byte-for-byte.
/// </summary>
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

/// <summary>
/// A relocation stub written in slack space (a file-backed code cave) for a patch too large for its site. The site's
/// instructions were displaced into the stub (re-encoded for the stub address), which runs the new code in the chosen
/// order and jumps back to <see cref="ReturnRva"/>, the instruction after the site. <see cref="Original"/> and
/// <see cref="Replacement"/> are the cave bytes before and after, of equal length; applied/undone with the site patch.
/// </summary>
public sealed record NativeStub(
    uint Rva, long FileOffset, byte[] Original, byte[] Replacement, uint ReturnRva, string Mode, string Placement)
{
    public int Length => Replacement.Length;
    public uint EndRva => Rva + (uint)Replacement.Length;
}
