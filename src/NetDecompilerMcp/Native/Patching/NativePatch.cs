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
