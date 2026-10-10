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
}
