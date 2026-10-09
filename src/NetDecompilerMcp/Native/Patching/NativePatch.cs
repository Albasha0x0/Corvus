namespace NetDecompilerMcp.Native.Patching;

/// <summary>
/// One recorded byte patch: the bytes at <see cref="Rva"/> (file offset <see cref="FileOffset"/>) were changed from
/// <see cref="Original"/> to <see cref="Replacement"/>. Both arrays have the same length.
/// </summary>
public sealed record NativePatch(uint Rva, long FileOffset, byte[] Original, byte[] Replacement, string Description)
{
    public int Length => Replacement.Length;
    public uint EndRva => Rva + (uint)Replacement.Length;
}
