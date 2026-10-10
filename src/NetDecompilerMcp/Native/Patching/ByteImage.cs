namespace NetDecompilerMcp.Native.Patching;

/// <summary>
/// A read-only view of an image with a window of replacement bytes overlaid at one RVA, used to disassemble a
/// candidate patch before it is applied. Everything but <see cref="Read"/> delegates to the underlying image, so
/// branch and RIP-relative targets are resolved against the real layout and image base.
/// </summary>
internal sealed class ByteImage(INativeImage inner, uint windowRva, byte[] window) : INativeImage
{
    public string Path => inner.Path;
    public string Sha256 => inner.Sha256;
    public NativeArch Arch => inner.Arch;
    public bool Is64Bit => inner.Is64Bit;
    public bool IsDll => inner.IsDll;
    public ulong ImageBase => inner.ImageBase;
    public uint EntryPointRva => inner.EntryPointRva;
    public uint SizeOfImage => inner.SizeOfImage;
    public IReadOnlyList<NativeSection> Sections => inner.Sections;
    public IReadOnlyList<NativeImport> Imports => inner.Imports;
    public IReadOnlyList<NativeExport> Exports => inner.Exports;
    public IReadOnlyList<RuntimeFunction> RuntimeFunctions => inner.RuntimeFunctions;
    public IReadOnlyList<uint> RelocationRvas => inner.RelocationRvas;
    public IReadOnlyList<uint> TlsCallbackRvas => inner.TlsCallbackRvas;
    public IReadOnlyList<ParseIssue> Issues => inner.Issues;
    public ImageFormat Format => inner.Format;
    public IReadOnlyList<ImageSymbol> Symbols => inner.Symbols;
    public IReadOnlyList<DeclaredFunction> DeclaredFunctions => inner.DeclaredFunctions;
    public IReadOnlyList<string> Dependencies => inner.Dependencies;
    public string? BuildId => inner.BuildId;
    public IReadOnlyList<EncryptedRange> EncryptedRanges => inner.EncryptedRanges;

    public int Read(uint rva, Span<byte> destination)
    {
        int n = inner.Read(rva, destination);
        // Overlay the window where it intersects the request, and serve it even past what the inner image maps (the
        // window can describe a stub in a new section that is not yet part of the image).
        int filled = n;
        for (int i = 0; i < destination.Length; i++)
        {
            uint cur = rva + (uint)i;
            if (cur >= windowRva && cur - windowRva < window.Length)
            {
                destination[i] = window[cur - windowRva];
                if (i + 1 > filled) filled = i + 1;
            }
        }
        return filled;
    }

    public bool TryRvaToFileOffset(uint rva, out long fileOffset) => inner.TryRvaToFileOffset(rva, out fileOffset);
    public bool TryFileOffsetToRva(long fileOffset, out uint rva) => inner.TryFileOffsetToRva(fileOffset, out rva);
    public NativeSection? SectionAt(uint rva) => inner.SectionAt(rva);
}
