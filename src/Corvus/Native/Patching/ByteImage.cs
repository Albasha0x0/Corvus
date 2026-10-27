namespace Corvus.Native.Patching;

/// <summary>An image with replacement bytes overlaid at one RVA, to disassemble a patch before it is applied.</summary>
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
        // Serve the window even past what the inner image maps: it can hold a stub in a section not yet added.
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
