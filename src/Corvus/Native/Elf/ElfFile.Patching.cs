namespace Corvus.Native.Elf;

public sealed partial class ElfFile
{
    /// <summary>e_phoff: the program header table's file offset.</summary>
    public long ProgramHeaderOffset => (long)Math.Min(Is64Bit ? view.U64(32) : view.U32(28), long.MaxValue / 2);

    /// <summary>e_phentsize (the standard size when the field is zero).</summary>
    public int ProgramHeaderEntrySize => view.U16(Is64Bit ? 54 : 42) is var s and > 0 ? s : Is64Bit ? 56 : 32;

    /// <summary>e_phnum as stored; 0xFFFF means PN_XNUM (extended numbering), where the field cannot simply be incremented.</summary>
    public int ProgramHeaderCountField => view.U16(Is64Bit ? 56 : 44);

    /// <summary>File offset of the e_phnum u16, for a header edit.</summary>
    public int ProgramHeaderCountFieldOffset => Is64Bit ? 56 : 44;

    /// <summary>e_shoff: the section header table's file offset (0 when the file has no section headers).</summary>
    public long SectionHeaderOffset => (long)Math.Min(Is64Bit ? view.U64(40) : view.U32(32), long.MaxValue / 2);
}
