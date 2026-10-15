namespace Corvus.Native.Elf;

/// <summary>
/// Hardening an ELF image shows in its own structures: PIE, NX stack, RELRO, BIND_NOW, the stack protector and FORTIFY
/// imports, and the control-flow protection its GNU property note declares (x86 IBT and shadow stack, AArch64 BTI and PAC).
/// </summary>
public static class ElfMitigations
{
    private const uint NtGnuPropertyType0 = 5;
    private const uint X86Feature1And = 0xC0000002, Aarch64Feature1And = 0xC0000000;

    /// <summary>Each mitigation with whether it is on, in report order; the CET or BTI rows only for the machines that have them.</summary>
    public static List<(string Name, bool On)> Of(ElfFile elf)
    {
        var result = new List<(string, bool)>
        {
            ("PIE", elf.Type == 3),
            ("NX stack", elf.Segments.Any(s => s.Type == 0x6474E551 && !s.Executable)),
            ("RELRO", elf.Segments.Any(s => s.Type == 0x6474E552)),
            ("BIND_NOW", elf.BindNow),
            ("stack protector", elf.Imports.Any(i => i.Name is "__stack_chk_fail" or "__stack_chk_fail_local" or "__stack_chk_guard")),
            ("FORTIFY_SOURCE", elf.Imports.Any(i => i.Name is { } n && n.StartsWith("__", StringComparison.Ordinal) && n.EndsWith("_chk", StringComparison.Ordinal) && !n.StartsWith("__stack_chk", StringComparison.Ordinal))),
        };
        switch (elf.Arch)
        {
            case NativeArch.X86 or NativeArch.X64:
                uint x86 = Feature1And(elf, X86Feature1And);
                result.Add(("CET IBT", (x86 & 1) != 0));
                result.Add(("CET shadow stack", (x86 & 2) != 0));
                break;
            case NativeArch.Arm64:
                uint arm = Feature1And(elf, Aarch64Feature1And);
                result.Add(("BTI", (arm & 1) != 0));
                result.Add(("PAC", (arm & 2) != 0));
                break;
        }
        return result;
    }

    /// <summary>The FEATURE_1_AND bits of the NT_GNU_PROPERTY_TYPE_0 note: properties of type, size, data, each padded to the word size.</summary>
    public static uint Feature1And(ElfFile elf, uint type)
    {
        int pad = elf.Is64Bit ? 8 : 4;
        foreach (var note in elf.Notes)
        {
            if (note.Name != "GNU" || note.Type != NtGnuPropertyType0) continue;
            var d = new ByteView(note.Description, elf.BigEndian);
            for (long at = 0; at + 8 <= d.Length;)
            {
                uint prType = d.U32(at), size = d.U32(at + 4);
                if (size > d.Length - at - 8) break;
                if (prType == type && size >= 4) return d.U32(at + 8);
                at += 8 + ((size + pad - 1) & ~(long)(pad - 1));
            }
        }
        return 0;
    }
}
