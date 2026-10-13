namespace Corvus.Native.Code;

/// <summary>How much of the code analysis an instruction set supports.</summary>
public enum CodeSupport
{
    /// <summary>Disassembly, function discovery by descent, basic blocks, switches and cross-references.</summary>
    Full,
    /// <summary>Only the function starts the image declares (.pdata, exports, entry point, TLS callbacks); no decoding.</summary>
    DeclaredFunctionsOnly,
}

/// <summary>Instruction set capabilities of the code analysis.</summary>
public static class InstructionSets
{
    /// <summary>What the analysis can do for <paramref name="arch"/>, and why not more.</summary>
    public static (CodeSupport Support, string? Reason) For(NativeArch arch) => arch switch
    {
        NativeArch.X86 or NativeArch.X64 or NativeArch.Arm64 or NativeArch.Arm => (CodeSupport.Full, null),
        _ => (CodeSupport.DeclaredFunctionsOnly, $"instruction set {arch} is not decoded by the built-in analysis"),
    };

    /// <summary><see cref="For(NativeArch)"/> with the instruction set as the file names it (EM_S390, not Other).</summary>
    public static (CodeSupport Support, string? Reason) For(INativeImage image) => For(image.Arch) is { Support: CodeSupport.DeclaredFunctionsOnly } r
        ? (r.Support, $"instruction set {image.ArchName()} is not decoded by the built-in analysis") : For(image.Arch);
}
