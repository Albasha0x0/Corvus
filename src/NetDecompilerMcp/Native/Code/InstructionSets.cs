namespace NetDecompilerMcp.Native.Code;

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
        NativeArch.X86 or NativeArch.X64 or NativeArch.Arm64 => (CodeSupport.Full, null),
        NativeArch.Arm => (CodeSupport.DeclaredFunctionsOnly, "ARM (Thumb-2) decoding is not supported"),
        _ => (CodeSupport.DeclaredFunctionsOnly, $"instruction set {arch} is not supported"),
    };
}
