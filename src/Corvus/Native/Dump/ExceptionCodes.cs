namespace Corvus.Native.Dump;

/// <summary>Names and descriptions of exception codes (NTSTATUS and well-known software exceptions).</summary>
public static class ExceptionCodes
{
    public const uint AccessViolation = 0xC0000005;
    public const uint InPageError = 0xC0000006;
    public const uint StackBufferOverrun = 0xC0000409;
    public const uint CxxException = 0xE06D7363;
    public const uint ClrException = 0xE0434352;
    public const uint CxxMagic1 = 0x19930520, CxxMagic2 = 0x19930521, CxxMagic3 = 0x19930522, CxxPure = 0x01994000;

    private static readonly Dictionary<uint, string> Names = new()
    {
        [0x80000001] = "STATUS_GUARD_PAGE_VIOLATION",
        [0x80000002] = "EXCEPTION_DATATYPE_MISALIGNMENT",
        [0x80000003] = "EXCEPTION_BREAKPOINT",
        [0x80000004] = "EXCEPTION_SINGLE_STEP",
        [0x80000026] = "STATUS_LONGJUMP",
        [0x80000029] = "STATUS_UNWIND_CONSOLIDATE",
        [0x4000001F] = "STATUS_WX86_BREAKPOINT",
        [0x40010005] = "DBG_CONTROL_C",
        [0x40010008] = "DBG_CONTROL_BREAK",
        [0x406D1388] = "MS_VC_EXCEPTION (thread name)",
        [AccessViolation] = "EXCEPTION_ACCESS_VIOLATION",
        [InPageError] = "EXCEPTION_IN_PAGE_ERROR",
        [0xC0000008] = "EXCEPTION_INVALID_HANDLE",
        [0xC000000D] = "STATUS_INVALID_PARAMETER",
        [0xC0000017] = "STATUS_NO_MEMORY",
        [0xC000001D] = "EXCEPTION_ILLEGAL_INSTRUCTION",
        [0xC0000025] = "EXCEPTION_NONCONTINUABLE_EXCEPTION",
        [0xC0000026] = "EXCEPTION_INVALID_DISPOSITION",
        [0xC000008C] = "EXCEPTION_ARRAY_BOUNDS_EXCEEDED",
        [0xC000008D] = "EXCEPTION_FLT_DENORMAL_OPERAND",
        [0xC000008E] = "EXCEPTION_FLT_DIVIDE_BY_ZERO",
        [0xC000008F] = "EXCEPTION_FLT_INEXACT_RESULT",
        [0xC0000090] = "EXCEPTION_FLT_INVALID_OPERATION",
        [0xC0000091] = "EXCEPTION_FLT_OVERFLOW",
        [0xC0000092] = "EXCEPTION_FLT_STACK_CHECK",
        [0xC0000093] = "EXCEPTION_FLT_UNDERFLOW",
        [0xC0000094] = "EXCEPTION_INT_DIVIDE_BY_ZERO",
        [0xC0000095] = "EXCEPTION_INT_OVERFLOW",
        [0xC0000096] = "EXCEPTION_PRIV_INSTRUCTION",
        [0xC00000FD] = "EXCEPTION_STACK_OVERFLOW",
        [0xC0000135] = "STATUS_DLL_NOT_FOUND",
        [0xC0000139] = "STATUS_ENTRYPOINT_NOT_FOUND",
        [0xC0000142] = "STATUS_DLL_INIT_FAILED",
        [0xC0000194] = "STATUS_POSSIBLE_DEADLOCK",
        [0xC00002B4] = "STATUS_FLOAT_MULTIPLE_FAULTS",
        [0xC00002B5] = "STATUS_FLOAT_MULTIPLE_TRAPS",
        [0xC0000374] = "STATUS_HEAP_CORRUPTION",
        [StackBufferOverrun] = "STATUS_STACK_BUFFER_OVERRUN (fail fast)",
        [0xC000041D] = "STATUS_FATAL_USER_CALLBACK_EXCEPTION",
        [0xC0000420] = "STATUS_ASSERTION_FAILURE",
        [0xC0000602] = "STATUS_FAIL_FAST_EXCEPTION",
        [0xC06D007E] = "delay-load module not found (VcppException ERROR_MOD_NOT_FOUND)",
        [0xC06D007F] = "delay-load procedure not found (VcppException ERROR_PROC_NOT_FOUND)",
        [CxxException] = "C++ exception (MSVC throw)",
        [ClrException] = "CLR exception (.NET)",
        [0xE0434F4D] = "CLR exception (.NET Framework 1.x-2.0)",
        [0xE0564552] = "CLR fatal error",
    };

    private static readonly string[] FastFail =
    [
        "LEGACY_GS_VIOLATION", "VTGUARD_CHECK_FAILURE", "STACK_COOKIE_CHECK_FAILURE", "CORRUPT_LIST_ENTRY", "INCORRECT_STACK", "INVALID_ARG",
        "GS_COOKIE_INIT", "FATAL_APP_EXIT", "RANGE_CHECK_FAILURE", "UNSAFE_REGISTRY_ACCESS", "GUARD_ICALL_CHECK_FAILURE", "GUARD_WRITE_CHECK_FAILURE",
        "INVALID_FIBER_SWITCH", "INVALID_SET_OF_CONTEXT", "INVALID_REFERENCE_COUNT", "", "", "", "INVALID_JUMP_BUFFER", "MRDATA_MODIFIED",
        "CERTIFICATION_FAILURE", "INVALID_EXCEPTION_CHAIN", "CRYPTO_LIBRARY", "INVALID_CALL_IN_DLL_CALLOUT", "INVALID_IMAGE_BASE",
        "DLOAD_PROTECTION_FAILURE", "UNSAFE_EXTENSION_CALL", "DEPRECATED_SERVICE_INVOKED", "INVALID_BUFFER_ACCESS", "INVALID_BALANCED_TREE",
        "INVALID_NEXT_THREAD", "GUARD_ICALL_CHECK_SUPPRESSED", "APCS_DISABLED", "INVALID_IDLE_STATE", "MRDATA_PROTECTION_FAILURE",
        "UNEXPECTED_HEAP_EXCEPTION", "INVALID_LOCK_STATE", "GUARD_JUMPTABLE", "INVALID_LONGJUMP_TARGET", "INVALID_DISPATCH_CONTEXT",
        "INVALID_THREAD", "INVALID_SYSCALL_NUMBER", "INVALID_FILE_OPERATION", "LPAC_ACCESS_DENIED", "GUARD_SS_FAILURE",
        "LOADER_CONTINUITY_FAILURE", "GUARD_EXPORT_SUPPRESSION_FAILURE", "INVALID_CONTROL_STACK", "SET_CONTEXT_DENIED", "INVALID_IAT",
        "HEAP_METADATA_CORRUPTION",
    ];

    /// <summary>The symbolic name, or null when the code is not known.</summary>
    public static string? Name(uint code) => Names.GetValueOrDefault(code);

    /// <summary>A one-line description using the exception parameters (access kind and address, fail-fast code...).</summary>
    public static string Describe(uint code, IReadOnlyList<ulong> p, bool is64)
    {
        string Hex(ulong v) => is64 ? $"0x{v:X16}" : $"0x{v & 0xFFFFFFFF:X8}";
        switch (code)
        {
            case AccessViolation when p.Count >= 2:
            case InPageError when p.Count >= 2:
            {
                string kind = p[0] switch { 0 => "reading", 1 => "writing", 8 => "executing (DEP)", _ => $"access kind {p[0]}" };
                string what = code == AccessViolation ? "access violation" : "in-page error";
                string extra = code == InPageError && p.Count >= 3 ? $" (status 0x{p[2]:X8})" : "";
                string near = p[1] < 0x10000 ? " (a null or near-null pointer)" : "";
                return $"{what} {kind} {Hex(p[1])}{near}{extra}";
            }
            case StackBufferOverrun when p.Count >= 1:
                return $"fail fast: {FastFailName(p[0])}";
            case CxxException when p.Count >= 3:
                return $"C++ exception, object at {Hex(p[1])}, ThrowInfo at {Hex(p[2])}" + (p.Count >= 4 && p[3] != 0 ? $", thrown from the image at {Hex(p[3])}" : "");
            case ClrException:
                return "CLR exception: the managed exception object needs the runtime's DAC (managed.dac says why it was not decoded)";
            default:
                return Name(code) ?? $"exception 0x{code:X8}";
        }
    }

    public static string FastFailName(ulong code) =>
        code < (ulong)FastFail.Length && FastFail[code].Length > 0 ? $"FAST_FAIL_{FastFail[code]} ({code})" : $"code {code}";
}
