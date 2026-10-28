using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using Corvus.Core;

namespace Corvus.Native.Providers.Worker.Yara;

/// <summary>The YARA-X 1.22.1 C API, loaded only in a <c>corvus worker</c> as its native faults are real (VirusTotal/yara-x#663, #720).</summary>
internal static class YaraX
{
    /// <summary>Full path of a libyara_x_capi build to load instead of the one shipped under runtimes/&lt;rid&gt;/native.</summary>
    public const string LibraryVariable = "CORVUS_YARA_LIBRARY";

    public const string Version = "1.22.1";

    private const string Library = "yara_x_capi";

    private static readonly Lock Gate = new();
    private static bool _resolverSet;

    /// <summary>The library file name on this system.</summary>
    public static string FileName => OperatingSystem.IsWindows() ? "yara_x_capi.dll" : OperatingSystem.IsMacOS() ? "libyara_x_capi.dylib" : "libyara_x_capi.so";

    /// <summary>Loads the library once from <see cref="LibraryVariable"/>, runtimes/&lt;rid&gt;/native or the program folder; else provider_unavailable.</summary>
    public static void Load()
    {
        lock (Gate)
        {
            if (!_resolverSet)
            {
                // A framework-dependent tool's deps.json omits the per-RID files, so the runtime would not find them.
                NativeLibrary.SetDllImportResolver(typeof(YaraX).Assembly, Resolve);
                _resolverSet = true;
            }
        }
        try { _ = yrx_last_error(); }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            throw new ToolError(ErrorCode.ProviderUnavailable,
                $"YARA-X {Version} is not available for {RuntimeInformation.RuntimeIdentifier}: {e.Message}",
                $"set {LibraryVariable} to a libyara_x_capi {Version} build for this platform");
        }
    }

    private static IntPtr Resolve(string name, Assembly assembly, DllImportSearchPath? path)
    {
        if (name != Library) return IntPtr.Zero;
        foreach (var candidate in Candidates())
            if (File.Exists(candidate) && NativeLibrary.TryLoad(candidate, out var handle)) return handle;
        return IntPtr.Zero;
    }

    private static IEnumerable<string> Candidates()
    {
        if (Environment.GetEnvironmentVariable(LibraryVariable) is { Length: > 0 } configured) yield return configured;
        var dir = AppContext.BaseDirectory;
        yield return Path.Combine(dir, "runtimes", RuntimeInformation.RuntimeIdentifier, "native", FileName);
        yield return Path.Combine(dir, FileName);
    }

    /// <summary>The UTF-8 text at <paramref name="data"/> of <paramref name="length"/> bytes.</summary>
    public static string Text(IntPtr data, nuint length) => data == IntPtr.Zero ? "" : Marshal.PtrToStringUTF8(data, checked((int)length));

    /// <summary>Throws a failed error naming <paramref name="what"/> and the library's message unless <paramref name="result"/> is success.</summary>
    public static void Check(int result, string what)
    {
        if (result != Success) throw new ToolError(ErrorCode.Failed, $"YARA-X could not {what}: {LastError()}");
    }

    /// <summary>The library's message for the last failed call on this thread.</summary>
    public static string LastError() => Marshal.PtrToStringUTF8(yrx_last_error()) ?? "unknown error";

    public const int Success = 0;
    public const int ScanTimeout = 4;
    public const uint RelaxedReSyntax = 2;

    [StructLayout(LayoutKind.Sequential)]
    public struct Buffer
    {
        public IntPtr Data;
        public nuint Length;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Match
    {
        public nuint Offset;
        public nuint Length;
        public short XorKey;
    }

    public enum MetadataType { I64, F64, Boolean, String, Bytes }

    /// <summary>YRX_METADATA: identifier, type, then a union whose largest member is two pointers.</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct Metadata
    {
        public IntPtr Identifier;
        public MetadataType Type;
        public IntPtr Value0;
        public IntPtr Value1;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate void RuleCallback(IntPtr rule, IntPtr user);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate void PatternCallback(IntPtr pattern, IntPtr user);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate void MatchCallback(in Match match, IntPtr user);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate void TagCallback(IntPtr tag, IntPtr user);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate void MetadataCallback(in Metadata metadata, IntPtr user);

    [DllImport(Library)] public static extern IntPtr yrx_last_error();
    [DllImport(Library)] public static extern void yrx_buffer_destroy(IntPtr buffer);
    [DllImport(Library)] public static extern int yrx_compiler_create(uint flags, out IntPtr compiler);
    [DllImport(Library)] public static extern void yrx_compiler_destroy(IntPtr compiler);
    [DllImport(Library)] public static extern int yrx_compiler_add_source_with_origin(IntPtr compiler, byte[] source, byte[] origin);
    [DllImport(Library)] public static extern int yrx_compiler_ban_module(IntPtr compiler, byte[] module, byte[] title, byte[] message);
    [DllImport(Library)] public static extern int yrx_compiler_errors_json(IntPtr compiler, out IntPtr buffer);
    [DllImport(Library)] public static extern IntPtr yrx_compiler_build(IntPtr compiler);
    [DllImport(Library)] public static extern int yrx_rules_count(IntPtr rules);
    [DllImport(Library)] public static extern void yrx_rules_destroy(IntPtr rules);
    [DllImport(Library)] public static extern int yrx_scanner_create(IntPtr rules, out IntPtr scanner);
    [DllImport(Library)] public static extern void yrx_scanner_destroy(IntPtr scanner);
    [DllImport(Library)] public static extern int yrx_scanner_set_timeout(IntPtr scanner, ulong seconds);
    [DllImport(Library)] public static extern int yrx_scanner_max_matches_per_pattern(IntPtr scanner, nuint n);
    [DllImport(Library)] public static extern int yrx_scanner_on_matching_rule(IntPtr scanner, RuleCallback callback, IntPtr user);
    [DllImport(Library)] public static extern int yrx_scanner_scan(IntPtr scanner, byte[] data, nuint length);
    [DllImport(Library)] public static extern int yrx_scanner_scan_file(IntPtr scanner, byte[] path);
    [DllImport(Library)] public static extern int yrx_scanner_scan_block(IntPtr scanner, nuint @base, byte[] data, nuint length);
    [DllImport(Library)] public static extern int yrx_scanner_finish(IntPtr scanner);
    [DllImport(Library)] public static extern int yrx_rule_identifier(IntPtr rule, out IntPtr ident, out nuint length);
    [DllImport(Library)] public static extern int yrx_rule_namespace(IntPtr rule, out IntPtr ns, out nuint length);
    [DllImport(Library)] public static extern int yrx_rule_iter_tags(IntPtr rule, TagCallback callback, IntPtr user);
    [DllImport(Library)] public static extern int yrx_rule_iter_metadata(IntPtr rule, MetadataCallback callback, IntPtr user);
    [DllImport(Library)] public static extern int yrx_rule_iter_patterns(IntPtr rule, PatternCallback callback, IntPtr user);
    [DllImport(Library)] public static extern int yrx_pattern_identifier(IntPtr pattern, out IntPtr ident, out nuint length);
    [DllImport(Library)] public static extern int yrx_pattern_iter_matches(IntPtr pattern, MatchCallback callback, IntPtr user);

    /// <summary>A NUL-terminated UTF-8 copy of <paramref name="text"/> for the API's char* arguments.</summary>
    public static byte[] Utf8(string text) => Encoding.UTF8.GetBytes(text + "\0");
}
