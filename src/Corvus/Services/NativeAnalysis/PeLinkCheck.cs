using Corvus.Native.Linking;
using Corvus.Native.Pe;
using Check = Corvus.Services.NativeImportVerifier.Check;

namespace Corvus.Services;

/// <summary>
/// verify_native_imports for a native PE image: binds each import to the
/// export of the module the loader finds, following forwarders.
/// </summary>
internal static class PeLinkCheck
{
    /// <summary>
    /// Returns one row per import, delay-load included: verified when the module
    /// exports it, contradicted when the module is found without it, unresolved
    /// when no module is found. An image with no imports returns an empty list;
    /// cancellation throws <see cref="OperationCanceledException"/>.
    /// </summary>
    public static List<Check> Check(PeFile image, string imagePath, Func<string, Corvus.Native.INativeImage?> open, CancellationToken ct)
    {
        var linker = new NativeLinker(open);
        var x86 = !image.Is64Bit;
        var rows = new List<Check>();
        foreach (var import in image.Imports)
        {
            ct.ThrowIfCancellationRequested();
            var entry = import.Name ?? $"#{import.Ordinal}";
            var link = linker.BindImport(imagePath, x86, import);
            var (status, reason) = link.Status switch
            {
                NativeLinker.Resolved => (NativeImportVerifier.Verified, link.Hops.Count > 1 ? "forwarded" : import.Name == null ? "ordinal" : "exact"),
                NativeLinker.MissingExport or NativeLinker.MissingOrdinal or NativeLinker.ForwarderBroken or NativeLinker.ForwarderTooDeep =>
                    (NativeImportVerifier.Contradicted, link.Status),
                // Off Windows a system module is unknown, not absent.
                NativeLinker.DllNotFound or NativeLinker.ApiSetUnmapped when !OperatingSystem.IsWindows() && NativeImportVerifier.IsSystemDll(import.Module) =>
                    (NativeImportVerifier.Unresolved, "system_dll_not_on_host"),
                var other => (NativeImportVerifier.Unresolved, other),
            };
            rows.Add(new Check(Method: entry, Token: "", Module: import.Module, EntryPoint: entry, CharSet: "", ExactSpelling: true, CallingConvention: "",
                Status: status, Reason: reason, ResolvedFile: link.File, Export: link.Final?.Export, Detail: link.Detail, Location: null));
        }
        return rows;
    }
}
