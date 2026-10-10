using dnlib.DotNet;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services;

/// <summary>Mixed-mode (C++/CLI) images: managed methods with native bodies.</summary>
public sealed partial class NativeLinkService
{
    /// <summary>The native body of a method in a mixed-mode image, or null.</summary>
    private ManagedLink? NativeBody(LoadedAssembly asm, MethodDef method) => null;

    /// <summary>Lines for native code calling a managed method, in a callers tree.</summary>
    public string NativeCallers(MethodDef method, int levels, int indent, int maxNodes, CancellationToken ct) => "";

    /// <summary>Native call sites of a managed method (C++/CLI thunks), as rows.</summary>
    public List<string> NativeCallSitesOf(MethodDef method, CancellationToken ct) => [];
}
