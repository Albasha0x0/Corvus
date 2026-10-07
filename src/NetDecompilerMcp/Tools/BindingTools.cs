using System.ComponentModel;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class BindingTools(AssemblyWorkspace workspace, CppBindingGenerator generator, OutputPager pager)
{
    [McpServerTool(Name = "generate_cpp_binding", Title = "Generate C++ binding", ReadOnly = true, OpenWorld = false)]
    [Description("Generate C++ binding code for a managed type in a Mono game or app: a struct that resolves the class, field offsets, " +
                 "static field data and methods once, with typed field accessors, property getters and method invoke wrappers. " +
                 "style=mono (default): a self-contained header on the standard Mono embedding API (mono_class_from_name, " +
                 "mono_field_get_offset, mono_runtime_invoke, ...), loaded from the runtime's exports; works with any injector or host. " +
                 "style=hostapi: for plugin frameworks whose host passes a HostApi table (FindClass / FieldOffset / GetMethod / Invoke). " +
                 "The assembly, namespace and class strings come from the real metadata, so they are exactly what mono_class_from_name expects.")]
    public Task<string> GenerateCppBinding(
        [Description("Type to bind. " + SymbolDescription)] string type,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Only these members (comma-separated field/property/method names). Default: all non-compiler-generated members.")] string? members = null,
        [Description("Also bind instance property getters inherited from base classes.")] bool includeInherited = false,
        [Description("Output style: mono (standard Mono embedding API, default) or hostapi (host-provided HostApi plugin ABI).")] string style = "mono",
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, type, SymbolKind.Type);
        var only = members?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        return pager.Page(generator.Generate(sym.Assembly, (TypeDef)sym.Member, only, includeInherited, style), offset, maxChars);
    }, cancellationToken);
}
