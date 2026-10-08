using System.ComponentModel;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class BindingTools(AssemblyWorkspace workspace, CppBindingGenerator generator, OutputPager pager, ServerOptions options)
{
    [McpServerTool(Name = "generate_cpp_binding", Title = "Generate C++ binding", ReadOnly = true, OpenWorld = false)]
    [Description("Generate C++ binding code for a managed type in a Mono-hosted application: a struct that resolves the class, field offsets, " +
                 "static field data and methods once, with typed field accessors, property getters and method invoke wrappers. " +
                 "style=mono: a self-contained header on the standard Mono embedding API (mono_class_from_name, " +
                 "mono_field_get_offset, mono_runtime_invoke, ...), loaded from the runtime's exports; works with any injector or host. " +
                 "style=hostapi: for projects whose host passes a function table (a struct with FindClass, GetMethod, FieldOffset, " +
                 "StaticFieldOffset, GetStaticFieldData and Invoke). Without style, projectDir is scanned for such a table: found -> hostapi " +
                 "with #include paths relative to headerPath; otherwise the server's --binding-style, else mono. The first line of the output " +
                 "says which style was chosen and why. " +
                 "The assembly, namespace and class strings come from the real metadata, so they are exactly what mono_class_from_name expects.")]
    public Task<string> GenerateCppBinding(
        [Description("Type to bind. " + SymbolDescription)] string type,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Only these members (comma-separated field/property/method names). Default: all non-compiler-generated members.")] string? members = null,
        [Description("Also bind every property getter (static and instance) inherited from base classes. Base-class members named in members are bound without it.")] bool includeInherited = false,
        [Description("Output style: mono or hostapi. Omit to detect it from projectDir (see the description).")] string? style = null,
        [Description("The C/C++ project the header is for: scanned for a host function table and the helpers the hostapi code calls.")] string? projectDir = null,
        [Description("Where the header will be saved (absolute, or relative to projectDir); #include paths are computed from its folder. Default: projectDir.")] string? headerPath = null,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, type, SymbolKind.Type);
        var only = members?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        var target = CppBindingGenerator.ChooseStyle(style, projectDir, headerPath, options, cancellationToken);
        return pager.Page(generator.Generate(sym.Assembly, (TypeDef)sym.Member, only, includeInherited, target), offset, maxChars);
    }, cancellationToken);
}
