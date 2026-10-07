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
    [McpServerTool(Name = "generate_cpp_binding", Title = "Generate C++ binding (ModHost)", ReadOnly = true, OpenWorld = false)]
    [Description("Generate C++ binding code for a managed type in ModHost's plugin style (HostApi FindClass / FieldOffset / StaticFieldOffset / GetMethod, " +
                 "GetMethodExact for overloads, GetMethodInHierarchy for inherited getters, ReadField/WriteField/CallValue accessors and Invoke wrappers). " +
                 "The assembly, namespace and class strings come from the real Mono metadata, so FindClass gets exactly what mono_class_from_name expects.")]
    public Task<string> GenerateCppBinding(
        [Description("Type to bind. " + SymbolDescription)] string type,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Only these members (comma-separated field/property/method names). Default: all non-compiler-generated members.")] string? members = null,
        [Description("Also bind instance property getters inherited from base classes (resolved with GetMethodInHierarchy).")] bool includeInherited = false,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, type, SymbolKind.Type);
        var only = members?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        return pager.Page(generator.Generate(sym.Assembly, (TypeDef)sym.Member, only, includeInherited), offset, maxChars);
    }, cancellationToken);
}
