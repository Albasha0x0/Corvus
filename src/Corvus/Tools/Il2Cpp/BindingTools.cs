using System.ComponentModel;
using dnlib.DotNet;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class BindingTools(AssemblyWorkspace workspace, CppBindingGenerator generator, OutputPager pager, ServerOptions options)
{
    [McpServerTool(Name = "generate_cpp_binding", Title = "Generate C++ binding", UseStructuredContent = true, OutputSchemaType = typeof(TextPageRecord))]
    [Description("Generate C++ binding code for a managed type of a Mono or Il2Cpp app: a struct resolving the class, field offsets, static " +
                 "fields and methods once, with typed accessors, property getters and invoke wrappers. style: mono (embedding API), il2cpp " +
                 "(runtime exports) or hostapi (a host's function table); omitted: detected, else mono.")]
    public Task<string> GenerateCppBinding(
        [Description(SymbolDescription)] string type,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Comma-separated member names; default all but compiler-generated ones.")] string? members = null,
        [Description("Also bind property getters inherited from base classes.")] bool includeInherited = false,
        [Description("Omit to detect it.")] string? style = null,
        [Description("C/C++ project the header is for, scanned for a host function table and helpers.")] string? projectDir = null,
        [Description("Header save path (absolute or under projectDir; default projectDir); #include base.")] string? headerPath = null,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, type, SymbolKind.Type);
        var only = members?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        var target = CppBindingGenerator.ChooseStyle(style, projectDir, headerPath, options, cancellationToken,
            il2cppAssembly: style == null && IsIl2CppDummy(sym.Assembly.Module));
        return pager.Page(generator.Generate(sym.Assembly, (TypeDef)sym.Member, only, includeInherited, target), offset, maxTokens);
    }, cancellationToken);

    /// <summary>Whether the module's methods carry a dumper's [Address] attribute (the first 2,000 looked at).</summary>
    private static bool IsIl2CppDummy(ModuleDef module) =>
        module.GetTypes().SelectMany(t => t.Methods).Take(2_000).Any(m => m.CustomAttributes.Any(a => a.AttributeType?.Name == "AddressAttribute"));
}
