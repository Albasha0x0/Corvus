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
    [Description("Generate C++ binding code for a managed type of a Mono or AOT app: a struct that resolves the class once, typed " +
                 "field accessors, property getters and invoke wrappers.")]
    public Task<string> GenerateCppBinding(
        [Description(SymbolDescription)] string type,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Comma-separated member names; default all but compiler-generated.")] string? members = null,
        [Description("Also bind inherited property getters.")] bool includeInherited = false,
        [Description("mono: embedding API; aot: runtime exports; hostapi: host function table. Default detected, else mono.")] string? style = null,
        [Description("C/C++ project of the header, scanned for a host function table and helpers.")] string? projectDir = null,
        [Description("Header path (absolute or under projectDir; default projectDir); #include base.")] string? headerPath = null,
        [Description(CharOffsetDescription)] int offset = 0,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, type, SymbolKind.Type);
        var only = members?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        var target = CppBindingGenerator.ChooseStyle(style, projectDir, headerPath, options, cancellationToken,
            aotAssembly: style == null && IsAotDummy(sym.Assembly.Module));
        return pager.Page(generator.Generate(sym.Assembly, (TypeDef)sym.Member, only, includeInherited, target), offset, maxTokens);
    }, cancellationToken);

    /// <summary>Whether the module's methods carry an [Address] attribute (the first 2,000 looked at).</summary>
    private static bool IsAotDummy(ModuleDef module) =>
        module.GetTypes().SelectMany(t => t.Methods).Take(2_000).Any(m => m.CustomAttributes.Any(a => a.AttributeType?.Name == "AddressAttribute"));
}
