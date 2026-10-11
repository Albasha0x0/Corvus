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
    [McpServerTool(Name = "generate_cpp_binding", Title = "Generate C++ binding")]
    [Description("Generate C++ binding code for a managed type of a Mono or Il2Cpp application: a struct that resolves the class, field offsets, " +
                 "static fields and methods once, with typed field accessors, property getters and invoke wrappers; class lookup strings come from the metadata. " +
                 "style=mono: a self-contained header on the Mono embedding API exports. style=il2cpp: one on the Il2Cpp runtime exports, plus each method's " +
                 "native code pointer (to hook) and a typed direct call. style=hostapi: for a host that passes a function table (FindClass, GetMethod, " +
                 "FieldOffset, StaticFieldOffset, GetStaticFieldData, Invoke). Without style it is detected from projectDir (such a table, or its own il2cpp_* / mono_* calls), " +
                 "an Il2Cpp dummy assembly, the server's --binding-style, else mono; the first output line says which and why. " +
                 "A generic definition (List`1) binds as a C++ template resolved with Resolve(api, instanceClass).")]
    public Task<string> GenerateCppBinding(
        [Description(SymbolDescription)] string type,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Only these members (comma-separated names); default all but compiler-generated ones.")] string? members = null,
        [Description("Also bind property getters inherited from base classes (base members named in members are bound anyway).")] bool includeInherited = false,
        [Description("Omit to detect it.")] string? style = null,
        [Description("The C/C++ project the header is for, scanned for a host function table and helpers.")] string? projectDir = null,
        [Description("Where the header will be saved (absolute or relative to projectDir; default projectDir); #include paths are relative to it.")] string? headerPath = null,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) => Read(workspace, () =>
    {
        var sym = SymbolResolver.ResolveOne(workspace, assembly, type, SymbolKind.Type);
        var only = members?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        var target = CppBindingGenerator.ChooseStyle(style, projectDir, headerPath, options, cancellationToken,
            il2cppAssembly: style == null && IsIl2CppDummy(sym.Assembly.Module));
        return pager.Page(generator.Generate(sym.Assembly, (TypeDef)sym.Member, only, includeInherited, target), offset, maxChars);
    }, cancellationToken);

    /// <summary>Whether the module's methods carry a dumper's [Address] attribute (the first 2,000 looked at).</summary>
    private static bool IsIl2CppDummy(ModuleDef module) =>
        module.GetTypes().SelectMany(t => t.Methods).Take(2_000).Any(m => m.CustomAttributes.Any(a => a.AttributeType?.Name == "AddressAttribute"));
}
