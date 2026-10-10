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
    [McpServerTool(Name = "generate_cpp_binding", Title = "Generate C++ binding")]
    [Description("Generate C++ binding code for a managed type of a Mono or Il2Cpp application: a struct that resolves the class, field offsets, " +
                 "static fields and methods once, with typed field accessors, property getters and method invoke wrappers. " +
                 "style=mono: a self-contained header on the standard Mono embedding API (mono_class_from_name, " +
                 "mono_field_get_offset, mono_runtime_invoke, ...), loaded from the runtime's exports; works with any injector or host. " +
                 "style=il2cpp: a self-contained header on the Il2Cpp runtime's exports (il2cpp_class_from_name, il2cpp_field_get_offset, " +
                 "il2cpp_runtime_invoke, ...) from GameAssembly.dll, plus each method's native code pointer (to hook) and a typed direct call. " +
                 "style=hostapi: for projects whose host passes a function table (a struct with FindClass, GetMethod, FieldOffset, " +
                 "StaticFieldOffset, GetStaticFieldData and Invoke). Without style: projectDir has such a table -> hostapi with #include " +
                 "paths relative to headerPath; projectDir calls Il2Cpp or Mono exports itself (il2cpp_class_from_name, typedef il2cpp_*_t, " +
                 "using fn_* = ..., mono_class_from_name) -> il2cpp or mono; an Il2Cpp dummy assembly -> il2cpp; else the server's " +
                 "--binding-style, else mono. The first line of the output says which style was chosen and why. " +
                 "A generic definition (List`1) binds as a C++ template over its type parameters, resolved with Resolve(api, instanceClass) on an instantiation's class; style=il2cpp adds a layout template of its instances. " +
                 "The assembly, namespace and class strings come from the real metadata, so they are exactly what the runtime's class lookup expects.")]
    public Task<string> GenerateCppBinding(
        [Description("Type to bind. " + SymbolDescription)] string type,
        [Description(AssemblyFilterDescription)] string? assembly = null,
        [Description("Only these members (comma-separated field/property/method names). Default: all non-compiler-generated members.")] string? members = null,
        [Description("Also bind every property getter (static and instance) inherited from base classes. Base-class members named in members are bound without it.")] bool includeInherited = false,
        [Description("Output style: mono, il2cpp or hostapi. Omit to detect it (see the description).")] string? style = null,
        [Description("The C/C++ project the header is for: scanned for a host function table and the helpers the hostapi code calls.")] string? projectDir = null,
        [Description("Where the header will be saved (absolute, or relative to projectDir); #include paths are computed from its folder. Default: projectDir.")] string? headerPath = null,
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
