using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>The .NET transformation tool named from what each leaves in a module: markers and the shapes of its runtime code.</summary>
public sealed class TransformerTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new();

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    private static List<TransformerFinding> Identify(Action<ModuleDefUser> build) => Transformers.Identify(ModuleDefMD.Load(ContainerFixtures.Module("App", build)));

    private static MethodDefUser Static(ModuleDef m, string name, TypeSig ret, params TypeSig[] parameters) =>
        new(name, MethodSig.CreateStatic(ret, parameters), MethodImplAttributes.IL | MethodImplAttributes.Managed, MethodAttributes.Public | MethodAttributes.Static);

    private static void Body(MethodDef method, params Instruction[] code)
    {
        method.Body = new CilBody();
        foreach (var i in code) method.Body.Instructions.Add(i);
    }

    private static TypeDefUser Type(ModuleDef m, string ns, string name)
    {
        var t = new TypeDefUser(ns, name, m.CorLibTypes.Object.TypeDefOrRef);
        m.Types.Add(t);
        return t;
    }

    /// <summary>ConfuserEx's constants decoder: a generic static method of &lt;Module&gt; taking a uint and returning T.</summary>
    private static void Confuser(ModuleDefUser m)
    {
        var get = Static(m, "​‌", new GenericMVar(0), m.CorLibTypes.UInt32);
        get.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
        get.MethodSig.GenParamCount = 1;
        Body(get, OpCodes.Ldnull.ToInstruction(), OpCodes.Unbox_Any.ToInstruction(new TypeSpecUser(new GenericMVar(0))), OpCodes.Ret.ToInstruction());
        m.GlobalType.Methods.Add(get);
    }

    [Fact]
    public void ConfuserEx_is_identified_by_its_constants_decoder()
    {
        var f = Assert.Single(Identify(Confuser));
        Assert.Equal(("ConfuserEx", "strong"), (f.Name, f.Confidence));
        Assert.StartsWith("constants decoder <Module>::", f.Evidence[0]);
    }

    [Fact]
    public void MarkerTools_SmartAssembly_Dotfuscator_Babel()
    {
        var found = Identify(m =>
        {
            Type(m, "SmartAssembly.StringsEncoding", "Strings");
            Type(m, "", "DotfuscatorAttribute");
            Type(m, "", "BabelObfuscatorAttribute");
        });
        Assert.Equal([("SmartAssembly", "marker"), ("Dotfuscator", "marker"), ("Babel.NET", "marker")], found.Select(f => (f.Name, f.Confidence)));
        Assert.Equal("runtime type SmartAssembly.StringsEncoding.Strings", found[0].Evidence[0]);
    }

    [Fact]
    public void Reactor_is_identified_by_its_holder_type_and_bodyless_stubs()
    {
        var f = Assert.Single(Identify(m =>
        {
            Type(m, "", "<PrivateImplementationDetails>{0F3A6D2B-1C4E-4B7A-9D2E-5A6B7C8D9E0F}");
            Type(m, "App", "Program").Methods.Add(Static(m, "Run", m.CorLibTypes.Void)); // no body: moved to native code
        }));
        Assert.Equal((".NET Reactor", "strong"), (f.Name, f.Confidence));
        Assert.Contains("1 method(s) without an IL body (NecroBit moves bodies to native code)", f.Evidence);
    }

    [Fact]
    public void Eazfuscator_is_identified_by_its_resource_string_decoder()
    {
        var f = Assert.Single(Identify(m =>
        {
            var holder = Type(m, "", "\u0002");
            var decode = Static(m, "\u0003", m.CorLibTypes.String, m.CorLibTypes.Int32);
            var getStream = new MemberRefUser(m, "GetManifestResourceStream", MethodSig.CreateInstance(new ClassSig(m.CorLibTypes.GetTypeRef("System.IO", "Stream")), m.CorLibTypes.String),
                m.CorLibTypes.GetTypeRef("System.Reflection", "Assembly"));
            Body(decode, OpCodes.Ldnull.ToInstruction(), OpCodes.Ldstr.ToInstruction("x"), OpCodes.Callvirt.ToInstruction(getStream), OpCodes.Pop.ToInstruction(),
                OpCodes.Ldnull.ToInstruction(), OpCodes.Ret.ToInstruction());
            holder.Methods.Add(decode);
        }));
        Assert.Equal(("Eazfuscator.NET", "likely"), (f.Name, f.Confidence));
        Assert.Equal(@"string decoder \u0002::\u0003(int) reading an embedded resource", f.Evidence[0]);
    }

    [Fact]
    public void PlainModule_NamesNone() => Assert.Empty(Identify(_ => { }));

    [Fact]
    public void Fuzzed_Module_NeverThrows()
    {
        var failures = FormatFuzz.Run(ContainerFixtures.Module("App", Confuser), b =>
        {
            ModuleDefMD module;
            try { module = ModuleDefMD.Load(b); }
            catch (Exception) { return; } // a module dnlib refuses is not ours to read
            using (module) Transformers.Identify(module);
        }, 800);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(5)));
    }

    /// <summary>ConfuserEx's resource protection: a &lt;Module&gt; method that registers AssemblyResolve and loads bytes.</summary>
    private static void ResourceProtection(ModuleDefUser m)
    {
        var resolve = Static(m, "‍", m.CorLibTypes.Void);
        Body(resolve,
            OpCodes.Call.ToInstruction(m.Import(typeof(AppDomain).GetProperty(nameof(AppDomain.CurrentDomain))!.GetMethod!)),
            OpCodes.Ldnull.ToInstruction(),
            OpCodes.Callvirt.ToInstruction(m.Import(typeof(AppDomain).GetEvent(nameof(AppDomain.AssemblyResolve))!.AddMethod!)),
            OpCodes.Ldnull.ToInstruction(),
            OpCodes.Call.ToInstruction(m.Import(typeof(System.Reflection.Assembly).GetMethod(nameof(System.Reflection.Assembly.Load), [typeof(byte[])])!)),
            OpCodes.Pop.ToInstruction(),
            OpCodes.Ret.ToInstruction());
        m.GlobalType.Methods.Add(resolve);
    }

    [Fact]
    public void The_transforms_view_joins_a_layer_to_the_transformer_whose_evidence_explains_it()
    {
        var path = _dir.File("app.dll");
        File.WriteAllBytes(path, ContainerFixtures.Module("App", m => { Confuser(m); ResourceProtection(m); }));
        var asm = _workspace.Load(path);
        Corvus.Services.AssemblyReport.Summary summary = null!;
        _workspace.Read(() => new Corvus.Services.AssemblyReport(_workspace, new Corvus.Services.AotMetadataService(_workspace)).Build(asm, "transforms", out summary));
        var loads = Assert.Single(summary.Transformers!, t => t.Name == "layer: loaded assemblies");
        Assert.Contains(loads.Evidence, e => e.StartsWith("identified: ConfuserEx (strong): resource protection", StringComparison.Ordinal));
        Assert.DoesNotContain(summary.Transformers!, t => t.Name.StartsWith("layer: ", StringComparison.Ordinal) && t.Name != "layer: loaded assemblies"
            && t.Evidence.Any(e => e.Contains("resource protection", StringComparison.Ordinal)));
    }

    [Fact]
    public void Summarize_file_and_assembly_info_name_it()
    {
        var path = _dir.File("app.dll");
        File.WriteAllBytes(path, ContainerFixtures.Module("App", Confuser));
        var summary = new InspectionService(_workspace).Summarize(null, path, default);
        Assert.Contains(summary.Highlights, h => h.StartsWith("Transformed with ConfuserEx (strong: constants decoder", StringComparison.Ordinal));
        var asm = _workspace.Load(path);
        var text = new Corvus.Services.AssemblyReport(_workspace, new Corvus.Services.AotMetadataService(_workspace)).Build(asm, "summary", out var record);
        Assert.Contains("Transformer: ConfuserEx (strong): constants decoder", text);
        Assert.Equal("ConfuserEx", Assert.Single(record.Transformers!).Name);
    }
}
