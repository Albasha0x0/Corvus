using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>Global functions (&lt;Module&gt;), native C++/CLI bodies and reference assemblies are reported for what they are.</summary>
public class MetadataFactsTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    /// <summary>A module with two global functions on &lt;Module&gt; and a module initializer.</summary>
    private string GlobalFunctions()
    {
        var bytes = ContainerFixtures.Module("Globals", m =>
        {
            foreach (var name in new[] { "Init", "Helper" })
            {
                var method = new MethodDefUser(name, MethodSig.CreateStatic(m.CorLibTypes.Int32),
                    MethodImplAttributes.IL | MethodImplAttributes.Managed, MethodAttributes.Assembly | MethodAttributes.Static);
                method.Body = new CilBody { Instructions = { OpCodes.Ldc_I4_7.ToInstruction(), OpCodes.Ret.ToInstruction() } };
                m.GlobalType.Methods.Add(method);
            }
        });
        var path = _dir.File("Globals.dll");
        File.WriteAllBytes(path, bytes);
        return path;
    }

    [Fact]
    public void GlobalFunctions_ResolveByModuleTypeName_AndAreCounted()
    {
        using var env = new Env(GlobalFunctions());
        Assert.Equal("<Module>::Init()", env.One("<Module>::Init").Label);
        Assert.Equal("<Module>::Helper()", env.One("<Module>::Helper()").Label);
        Assert.Contains("return 7;", env.Decompile("<Module>::Init"));
        Assert.IsAssignableFrom<TypeDef>(env.One("<Module>", SymbolKind.Type).Member);
        var info = env.Workspace.Read(() => env.Report.Build(env.Fixture));
        Assert.Contains("Types: 1 (0 nested)", info);  // <Module> is not counted as a type...
        Assert.Contains("Methods: 2 ", info);          // ...but its functions are counted as methods
        // Generic arity is still normalized.
        Assert.Equal("List`1", SymbolResolver.NormalizeTypeName("List<T>"));
        Assert.Equal("Ns.<>c", SymbolResolver.NormalizeTypeName("Ns.<>c"));
    }

    [Fact]
    public void NativeCppCliBodies_AreNotInvalidIl()
    {
        var wrapper = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"Microsoft.NET\Framework64\v4.0.30319\System.EnterpriseServices.Wrapper.dll");
        if (!File.Exists(wrapper)) return; // a mixed-mode C++/CLI module shipped with .NET Framework
        var balance = IlHealth.Assess(File.ReadAllBytes(wrapper));
        Assert.True(balance.Bodies > 100);
        Assert.Equal(0, balance.Invalid);
    }

    [Fact]
    public void ReferenceAssemblies_AreFlagged()
    {
        var path = _dir.File("Api.dll");
        File.WriteAllBytes(path, ReferenceResolutionTests.Compile("Api",
            "[assembly: System.Runtime.CompilerServices.ReferenceAssembly] public class Client { public string Get() => throw null; }"));
        using var env = new Env(path);
        Assert.Contains("Reference assembly: metadata only", env.Workspace.Read(() => env.Report.Build(env.Fixture)));
        Assert.Contains("// Note: reference assembly", env.Decompile("Client::Get"));
        using var normal = new Env();
        Assert.DoesNotContain("Reference assembly", normal.Workspace.Read(() => normal.Report.Build(normal.Fixture)));
    }
}
