using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services.Mobile;

namespace NetDecompilerMcp.Tests;

/// <summary>Assemblies shaped like a .NET for Android app: a Mono.Android with bound types and an app with Java peers.</summary>
internal static class XamarinSample
{
    public static (byte[] MonoAndroid, byte[] App) Build()
    {
        var mono = new ModuleDefUser("Mono.Android.dll") { Kind = ModuleKind.Dll };
        new AssemblyDefUser("Mono.Android", new Version(0, 0, 0, 0)).Modules.Add(mono);
        var corlib = mono.CorLibTypes;
        TypeDefUser Type(ModuleDef m, string ns, string name, ITypeDefOrRef? baseType, TypeAttributes attrs = TypeAttributes.Public | TypeAttributes.Class)
        {
            var t = new TypeDefUser(ns, name, baseType) { Attributes = attrs };
            m.Types.Add(t);
            return t;
        }
        var attribute = mono.Import(typeof(Attribute));
        var register = Type(mono, "Android.Runtime", "RegisterAttribute", attribute);
        var registerCtor1 = Ctor(register, corlib.String);
        var registerCtor3 = Ctor(register, corlib.String, corlib.String, corlib.String);
        register.Properties.Add(new PropertyDefUser("DoNotGenerateAcw", PropertySig.CreateInstance(corlib.Boolean)));
        var activityAttribute = Type(mono, "Android.App", "ActivityAttribute", attribute);
        var activityAttributeCtor = Ctor(activityAttribute);
        var ijava = Type(mono, "Android.Runtime", "IJavaObject", null, TypeAttributes.Public | TypeAttributes.Interface | TypeAttributes.Abstract);

        CustomAttribute Bind(string java)
        {
            var a = new CustomAttribute(registerCtor1, [new CAArgument(corlib.String, java)]);
            a.NamedArguments.Add(new CANamedArgument(false, corlib.Boolean, "DoNotGenerateAcw", new CAArgument(corlib.Boolean, true)));
            return a;
        }
        var javaObject = Type(mono, "Java.Lang", "Object", corlib.Object.TypeDefOrRef);
        javaObject.Interfaces.Add(new InterfaceImplUser(ijava));
        javaObject.CustomAttributes.Add(Bind("java/lang/Object"));
        var bundle = Type(mono, "Android.OS", "Bundle", javaObject);
        bundle.CustomAttributes.Add(Bind("android/os/Bundle"));
        var activity = Type(mono, "Android.App", "Activity", javaObject);
        activity.CustomAttributes.Add(Bind("android/app/Activity"));
        var onCreate = Method(activity, "OnCreate", MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.NewSlot | MethodAttributes.HideBySig, bundle.ToTypeSig());
        onCreate.CustomAttributes.Add(new CustomAttribute(registerCtor3, [
            new CAArgument(corlib.String, "onCreate"), new CAArgument(corlib.String, "(Landroid/os/Bundle;)V"), new CAArgument(corlib.String, "GetOnCreate_Landroid_os_Bundle_Handler")]));
        Method(activity, "OnResume", MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.NewSlot | MethodAttributes.HideBySig).CustomAttributes
            .Add(new CustomAttribute(registerCtor3, [new CAArgument(corlib.String, "onResume"), new CAArgument(corlib.String, "()V"), new CAArgument(corlib.String, "GetOnResumeHandler")]));

        var app = new ModuleDefUser("MyApp.dll") { Kind = ModuleKind.Dll };
        new AssemblyDefUser("MyApp", new Version(1, 0, 0, 0)).Modules.Add(app);
        var importer = new Importer(app);
        var activityRef = importer.Import(activity);
        var bundleSig = importer.Import(bundle).ToTypeSig();
        var link = Type(app, "MyApp", "LinkActivity", activityRef);
        Method(link, "OnCreate", MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.HideBySig, bundleSig);
        Method(link, "Helper", MethodAttributes.Public);
        var main = Type(app, "MyApp", "MainActivity", activityRef);
        var named = new CustomAttribute((ICustomAttributeType)importer.Import(activityAttributeCtor));
        named.NamedArguments.Add(new CANamedArgument(false, app.CorLibTypes.String, "Name", new CAArgument(app.CorLibTypes.String, "com.example.app.Main")));
        main.CustomAttributes.Add(named);
        Method(main, "OnResume", MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.HideBySig);
        var outer = Type(app, "MyApp", "Outer", app.CorLibTypes.Object.TypeDefOrRef);
        var inner = new TypeDefUser("", "Inner", importer.Import(javaObject)) { Attributes = TypeAttributes.NestedPublic | TypeAttributes.Class };
        outer.NestedTypes.Add(inner);
        Type(app, "MyApp", "PlainClass", app.CorLibTypes.Object.TypeDefOrRef);
        return (Write(mono), Write(app));
    }

    private static MethodDefUser Ctor(TypeDef type, params TypeSig[] args)
    {
        var m = new MethodDefUser(".ctor", MethodSig.CreateInstance(type.Module.CorLibTypes.Void, args),
            MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName);
        m.Body = new CilBody { Instructions = { OpCodes.Ret.ToInstruction() } };
        type.Methods.Add(m);
        return m;
    }

    private static MethodDefUser Method(TypeDef type, string name, MethodAttributes attrs, params TypeSig[] args)
    {
        var m = new MethodDefUser(name, MethodSig.CreateInstance(type.Module.CorLibTypes.Void, args), MethodImplAttributes.IL, attrs);
        m.Body = new CilBody { Instructions = { OpCodes.Ret.ToInstruction() } };
        type.Methods.Add(m);
        return m;
    }

    private static byte[] Write(ModuleDef m)
    {
        using var ms = new MemoryStream();
        m.Write(ms);
        return ms.ToArray();
    }
}

public sealed class JavaDotNetMapTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    private string Apk() => AndroidSamples.SaveXamarin(_dir);

    [Theory]
    [InlineData("hello", "ad3d04bd697eb3c5")]
    [InlineData("System.Xml.XmlDocument, System.Xml", "348bbd9fecf1b865")]
    public void Crc64_MatchesJavaInterop(string input, string expected) => Assert.Equal(expected, JavaDotNetMap.Crc64(input));

    [Fact]
    public void JavaToDotNet_WrappersBindingsAndOverrides_FromThePackage()
    {
        var map = new JavaDotNetMap(_workspace);
        var apk = Apk();
        var link = map.Map(AndroidSamples.Link, apk, default).Items.Single();
        Assert.Equal(("MyApp.LinkActivity", "assemblies/MyApp.dll", false, "crc64_package"), (link.DotNet, link.Assembly, link.Loaded, link.Basis));
        var onCreate = map.Map(AndroidSamples.Link + "->onCreate(Landroid/os/Bundle;)V", apk, default).Items.Single();
        Assert.Equal(("MyApp.LinkActivity::OnCreate(Bundle)", "override"), (onCreate.DotNet, onCreate.Basis));
        var bound = map.Map("Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V", apk, default).Items.Single();
        Assert.Equal(("Android.App.Activity::OnCreate(Bundle)", "register_attribute"), (bound.DotNet, bound.Basis));
        Assert.Equal(("MyApp.MainActivity", "component_name"), map.Map("com/example/app/Main", apk, default).Items.Select(i => (i.DotNet, i.Basis)).Single());
        Assert.Equal("MyApp.Outer+Inner", map.Map($"L{AndroidSamples.LinkPackage}/Outer_Inner;", apk, default).Items.Single().DotNet);
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => map.Map("Lcom/example/app/Helper;", apk, default)).Code);
    }

    [Fact]
    public void DotNetToJava_PrefersLoadedAssemblies()
    {
        var (mono, app) = XamarinSample.Build();
        File.WriteAllBytes(_dir.File("Mono.Android.dll"), mono);
        File.WriteAllBytes(_dir.File("MyApp.dll"), app);
        _workspace.Load(_dir.File("Mono.Android.dll"));
        _workspace.Load(_dir.File("MyApp.dll"));
        var map = new JavaDotNetMap(_workspace);
        var type = map.Map("MyApp.LinkActivity", null, default).Items.Single();
        Assert.Equal((AndroidSamples.Link, "MyApp", true), (type.Java, type.Assembly, type.Loaded));
        Assert.Equal("Lcom/example/app/Main;->onResume()V", map.Map("MyApp.MainActivity::OnResume", null, default).Items.Single().Java);
        Assert.Equal("MyApp", map.Map("MyApp.LinkActivity", Apk(), default).Items.Single().Assembly); // the loaded copy wins over the package's
        Assert.Contains("not a Java peer", Assert.Throws<ToolError>(() => map.Map("MyApp.PlainClass", null, default)).Message);
        Assert.Contains("not registered", Assert.Throws<ToolError>(() => map.Map("MyApp.LinkActivity::Helper", null, default)).Message);
        Assert.Equal(ErrorCode.NotLoaded, Assert.Throws<ToolError>(() => new JavaDotNetMap(new AssemblyWorkspace(new ServerOptions())).Map("X", null, default)).Code);
    }

    /// <summary>The real Mono.Android of a .NET for Android runtime pack: thousands of bound types and registered methods.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void RealMonoAndroid()
    {
        _workspace.Load(RealPackages.File("Microsoft.Android.Runtime.35.android-arm64", "35.0.105", "runtimes", "android-arm64", "lib", "net9.0", "Mono.Android.dll"));
        var map = new JavaDotNetMap(_workspace);
        Assert.Equal("Android.App.Activity::OnCreate(Bundle)", map.Map("Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V", null, default).Items.Single().DotNet);
        Assert.Equal("Landroid/widget/TextView;", map.Map("Android.Widget.TextView", null, default).Items.Single().Java);
        Assert.Contains(map.Map("Android.App.Activity::OnCreate", null, default).Items, i => i.Java == "Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V");
    }

    [Fact]
    public void Manifest_NamesTheDotNetTypeOfEachComponent()
    {
        var service = new AndroidPackageService(new OutputPager(new ServerOptions()), new JavaDotNetMap(_workspace));
        var m = service.Manifest(Apk());
        Assert.Equal("MyApp.LinkActivity (assemblies/MyApp.dll, crc64_package)", m.Components.Single(c => c.Name.EndsWith(".LinkActivity", StringComparison.Ordinal)).DotNetType);
        Assert.Equal("MyApp.MainActivity (assemblies/MyApp.dll, component_name)", m.Components.Single(c => c.Name == "com.example.app.Main").DotNetType);
        Assert.Null(m.Components.Single(c => c.Name == "com.example.app.Sync").DotNetType);
        Assert.Null(new AndroidPackageService(new OutputPager(new ServerOptions()), new JavaDotNetMap(_workspace))
            .Manifest(AndroidSamples.Save(_dir, "java.apk", AndroidSamples.Apk())).Components[0].DotNetType); // not a .NET app
    }
}
