using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;
using Corvus.Services.Mobile;

namespace Corvus.Tests;

/// <summary>Assemblies shaped like a .NET for Android app: a Mono.Android with bound types and an app with Java peers.</summary>
internal static class XamarinSample
{
    /// <summary><paramref name="trimmed"/>: no [Register] on Mono.Android's methods, as release builds ship it.</summary>
    public static (byte[] MonoAndroid, byte[] App) Build(bool trimmed = false)
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
        var onResume = Method(activity, "OnResume", MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.NewSlot | MethodAttributes.HideBySig);
        if (!trimmed)
        {
            onCreate.CustomAttributes.Add(new CustomAttribute(registerCtor3, [
                new CAArgument(corlib.String, "onCreate"), new CAArgument(corlib.String, "(Landroid/os/Bundle;)V"), new CAArgument(corlib.String, "GetOnCreate_Landroid_os_Bundle_Handler")]));
            onResume.CustomAttributes.Add(new CustomAttribute(registerCtor3, [
                new CAArgument(corlib.String, "onResume"), new CAArgument(corlib.String, "()V"), new CAArgument(corlib.String, "GetOnResumeHandler")]));
        }

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
        // A framework base with an unregistered override (MauiAppCompatActivity) between the app's activity and Activity.
        var framework = Type(app, "MyApp", "FrameworkActivity", activityRef);
        Method(framework, "OnCreate", MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.HideBySig, bundleSig);
        var home = Type(app, "MyApp", "HomeActivity", framework);
        Method(home, "OnCreate", MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.HideBySig, bundleSig);
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
        // the dotted form the manifest prints
        Assert.Equal(("MyApp.MainActivity", "Lcom/example/app/Main;"), map.Map("com.example.app.Main", apk, default).Items.Select(i => (i.DotNet, i.Java)).Single());
        Assert.Equal("MyApp.LinkActivity", map.Map(AndroidSamples.LinkPackage + ".LinkActivity", apk, default).Items.Single().DotNet);
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => map.Map("Lcom/example/app/Helper;", apk, default)).Code);
    }

    /// <summary>Release builds strip [Register] from Mono.Android's methods: the Java callable wrapper's registration in the DEX names the overrides.</summary>
    [Fact]
    public void TrimmedBindings_OverridesComeFromTheWrapperRegistration()
    {
        var (mono, app) = XamarinSample.Build(trimmed: true);
        var home = $"L{AndroidSamples.LinkPackage}/HomeActivity;";
        var dex = new DexBuilder();
        dex.Class(home, 1, "Landroid/app/Activity;").Method("<clinit>", "V", [], 0x10008,
            Asm.ConstString(0, "n_onCreate:(Landroid/os/Bundle;)V:GetOnCreate_Landroid_os_Bundle_Handler\nn_onResume:()V:GetOnResumeHandler\n"), Asm.ReturnVoid()).Registers = 1;
        var apk = AndroidSamples.Save(_dir, "trimmed.apk",
            AndroidSamples.Apk(30, ("classes.dex", dex.Build()), ("assemblies/Mono.Android.dll", mono), ("assemblies/MyApp.dll", app)));
        var map = new JavaDotNetMap(_workspace, new DexService());
        var java = map.Map("MyApp.HomeActivity::OnCreate", apk, default).Items.Single();
        Assert.Equal((home + "->onCreate(Landroid/os/Bundle;)V", "override"), (java.Java, java.Basis));
        Assert.Equal("MyApp.HomeActivity::OnCreate(Bundle)", map.Map(home + "->onCreate(Landroid/os/Bundle;)V", apk, default).Items.Single().DotNet);
        File.WriteAllBytes(_dir.File("Mono.Android.dll"), mono);
        File.WriteAllBytes(_dir.File("MyApp.dll"), app);
        _workspace.Load(_dir.File("Mono.Android.dll"));
        _workspace.Load(_dir.File("MyApp.dll"));
        Assert.Contains("pass path=the package", Assert.Throws<ToolError>(() => map.Map("MyApp.HomeActivity::OnCreate", null, default)).Remediation);
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
        var home = map.Map("MyApp.HomeActivity::OnCreate", null, default).Items.Single();
        Assert.Equal(("MyApp.HomeActivity::OnCreate(Bundle)", "override"), (home.DotNet, home.Basis));
        Assert.EndsWith("/HomeActivity;->onCreate(Landroid/os/Bundle;)V", home.Java);
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

    private const string UnitySource = """
        namespace UnityEngine
        {
            public class AndroidJavaObject : System.IDisposable
            {
                public AndroidJavaObject(string className, params object[] args) { }
                public void Call(string methodName, params object[] args) { }
                public T Call<T>(string methodName, params object[] args) => default;
                public void CallStatic(string methodName, params object[] args) { }
                public T CallStatic<T>(string methodName, params object[] args) => default;
                public T GetStatic<T>(string fieldName) => default;
                public void Dispose() { }
            }
            public class AndroidJavaClass : AndroidJavaObject { public AndroidJavaClass(string className) : base(className) { } }
            public class AndroidJavaProxy { public AndroidJavaProxy(string javaInterface) { } }
            public static class AndroidJNI
            {
                public static System.IntPtr FindClass(string name) => default;
                public static System.IntPtr GetStaticMethodID(System.IntPtr clazz, string name, string sig) => default;
            }
        }
        namespace Game
        {
            using UnityEngine;
            public class Bridge
            {
                private AndroidJavaObject _plugin;
                public void Init()
                {
                    using (var unity = new AndroidJavaClass("com.unity3d.player.UnityPlayer"))
                    {
                        var activity = unity.GetStatic<AndroidJavaObject>("currentActivity");
                        _plugin = new AndroidJavaObject("com.example.plugin.Bridge", activity);
                    }
                }
                public void Send(string message) => _plugin.Call("send", message);
                public int Count() => _plugin.Call<int>("count");
                public static void Vibrate()
                {
                    var haptics = new AndroidJavaClass("com.example.plugin.Haptics");
                    haptics.CallStatic("vibrate", 50L, 2);
                }
                public static void Raw() => AndroidJNI.GetStaticMethodID(AndroidJNI.FindClass("com/example/plugin/Haptics"), "vibrate", "(JI)V");
            }
            public class Listener : AndroidJavaProxy
            {
                public Listener() : base("com.example.plugin.Bridge$Callback") { }
                public void onResult(string value) { }
            }
        }
        """;

    /// <summary>A Unity Mono player's package: Assembly-CSharp under assets/bin/Data/Managed and the plugin's Java side in DEX.</summary>
    private string UnityApk()
    {
        var b = new DexBuilder();
        b.Class("Lcom/unity3d/player/UnityPlayer;").Field("currentActivity", "Landroid/app/Activity;", 9);
        var bridge = b.Class("Lcom/example/plugin/Bridge;");
        bridge.Method("<init>", "V", ["Landroid/app/Activity;"], 1, Asm.ReturnVoid()).Registers = 2;
        bridge.Method("send", "V", ["Ljava/lang/String;"], 1, Asm.ReturnVoid()).Registers = 2;
        bridge.Method("count", "I", [], 1, Asm.Const4(0, 0), Asm.Return(0x0f, 0)).Registers = 1;
        var haptics = b.Class("Lcom/example/plugin/Haptics;");
        haptics.Method("vibrate", "V", ["J", "I"], 9, Asm.ReturnVoid()).Registers = 3;
        haptics.Method("vibrate", "V", ["J"], 9, Asm.ReturnVoid()).Registers = 2;
        b.Class("Lcom/example/plugin/Bridge$Callback;", 0x601).Method("onResult", "V", ["Ljava/lang/String;"], 0x401);
        var game = Roslyn.Release("Assembly-CSharp", UnitySource);
        return AndroidSamples.Save(_dir, "unity.apk", AndroidSamples.Apk(30, ("classes.dex", b.Build()), ("assets/bin/Data/Managed/Assembly-CSharp.dll", game)));
    }

    [Fact]
    public void Unity_JavaToCSharp_CallSitesProxiesAndJni()
    {
        var map = new JavaDotNetMap(_workspace, new DexService());
        var apk = UnityApk();
        string Pairs(string symbol) => string.Join(" | ", map.Map(symbol, apk, default).Items.Select(i => $"{i.DotNet} {i.Basis} {i.Confidence}"));
        Assert.Equal("Game.Bridge::Send(string) unity_call name_and_arity", Pairs("Lcom/example/plugin/Bridge;->send(Ljava/lang/String;)V"));
        Assert.Equal("Game.Bridge::Count() unity_call name_and_arity", Pairs("Lcom/example/plugin/Bridge;->count()I"));
        Assert.Equal("Game.Bridge::Vibrate() unity_call name_and_arity | Game.Bridge::Raw() unity_jni descriptor", Pairs("Lcom/example/plugin/Haptics;->vibrate(JI)V"));
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => map.Map("Lcom/example/plugin/Haptics;->vibrate(J)V", apk, default)).Code);
        Assert.Equal("Game.Listener::onResult(string) unity_proxy name_and_arity", Pairs("Lcom/example/plugin/Bridge$Callback;->onResult(Ljava/lang/String;)V"));
        Assert.Equal("Game.Listener unity_proxy name_match", Pairs("Lcom/example/plugin/Bridge$Callback;"));
        Assert.Contains("Game.Bridge::Init() unity_new", Pairs("Lcom/example/plugin/Bridge;"));
        Assert.Equal("assets/bin/Data/Managed/Assembly-CSharp.dll", map.Map("Lcom/example/plugin/Bridge;", apk, default).Items[0].Assembly);
    }

    [Fact]
    public void Unity_CSharpToJava_ExactDexIdsWhenThePackageHasThem()
    {
        var map = new JavaDotNetMap(_workspace, new DexService());
        var apk = UnityApk();
        string Pairs(string symbol, string? path) => string.Join(" | ", map.Map(symbol, path, default).Items.Select(i => $"{i.Java} {i.Basis} {i.Confidence}"));
        Assert.Equal("Lcom/example/plugin/Haptics; unity_new name_match | Lcom/example/plugin/Haptics;->vibrate(JI)V unity_call name_and_arity",
            Pairs("Game.Bridge::Vibrate", apk));
        var init = Pairs("Game.Bridge::Init", apk);
        Assert.Contains("Lcom/unity3d/player/UnityPlayer; unity_new name_match", init);
        Assert.Contains("Lcom/unity3d/player/UnityPlayer;->currentActivity:Landroid/app/Activity; unity_call name_and_arity", init);
        Assert.Contains("Lcom/example/plugin/Bridge; unity_new name_match", init);
        Assert.Equal("Lcom/example/plugin/Bridge$Callback;->onResult(Ljava/lang/String;)V unity_proxy name_and_arity", Pairs("Game.Listener::onResult", apk));
        Assert.Contains("Lcom/example/plugin/Haptics;->vibrate(JI)V unity_jni descriptor", Pairs("Game.Bridge", apk));

        // loaded without the package: names, not DEX ids
        File.WriteAllBytes(_dir.File("Assembly-CSharp.dll"), Roslyn.Release("Assembly-CSharp", UnitySource));
        _workspace.Load(_dir.File("Assembly-CSharp.dll"));
        Assert.Equal("Lcom/example/plugin/Bridge;->send unity_call name_match", Pairs("Game.Bridge::Send", null));
        Assert.True(map.Map("Game.Bridge::Send", null, default).Items.Single().Loaded);
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
