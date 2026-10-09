using System.Diagnostics;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Metadata ↔ native navigation on a synthetic dump: the fixture's stand-in dummy types (NativeThing::First at RVA
/// 0x1000, ::Second at 0x1100, Slot 4) in dump/DummyDll, and a script.json naming generic instantiations (no dummy
/// method) and metadata slots.
/// </summary>
public sealed class Il2CppNavigationTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    private const string ScriptJson = """
        {
          "ScriptMethod": [
            { "Address": 4096, "Name": "Fixture.Native.NativeThing$$First" },
            { "Address": 4352, "Name": "Fixture.Native.NativeThing$$Second" },
            { "Address": 4352, "Name": "Fixture.Native.NativeThing$$Shared<object>" },
            { "Address": 4608, "Name": "Fixture.Native.NativeThing$$Shared<int>" },
            { "Address": 4608, "Name": "System.Collections.Generic.List<int>$$Add" },
            { "Address": 4864, "Name": "Fixture.Native.NativeThing$$Shared<uint>" }
          ],
          "ScriptMetadata": [
            { "Address": 20480, "Name": "Fixture.Native.NativeThing_TypeInfo", "Signature": "Fixture_Native_NativeThing_c*" },
            { "Address": 20488, "Name": "Fixture.Native.NativeThing_var", "Signature": "Il2CppType*" }
          ],
          "ScriptMetadataMethod": [
            { "Address": 20496, "Name": "Method$Fixture.Native.NativeThing.First()", "MethodAddress": 4096 },
            { "Address": 20504, "Name": "Method$Fixture.Native.NativeThing.Shared<int>()", "MethodAddress": 4608 },
            { "Address": 20512, "Name": "Method$Fixture.Native.NativeThing.Second()", "MethodAddress": 4352 }
          ],
          "Addresses": [ 4096, 4352, 4608, 4864, 4928, 8192 ]
        }
        """;

    public void Dispose() => _dir.Dispose();

    private Env LoadDump(bool binary = false)
    {
        var dump = Path.Combine(_dir.Path, "dump");
        var dummies = Path.Combine(dump, "DummyDll");
        Directory.CreateDirectory(dummies);
        var dll = Path.Combine(dummies, Path.GetFileName(Env.FixturePath));
        File.Copy(Env.FixturePath, dll);
        File.WriteAllText(Path.Combine(dump, "script.json"), ScriptJson);
        if (binary) // .text at 0x1000-0x1400, .data at 0x5000
            File.WriteAllBytes(Path.Combine(dump, "GameAssembly.dll"), Il2CppStringTests.Pe64([(".text", 0x1000, new byte[0x400], 0x60000020), (".data", 0x5000, new byte[0x100], 0xC0000040)]));
        return new Env(dll);
    }

    [Fact]
    public async Task AddressesNameFunctionsBoundedByTheNextStartAndMetadataSlots()
    {
        using var env = LoadDump();
        var first = Assert.Single(env.Locate(0x1000));
        Assert.Equal(("exact start", (uint?)0x1100), (first.Function!.Relation, first.Function.End));
        Assert.Equal("First", Assert.Single(first.Methods).Method.Name);
        Assert.Empty(first.ScriptMethods); // the dummy method's own script.json entry

        var shared = Assert.Single(env.Locate(0x1180));
        Assert.StartsWith("inside (+0x80 of 0x100 bytes", shared.Function!.Relation);
        Assert.Equal("Second", Assert.Single(shared.Methods).Method.Name);
        Assert.Equal(["Fixture.Native.NativeThing$$Shared<object>"], shared.ScriptMethods.Select(e => shared.Image.Script!.MethodName(e)));

        var generic = Assert.Single(env.Locate(0x1210));
        Assert.Empty(generic.Methods);
        Assert.Equal(2, generic.ScriptMethods.Count);
        Assert.Equal(0, Assert.Single(env.Locate(0x1350)).Total); // a function without a name
        Assert.Empty(env.Locate(0x2000 + Il2CppService.MaxFunctionSpan, "rva"));
        var va = Assert.Single(env.Locate(0x180001180));
        Assert.Equal((0x1180UL, "va"), (va.Rva, va.Kind));
        var offset = Assert.Single(env.Locate(0x480, "offset")); // the methods' Offset values: RVA - 0xC00
        Assert.Equal((0x1080UL, "offset"), (offset.Rva, offset.Kind));
        var metadata = Assert.Single(env.Locate(0x5004)).Slot!;
        Assert.Equal((Il2CppNavigator.SlotKind.Metadata, 0x5000u), (metadata.Kind, metadata.Address));
        Assert.Equal(Il2CppNavigator.SlotKind.MethodInfo, Assert.Single(env.Locate(0x5018)).Slot!.Kind);

        var tools = env.Il2CppTools();
        var text = await tools.FindMethodByAddress("0x1210");
        Assert.Contains("function at RVA 0x1200 (0x100 bytes up to the next function start): 2 methods share this code (0 dummy-DLL, 2 script.json only)", text);
        Assert.Contains("[RVA] inside (+0x10 of 0x100 bytes up to the next function start): System.Collections.Generic.List<int>$$Add  (start 0x1200)  script.json", text);
        var paged = await tools.FindMethodByAddress("0x1100", limit: 1);
        Assert.Contains("[RVA] exact start: Fixture.Native.NativeThing::Second()", paged);
        Assert.DoesNotContain("Shared<object>", paged);
        Assert.Contains("[More: call again with offset=1]", paged);
        Assert.Contains("Shared<object>", await tools.FindMethodByAddress("0x1100", offset: 1));
        Assert.Contains("0x52000 is not inside a known function or at a metadata slot", await tools.FindMethodByAddress("0x52000"));
        var type = await tools.FindMethodByAddress("0x5000");
        Assert.Contains("[RVA] metadata slot: Fixture.Native.NativeThing_TypeInfo  (Fixture_Native_NativeThing_c*)", type);
        Assert.Contains("type Fixture.Native.NativeThing  [TestFixture]", type);
        var info = await tools.FindMethodByAddress("0x5010");
        Assert.Contains("[RVA] MethodInfo slot: Method$Fixture.Native.NativeThing.First()", info);
        Assert.Contains("its code: RVA 0x1000 (Fixture.Native.NativeThing::First()", info);
    }

    [Fact]
    public async Task EntitiesNameTheirCodeAndSlots()
    {
        using var env = LoadDump();
        var tools = env.Il2CppTools();
        var second = await tools.GetIl2CppInfo("Fixture.Native.NativeThing::Second");
        Assert.Contains("native code: RVA 0x1100-0x1200 (0x100 bytes up to the next function start)", second);
        Assert.Contains("code shared by 2 methods", second);
        Assert.Contains("MethodInfo slot: RVA 0x5020 (describes the function at RVA 0x1100)", second);
        var generic = await tools.GetIl2CppInfo("Fixture.Native.NativeThing::Shared", limit: 2);
        Assert.Contains("generic instantiations in script.json: 3 (showing 1-2)", generic);
        Assert.Contains("Fixture.Native.NativeThing$$Shared<object>  RVA 0x1100", generic);
        Assert.Contains("[More: call again with offset=2]", generic);
        Assert.Contains("Fixture.Native.NativeThing_TypeInfo  RVA 0x5000  (Fixture_Native_NativeThing_c*)", await tools.GetIl2CppInfo("NativeThing"));

        // Names that only script.json has, as users write them.
        foreach (var query in new[] { "List`1<int>::Add", "System.Collections.Generic.List<int>$$Add", "List<System.Int32>.Add" })
            Assert.Contains("System.Collections.Generic.List<int>$$Add  RVA 0x1200 (0x100 bytes); code shared by 2 methods", await tools.GetIl2CppInfo(query));
        var instance = await tools.GetIl2CppInfo("NativeThing::Shared<System.Int32>");
        Assert.Contains("Fixture.Native.NativeThing$$Shared<int>  RVA 0x1200 (0x100 bytes); code shared by 2 methods; MethodInfo slot RVA 0x5018", instance);
        Assert.Contains("definition: Fixture.Native.NativeThing::Shared(T)  [TestFixture]", instance);
        Assert.Contains("metadata slot Fixture.Native.NativeThing_var: RVA 0x5008", await tools.GetIl2CppInfo("Fixture.Native.NativeThing_var"));
        Assert.Contains("RVA 0x5010; its code: RVA 0x1000", await tools.GetIl2CppInfo("Method$Fixture.Native.NativeThing.First()"));
        await Assert.ThrowsAsync<ToolError>(() => tools.GetIl2CppInfo("List<long>::Add"));
    }

    [Fact]
    public void TheBinaryBoundsFunctionsBySection()
    {
        using var env = LoadDump(binary: true);
        Assert.StartsWith("inside (+0x10 of 0xC0 bytes up to the end of .text", Assert.Single(env.Locate(0x1350)).Function!.Relation);
        Assert.Empty(env.Locate(0x1500, "rva")); // past .text: no function, though 0x2000 is the next start
        Assert.Equal(Il2CppNavigator.SlotKind.Metadata, Assert.Single(env.Locate(0x5008)).Slot!.Kind);
        Assert.Equal(0x1180UL, Assert.Single(env.Locate(0x380, "offset")).Rva); // .text raw data at 0x200
    }

    [Fact]
    public async Task VTableSlotsResolveThroughBaseTypes()
    {
        var path = _dir.File("Vt.dll");
        File.WriteAllBytes(path, ContainerFixtures.Module("Vt", BuildVTableTypes));
        using var env = new Env(path);
        var tools = env.Il2CppTools();
        Assert.Contains("slot 5: Vt.Base::Run()  RVA=0x1400 Offset=0x800 VA=0x180001400 Slot=5  (inherited from Vt.Base)", await tools.GetIl2CppInfo("Vt.Derived", slot: "5"));
        Assert.Contains("slot 6: Vt.Derived::Stop()  RVA=0x1500", await tools.GetIl2CppInfo("Vt.Derived", slot: "6"));
        Assert.Contains("slot 6: Vt.Base::Stop()", await tools.GetIl2CppInfo("Vt.Base", slot: "6"));
        Assert.Contains("slot 9: no method of Vt.Derived or its base types declares it (declared slots: 5-6)", await tools.GetIl2CppInfo("Vt.Derived", slot: "9"));
        var all = await tools.GetIl2CppInfo("Vt.Derived", slot: "all");
        Assert.Contains("vtable slots declared by it and its base types: 2", all);
        await Assert.ThrowsAsync<ToolError>(() => tools.GetIl2CppInfo("Vt.Derived::Stop", slot: "6"));
    }

    /// <summary>Vt.Base with virtual Run (slot 5) and Stop (slot 6); Vt.Derived overrides Stop only.</summary>
    private static void BuildVTableTypes(ModuleDefUser module)
    {
        var attribute = new TypeDefUser("Il2CppDummyDll", "AddressAttribute", module.Import(typeof(Attribute)));
        var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void),
            MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = Ret() };
        attribute.Methods.Add(ctor);
        foreach (var field in new[] { "RVA", "Offset", "VA", "Slot" })
            attribute.Fields.Add(new FieldDefUser(field, new FieldSig(module.CorLibTypes.String), FieldAttributes.Public));
        module.Types.Add(attribute);

        MethodDefUser Virtual(string name, uint rva, int slot)
        {
            var m = new MethodDefUser(name, MethodSig.CreateInstance(module.CorLibTypes.Void),
                MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.HideBySig) { Body = Ret() };
            var ca = new CustomAttribute(ctor);
            foreach (var (field, value) in new[] { ("RVA", $"0x{rva:X}"), ("Offset", $"0x{rva - 0xC00:X}"), ("VA", $"0x{0x180000000 + rva:X}"), ("Slot", slot.ToString()) })
                ca.NamedArguments.Add(new CANamedArgument(true, module.CorLibTypes.String, field, new CAArgument(module.CorLibTypes.String, value)));
            m.CustomAttributes.Add(ca);
            return m;
        }
        var baseType = new TypeDefUser("Vt", "Base", module.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.Public };
        baseType.Methods.Add(Virtual("Run", 0x1400, 5));
        baseType.Methods.Add(Virtual("Stop", 0x1440, 6));
        var derived = new TypeDefUser("Vt", "Derived", baseType) { Attributes = TypeAttributes.Public };
        derived.Methods.Add(Virtual("Stop", 0x1500, 6));
        module.Types.Add(baseType);
        module.Types.Add(derived);

        static CilBody Ret() => new() { Instructions = { OpCodes.Ret.ToInstruction() } };
    }

    /// <summary>
    /// A real Il2CppDumper dump (NDM_IL2CPP_STRINGS_DIR): navigation index build time and memory, and round trips —
    /// dummy method → RVA → method, instantiation name → RVA → name, type → TypeInfo slot → type, slot → method.
    /// </summary>
    [RequiresRealDataFact(RealData.Il2CppStringsDir)]
    [Trait("Speed", "Slow")]
    public void RealDump()
    {
        using var ws = new AssemblyWorkspace();
        ws.LoadDirectory(RealData.Path(RealData.Il2CppStringsDir), false);
        var il2cpp = new Il2CppService(ws);
        var strings = new Il2CppStringService(ws, il2cpp);
        var navigator = new Il2CppNavigator(ws, il2cpp, strings);
        ws.Read(() => ws.Assemblies.Sum(a => il2cpp.GetIndex(a).Count));
        var sw = Stopwatch.StartNew();
        var image = Assert.Single(ws.Read(() => navigator.ImagesFor(ws.Assemblies)), i => i.Script != null);
        var script = image.Script!;
        output.WriteLine($"images in {sw.ElapsedMilliseconds} ms: script.json {script.FunctionStarts.Length} function starts, {script.MethodCount} methods ({script.TypeNames.Count} type names, " +
                         $"{script.MethodNames.Count} method names), {script.MetadataCount} metadata and {script.MethodInfoCount} MethodInfo slots, read in {script.LoadTime.TotalMilliseconds:F0} ms");
        long before = GC.GetTotalMemory(true);
        var again = Il2CppScript.Load(script.Path);
        output.WriteLine($"script.json index alone: {again.LoadTime.TotalMilliseconds:F0} ms, retained {(GC.GetTotalMemory(true) - before) / (1 << 20)} MB (arrays {again.RetainedBytes / (1 << 20)} MB)");
        GC.KeepAlive(again);

        var rng = new Random(7);
        var methods = ws.Assemblies.SelectMany(il2cpp.GetIndex).Where(e => e.Rva is <= uint.MaxValue).ToList();
        int methodTrips = 0;
        sw.Restart();
        foreach (var e in Enumerable.Range(0, 500).Select(_ => methods[rng.Next(methods.Count)]))
            if (ws.Read(() => navigator.Locate(e.Rva!.Value, "rva", ws.Assemblies)) is [{ Function.IsExactStart: true } r] && r.Methods.Any(m => m.Method == e.Method)) methodTrips++;
        output.WriteLine($"method -> RVA -> method: {methodTrips}/500 ({sw.ElapsedMilliseconds} ms)");

        int nameTrips = 0;
        sw.Restart();
        for (int i = 0; i < 200; i++)
        {
            int entry = rng.Next(script.MethodCount);
            var name = script.MethodName(entry);
            var found = Il2CppNavigator.FindScriptMethods(script, name);
            if (found.Contains(entry) && ws.Read(() => navigator.Locate(script.MethodAddress(entry), "rva", ws.Assemblies)) is [var r]
                && (r.ScriptMethods.Contains(entry) || r.Methods.Any(m => Il2CppNames.MethodKey(m.Method) == name))) nameTrips++;
        }
        output.WriteLine($"script.json name -> RVA -> name: {nameTrips}/200 ({sw.ElapsedMilliseconds} ms)");

        var types = ws.Assemblies.SelectMany(a => a.Module.GetTypes()).Where(t => !t.HasGenericParameters).ToList();
        int typeSlots = 0, typeTrips = 0;
        sw.Restart();
        foreach (var t in Enumerable.Range(0, 500).Select(_ => types[rng.Next(types.Count)]))
        {
            if (script.MetadataNamed(Il2CppNames.TypeKey(t) + "_TypeInfo") is not [var slot]) continue;
            typeSlots++;
            if (ws.Read(() => navigator.Locate(script.MetadataAddress(slot), "rva", ws.Assemblies)) is [{ Slot: { } s } r]
                && ws.Read(() => navigator.TypeOfMetadata(r.Image, script.MetadataName(s.Entry))).Any(x => x.Member == t)) typeTrips++;
            else if (typeSlots - typeTrips <= 5) output.WriteLine($"  not back to {t.FullName}: {script.MetadataName(slot)}");
        }
        output.WriteLine($"type -> TypeInfo slot -> type: {typeTrips}/{typeSlots} of 500 sampled types have a TypeInfo slot ({sw.ElapsedMilliseconds} ms)");

        var withSlots = methods.Where(e => e.Slot is { Length: > 0 } s && s != "-1").ToList();
        int slotTrips = 0;
        foreach (var e in Enumerable.Range(0, 500).Select(_ => withSlots[rng.Next(withSlots.Count)]))
            if (Il2CppNavigator.SlotMethod(e.Method.DeclaringType, Il2CppNavigator.SlotOf(e.Method)!.Value) == e.Method) slotTrips++;
        output.WriteLine($"(type, slot) -> method: {slotTrips}/500 of {withSlots.Count} methods with a slot");
        Assert.True(methodTrips > 490 && nameTrips > 190);
        GC.KeepAlive(script);
    }
}
