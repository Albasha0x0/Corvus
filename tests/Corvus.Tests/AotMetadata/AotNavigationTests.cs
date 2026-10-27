using System.Diagnostics;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Metadata to native navigation on synthetic dummy assemblies and a script.json.</summary>
public sealed class AotNavigationTests(ITestOutputHelper output) : IDisposable
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
        // .text at 0x1000-0x1400, .data at 0x5000.
        if (binary)
            File.WriteAllBytes(Path.Combine(dump, "GameAssembly.dll"), AotStringTests.Pe64([(".text", 0x1000, new byte[0x400], 0x60000020), (".data", 0x5000, new byte[0x100], 0xC0000040)]));
        return new Env(dll);
    }

    [Fact]
    public async Task Addresses_name_functions_bounded_by_the_next_start_and_metadata_slots()
    {
        using var env = LoadDump();
        var first = Assert.Single(env.Locate(0x1000));
        Assert.Equal(("exact start", (uint?)0x1100), (first.Function!.Relation, first.Function.End));
        Assert.Equal("First", Assert.Single(first.Methods).Method.Name);
        // The dummy method's own script.json entry.
        Assert.Empty(first.ScriptMethods);

        var shared = Assert.Single(env.Locate(0x1180));
        Assert.StartsWith("inside (+0x80 of 0x100 bytes", shared.Function!.Relation);
        Assert.Equal("Second", Assert.Single(shared.Methods).Method.Name);
        Assert.Equal(["Fixture.Native.NativeThing$$Shared<object>"], shared.ScriptMethods.Select(e => shared.Image.Script!.MethodName(e)));

        var generic = Assert.Single(env.Locate(0x1210));
        Assert.Empty(generic.Methods);
        Assert.Equal(2, generic.ScriptMethods.Count);
        // A function without a name.
        Assert.Equal(0, Assert.Single(env.Locate(0x1350)).Total);
        Assert.Empty(env.Locate(0x2000 + AotMetadataService.MaxFunctionSpan, "rva"));
        var va = Assert.Single(env.Locate(0x180001180));
        Assert.Equal((0x1180UL, "va"), (va.Rva, va.Kind));
        // The methods' Offset values: RVA - 0xC00.
        var offset = Assert.Single(env.Locate(0x480, "offset"));
        Assert.Equal((0x1080UL, "offset"), (offset.Rva, offset.Kind));
        var metadata = Assert.Single(env.Locate(0x5004)).Slot!;
        Assert.Equal((AotNavigator.SlotKind.Metadata, 0x5000u), (metadata.Kind, metadata.Address));
        Assert.Equal(AotNavigator.SlotKind.MethodInfo, Assert.Single(env.Locate(0x5018)).Slot!.Kind);

        var tools = env.MethodAddressTools();
        var text = await tools.FindMethodByAddress("0x1210");
        Assert.Contains("function at RVA 0x1200 (0x100 bytes up to the next function start): 2 methods share this code (0 dummy-DLL, 2 script.json only)", text);
        Assert.Contains("[RVA] inside (+0x10 of 0x100 bytes up to the next function start): System.Collections.Generic.List<int>$$Add  (start 0x1200)  script.json", text);
        var paged = await tools.FindMethodByAddress("0x1100", limit: 1);
        Assert.Contains("[RVA] exact start: Fixture.Native.NativeThing::Second()", paged);
        Assert.DoesNotContain("Shared<object>", paged);
        Assert.Contains("[More: offset=1]", paged);
        Assert.Contains("Shared<object>", await tools.FindMethodByAddress("0x1100", offset: 1));
        // Offset + limit must not wrap.
        Assert.DoesNotContain("[More:", await tools.FindMethodByAddress("0x1100", offset: int.MaxValue));
        Assert.Contains("0x52000 is not inside a known function or at a metadata slot", await tools.FindMethodByAddress("0x52000"));
        var type = await tools.FindMethodByAddress("0x5000");
        Assert.Contains("[RVA] metadata slot: Fixture.Native.NativeThing_TypeInfo  (Fixture_Native_NativeThing_c*)", type);
        Assert.Contains("type Fixture.Native.NativeThing  [TestFixture]", type);
        var info = await tools.FindMethodByAddress("0x5010");
        Assert.Contains("[RVA] MethodInfo slot: Method$Fixture.Native.NativeThing.First()", info);
        Assert.Contains("its code: RVA 0x1000 (Fixture.Native.NativeThing::First()", info);
    }

    /// <summary>get_method_addresses and find_method_by_address records: members with their numbers, long lists and matches as paged items.</summary>
    [Fact]
    public async Task Records_carry_the_addresses_and_pages()
    {
        using var env = LoadDump();
        var tools = env.MethodAddressTools();
        var collector = Corvus.Mcp.ToolOutput.Collect();
        await tools.GetMethodAddresses("Fixture.Native.NativeThing::Shared", limit: 2);
        var info = Assert.IsType<Corvus.Tools.MethodAddressInfo>(collector.Value);
        Assert.Equal(("method", "TestFixture"), (info.Members[0].Kind, info.Members[0].Assembly));
        Assert.Equal((2, 3), (info.Items.Count, info.Total));
        Assert.All(info.Items, i => Assert.Equal("instantiation", i.Kind));
        Assert.Equal("0x1100", info.Items.Single(i => i.Name == "Fixture.Native.NativeThing$$Shared<object>").Rva);

        collector = Corvus.Mcp.ToolOutput.Collect();
        await tools.FindMethodByAddress("0x1100", limit: 1);
        var lookup = Assert.IsType<Corvus.Tools.MethodAddressLookup>(collector.Value);
        var match = Assert.Single(lookup.Items);
        Assert.Equal(("method", "Fixture.Native.NativeThing::Second()", "0x1100", "0x0", 2), (match.Kind, match.Method, match.Function, match.OffsetInFunction, lookup.Total));
        Assert.Null(match.Basis);
        collector = Corvus.Mcp.ToolOutput.Collect();
        await tools.FindMethodByAddress("0x5010");
        Assert.Equal("method_info", Assert.Single(Assert.IsType<Corvus.Tools.MethodAddressLookup>(collector.Value).Items).Kind);
    }

    [Trait("Smoke", "push")]
    [Fact]
    public async Task Entities_name_their_code_and_slots()
    {
        using var env = LoadDump();
        var tools = env.MethodAddressTools();
        var second = await tools.GetMethodAddresses("Fixture.Native.NativeThing::Second");
        Assert.Contains("native code: RVA 0x1100-0x1200 (0x100 bytes up to the next function start)", second);
        Assert.Contains("code shared by 2 methods", second);
        Assert.Contains("MethodInfo slot: RVA 0x5020 (describes the function at RVA 0x1100)", second);
        var generic = await tools.GetMethodAddresses("Fixture.Native.NativeThing::Shared", limit: 2);
        Assert.Contains("generic instantiations in script.json: 3 (showing 1-2)", generic);
        Assert.Contains("Fixture.Native.NativeThing$$Shared<object>  RVA 0x1100", generic);
        Assert.Contains("[More: offset=2]", generic);
        Assert.Contains("Fixture.Native.NativeThing_TypeInfo  RVA 0x5000  (Fixture_Native_NativeThing_c*)", await tools.GetMethodAddresses("NativeThing"));

        // Names that only script.json has, as users write them.
        foreach (var query in new[] { "List`1<int>::Add", "System.Collections.Generic.List<int>$$Add", "List<System.Int32>.Add" })
            Assert.Contains("System.Collections.Generic.List<int>$$Add  RVA 0x1200 (0x100 bytes); code shared by 2 methods", await tools.GetMethodAddresses(query));
        var instance = await tools.GetMethodAddresses("NativeThing::Shared<System.Int32>");
        Assert.Contains("Fixture.Native.NativeThing$$Shared<int>  RVA 0x1200 (0x100 bytes); code shared by 2 methods; MethodInfo slot RVA 0x5018", instance);
        Assert.Contains("definition: Fixture.Native.NativeThing::Shared<T>(T)  [TestFixture]", instance);
        Assert.Contains("metadata slot Fixture.Native.NativeThing_var: RVA 0x5008", await tools.GetMethodAddresses("Fixture.Native.NativeThing_var"));
        Assert.Contains("RVA 0x5010; its code: RVA 0x1000", await tools.GetMethodAddresses("Method$Fixture.Native.NativeThing.First()"));
        await Assert.ThrowsAsync<ToolError>(() => tools.GetMethodAddresses("List<long>::Add"));
    }

    [Fact]
    public void The_binary_bounds_functions_by_section()
    {
        using var env = LoadDump(binary: true);
        Assert.StartsWith("inside (+0x10 of 0xC0 bytes up to the end of .text", Assert.Single(env.Locate(0x1350)).Function!.Relation);
        Assert.Empty(env.Locate(0x1500, "rva")); // past .text: no function, though 0x2000 is the next start
        Assert.Equal(AotNavigator.SlotKind.Metadata, Assert.Single(env.Locate(0x5008)).Slot!.Kind);
        Assert.Equal(0x1180UL, Assert.Single(env.Locate(0x380, "offset")).Rva); // .text raw data at 0x200
    }

    [Fact]
    public async Task Vtable_slots_resolve_through_base_types()
    {
        var path = _dir.File("Vt.dll");
        File.WriteAllBytes(path, ContainerFixtures.Module("Vt", BuildVTableTypes));
        using var env = new Env(path);
        var tools = env.MethodAddressTools();
        Assert.Contains("slot 5: Vt.Base::Run()  RVA=0x1400 Offset=0x800 VA=0x180001400 Slot=5  (inherited from Vt.Base)", await tools.GetMethodAddresses("Vt.Derived", slot: "5"));
        Assert.Contains("slot 6: Vt.Derived::Stop()  RVA=0x1500", await tools.GetMethodAddresses("Vt.Derived", slot: "6"));
        Assert.Contains("slot 6: Vt.Base::Stop()", await tools.GetMethodAddresses("Vt.Base", slot: "6"));
        Assert.Contains("slot 9: no method of Vt.Derived or its base types declares it (declared slots: 5-6)", await tools.GetMethodAddresses("Vt.Derived", slot: "9"));
        var all = await tools.GetMethodAddresses("Vt.Derived", slot: "all");
        Assert.Contains("vtable slots declared by it and its base types: 2", all);
        await Assert.ThrowsAsync<ToolError>(() => tools.GetMethodAddresses("Vt.Derived::Stop", slot: "6"));
    }

    /// <summary>Vt.Base with virtual Run (slot 5) and Stop (slot 6); Vt.Derived overrides Stop only.</summary>
    private static void BuildVTableTypes(ModuleDefUser module)
    {
        var address = AddressAttribute(module);
        MethodDefUser Virtual(string name, uint rva, int slot)
        {
            var m = new MethodDefUser(name, MethodSig.CreateInstance(module.CorLibTypes.Void),
                MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.HideBySig) { Body = Ret() };
            m.CustomAttributes.Add(Address(module, address, rva, slot));
            return m;
        }
        var baseType = new TypeDefUser("Vt", "Base", module.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.Public };
        baseType.Methods.Add(Virtual("Run", 0x1400, 5));
        baseType.Methods.Add(Virtual("Stop", 0x1440, 6));
        var derived = new TypeDefUser("Vt", "Derived", baseType) { Attributes = TypeAttributes.Public };
        derived.Methods.Add(Virtual("Stop", 0x1500, 6));
        module.Types.Add(baseType);
        module.Types.Add(derived);
    }

    private static CilBody Ret() => new() { Instructions = { OpCodes.Ret.ToInstruction() } };

    /// <summary>Il2CppDummyDll.AddressAttribute (RVA, Offset, VA, Slot); returns its constructor.</summary>
    private static MethodDefUser AddressAttribute(ModuleDefUser module)
    {
        var attribute = new TypeDefUser("Il2CppDummyDll", "AddressAttribute", module.Import(typeof(Attribute)));
        var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void),
            MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName) { Body = Ret() };
        attribute.Methods.Add(ctor);
        foreach (var field in new[] { "RVA", "Offset", "VA", "Slot" })
            attribute.Fields.Add(new FieldDefUser(field, new FieldSig(module.CorLibTypes.String), FieldAttributes.Public));
        module.Types.Add(attribute);
        return ctor;
    }

    private static CustomAttribute Address(ModuleDefUser module, MethodDefUser ctor, uint rva, int slot = -1)
    {
        var ca = new CustomAttribute(ctor);
        foreach (var (field, value) in new[] { ("RVA", $"0x{rva:X}"), ("Offset", $"0x{rva - 0xC00:X}"), ("VA", $"0x{0x180000000 + rva:X}"), ("Slot", slot.ToString()) })
            ca.NamedArguments.Add(new CANamedArgument(true, module.CorLibTypes.String, field, new CAArgument(module.CorLibTypes.String, value)));
        return ca;
    }

    private const string OverloadScript = """
        {
          "ScriptMethod": [
            { "Address": 4096, "Name": "Ov.Plain$$Run", "Signature": "void Ov_Plain__Run (Ov_Plain_o* __this, const MethodInfo* method);" },
            { "Address": 8192, "Name": "Ov.Box<int>$$Put", "Signature": "void Ov_Box_int__Put (Ov_Box_int__o* __this, int32_t item, const MethodInfo* method);" },
            { "Address": 8448, "Name": "Ov.Box<int>$$Put", "Signature": "void Ov_Box_int__Put (Ov_Box_int__o* __this, int32_t item, int32_t count, const MethodInfo_2100* method);" },
            { "Address": 8704, "Name": "Ov.Box<int>$$Get", "Signature": "int32_t Ov_Box_int__Get (Ov_Box_int__o* __this, int32_t , const MethodInfo* method);" },
            { "Address": 8960, "Name": "Ov.Box<int>$$Get", "Signature": "int32_t Ov_Box_int__Get (Ov_Box_int__o* __this, System_String_o* key, const MethodInfo* method);" },
            { "Address": 9216, "Name": "Ov.Box<int>$$Same", "Signature": "void Ov_Box_int__Same (Ov_Box_int__o* __this, int32_t value, const MethodInfo* method);" },
            { "Address": 9472, "Name": "Ov.Box<string>$$Same", "Signature": "void Ov_Box_string__Same (Ov_Box_string__o* __this, System_String_o* value, const MethodInfo* method);" },
            { "Address": 9728, "Name": "Ov.Box<int, string>$$Put", "Signature": "void Ov_Box_int__string__Put (Ov_Box_int__string__o* __this, int32_t a, System_String_o* b, const MethodInfo* method);" },
            { "Address": 9984, "Name": "Ov.Box<int>$$Put", "TypeSignature": "viiiii" }
          ],
          "Addresses": [ 4096, 8192, 8448, 8704, 8960, 9216, 9472, 9728, 9984, 10240 ]
        }
        """;

    /// <summary>
    /// Ov.Box`1 with Put(T) / Put(T, int) (told apart by count), Get(int) / Get(string) (by type), Same(T) / Same(int)
    /// (one C signature when T is int); Ov.Box`2 with Put(T1, T2) (by generic arity).
    /// </summary>
    private static void BuildOverloads(ModuleDefUser module)
    {
        var address = AddressAttribute(module);
        var types = module.CorLibTypes;
        var plain = new TypeDefUser("Ov", "Plain", types.Object.TypeDefOrRef) { Attributes = TypeAttributes.Public };
        var run = new MethodDefUser("Run", MethodSig.CreateInstance(types.Void), MethodAttributes.Public) { Body = Ret() };
        run.CustomAttributes.Add(Address(module, address, 0x1000));
        plain.Methods.Add(run);
        module.Types.Add(plain);
        TypeDefUser Box(int arity)
        {
            var box = new TypeDefUser("Ov", $"Box`{arity}", types.Object.TypeDefOrRef) { Attributes = TypeAttributes.Public };
            for (int i = 0; i < arity; i++) box.GenericParameters.Add(new GenericParamUser((ushort)i, GenericParamAttributes.NonVariant, arity == 1 ? "T" : $"T{i + 1}"));
            module.Types.Add(box);
            return box;
        }
        void Add(TypeDef type, string name, TypeSig ret, params TypeSig[] parameters) =>
            type.Methods.Add(new MethodDefUser(name, MethodSig.CreateInstance(ret, parameters), MethodAttributes.Public | MethodAttributes.HideBySig) { Body = Ret() });
        var box1 = Box(1);
        var t = new GenericVar(0, box1);
        Add(box1, "Put", types.Void, t);
        Add(box1, "Put", types.Void, t, types.Int32);
        Add(box1, "Get", types.Int32, types.Int32);
        Add(box1, "Get", types.Int32, types.String);
        Add(box1, "Same", types.Void, t);
        Add(box1, "Same", types.Void, types.Int32);
        var box2 = Box(2);
        Add(box2, "Put", types.Void, new GenericVar(0, box2), new GenericVar(1, box2));
    }

    private Env LoadOverloads()
    {
        var dummies = Path.Combine(_dir.Path, "ov", "DummyDll");
        Directory.CreateDirectory(dummies);
        var dll = Path.Combine(dummies, "Ov.dll");
        File.WriteAllBytes(dll, ContainerFixtures.Module("Ov", BuildOverloads));
        File.WriteAllText(Path.Combine(dummies, "..", "script.json"), OverloadScript);
        return new Env(dll);
    }

    [Fact]
    public async Task Instantiations_resolve_to_their_overload()
    {
        using var env = LoadOverloads();
        var tools = env.MethodAddressTools();
        var put = (await tools.GetMethodAddresses("Ov.Box<int>$$Put")).ReplaceLineEndings("\n");
        Assert.Contains("Ov.Box<int>$$Put  RVA 0x2000 (0x100 bytes)\n      definition: Ov.Box`1::Put(T)  [Ov] 0x06000003 (one of 3 methods named like it, by parameter count)", put);
        Assert.Contains("RVA 0x2100 (0x100 bytes)\n      definition: Ov.Box`1::Put(T, int)  [Ov]", put);
        Assert.Contains("RVA 0x2700 (0x100 bytes)\n      definition: none of the 3 methods named like it has its parameter count: Ov.Box`1::Put(T)", put);
        Assert.Contains("definition: Ov.Box`2::Put(T1, T2)  [Ov] 0x06000009 (one of 3 methods named like it, by generic arity)", await tools.GetMethodAddresses("Ov.Box<int, string>$$Put"));
        var get = (await tools.GetMethodAddresses("Ov.Box<int>$$Get")).ReplaceLineEndings("\n");
        Assert.Contains("RVA 0x2200 (0x100 bytes)\n      definition: Ov.Box`1::Get(int)  [Ov] 0x06000005 (one of 2 methods named like it, by parameter types)", get);
        Assert.Contains("RVA 0x2300 (0x100 bytes)\n      definition: Ov.Box`1::Get(string)  [Ov]", get);
        Assert.Contains("definition: ambiguous between 2 of the 2 methods named like it (the same C signature): Ov.Box`1::Same(T)  [Ov] 0x06000007; Ov.Box`1::Same(int)",
            await tools.GetMethodAddresses("Ov.Box<int>$$Same"));
        Assert.Contains("definition: Ov.Box`1::Same(T)  [Ov] 0x06000007 (one of 2 methods named like it, by parameter types)", await tools.GetMethodAddresses("Ov.Box<string>$$Same"));
        Assert.Contains("definition: Ov.Box`1::Get(string)", await tools.FindMethodByAddress("0x2300"));

        // The other way: each overload lists its own instantiations, the ambiguous one with the alternative.
        var putT = (await tools.GetMethodAddresses("Ov.Box`1::Put(T)")).ReplaceLineEndings("\n");
        Assert.Contains("generic instantiations in script.json: 1; 3 methods share the name, told apart by generic arity and C signature\n    Ov.Box<int>$$Put  RVA 0x2000\n", putT);
        Assert.Contains("(1 more script.json entry of the name fit no overload's parameter count)", putT);
        Assert.Contains("generic instantiations in script.json: 1;", await tools.GetMethodAddresses("Ov.Box`2::Put"));
        var same = await tools.GetMethodAddresses("Ov.Box`1::Same(int)");
        Assert.Contains("generic instantiations in script.json: 1; 2 methods share the name, told apart by generic arity and C signature (1 ambiguous)", same);
        Assert.Contains("Ov.Box<int>$$Same  RVA 0x2400  (ambiguous, the same C signature as Ov.Box`1::Same(T)  [Ov] 0x06000007)", same);
        Assert.Contains("Ov.Box<string>$$Same  RVA 0x2500\n", await tools.GetMethodAddresses("Ov.Box`1::Same(T)"));
    }

    /// <summary>
    /// Real dummy assemblies (CORVUS_AOT_STRINGS_DIR): navigation index build time and memory, and round trips:
    /// dummy method → RVA → method, instantiation name → RVA → name, type → TypeInfo slot → type, slot → method.
    /// </summary>
    [RequiresRealDataFact(RealData.AotStringsDir)]
    [Trait("Speed", "Slow")]
    public void Real_dummy_assemblies_round_trip_addresses_slots_and_names()
    {
        using var ws = new AssemblyWorkspace();
        ws.LoadDirectory(RealData.Path(RealData.AotStringsDir), false);
        var aot = new AotMetadataService(ws);
        var strings = new AotStringService(ws, aot);
        var navigator = new AotNavigator(ws, aot, strings);
        ws.Read(() => ws.Assemblies.Sum(a => aot.GetIndex(a).Count));
        var sw = Stopwatch.StartNew();
        var image = Assert.Single(ws.Read(() => navigator.ImagesFor(ws.Assemblies)), i => i.Script != null);
        var script = image.Script!;
        output.WriteLine($"images in {sw.ElapsedMilliseconds} ms: script.json {script.FunctionStarts.Length} function starts, {script.MethodCount} methods ({script.TypeNames.Count} type names, " +
                         $"{script.MethodNames.Count} method names), {script.MetadataCount} metadata and {script.MethodInfoCount} MethodInfo slots, read in {script.LoadTime.TotalMilliseconds:F0} ms");
        long before = GC.GetTotalMemory(true);
        var again = AotScript.Load(script.Path);
        output.WriteLine($"script.json index alone: {again.LoadTime.TotalMilliseconds:F0} ms, retained {(GC.GetTotalMemory(true) - before) / (1 << 20)} MB (arrays {again.RetainedBytes / (1 << 20)} MB)");
        GC.KeepAlive(again);

        var rng = new Random(7);
        var methods = ws.Assemblies.SelectMany(aot.GetIndex).Where(e => e.Rva is <= uint.MaxValue).ToList();
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
            var found = AotNavigator.FindScriptMethods(script, name);
            if (found.Contains(entry) && ws.Read(() => navigator.Locate(script.MethodAddress(entry), "rva", ws.Assemblies)) is [var r]
                && (r.ScriptMethods.Contains(entry) || r.Methods.Any(m => AotNames.MethodKey(m.Method) == name))) nameTrips++;
        }
        output.WriteLine($"script.json name -> RVA -> name: {nameTrips}/200 ({sw.ElapsedMilliseconds} ms)");

        var types = ws.Assemblies.SelectMany(a => a.Module.GetTypes()).Where(t => !t.HasGenericParameters).ToList();
        int typeSlots = 0, typeTrips = 0;
        sw.Restart();
        foreach (var t in Enumerable.Range(0, 500).Select(_ => types[rng.Next(types.Count)]))
        {
            if (script.MetadataNamed(AotNames.TypeKey(t) + "_TypeInfo") is not [var slot]) continue;
            typeSlots++;
            if (ws.Read(() => navigator.Locate(script.MetadataAddress(slot), "rva", ws.Assemblies)) is [{ Slot: { } s } r]
                && ws.Read(() => navigator.TypeOfMetadata(r.Image, script.MetadataName(s.Entry))).Any(x => x.Member == t)) typeTrips++;
            else if (typeSlots - typeTrips <= 5) output.WriteLine($"  not back to {t.FullName}: {script.MetadataName(slot)}");
        }
        output.WriteLine($"type -> TypeInfo slot -> type: {typeTrips}/{typeSlots} of 500 sampled types have a TypeInfo slot ({sw.ElapsedMilliseconds} ms)");

        var withSlots = methods.Where(e => e.Slot is { Length: > 0 } s && s != "-1").ToList();
        int slotTrips = 0;
        foreach (var e in Enumerable.Range(0, 500).Select(_ => withSlots[rng.Next(withSlots.Count)]))
            if (AotNavigator.SlotMethod(e.Method.DeclaringType, AotNavigator.SlotOf(e.Method)!.Value) == e.Method) slotTrips++;
        output.WriteLine($"(type, slot) -> method: {slotTrips}/500 of {withSlots.Count} methods with a slot");

        // Overloads: sampled instantiations of names several methods share, by outcome; resolved ones checked against
        // the prototype's parameter count, and instantiation -> definition -> its instantiations.
        var outcomes = new Dictionary<string, int>();
        int instantiations = 0, countChecked = 0, countAgrees = 0, trips = 0, tripsTried = 0;
        sw.Restart();
        ws.Read(() =>
        {
            for (int i = 0; i < 20_000; i++)
            {
                int entry = rng.Next(script.MethodCount);
                var (type, name) = (script.MethodTypeName(entry), script.MethodShortName(entry));
                if (AotNames.StripArgs(type) == type && AotNames.StripArgs(name) == name) continue;
                instantiations++;
                if (navigator.MethodsNamed(image, AotNames.StripArgs(type), AotNames.StripArgs(name)).Count < 2) continue;
                var match = navigator.DefinitionOf(image, entry);
                var key = $"{match.Outcome} ({match.Basis})";
                outcomes[key] = outcomes.GetValueOrDefault(key) + 1;
                if (match.Method is not { } method) continue;
                if (script.ReadMethod(entry).Signature is { } signature && signature.IndexOf('(') is var open and > 0)
                {
                    var parts = signature[(open + 1)..signature.LastIndexOf(')')].Split(',').Select(p => p.Trim()).Where(p => p.Length > 0).ToList();
                    int count = parts.Count - (parts.FirstOrDefault()?.EndsWith("__this") == true ? 1 : 0) - (parts.LastOrDefault()?.Contains("MethodInfo") == true ? 1 : 0);
                    countChecked++;
                    if (count == method.MethodSig.Params.Count) countAgrees++;
                }
                if (tripsTried < 200)
                {
                    tripsTried++;
                    if (navigator.Instantiations(image, method).Entries.Any(x => x.Entry == entry)) trips++;
                }
            }
            return 0;
        });
        int overloaded = outcomes.Values.Sum();
        output.WriteLine($"overloads: {overloaded} of {instantiations} sampled instantiations have a name several methods share ({sw.ElapsedMilliseconds} ms); " +
                         $"resolved ones with the prototype's parameter count: {countAgrees}/{countChecked}; instantiation -> definition -> instantiation: {trips}/{tripsTried}");
        foreach (var (key, n) in outcomes.OrderByDescending(kv => kv.Value)) output.WriteLine($"  {key}: {n}");
        Assert.Equal(countChecked, countAgrees);
        Assert.Equal(tripsTried, trips);
        Assert.True(methodTrips > 490 && nameTrips > 190);
        GC.KeepAlive(script);
    }
}
