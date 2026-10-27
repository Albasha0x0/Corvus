using System.Text;
using Iced.Intel;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Services;
using Corvus.Tests.NativeFormats;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>Node-API registration calls in synthetic x64 code, Windows and System V, read into the napi name layer.</summary>
public sealed class NodeApiTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static readonly string[] Imports = ["napi_create_function", "napi_define_properties", "napi_define_class", "napi_module_register"];

    // Callbacks at fixed offsets after the registering function; distinct bodies so none fold.
    internal const uint Hello = 0x200; private const uint Add = 0x210, Version = 0x220, Ctor = 0x230, Increment = 0x240, Init = 0x250;
    // Data offsets.
    private const uint SHello = 0x100, SAdd = 0x110, SVersion = 0x118, SCounter = 0x128, SIncrement = 0x138, SAddon = 0x148, Props = 0x200, ClassProps = 0x280, Module = 0x2C0;

    private static readonly string[] Expected =
    [
        "js_hello function hello", "js_add function add", "js_get_version getter version", "js_Counter constructor Counter",
        "js_Counter_increment method Counter.increment", "napi_module_init_addon module_init addon",
    ];

    /// <summary>The registering function and the callbacks; slots are the import slots in Imports order.</summary>
    private static byte[] Code(bool sysv, ulong textVa, ulong dataVa, Func<int, ulong> slotVa)
    {
        var a = new Assembler(64);
        Register[] args = sysv ? [rdi, rsi, rdx, rcx, r8, r9] : [rcx, rdx, r8, r9];
        void Lea(Register r, ulong va) => a.AddInstruction(Instruction.Create(Iced.Intel.Code.Lea_r64_m, r, new MemoryOperand(Register.RIP, (long)va, 8)));
        void Call(int import) => a.AddInstruction(Instruction.Create(Iced.Intel.Code.Call_rm64, new MemoryOperand(Register.RIP, (long)slotVa(import), 8)));
        // Argument i: a register, else the stack slot past the Windows home area or at [rsp] under System V.
        void Set(int i, Action<AssemblerRegister64> reg, Action<AssemblerMemoryOperand> stack)
        {
            if (i < args.Length) reg(new AssemblerRegister64(args[i]));
            else stack(__qword_ptr[rsp + (sysv ? 8 * (i - 6) : 0x20 + 8 * (i - 4))]);
        }
        void Address(int i, ulong va) => Set(i, r => Lea(r.Value, va), m => { Lea(Register.RAX, va); a.mov(m, rax); });
        void Number(int i, long v) => Set(i, r => a.mov(r, v), m => a.mov(m, (int)v));

        a.sub(rsp, 0x58);
        // napi_create_function(env, "hello", NAPI_AUTO_LENGTH, Hello, NULL, &result).
        Number(0, 0); Address(1, dataVa + SHello); Number(2, -1); Address(3, textVa + Hello); Number(4, 0); Address(5, dataVa + 0x3F0);
        Call(0);
        // napi_define_properties(env, exports, 2, Props).
        Number(0, 0); Number(1, 0); Number(2, 2); Address(3, dataVa + Props);
        Call(1);
        // napi_define_class(env, "Counter", 7, Ctor, NULL, 1, ClassProps, &result).
        Number(0, 0); Address(1, dataVa + SCounter); Number(2, 7); Address(3, textVa + Ctor); Number(4, 0); Number(5, 1); Address(6, dataVa + ClassProps); Address(7, dataVa + 0x3F0);
        Call(2);
        // napi_module_register(&Module).
        Address(0, dataVa + Module);
        Call(3);
        a.add(rsp, 0x58);
        a.ret();
        var stream = new MemoryStream();
        a.Assemble(new StreamCodeWriter(stream), textVa);
        var code = new byte[0x260];
        var main = stream.ToArray();
        Assert.True(main.Length < Hello);
        main.CopyTo(code, 0);
        foreach (var (at, value) in new[] { (Hello, 1), (Add, 2), (Version, 3), (Ctor, 4), (Increment, 5), (Init, 6) })
            new byte[] { 0xB8, (byte)value, 0, 0, 0, 0xC3 }.CopyTo(code, at); // mov eax, value; ret
        return code;
    }

    /// <summary>Strings, property descriptor arrays and the napi_module; pointers are VAs, listed in <paramref name="pointers"/> for relocations.</summary>
    private static byte[] Data(ulong textVa, ulong dataVa, List<uint> pointers)
    {
        var d = new byte[0x400];
        void Str(uint at, string s) => Encoding.ASCII.GetBytes(s + "\0").CopyTo(d, at);
        void Ptr(uint at, ulong va) { BitConverter.GetBytes(va).CopyTo(d, at); pointers.Add(at); }
        Str(SHello, "hello"); Str(SAdd, "add"); Str(SVersion, "version"); Str(SCounter, "CounterWithSuffix"); Str(SIncrement, "increment"); Str(SAddon, "addon");
        // napi_property_descriptor: utf8name, name, method, getter, setter, value, attributes, data.
        Ptr(Props, dataVa + SAdd); Ptr(Props + 16, textVa + Add);
        Ptr(Props + 64, dataVa + SVersion); Ptr(Props + 64 + 24, textVa + Version);
        Ptr(ClassProps, dataVa + SIncrement); Ptr(ClassProps + 16, textVa + Increment);
        // napi_module: nm_version, nm_flags, nm_filename, nm_register_func, nm_modname.
        BitConverter.GetBytes(1).CopyTo(d, Module);
        Ptr(Module + 16, textVa + Init); Ptr(Module + 24, dataVa + SAddon);
        return d;
    }

    private static List<string> Rows(NodeApi.Result found, INativeImage image)
    {
        var (names, _) = NodeApi.Names(image, found.Registrations);
        return found.Registrations.Select(r => $"{names[r.Function]} {r.Kind} {r.JsName}").ToList();
    }

    [Theory]
    [InlineData(ImageFormat.Pe)]
    [InlineData(ImageFormat.MachO)]
    public void Registrations_are_read_from_constant_arguments(ImageFormat format)
    {
        const uint text = CodeTestImage.SyntheticCodeRva, data = CodeTestImage.SyntheticDataRva;
        const ulong b = 0x140000000UL;
        bool sysv = format != ImageFormat.Pe;
        var code = Code(sysv, b + text, b + data, i => b + data + 8 * (uint)i);
        string prefix = format == ImageFormat.MachO ? "_" : "";
        var image = CodeTestImage.Synthetic(NativeArch.X64, code, Data(b + text, b + data, []),
            Imports.Select((n, i) => new NativeImport(format == ImageFormat.Pe ? "node.exe" : "", prefix + n, null, 0, data + 8 * (uint)i, true)),
            exports: [new NativeExport(prefix + "napi_register_module_v1", 1, text, null)], format: format);
        Assert.True(NodeApi.IsAddon(image));
        var index = NativeCodeIndex.Build(image);
        var found = NodeApi.Find(index);
        Assert.Equal(Expected, Rows(found, image));
        Assert.Equal(text + Hello, found.Registrations[0].Function);
        Assert.Empty(found.Notes);
    }

    /// <summary>node-addon-api's exports.Set("hello", Function::New(env, Hello)): the callback passed to a helper, then the named setter.</summary>
    [Fact]
    public void Named_setters_after_a_function_helper_are_registrations()
    {
        const uint text = CodeTestImage.SyntheticCodeRva, data = CodeTestImage.SyntheticDataRva, helper = Add;
        const ulong b = 0x140000000UL;
        var a = new Assembler(64);
        a.sub(rsp, 0x28);
        a.AddInstruction(Instruction.Create(Iced.Intel.Code.Lea_r64_m, Register.R8, new MemoryOperand(Register.RIP, (long)(b + text + Hello), 8)));
        a.AddInstruction(Instruction.CreateBranch(Iced.Intel.Code.Call_rel32_64, b + text + helper));
        a.mov(rcx, 0); a.mov(rdx, 0);
        a.AddInstruction(Instruction.Create(Iced.Intel.Code.Lea_r64_m, Register.R8, new MemoryOperand(Register.RIP, (long)(b + data + SHello), 8)));
        a.mov(r9, rax);
        a.AddInstruction(Instruction.Create(Iced.Intel.Code.Call_rm64, new MemoryOperand(Register.RIP, (long)(b + data), 8)));
        a.add(rsp, 0x28);
        a.ret();
        var stream = new MemoryStream();
        a.Assemble(new StreamCodeWriter(stream), b + text);
        var code = new byte[0x260];
        stream.ToArray().CopyTo(code, 0);
        new byte[] { 0xB8, 1, 0, 0, 0, 0xC3 }.CopyTo(code, Hello);
        new byte[] { 0x48, 0x8B, 0xC1, 0xC3 }.CopyTo(code, helper); // mov rax, rcx; ret
        var d = new byte[0x400];
        Encoding.ASCII.GetBytes("hello\0").CopyTo(d, SHello);
        var image = CodeTestImage.Synthetic(NativeArch.X64, code, d, [new NativeImport("node.exe", "napi_set_named_property", null, 0, data, true)],
            exports: [new NativeExport("napi_register_module_v1", 1, text, null)], format: ImageFormat.Pe);
        var r = Assert.Single(NodeApi.Find(NativeCodeIndex.Build(image)).Registrations);
        Assert.Equal((text + Hello, "hello", "napi_set_named_property"), (r.Function, r.JsName, r.Via));
    }

    /// <summary>An x64 ELF add-on registering hello and a Counter class through N-API.</summary>
    internal static byte[] ElfAddon()
    {
        var elf = new ElfWriter { Machine = ElfWriter.EmX64, Type = 3, SoName = "addon.node", Needed = ["libnode.so"], PltImports = [.. Imports] };
        ulong textVa = ElfWriter.TextRva, dataVa = ElfWriter.DataRva;
        elf.Text = Code(sysv: true, textVa, dataVa, i => elf.PltSlotRva(i));
        var pointers = new List<uint>();
        elf.Data = Data(textVa, dataVa, pointers);
        foreach (var at in pointers) elf.Relocations.Add(new ElfWriter.Reloc(ElfWriter.DataRva + at, 8, null, (long)BitConverter.ToUInt64(elf.Data, (int)at)));
        elf.Symbols.Add(new ElfWriter.Symbol("napi_register_module_v1", ElfWriter.TextRva, 0x60));
        return elf.Build();
    }

    [Fact]
    public async Task An_ELF_addon_gets_the_layer_when_indexed()
    {
        var path = _dir.File("addon.node");
        File.WriteAllBytes(path, ElfAddon());

        var options = new ServerOptions();
        using var ws = new AssemblyWorkspace(options);
        var code = new NativeCodeService(ws, options);
        var native = ws.LoadAny(path).Native!;
        var index = await code.Index(native, null, default);
        Assert.Equal(("js_hello", NativeNameSource.NodeApi), index.Sourced.NameAt(ElfWriter.TextRva + Hello));
        Assert.Equal(("js_Counter_increment", NativeNameSource.NodeApi), index.Sourced.NameAt(ElfWriter.TextRva + Increment));
        Assert.StartsWith("Node-API method 'Counter.increment' (napi_define_class at 0x", index.Sourced.CommentAt(ElfWriter.TextRva + Increment)!.Value.Text);
        Assert.StartsWith("Node-API registrations (6 callbacks", NativeNameLayers.Of(native).Get(NativeNameSource.NodeApi)!.Origin);
    }

    [RequiresRealDataFact(RealData.ElectronApps)]
    [Trait("Speed", "Slow")]
    public async Task Real_addons_name_their_callbacks()
    {
        var addons = Directory.EnumerateFiles(RealData.Path(RealData.ElectronApps), "*.node",
                new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 10, IgnoreInaccessible = true })
            .Where(f => new FileInfo(f).Length < 64 * 1024 * 1024).Take(20).ToList();
        var options = new ServerOptions();
        using var ws = new AssemblyWorkspace(options);
        var code = new NativeCodeService(ws, options);
        var report = new List<string>();
        foreach (var path in addons)
        {
            LoadedNative native;
            try { native = ws.LoadAny(path).Native!; }
            catch (ToolError ex) { report.Add($"{path}: not loaded ({ex.Message})"); continue; }
            var index = await code.Index(native, null, default);
            var layer = NativeNameLayers.Of(native).Get(NativeNameSource.NodeApi);
            report.Add($"{path}: {(layer == null ? "not an add-on" : layer.Origin)}; e.g. {string.Join(", ", layer?.Names.Values.Take(5) ?? [])}");
            ws.UnloadNative(native);
        }
        Console.WriteLine(string.Join(Environment.NewLine, report));
    }

    [Fact]
    public void Other_images_are_not_addons()
    {
        var image = CodeTestImage.Synthetic(NativeArch.X64, [0xC3], imports: [new NativeImport("KERNEL32.dll", "Sleep", null, 0, CodeTestImage.SyntheticDataRva, false)]);
        Assert.False(NodeApi.IsAddon(image));
    }
}
