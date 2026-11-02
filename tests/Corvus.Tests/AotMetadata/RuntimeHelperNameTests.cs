using Corvus.Native.Code;
using Corvus.Native.Providers;
using Corvus.Native.Annotations;
using Corvus.Services;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>Checks that runtime helpers are named from their instruction structure and near-miss bodies stay unnamed.</summary>
public sealed class RuntimeHelperNameTests : IDisposable
{
    private const ulong Base = 0x180000000UL;
    private const uint Start = 0x2000, Resolver = 0x2400, Raiser = 0x2440;

    // Provisional names, fixed when helper recognition defines them.
    private static readonly (string Name, uint Rva)[] Helpers =
    [
        ("runtime_initialize_metadata", 0x2100),
        ("runtime_allocate_object", 0x2140),
        ("runtime_throw_exception", 0x2180),
        ("runtime_throw_null_reference", 0x21C0),
        ("runtime_run_class_initializer", 0x2200),
    ];

    // One near-miss per category: same size and call shape, different body.
    private static readonly uint[] Decoys = [0x2240, 0x2280, 0x22C0, 0x2300];

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static byte[] Assemble(uint rva, Action<Assembler> build)
    {
        var a = new Assembler(64);
        build(a);
        var stream = new MemoryStream();
        a.Assemble(new StreamCodeWriter(stream), Base + rva);
        return stream.ToArray();
    }

    // Context pointer in rdx: flag at +0, class record at +8.
    private static byte[] Image()
    {
        var code = Enumerable.Repeat((byte)0xCC, 0x500).ToArray();
        void Put(uint rva, Action<Assembler> build) => Assemble(rva, build).CopyTo(code, (int)(rva - Start));
        // Driver and entry point: calls every helper so each is a function start.
        Put(Start, a =>
        {
            a.sub(rsp, 0x28);
            foreach (var (_, rva) in Helpers) a.call(Base + rva);
            foreach (var rva in Decoys) a.call(Base + rva);
            a.add(rsp, 0x28);
            a.ret();
        });
        // Guard flag: test it, call the resolver once, set it.
        Put(0x2100, a =>
        {
            var done = a.CreateLabel();
            a.cmp(__byte_ptr[rdx], 0);
            a.jne(done);
            a.call(Base + Resolver);
            a.mov(__byte_ptr[rdx], 1);
            a.Label(ref done);
            a.ret();
        });
        // Allocate: read the class record, call the allocator, store the class.
        Put(0x2140, a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rcx, __qword_ptr[rdx + 8]);
            a.call(Base + Resolver);
            a.mov(rcx, __qword_ptr[rdx + 8]);
            a.mov(__qword_ptr[rax], rcx);
            a.add(rsp, 0x28);
            a.ret();
        });
        // Throw: hand the exception to the raiser; it never returns.
        Put(0x2180, a => { a.sub(rsp, 0x28); a.call(Base + Raiser); a.int3(); });
        // Throw with no argument: build the exception first.
        Put(0x21C0, a =>
        {
            a.sub(rsp, 0x28);
            a.xor(ecx, ecx);
            a.call(Base + Resolver);
            a.mov(rcx, rax);
            a.call(Base + Raiser);
            a.int3();
        });
        // Class initializer: run once behind a flag held in the class record.
        Put(0x2200, a =>
        {
            var done = a.CreateLabel();
            a.mov(rax, __qword_ptr[rdx + 8]);
            a.cmp(__byte_ptr[rax + 0x10], 0);
            a.jne(done);
            a.call(Base + Resolver);
            a.mov(__byte_ptr[rax + 0x10], 1);
            a.Label(ref done);
            a.ret();
        });
        // Flag check that never calls the resolver.
        Put(Decoys[0], a =>
        {
            var done = a.CreateLabel();
            a.cmp(__byte_ptr[rdx], 0);
            a.jne(done);
            a.nop();
            a.nop();
            a.nop();
            a.nop();
            a.nop();
            a.mov(__byte_ptr[rdx], 1);
            a.Label(ref done);
            a.ret();
        });
        // Allocator call without storing the class.
        Put(Decoys[1], a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rcx, __qword_ptr[rdx + 8]);
            a.call(Base + Resolver);
            a.mov(rcx, __qword_ptr[rdx + 8]);
            a.mov(rax, rcx);
            a.add(rsp, 0x28);
            a.ret();
        });
        // Raiser call that returns.
        Put(Decoys[2], a => { a.sub(rsp, 0x28); a.call(Base + Raiser); a.add(rsp, 0x28); a.ret(); });
        // Initializer body without the once-only flag test.
        Put(Decoys[3], a =>
        {
            a.mov(rax, __qword_ptr[rdx + 8]);
            a.nop();
            a.nop();
            a.nop();
            a.nop();
            a.call(Base + Resolver);
            a.mov(__byte_ptr[rax + 0x10], 1);
            a.ret();
        });
        Put(Resolver, a => a.ret());
        Put(Raiser, a => a.int3());
        var b = new PeBuilder { ImageBase = Base };
        var text = b.Add(".text", code, 0x60000020);
        text.Rva = Start;
        b.EntryPoint = Start;
        b.Add(".data", new byte[0x100], 0xC0000040).Rva = 0x5000;
        return b.Build();
    }

    [Fact(Skip = "Needs helper recognition in AotNativeNames.Apply")]
    public async Task Runtime_helpers_are_named_from_their_structure_and_near_misses_are_not()
    {
        var (dll, path) = AotNativeNamesTests.CreateDump(_dir);
        // Only the driver has a metadata entry: only structure can name the rest.
        File.WriteAllText(Path.Combine(Path.GetDirectoryName(path)!, "script.json"),
            "{ \"ScriptMethod\": [ { \"Address\": 8192, \"Name\": \"Fixture.Native.NativeThing$$Run\" } ], \"ScriptMetadata\": [], \"ScriptMetadataMethod\": [], \"Addresses\": [ 8192 ] }");
        File.WriteAllBytes(path, Image());
        var env = new Env(dll);
        var code = new NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(_dir.File("ann")));
        var native = env.Workspace.LoadAny(path).Native!;
        var index = await code.Index(native, null, default);
        new AotNativeNames(env.AotMetadata, env.AotNavigator, code).Apply(native, index, env.Workspace.Assemblies, default);

        foreach (var (_, rva) in Helpers) Assert.NotNull(index.FunctionByStart(rva));
        foreach (var rva in Decoys) Assert.NotNull(index.FunctionByStart(rva));
        foreach (var (name, rva) in Helpers)
            Assert.Equal(name, index.NameAt(rva));
        foreach (var rva in Decoys)
            Assert.Equal($"sub_{Base + rva:X}", index.NameAt(rva));
    }
}
