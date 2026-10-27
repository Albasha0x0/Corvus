using System.Diagnostics;
using System.Text;
using Iced.Intel;
using Corvus.Native;
using Corvus.Native.Calls;
using Corvus.Native.Code;
using Corvus.Native.Pe;
using Xunit.Abstractions;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>Call-site arguments: synthetic x86 / x64 code, MSVC-compiled samples and a System32 recovery runner.</summary>
public class CallArgumentTests(ITestOutputHelper output)
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;
    private const uint Data = CodeTestImage.SyntheticDataRva;
    private const ulong Base64 = 0x140000000UL;
    private const ulong Base32 = 0x10000000UL;

    private static byte[] Assemble(int bitness, Action<Assembler> build)
    {
        var a = new Assembler(bitness);
        build(a);
        var stream = new MemoryStream();
        a.Assemble(new StreamCodeWriter(stream), (bitness == 64 ? Base64 : Base32) + Code);
        return stream.ToArray();
    }

    private static Instruction Rip(Iced.Intel.Code code, Register reg, uint rva) =>
        Instruction.Create(code, reg, new MemoryOperand(Register.RIP, (long)(Base64 + rva), 8));

    private static NativeImport Import(string name, uint slot) => new("KERNEL32.dll", name, null, 0, slot, false);

    [Fact]
    public void X64_arguments_are_recovered_from_registers_stack_slots_and_merges()
    {
        var code = Assemble(64, a =>
        {
            var l1 = a.CreateLabel();
            var l2 = a.CreateLabel();
            a.sub(rsp, 0x38);
            a.xor(r9d, r9d);
            a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RCX, Data + 0x100));
            a.mov(edx, 0x80000000);
            a.lea(r8d, __[r9 + 1]);
            a.mov(__dword_ptr[rsp + 0x20], 3);
            a.mov(__dword_ptr[rsp + 0x28], 0x80);
            a.and(__qword_ptr[rsp + 0x30], 0);
            a.AddInstruction(Instruction.Create(Iced.Intel.Code.Call_rm64, new MemoryOperand(Register.RIP, (long)(Base64 + Data), 8)));
            // Different values on two paths: unknown.
            a.mov(ecx, 1000);
            a.test(eax, eax);
            a.jz(l1);
            a.mov(ecx, 2000);
            a.Label(ref l1);
            a.AddInstruction(Instruction.Create(Iced.Intel.Code.Call_rm64, new MemoryOperand(Register.RIP, (long)(Base64 + Data + 8), 8)));
            // The same value on both paths.
            a.mov(ecx, 5);
            a.test(eax, eax);
            a.jz(l2);
            a.nop();
            a.Label(ref l2);
            a.AddInstruction(Instruction.Create(Iced.Intel.Code.Call_rm64, new MemoryOperand(Register.RIP, (long)(Base64 + Data + 8), 8)));
            a.add(rsp, 0x38);
            a.ret();
        });
        var data = new byte[0x200];
        Encoding.Unicode.GetBytes("config.ini\0").CopyTo(data, 0x100);
        var image = CodeTestImage.Synthetic(NativeArch.X64, code, data, [Import("CreateFileW", Data), Import("Sleep", Data + 8)], entry: Code);
        var index = NativeCodeIndex.Build(image);
        var calls = CallAnalysis.For(index).CallsIn(index.FunctionByStart(Code)!);

        Assert.Equal(3, calls.Count);
        Assert.Equal("CreateFileW(L\"config.ini\", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)", calls[0].Display);
        Assert.Equal(CalleeKind.Import, calls[0].Kind);
        var args = calls[0].Arguments;
        Assert.Equal(ArgKind.String, args[0].Kind);
        Assert.Equal("rcx", args[0].Location);
        Assert.Equal("[rsp+20h]", args[4].Location);
        Assert.Equal(3UL, args[4].Value);
        Assert.Contains("lea r8d", args[2].Derivation);
        Assert.Contains("xor r9d", args[2].Derivation);

        Assert.Equal(ArgKind.Unknown, calls[1].Arguments[0].Kind);
        Assert.Contains("differs between paths", calls[1].Arguments[0].Derivation);
        Assert.Equal("Sleep(5)", calls[2].Display);

        // A guessed call counts stack slots only from the first one up: a local stored above a gap is no argument.
        var guessed = Assemble(64, a =>
        {
            var callee = a.CreateLabel();
            a.sub(rsp, 0x88);
            a.mov(__qword_ptr[rsp + 0x60], rax);
            a.mov(ecx, 0x10);
            a.call(callee);
            a.add(rsp, 0x88);
            a.ret();
            a.Label(ref callee);
            a.mov(eax, ecx);
            a.ret();
        });
        var guessedIndex = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, guessed, entry: Code));
        var call = Assert.Single(CallAnalysis.For(guessedIndex).CallsIn(guessedIndex.FunctionByStart(Code)!));
        Assert.True(call.Guessed);
        Assert.Equal(["rcx"], call.Arguments.Select(x => x.Location));

        // Reference rows carry arguments only on the page asked for.
        var rows = Corvus.Tools.NativeCallTools.WithArguments(index, calls.Select(c => (c.Rva, "Call", true)), _ => "f", default, first: 2, count: 1);
        Assert.Equal([false, false, true], rows.Select(r => r.Contains('(')).ToArray());
        Assert.EndsWith("Sleep(5)", rows[2]);
    }

    [Fact]
    public void X86_pushes_cross_calls_by_their_stack_effect()
    {
        var code = Assemble(32, a =>
        {
            var helper = a.CreateLabel();
            a.push(0);
            a.push(0x80);
            a.push(3);
            a.push(0);
            a.push(1);
            a.push(0x80000000);
            a.call(helper);                          // cdecl, no arguments: ret 0
            a.push(eax);
            a.call(__dword_ptr[(int)(Base32 + Data)]); // CreateFileA
            a.push(7);
            a.push((int)(Base32 + Data + 0x120));
            a.push((int)(Base32 + Data + 0x100));
            a.call(__dword_ptr[(int)(Base32 + Data + 4)]); // printf
            a.add(esp, 12);
            a.mov(esi, __dword_ptr[(int)(Base32 + Data + 8)]);
            a.push(250);
            a.call(esi);                             // Sleep through a register
            a.ret();
            a.Label(ref helper);
            a.xor(eax, eax);
            a.ret();
        });
        var data = new byte[0x200];
        Encoding.ASCII.GetBytes("%s=%d\0").CopyTo(data, 0x100);
        Encoding.ASCII.GetBytes("key\0").CopyTo(data, 0x120);
        var image = CodeTestImage.Synthetic(NativeArch.X86, code, data,
            [Import("CreateFileA", Data), new NativeImport("msvcrt.dll", "printf", null, 0, Data + 4, false), Import("Sleep", Data + 8)], entry: Code);
        var index = NativeCodeIndex.Build(image);
        var analysis = CallAnalysis.For(index);
        var calls = analysis.CallsIn(index.FunctionByStart(Code)!);

        var create = calls.Single(c => c.Callee.EndsWith("CreateFileA"));
        Assert.StartsWith("CreateFileA(<result of sub_", create.Display);
        Assert.EndsWith(", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)", create.Display);
        Assert.Equal("printf(\"%s=%d\", \"key\", 7)", calls.Single(c => c.Callee.EndsWith("printf")).Display);
        var sleep = calls.Single(c => c.Callee.EndsWith("Sleep"));
        Assert.Equal("Sleep(250)", sleep.Display);
        Assert.Contains(analysis.CallsTo(image.Imports[2]), c => c.Rva == sleep.Rva);
    }

    [Fact]
    public void Late_bound_imports_resolve_names_modules_and_pointer_calls()
    {
        const uint LoadLibraryW = Data, GetProcAddress = Data + 8, GetModuleHandleW = Data + 16;
        const uint Handle = Data + 0x200, Fls = Data + 0x208, Ord = Data + 0x210;
        Instruction Mem(Iced.Intel.Code code, uint rva) => Instruction.Create(code, new MemoryOperand(Register.RIP, (long)(Base64 + rva), 8));
        Instruction Store(uint rva, Register reg) => Instruction.Create(Iced.Intel.Code.Mov_rm64_r64, new MemoryOperand(Register.RIP, (long)(Base64 + rva), 8), reg);
        Label user = default;
        var code = Assemble(64, a =>
        {
            var have = a.CreateLabel();
            user = a.CreateLabel();
            a.sub(rsp, 0x28);
            a.AddInstruction(Rip(Iced.Intel.Code.Mov_r64_rm64, Register.RAX, Handle)); // cached handle, or load it
            a.test(rax, rax);
            a.jnz(have);
            a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RCX, Data + 0x100));
            a.AddInstruction(Mem(Iced.Intel.Code.Call_rm64, LoadLibraryW));
            a.AddInstruction(Store(Handle, Register.RAX));
            a.Label(ref have);
            a.mov(rcx, rax);
            a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RDX, Data + 0x140));
            a.AddInstruction(Mem(Iced.Intel.Code.Call_rm64, GetProcAddress));
            a.AddInstruction(Store(Fls, Register.RAX));
            a.call(user);
            a.add(rsp, 0x28);
            a.ret();
            // user: GetProcAddress(GetModuleHandleW(L"user32.dll"), 5), then calls through both pointers
            a.Label(ref user);
            a.sub(rsp, 0x28);
            a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RCX, Data + 0x160));
            a.AddInstruction(Mem(Iced.Intel.Code.Call_rm64, GetModuleHandleW));
            a.mov(rcx, rax);
            a.mov(edx, 5);
            a.AddInstruction(Mem(Iced.Intel.Code.Call_rm64, GetProcAddress));
            a.AddInstruction(Store(Ord, Register.RAX));
            a.xor(ecx, ecx);
            a.AddInstruction(Mem(Iced.Intel.Code.Call_rm64, Fls));
            a.AddInstruction(Rip(Iced.Intel.Code.Mov_r64_rm64, Register.RAX, Fls));
            a.call(rax);
            a.AddInstruction(Mem(Iced.Intel.Code.Call_rm64, Ord));
            a.add(rsp, 0x28);
            a.ret();
        });
        var data = new byte[0x300];
        Encoding.Unicode.GetBytes("kernel32.dll\0").CopyTo(data, 0x100);
        Encoding.ASCII.GetBytes("FlsAlloc\0").CopyTo(data, 0x140);
        Encoding.Unicode.GetBytes("user32.dll\0").CopyTo(data, 0x160);
        var image = CodeTestImage.Synthetic(NativeArch.X64, code, data,
            [Import("LoadLibraryW", LoadLibraryW), Import("GetProcAddress", GetProcAddress), Import("GetModuleHandleW", GetModuleHandleW)], entry: Code);
        var index = NativeCodeIndex.Build(image);
        var analysis = CallAnalysis.For(index);
        var set = analysis.DynamicImports();

        Assert.Equal(2, set.GetProcAddressSites);
        var fls = Assert.Single(set.Find("kernel32!FlsAlloc"));
        Assert.Equal("kernel32.dll", fls.Module);
        Assert.Equal("medium", fls.Confidence); // the handle may come from the global written once
        Assert.Equal(Fls, fls.PointerGlobal);
        Assert.Equal(2, fls.PointerCalls.Count);
        var ord = Assert.Single(set.Find("user32!#5"));
        Assert.Equal("high", ord.Confidence);
        Assert.Contains(set.Modules, m => m.Module == "kernel32.dll" && m.Api == "LoadLibraryW");
        Assert.Contains(set.Modules, m => m.Module == "user32.dll" && m.Api == "GetModuleHandleW");

        var userFn = index.FunctionAt(fls.PointerCalls[0])!;
        var calls = analysis.CallsIn(userFn).Where(c => c.Kind == CalleeKind.Dynamic).ToList();
        Assert.Equal(["kernel32!FlsAlloc", "kernel32!FlsAlloc", "user32!#5"], calls.Select(c => c.Callee));
        Assert.Contains(set.CallsByFunction[userFn.Start], c => c.Import == fls);
    }

    /// <summary>resolve(name) returns GetProcAddress(GetModuleHandleW(L"kernel32.dll"), name); main: resolve("FlsAlloc")(0).</summary>
    [Fact]
    public void A_name_passed_to_a_resolver_wrapper_names_the_register_call()
    {
        const uint GetProcAddress = Data, GetModuleHandleW = Data + 8;
        Instruction Mem(Iced.Intel.Code code, uint rva) => Instruction.Create(code, new MemoryOperand(Register.RIP, (long)(Base64 + rva), 8));
        Label resolve = default, late = default;
        var code = Assemble(64, a =>
        {
            resolve = a.CreateLabel();
            late = a.CreateLabel();
            a.sub(rsp, 0x28);
            a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RCX, Data + 0x140));
            a.call(resolve);
            a.xor(ecx, ecx);
            a.Label(ref late);
            a.call(rax);
            a.add(rsp, 0x28);
            a.ret();
            a.Label(ref resolve);
            a.push(rbx);
            a.sub(rsp, 0x20);
            a.mov(rbx, rcx);
            a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RCX, Data + 0x100));
            a.AddInstruction(Mem(Iced.Intel.Code.Call_rm64, GetModuleHandleW));
            a.mov(rcx, rax);
            a.mov(rdx, rbx);
            a.AddInstruction(Mem(Iced.Intel.Code.Call_rm64, GetProcAddress));
            a.add(rsp, 0x20);
            a.pop(rbx);
            a.ret();
        });
        var data = new byte[0x200];
        Encoding.Unicode.GetBytes("kernel32.dll\0").CopyTo(data, 0x100);
        Encoding.ASCII.GetBytes("FlsAlloc\0").CopyTo(data, 0x140);
        var image = CodeTestImage.Synthetic(NativeArch.X64, code, data, [Import("GetProcAddress", GetProcAddress), Import("GetModuleHandleW", GetModuleHandleW)], entry: Code);
        var index = NativeCodeIndex.Build(image);
        var analysis = CallAnalysis.For(index);
        var fls = Assert.Single(analysis.DynamicImports().Find("kernel32!FlsAlloc"));
        Assert.Contains("passed to", fls.How);
        var call = analysis.CallsIn(index.FunctionByStart(Code)!).Single(c => c.Kind == CalleeKind.Dynamic);
        Assert.Equal("kernel32!FlsAlloc", call.Callee);
        var target = CallTargets.At(analysis, call.Rva, deep: false)!;
        Assert.Equal(("resolved", "getprocaddress"), (target.Status, target.Targets.Single().Basis));
    }

    [Fact]
    public void Flags_and_enumerations_decode_by_mask()
    {
        var mb = ApiSignatures.Find("user32!MessageBoxW")!.Params[3].Enum!;
        Assert.Equal("MB_YESNO|MB_ICONERROR", mb.Describe(0x14));
        Assert.Equal("MB_OK", mb.Describe(0));
        var access = ApiSignatures.Enums["Access"];
        Assert.Equal("GENERIC_READ|GENERIC_WRITE", access.Describe(0xC0000000));
        Assert.Equal("FILE_GENERIC_READ|FILE_WRITE_DATA", access.Describe(0x12008B));
        Assert.Equal("HKEY_LOCAL_MACHINE", ApiSignatures.Enums["HKEY"].Describe(0xFFFFFFFF80000002));
        Assert.True(ApiSignatures.Enums["PageProtect"].Has(0x140, "PAGE_EXECUTE_READWRITE"));
        Assert.NotNull(ApiSignatures.Find("_CreateFileW@28"));
        var open64 = ApiSignatures.ForOs(ApiSignatures.Find("libc.so.6!open64"), ApiOs.Linux)!;
        Assert.Equal("O_RDONLY|O_CLOEXEC", open64.Params[1].Enum!.Describe(0x80000));
        Assert.Equal([ApiParamType.WideString, ApiParamType.Int, ApiParamType.Int, ApiParamType.Int64, ApiParamType.Pointer],
            ApiSignatures.FormatArguments("%s %*d %llx %p %%", wide: true));
    }

    /// <summary>open flags and address families decode by the image's OS (Linux, Darwin and the Microsoft CRT differ); an unknown OS keeps the number.</summary>
    [Fact]
    public void Os_dependent_flags_decode_by_the_images_operating_system()
    {
        string? Open(ApiOs os, ulong v) => ApiSignatures.ForOs(ApiSignatures.Find("openat"), os)!.Params[2].Enum?.Describe(v);
        Assert.Equal("O_WRONLY|O_CREAT|O_TRUNC", Open(ApiOs.Linux, 0x241));
        Assert.Equal("O_WRONLY|O_CREAT|O_TRUNC", Open(ApiOs.Darwin, 0x601));
        Assert.Equal("_O_WRONLY|_O_CREAT|_O_TRUNC", Open(ApiOs.Windows, 0x301));
        Assert.Null(Open(ApiOs.Unknown, 0x241));
        var raw = ApiSignatures.Find("open64")!.Params[1];
        Assert.Equal((ApiParamType.Hex, "OpenFlags"), (raw.Type, raw.TypeName));
        Assert.Equal("AF_INET6", ApiSignatures.ForOs(ApiSignatures.Find("socket"), ApiOs.Linux)!.Params[0].Enum!.Describe(10));
        Assert.Equal("AF_INET6", ApiSignatures.ForOs(ApiSignatures.Find("ws2_32!socket"), ApiOs.Windows)!.Params[0].Enum!.Describe(23));

        static Native.Elf.ElfFile Elf(Action<NativeFormats.ElfWriter> set)
        {
            var w = new NativeFormats.ElfWriter();
            set(w);
            return Native.Elf.ElfFile.FromBytes(w.Build(), "sample.so");
        }
        Assert.Equal(ApiOs.Linux, ApiSignatures.OsOf(Elf(w => w.Needed = ["libc.so.6"])));
        Assert.Equal(ApiOs.Linux, ApiSignatures.OsOf(Elf(w => w.AndroidIdent = (24, "r25"))));
        Assert.Equal(ApiOs.Linux, ApiSignatures.OsOf(Elf(w => w.Interpreter = "/lib/ld-linux-aarch64.so.1")));
        Assert.Equal(ApiOs.Unknown, ApiSignatures.OsOf(Elf(w => w.Needed = ["libc.so.7"])));
        Assert.Equal(ApiOs.Windows, ApiSignatures.OsOf(CodeTestImage.Synthetic(NativeArch.X64, [0xC3])));
        Assert.Equal(ApiOs.Darwin, ApiSignatures.OsOf(CodeTestImage.Synthetic(NativeArch.Arm64, [0xC0, 0x03, 0x5F, 0xD6], format: ImageFormat.MachO)));
    }

    // ---- MSVC samples (Slow) ----

    private const string SampleSource = """
        #include <windows.h>
        #include <stdio.h>
        #pragma comment(lib, "user32.lib")
        #pragma comment(lib, "advapi32.lib")

        __declspec(noinline) HANDLE OpenConfig(void)
        {
            return CreateFileW(L"config.ini", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        }

        __declspec(noinline) void* Exec(SIZE_T n)
        {
            void* p = VirtualAlloc(NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            DWORD old;
            VirtualProtect(p, n, PAGE_EXECUTE_READWRITE, &old);
            return p;
        }

        __declspec(noinline) LONG Reg(HKEY* key)
        {
            return RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Sample", 0, KEY_READ | KEY_WOW64_64KEY, key);
        }

        __declspec(noinline) int Ask(int code)
        {
            printf("code %d: %s\n", code, "sample");
            return MessageBoxA(NULL, "Continue?", "Sample", MB_YESNO | MB_ICONQUESTION);
        }

        __declspec(noinline) BOOL Spawn(wchar_t* cmd, STARTUPINFOW* si, PROCESS_INFORMATION* pi)
        {
            return CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, si, pi);
        }

        int main(void)
        {
            HKEY key;
            STARTUPINFOW si = { sizeof si };
            PROCESS_INFORMATION pi;
            wchar_t cmd[] = L"notepad.exe";
            HANDLE h = OpenConfig();
            Exec(4096);
            Reg(&key);
            Spawn(cmd, &si, &pi);
            return Ask((int)(INT_PTR)h);
        }
        """;

    /// <summary>Builds the sample with cl / link for <paramref name="arch"/>; null when the build tools are absent.</summary>
    internal static string? BuildSample(TempDir dir, string arch, string source, string name = "sample", string runtime = "/MD")
    {
        var vcvars = VisualStudio.VcVarsAll();
        if (vcvars == null) return null;
        File.WriteAllText(dir.File(name + ".c"), source);
        var psi = new ProcessStartInfo("cmd.exe")
        {
            WorkingDirectory = dir.Path,
            Arguments = $"/s /c \"\"{vcvars}\" {arch} >nul && cl /nologo /O2 /GS- {runtime} {name}.c /link /OUT:{name}.exe\"",
        };
        var (code, log) = Tools.Run(psi, 300_000);
        Assert.True(code == 0 && File.Exists(dir.File(name + ".exe")), log);
        return dir.File(name + ".exe");
    }

    [Theory]
    [Trait("Speed", "Slow")]
    [InlineData("x64")]
    [InlineData("x86")]
    public void Compiled_sample_arguments_match_the_source(string arch)
    {
        using var dir = new TempDir();
        var path = BuildSample(dir, arch, SampleSource);
        if (path == null) return;
        var pe = PeFile.Open(path);
        var index = NativeCodeIndex.Build(pe);
        var analysis = CallAnalysis.For(index);
        CallSiteInfo One(string api)
        {
            var imp = pe.Imports.First(i => i.Name == api);
            var sites = analysis.CallsTo(imp);
            foreach (var s in sites) output.WriteLine($"{arch} {s.Display}: {string.Join(" | ", s.Arguments.Select(a => a.Derivation))}");
            return Assert.Single(sites);
        }
        Assert.Equal("CreateFileW(L\"config.ini\", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)", One("CreateFileW").Display);
        Assert.Matches(@"^VirtualAlloc\(NULL, [^,]+, MEM_COMMIT\|MEM_RESERVE, PAGE_READWRITE\)$", One("VirtualAlloc").Display);
        Assert.Matches(@"^VirtualProtect\(<result of VirtualAlloc>, [^,]+, PAGE_EXECUTE_READWRITE, &local\)$", One("VirtualProtect").Display);
        Assert.Matches(@"^RegOpenKeyExW\(HKEY_LOCAL_MACHINE, L""Software\\\\Sample"", REG_OPTION_NON_VOLATILE, KEY_READ\|KEY_WOW64_64KEY, [^,]+\)$", One("RegOpenKeyExW").Display);
        Assert.Equal("MessageBoxA(NULL, \"Continue?\", \"Sample\", MB_YESNO|MB_ICONQUESTION)", One("MessageBoxA").Display);
        Assert.Matches(@"^CreateProcessW\(NULL, [^,]+, NULL, NULL, FALSE, CREATE_SUSPENDED\|CREATE_NO_WINDOW, NULL, NULL, [^,]+, [^,]+\)$", One("CreateProcessW").Display);
        // printf is an inline function of the UCRT headers, compiled into the image: its call gets guessed arguments
        var printf = index.Functions.SelectMany(f => analysis.CallsIn(f))
            .Single(s => s.Guessed && s.Arguments.Any(a => a.Text == "\"code %d: %s\\n\""));
        output.WriteLine($"{arch} {printf.Display}");
        Assert.Contains(printf.Arguments, a => a.Text == "\"sample\"");
    }

    // ---- System32 runner (Slow) ----

    /// <summary>APIs whose calls usually pass at least one constant: the recovery rate counts call sites where one is recovered.</summary>
    private static readonly string[] RunnerApis =
    [
        "CreateFileW", "CreateFileA", "VirtualAlloc", "VirtualProtect", "VirtualFree", "RegOpenKeyExW", "RegCreateKeyExW", "RegQueryValueExW",
        "RegGetValueW", "LoadLibraryExW", "LoadLibraryW", "GetModuleHandleW", "GetProcAddress", "HeapAlloc", "WaitForSingleObject",
        "CreateEventW", "InitializeCriticalSectionAndSpinCount", "MessageBoxW", "OpenProcess", "CreateMutexW", "LocalAlloc", "FormatMessageW",
    ];

    [Trait("Tier", "Release")]
    [Fact]
    [Trait("Speed", "Slow")]
    public void System32_argument_recovery_rates()
    {
        var files = new[] { "kernel32.dll", "advapi32.dll", "shell32.dll", "user32.dll", "combase.dll", "ole32.dll", "wininet.dll", "msi.dll", "explorer.exe", "notepad.exe", "cmd.exe", "taskmgr.exe" };
        foreach (var dir in MsvcCorpus.SystemDirectories())
        {
            int sites = 0, withConstant = 0, args = 0, recovered = 0, guessedSites = 0;
            var sw = Stopwatch.StartNew();
            foreach (var name in files)
            {
                var path = Path.Combine(dir, name);
                if (!File.Exists(path)) continue;
                var pe = PeFile.Open(path);
                if (pe.Arch is not (NativeArch.X64 or NativeArch.X86)) continue;
                var index = NativeCodeIndex.Build(pe);
                var analysis = CallAnalysis.For(index);
                int fileSites = 0, fileConst = 0;
                foreach (var imp in pe.Imports.Where(i => i.Name != null && RunnerApis.Contains(i.Name)))
                    foreach (var s in analysis.CallsTo(imp))
                    {
                        sites++; fileSites++;
                        args += s.Arguments.Count;
                        int known = s.Arguments.Count(a => a.Kind != ArgKind.Unknown);
                        recovered += known;
                        if (s.Arguments.Any(a => a.Kind is ArgKind.Immediate or ArgKind.String)) { withConstant++; fileConst++; }
                        else if (Environment.GetEnvironmentVariable("CORVUS_DEBUG_ARGS") == "1" && fileSites - fileConst < 3)
                            output.WriteLine($"    {s.Display} @{s.Rva:X}: {string.Join(" | ", s.Arguments.Select(a => a.Derivation))}");
                    }
                // Every call of the image: no exception, guessed arguments for unknown callees.
                foreach (var f in index.Functions.Take(3000))
                    foreach (var s in analysis.CallsIn(f))
                        if (s.Guessed) guessedSites++;
                output.WriteLine($"  {name}: {fileConst}/{fileSites} API call sites with a constant argument");
            }
            output.WriteLine($"{dir}: {withConstant}/{sites} API call sites with a recovered constant ({Pct(withConstant, sites)}), " +
                             $"{recovered}/{args} arguments recovered ({Pct(recovered, args)}), {guessedSites} calls without a signature, {sw.Elapsed.TotalSeconds:0.0} s");
            if (sites > 50) Assert.True(withConstant * 100 / sites >= 60, $"recovery rate {Pct(withConstant, sites)}");
        }
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void System32_dynamic_imports()
    {
        var files = new[] { "kernel32.dll", "kernelbase.dll", "advapi32.dll", "shell32.dll", "user32.dll", "combase.dll", "ole32.dll", "wininet.dll",
            "urlmon.dll", "dbghelp.dll", "msi.dll", "explorer.exe", "notepad.exe", "cmd.exe", "taskmgr.exe" };
        foreach (var dir in MsvcCorpus.SystemDirectories())
        {
            int sites = 0, resolved = 0, withModule = 0, high = 0, pointers = 0, pointerCalls = 0, modules = 0;
            var sw = Stopwatch.StartNew();
            foreach (var name in files)
            {
                var path = Path.Combine(dir, name);
                if (!File.Exists(path)) continue;
                var pe = PeFile.Open(path);
                if (pe.Arch is not (NativeArch.X64 or NativeArch.X86)) continue;
                var index = NativeCodeIndex.Build(pe);
                var t = Stopwatch.StartNew();
                var set = CallAnalysis.For(index).DynamicImports();
                sites += set.GetProcAddressSites;
                resolved += set.Imports.Count;
                withModule += set.Imports.Count(i => i.Module != null);
                high += set.Imports.Count(i => i.Confidence == "high");
                pointers += set.ByGlobal.Count;
                pointerCalls += set.ByGlobal.Values.Sum(i => i.PointerCalls.Count);
                modules += set.Modules.Count;
                output.WriteLine($"  {name}: {set.Imports.Count}/{set.GetProcAddressSites} GetProcAddress calls resolved ({set.Imports.Count(i => i.Module != null)} with module), " +
                                 $"{set.ByGlobal.Count} pointer globals, {set.ByGlobal.Values.Sum(i => i.PointerCalls.Count)} calls through them, " +
                                 $"{set.Modules.Count} modules by name, {t.ElapsedMilliseconds} ms; e.g. {string.Join(", ", set.Imports.Take(3).Select(i => i.FullName))}");
                if (Environment.GetEnvironmentVariable("CORVUS_DEBUG_ARGS") == "1")
                {
                    var analysis = CallAnalysis.For(index);
                    foreach (var d in set.Imports.Where(i => i.Module == null).Take(4))
                        output.WriteLine($"    no module: {d.Name} @{d.CallSite:X}: {analysis.CallAt(d.CallSite)?.Arguments[0].Derivation}");
                    foreach (var d in set.ByGlobal.Values.Where(i => i.PointerCalls.Count == 0).Take(2))
                        output.WriteLine($"    no calls: {d.FullName} [{d.PointerGlobal:X}]: {string.Join(", ", index.RefsTo(d.PointerGlobal!.Value).Select(x => $"{x.Kind}@{x.From:X}"))}");
                }
                foreach (var d in set.Imports)
                {
                    Assert.False(string.IsNullOrEmpty(d.Name));
                    Assert.Contains(d.Confidence, new[] { "high", "medium", "low" });
                }
            }
            output.WriteLine($"{dir}: {resolved}/{sites} GetProcAddress calls with a constant name ({Pct(resolved, sites)}), {withModule} with the module traced " +
                             $"({high} high confidence), {pointers} pointer globals with {pointerCalls} calls through them, {modules} LoadLibrary/GetModuleHandle " +
                             $"calls with a constant name; {sw.Elapsed.TotalSeconds:0.0} s");
        }
    }

    /// <summary>The tool surface on kernel32: disassembly comments, find_xrefs, get_call_arguments, get_pe_info, list_imports, call tree.</summary>
    [WindowsFact]
    [Trait("Speed", "Slow")]
    public async Task Tools_show_arguments_and_late_bound_imports()
    {
        var kernel32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll");
        using var env = new Env();
        var service = new Corvus.Services.NativeCodeService(env.Workspace, env.Options);
        var codeTools = new Corvus.Tools.NativeCodeTools(env.Workspace, service, env.Pager);
        var peTools = new Corvus.Tools.NativeTools(env.Workspace, env.Pager, service);
        var callTools = new Corvus.Tools.NativeCallTools(env.Workspace, service);

        var collector = Corvus.Mcp.ToolOutput.Collect();
        var text = await callTools.GetCallArguments(kernel32, callee: "CreateFileW", limit: 5);
        var report = Assert.IsType<Corvus.Tools.NativeCallTools.CallArgumentsReport>(collector.Value);
        Assert.True(report.Total > 0);
        var site = report.Items.First(c => c.Arguments.Count == 7);
        Assert.Matches($@"{site.Address}  \S+  CreateFileW\(", text);
        Assert.Contains("CreateFileW(", await codeTools.Disassemble(kernel32, site.Address));
        Assert.Contains("CreateFileW(", await codeTools.FindXrefs(kernel32, site.Callee));

        var native = env.Workspace.Read(() => env.Workspace.GetNative("kernel32.dll"));
        var index = await service.Index(native, null, default);
        var set = CallAnalysis.For(index).DynamicImports();
        Assert.Contains("[dynamic: GetProcAddress at", await peTools.ListImports(kernel32, filter: set.Imports[0].Name, includeDynamic: true));
        var codeView = await peTools.GetPeInfo(kernel32, view: "code");
        Assert.Contains("Dynamic imports (GetProcAddress):", codeView);
        if (set.Modules.Count > 0) Assert.Contains("Modules loaded or looked up by name: ", codeView);
        var called = set.Imports.FirstOrDefault(i => i.PointerCalls.Count > 0);
        if (called != null)
        {
            var xrefs = await codeTools.FindXrefs(kernel32, called.FullName);
            output.WriteLine(xrefs);
            Assert.Contains("DynCall", xrefs);
            var caller = index.FunctionAt(called.PointerCalls[0])!;
            var tree = await codeTools.NativeCallTree(kernel32, $"0x{index.Image.ImageBase + caller.Start:X}", depth: 1);
            output.WriteLine(tree);
            Assert.Contains($"{called.FullName}  [dynamic]", tree);
            // The cross-image tree (the server's configuration).
            var linked = new Corvus.Tools.NativeCodeTools(env.Workspace, service, env.Pager, new Corvus.Services.NativeLinkService(env.Workspace, service));
            Assert.Contains($"{called.FullName}  [dynamic]", await linked.NativeCallTree(kernel32, $"0x{index.Image.ImageBase + caller.Start:X}", depth: 1));
        }
    }

    private static string Pct(int a, int b) => b == 0 ? "n/a" : $"{100.0 * a / b:0.0}%";
}
