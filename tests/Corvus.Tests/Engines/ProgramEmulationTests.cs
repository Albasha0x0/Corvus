using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native.Dump;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Worker;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>A small x86 program for the emulator, built here: it allocates a page, decodes a fixed text into it, writes it to a file and exits.</summary>
internal static class EmulatorFixture
{
    public const string Text = "decoded by the fixture";
    public const string FileName = "out.txt";
    public const byte Key = 0x5A;
    public const string MissingFunction = "FixtureMissingFunction";

    /// <summary>The program; with <paramref name="unmodelled"/> it first calls a kernel32 function no emulator models.</summary>
    public static byte[] Build(bool unmodelled = false)
    {
        const uint Base = 0x400000, CodeRva = 0x1000, DataRva = 0x2000;
        string[] imports = unmodelled
            ? [MissingFunction, "VirtualAlloc", "CreateFileA", "WriteFile", "CloseHandle", "ExitProcess"]
            : ["VirtualAlloc", "CreateFileA", "WriteFile", "CloseHandle", "ExitProcess"];
        // Import descriptor (one and a terminator), lookup table, address table, hint/name entries, then the data.
        var rd = new PeBlob(DataRva);
        uint descriptor = rd.Zero(40);
        uint lookup = rd.Zero(4 * (imports.Length + 1));
        uint iat = rd.Zero(4 * (imports.Length + 1));
        var names = new List<uint>();
        foreach (var name in imports)
        {
            rd.Align(2);
            uint at = rd.U16(0);
            rd.Ascii(name);
            names.Add(at);
        }
        uint dll = rd.Ascii("KERNEL32.dll");
        uint encoded = rd.Bytes(Encoding.ASCII.GetBytes(Text).Select(b => (byte)(b ^ Key)).ToArray());
        uint file = rd.Ascii(FileName);
        rd.Align(4);
        uint written = rd.U32(0);
        for (int i = 0; i < names.Count; i++)
        {
            rd.Patch32(lookup + 4 * (uint)i, names[i]);
            rd.Patch32(iat + 4 * (uint)i, names[i]);
        }
        rd.Patch32(descriptor, lookup);
        rd.Patch32(descriptor + 12, dll);
        rd.Patch32(descriptor + 16, iat);

        var c = new List<byte>();
        void Push(uint v)
        {
            if (v < 0x80) c.AddRange([0x6A, (byte)v]);
            else { c.Add(0x68); c.AddRange(BitConverter.GetBytes(v)); }
        }
        void Call(string name)
        {
            c.AddRange([0xFF, 0x15]);
            c.AddRange(BitConverter.GetBytes(Base + iat + 4 * (uint)Array.IndexOf(imports, name)));
        }
        if (unmodelled) Call(MissingFunction);
        Push(4); Push(0x3000); Push(0x1000); Push(0); Call("VirtualAlloc");
        // mov edi, eax; mov esi, encoded; xor ecx, ecx
        c.AddRange([0x89, 0xC7, 0xBE]);
        c.AddRange(BitConverter.GetBytes(Base + encoded));
        c.AddRange([0x31, 0xC9]);
        int loop = c.Count;
        // mov al, [esi+ecx]; xor al, Key; mov [edi+ecx], al; inc ecx; cmp ecx, length; jb loop; mov byte [edi+ecx], 0
        c.AddRange([0x8A, 0x04, 0x0E, 0x34, Key, 0x88, 0x04, 0x0F, 0x41, 0x83, 0xF9, (byte)Text.Length]);
        c.AddRange([0x72, (byte)(loop - (c.Count + 2))]);
        c.AddRange([0xC6, 0x04, 0x0F, 0x00]);
        Push(0); Push(0x80); Push(2); Push(0); Push(0); Push(0x40000000); Push(Base + file); Call("CreateFileA");
        // mov ebx, eax
        c.AddRange([0x89, 0xC3]);
        Push(0); Push(Base + written); Push((uint)Text.Length);
        // push edi; push ebx
        c.AddRange([0x57, 0x53]);
        Call("WriteFile");
        c.Add(0x53);
        Call("CloseHandle");
        Push(0); Call("ExitProcess");

        var pe = new PeBuilder { Is64 = false, Machine = 0x14C, Characteristics = 0x0102, DllCharacteristics = 0, ImageBase = Base, EntryPoint = CodeRva };
        pe.Add(".text", [.. c], 0x60000020);
        pe.Add(".rdata", rd.ToArray(), 0xC0000040);
        pe.Directories[1] = (descriptor, 40);
        pe.Directories[12] = (iat, 4 * (uint)(imports.Length + 1));
        return pe.Build();
    }

    /// <summary>The same program for x64, calling by the Windows x64 convention.</summary>
    public static byte[] Build64()
    {
        const ulong Base = 0x140000000;
        const uint CodeRva = 0x1000, DataRva = 0x2000;
        string[] imports = ["VirtualAlloc", "CreateFileA", "WriteFile", "CloseHandle", "ExitProcess"];
        var rd = new PeBlob(DataRva);
        uint descriptor = rd.Zero(40);
        uint lookup = rd.Zero(8 * (imports.Length + 1));
        uint iat = rd.Zero(8 * (imports.Length + 1));
        var names = new List<uint>();
        foreach (var name in imports)
        {
            rd.Align(2);
            uint at = rd.U16(0);
            rd.Ascii(name);
            names.Add(at);
        }
        uint dll = rd.Ascii("KERNEL32.dll");
        uint encoded = rd.Bytes(Encoding.ASCII.GetBytes(Text).Select(b => (byte)(b ^ Key)).ToArray());
        uint file = rd.Ascii(FileName);
        rd.Align(8);
        uint written = rd.U32(0);
        for (int i = 0; i < names.Count; i++)
        {
            rd.Patch32(lookup + 8 * (uint)i, names[i]);
            rd.Patch32(iat + 8 * (uint)i, names[i]);
        }
        rd.Patch32(descriptor, lookup);
        rd.Patch32(descriptor + 12, dll);
        rd.Patch32(descriptor + 16, iat);

        var c = new List<byte>();
        // An instruction ending in a 32-bit displacement from its own end to the data at rva.
        void Relative(byte[] opcode, uint rva)
        {
            c.AddRange(opcode);
            c.AddRange(BitConverter.GetBytes((int)(rva - (CodeRva + (uint)c.Count + 4))));
        }
        void Call(string name) => Relative([0xFF, 0x15], iat + 8 * (uint)Array.IndexOf(imports, name));
        void Imm32(byte[] opcode, uint v)
        {
            c.AddRange(opcode);
            c.AddRange(BitConverter.GetBytes(v));
        }
        // sub rsp, 0x38: shadow space and three stack arguments, 16-byte aligned at each call.
        c.AddRange([0x48, 0x83, 0xEC, 0x38]);
        // VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        c.AddRange([0x31, 0xC9]);
        Imm32([0xBA], 0x1000);
        Imm32([0x41, 0xB8], 0x3000);
        Imm32([0x41, 0xB9], 4);
        Call("VirtualAlloc");
        // mov rdi, rax; lea rsi, [encoded]; xor ecx, ecx
        c.AddRange([0x48, 0x89, 0xC7]);
        Relative([0x48, 0x8D, 0x35], encoded);
        c.AddRange([0x31, 0xC9]);
        int loop = c.Count;
        // mov al, [rsi+rcx]; xor al, Key; mov [rdi+rcx], al; inc ecx; cmp ecx, length; jb loop; mov byte [rdi+rcx], 0
        c.AddRange([0x8A, 0x04, 0x0E, 0x34, Key, 0x88, 0x04, 0x0F, 0xFF, 0xC1, 0x83, 0xF9, (byte)Text.Length]);
        c.AddRange([0x72, (byte)(loop - (c.Count + 2))]);
        c.AddRange([0xC6, 0x04, 0x0F, 0x00]);
        // CreateFileA(name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
        Relative([0x48, 0x8D, 0x0D], file);
        Imm32([0xBA], 0x40000000);
        c.AddRange([0x45, 0x31, 0xC0, 0x45, 0x31, 0xC9]);
        Imm32([0xC7, 0x44, 0x24, 0x20], 2);
        Imm32([0xC7, 0x44, 0x24, 0x28], 0x80);
        Imm32([0x48, 0xC7, 0x44, 0x24, 0x30], 0);
        Call("CreateFileA");
        // mov rbx, rax; WriteFile(rbx, rdi, length, &written, NULL)
        c.AddRange([0x48, 0x89, 0xC3, 0x48, 0x89, 0xD9, 0x48, 0x89, 0xFA]);
        Imm32([0x41, 0xB8], (uint)Text.Length);
        Relative([0x4C, 0x8D, 0x0D], written);
        Imm32([0x48, 0xC7, 0x44, 0x24, 0x20], 0);
        Call("WriteFile");
        // CloseHandle(rbx); ExitProcess(0)
        c.AddRange([0x48, 0x89, 0xD9]);
        Call("CloseHandle");
        c.AddRange([0x31, 0xC9]);
        Call("ExitProcess");

        var pe = new PeBuilder { Is64 = true, Machine = 0x8664, Characteristics = 0x0022, DllCharacteristics = 0, ImageBase = Base, EntryPoint = CodeRva };
        pe.Add(".text", [.. c], 0x60000020);
        pe.Add(".rdata", rd.ToArray(), 0xC0000040);
        pe.Directories[1] = (descriptor, 40);
        pe.Directories[12] = (iat, 8 * (uint)(imports.Length + 1));
        return pe.Build();
    }
}

/// <summary>The speakeasy engine of emulate_native: the worker op against a stand-in emulator that writes a report of format 5.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class ProgramEmulationTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>A report as speakeasy 2.0.0b9 writes it for <see cref="EmulatorFixture"/>; <paramref name="error"/> ends the run early.</summary>
    internal static byte[] Report(JsonObject? error = null, string version = "5.0.0")
    {
        var data = new JsonObject();
        string Blob(byte[] bytes)
        {
            var key = Convert.ToHexStringLower(SHA256.HashData(bytes));
            using var packed = new MemoryStream();
            using (var z = new ZLibStream(packed, CompressionLevel.Fastest)) z.Write(bytes);
            data[key] = new JsonObject { ["compression"] = "zlib", ["encoding"] = "base64", ["size"] = bytes.Length, ["data"] = Convert.ToBase64String(packed.ToArray()) };
            return key;
        }
        var text = Encoding.ASCII.GetBytes(EmulatorFixture.Text);
        var page = new byte[0x1000];
        text.CopyTo(page, 0);
        static JsonObject Region(string tag, ulong at, ulong size, string prot, string? reference) =>
            new() { ["tag"] = tag, ["address"] = $"0x{at:x}", ["size"] = $"0x{size:x}", ["prot"] = prot, ["is_free"] = false, ["data_ref"] = reference };
        static JsonObject Api(uint pc, string name, string ret, params (string Name, string Display)[] args) => new()
        {
            ["pos"] = new JsonObject { ["tick"] = 0, ["tid"] = 1076, ["pid"] = 1056, ["pc"] = pc }, ["event"] = "api", ["api_name"] = name,
            ["args"] = new JsonArray([.. args.Select(a => (JsonNode)new JsonObject { ["name"] = a.Name, ["type"] = "ptr", ["value"] = 0, ["display"] = a.Display })]),
            ["ret_val"] = ret,
        };
        var ep = new JsonObject
        {
            ["ep_type"] = "module_entry", ["start_addr"] = "0x401000", ["tid"] = 1076, ["ret_val"] = error == null ? "0x0" : null,
            ["events"] = new JsonArray(
                new JsonObject { ["pos"] = new JsonObject { ["pid"] = 1056, ["pc"] = 4198420 }, ["event"] = "mem_alloc", ["base"] = "0x50000", ["size"] = "0x1000" },
                Api(0x401014, "kernel32.VirtualAlloc", "0x50000", ("lpAddress", "0x0"), ("dwSize", "0x1000"), ("flAllocationType", "MEM_RESERVE|MEM_COMMIT"), ("flProtect", "PAGE_READWRITE")),
                Api(0x401043, "kernel32.CreateFileA", "0x80", ("lpFileName", "out.txt"), ("dwDesiredAccess", "GENERIC_WRITE")),
                Api(0x401057, "kernel32.WriteFile", "0x1", ("hFile", "0x80"), ("lpBuffer", "0x50000"), ("nNumberOfBytesToWrite", "0x16"))),
            ["dropped_files"] = new JsonArray(new JsonObject
            {
                ["path"] = @"C:\Windows\system32\out.txt", ["size"] = text.Length, ["sha256"] = Convert.ToHexStringLower(SHA256.HashData(text)), ["data_ref"] = Blob(text),
            }),
            ["memory"] = new JsonObject
            {
                ["modules"] = new JsonArray(new JsonObject { ["name"] = "fixture.exe", ["base"] = "0x400000", ["size"] = "0x3000" },
                    new JsonObject { ["name"] = "kernel32.dll", ["base"] = "0x77000000", ["size"] = "0x1000" }),
                ["layout"] = new JsonArray(
                    Region("emu.module.fixture.exe.headers.0x400000", 0x400000, 0x1000, "r--", Blob(new byte[0x1000])),
                    Region("emu.module.fixture.exe..text.0x401000", 0x401000, 0x200, "r-x", Blob(new byte[0x200])),
                    Region("api.VirtualAlloc.0x50000", 0x50000, 0x1000, "rw-", Blob(page)),
                    Region("emu.stack.0x1200000", 0x1200000, 0x1000, "rw-", Blob(new byte[0x1000])),
                    Region("emu.struct.PEB.0x1030", 0x1030, 0x470, "rwx", Blob(new byte[0x470])),
                    Region("emu.module.kernel32.dll.headers.0x77000000", 0x77000000, 0x1000, "r--", Blob(new byte[0x1000]))),
            },
        };
        if (error != null) ep["error"] = error;
        var root = new JsonObject
        {
            ["report_version"] = version, ["emulation_total_runtime"] = 0.25, ["arch"] = "x86", ["size"] = 2048, ["image_base"] = "0x400000",
            ["data"] = data, ["entry_points"] = new JsonArray(ep),
        };
        return Encoding.UTF8.GetBytes(root.ToJsonString());
    }

    private JsonObject Request(FakeTool fake, string input)
    {
        if (!File.Exists(input)) File.WriteAllBytes(input, "MZ"u8.ToArray());
        return Request(fake.CopyAs("speakeasy"), input);
    }

    private JsonObject Request(string emulator, string input) => new()
    {
        ["emulator"] = emulator, ["input"] = input, ["output"] = _dir.File("run-" + Guid.NewGuid().ToString("N")[..6]), ["seconds"] = 5,
    };

    [Fact]
    public async Task A_run_gives_the_calls_the_written_file_and_a_region_set_holding_the_decoded_text()
    {
        using var fake = new FakeTool();
        fake.On("speakeasy|-t ", file: Report());
        using var env = new EnvironmentScope().Set(FakeTool.ScriptVariable, fake.ScriptPath);
        var input = _dir.File("fixture.exe");
        File.WriteAllBytes(input, EmulatorFixture.Build());
        var request = Request(fake, input);
        var answer = await ProgramEmulationOps.Emulate(request, default);
        var run = answer!.Deserialize<ProgramEmulation>(ProgramEmulationOps.Json)!;

        var argv = Assert.Single(fake.ArgumentLists);
        // The emulator gets a copy alone in its folder, as speakeasy mounts the files beside its input.
        Assert.Equal(["-t", Path.Combine((string)request["output"]!, "target", "fixture.exe")], argv[..2]);
        Assert.Contains("--no-modules-functions-always-exist", argv);
        Assert.Contains("--snapshot-memory-regions", argv);
        Assert.DoesNotContain("--entry-point", argv);
        Assert.Equal("-o", argv[^2]);
        Assert.Equal(("complete", "x86", "0x0"), (run.Stop, run.Arch, run.ReturnValue));
        Assert.Equal(["kernel32.VirtualAlloc", "kernel32.CreateFileA", "kernel32.WriteFile"], run.ApiCalls.Select(a => a.Api));
        Assert.Equal("0x401014", run.ApiCalls[0].Site);
        Assert.Contains("flAllocationType=MEM_RESERVE|MEM_COMMIT", run.ApiCalls[0].Arguments);
        Assert.Equal("0x50000", run.ApiCalls[0].Returned);
        var written = Assert.Single(run.FilesWritten);
        Assert.Equal((@"C:\Windows\system32\out.txt", (long)EmulatorFixture.Text.Length), (written.Path, written.Size));
        Assert.Equal(EmulatorFixture.Text, File.ReadAllText(written.SavedAs!));

        // The program's image, allocation and stack are kept; the emulator's own structures and system modules are not.
        Assert.Equal(4, run.Regions);
        Assert.Contains(run.Notes, n => n.StartsWith("2 region(s) of the emulator's own", StringComparison.Ordinal));
        var set = RegionSetFile.Open(run.RegionSet!);
        Assert.Equal((1056u, Native.NativeArch.X86), (set.ProcessId, set.Arch));
        var bytes = new byte[EmulatorFixture.Text.Length];
        Assert.Equal(bytes.Length, set.ReadMemory(0x50000, bytes));
        Assert.Equal(EmulatorFixture.Text, Encoding.ASCII.GetString(bytes));
        Assert.Equal(0x04u, set.Regions.Single(r => r.Base == 0x50000).Protect);
        Assert.Equal("fixture.exe", Assert.Single(set.Modules).Path);
    }

    [Fact]
    public async Task Raw_code_runs_from_its_offset_and_a_pe_from_an_address_other_than_its_entry()
    {
        using var fake = new FakeTool();
        fake.On("speakeasy|-t ", file: Report());
        using var env = new EnvironmentScope().Set(FakeTool.ScriptVariable, fake.ScriptPath);
        var input = _dir.File("code.bin");
        File.WriteAllBytes(input, [0xB8, 0x2A, 0, 0, 0, 0xC3]);
        var raw = Request(fake, input);
        raw["raw"] = true;
        raw["offset"] = 0x10;
        raw["arch"] = "amd64";
        await ProgramEmulationOps.Emulate(raw, default);
        var pe = Request(fake, input);
        pe["entry"] = 0x1234;
        await ProgramEmulationOps.Emulate(pe, default);

        var (first, second) = (fake.ArgumentLists[0], fake.ArgumentLists[1]);
        Assert.Equal(["--raw", "--raw-offset", "0x10", "--arch", "amd64"], first[^7..^2]);
        Assert.Equal(["--entry-point", "0x1234"], second[^4..^2]);
        Assert.Equal("-o", first[^2]);
    }

    [Fact]
    public async Task A_stop_before_the_end_keeps_the_calls_made_and_names_the_api()
    {
        using var fake = new FakeTool();
        var error = new JsonObject { ["type"] = "unsupported_api", ["api_name"] = "kernel32." + EmulatorFixture.MissingFunction, ["pc"] = "0x401006" };
        fake.On("speakeasy|-t ", file: Report(error));
        using var env = new EnvironmentScope().Set(FakeTool.ScriptVariable, fake.ScriptPath);
        var answer = await ProgramEmulationOps.Emulate(Request(fake, _dir.File("x.exe")), default);
        var run = answer!.Deserialize<ProgramEmulation>(ProgramEmulationOps.Json)!;
        Assert.Equal(("unsupported_api", "0x401006", "kernel32." + EmulatorFixture.MissingFunction), (run.Stop, run.StoppedAt, run.Detail));
        Assert.Null(run.ReturnValue);
        Assert.Equal(3, run.ApiCalls.Count);
    }

    [Fact]
    public async Task A_report_of_another_format_is_refused_with_the_tested_version()
    {
        using var fake = new FakeTool();
        fake.On("speakeasy|-t ", file: Report(version: "6.0.0"));
        using var env = new EnvironmentScope().Set(FakeTool.ScriptVariable, fake.ScriptPath);
        var e = await Assert.ThrowsAsync<ToolError>(() => ProgramEmulationOps.Emulate(Request(fake, _dir.File("x.exe")), default));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.Contains("format 6.0.0", e.Message);
        Assert.Contains("2.0.0b9", e.Message);
    }

    [Fact]
    public async Task An_emulator_that_writes_no_report_is_named_with_its_last_error_line()
    {
        using var fake = new FakeTool();
        fake.On("speakeasy|-t ", stderr: "starting\nUnsupported file type\n", exit: 1);
        using var env = new EnvironmentScope().Set(FakeTool.ScriptVariable, fake.ScriptPath);
        var e = await Assert.ThrowsAsync<ToolError>(() => ProgramEmulationOps.Emulate(Request(fake, _dir.File("x.exe")), default));
        Assert.Equal(ErrorCode.ProviderUnavailable, e.Code);
        Assert.Contains("exited with 1", e.Message);
        Assert.Contains("Unsupported file type", e.Message);
    }

    [Fact]
    public async Task Speakeasy_refuses_ghidra_only_arguments_and_a_missing_emulator_names_its_variable()
    {
        var tools = new NativeEmulationTools(null!, null!);
        var refused = await Assert.ThrowsAsync<ToolError>(() => tools.EmulateNative("x.exe", "entry", args: "1", stubs: "*=0", engine: "speakeasy"));
        Assert.Equal(ErrorCode.InvalidArgument, refused.Code);
        Assert.Contains("args, stubs", refused.Message);
        using var env = new EnvironmentScope().Set(ExternalTools.Emulator.Variable, Path.Combine(_dir.File("no-emulator"), "speakeasy.exe"));
        var missing = await Assert.ThrowsAsync<ToolError>(() => tools.EmulateNative("x.exe", "entry", engine: "speakeasy"));
        Assert.Equal(ErrorCode.ProviderUnavailable, missing.Code);
        Assert.Contains(ExternalTools.Emulator.Variable, missing.Message);
    }

    [Fact]
    public async Task Through_the_tool_an_unmodelled_api_is_an_error_whose_partial_result_lists_the_calls_before_it()
    {
        using var fake = new FakeTool();
        var error = new JsonObject { ["type"] = "unsupported_api", ["api_name"] = "kernel32." + EmulatorFixture.MissingFunction, ["pc"] = "0x401006" };
        fake.On("speakeasy|-t ", file: Report(error));
        using var env = new EnvironmentScope().Set(ExternalTools.Emulator.Variable, fake.CopyAs("speakeasy"));
        // The worker passes the stand-in's script on to the emulator it starts.
        using var pool = new WorkerPool(new WorkerPoolOptions
        {
            Enabled = true, MemoryLimitBytes = 0,
            Start = WorkerPool.OwnCommand() with { Environment = new Dictionary<string, string?> { [FakeTool.ScriptVariable] = fake.ScriptPath } },
        });
        using var shared = WorkerPool.UseShared(pool);
        var exe = _dir.File("fixture.exe");
        File.WriteAllBytes(exe, EmulatorFixture.Build(unmodelled: true));
        var before = NativeEmulationTools.RunsRoot;
        NativeEmulationTools.RunsRoot = _dir.File("runs");
        try
        {
            var options = new ServerOptions { BackgroundIndexing = false };
            using var workspace = new AssemblyWorkspace(options);
            var tools = new NativeEmulationTools(workspace, null!);
            var e = await Assert.ThrowsAsync<ToolError>(() => tools.EmulateNative(exe, "0x401000", engine: "speakeasy"));
            Assert.Equal(ErrorCode.Unsupported, e.Code);
            Assert.Contains(EmulatorFixture.MissingFunction, e.Message);
            var partial = Assert.IsType<string>(e.Partial);
            Assert.Contains("kernel32.WriteFile(", partial);
            Assert.Contains("wrote C:\\Windows\\system32\\out.txt", partial);
            Assert.Single(Directory.GetDirectories(Path.Combine(NativeEmulationTools.RunsRoot, workspace.Natives.Single().OriginalSha256[..16])));
        }
        finally { NativeEmulationTools.RunsRoot = before; }
    }

    [Fact]
    public void Runs_past_the_kept_count_are_deleted_oldest_first()
    {
        var before = NativeEmulationTools.RunsRoot;
        NativeEmulationTools.RunsRoot = _dir.File("kept");
        try
        {
            var made = Enumerable.Range(0, NativeEmulationTools.KeptRuns + 2).Select(_ => NativeEmulationTools.NewRunFolder("ab12")).ToList();
            var left = Directory.GetDirectories(Path.Combine(NativeEmulationTools.RunsRoot, "ab12")).Order(StringComparer.Ordinal).ToList();
            Assert.Equal(made.TakeLast(NativeEmulationTools.KeptRuns), left);
        }
        finally { NativeEmulationTools.RunsRoot = before; }
    }
}

/// <summary>emulate_native engine=speakeasy with the real emulator (<c>CORVUS_EMULATOR</c>) on <see cref="EmulatorFixture"/>.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
[Trait("Speed", "Slow")]
public sealed class ProgramEmulationRealTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private async Task<(string Text, NativeEmulationTools.EmulationReport? Report, ToolError? Error)> Run(bool unmodelled, bool x64 = false)
    {
        var exe = _dir.File(unmodelled ? "unmodelled.exe" : x64 ? "fixture64.exe" : "fixture.exe");
        File.WriteAllBytes(exe, x64 ? EmulatorFixture.Build64() : EmulatorFixture.Build(unmodelled));
        var before = NativeEmulationTools.RunsRoot;
        NativeEmulationTools.RunsRoot = _dir.File("runs");
        try
        {
            using var pool = new WorkerPool(new WorkerPoolOptions { Enabled = true, MemoryLimitBytes = 0 });
            using var shared = WorkerPool.UseShared(pool);
            using var workspace = new AssemblyWorkspace(new ServerOptions { BackgroundIndexing = false });
            var tools = new NativeEmulationTools(workspace, null!);
            try
            {
                var collector = Mcp.ToolOutput.Collect();
                var output = await tools.EmulateNative(exe, x64 ? "0x140001000" : "0x401000", engine: "speakeasy", timeoutSeconds: 60);
                return (output, Assert.IsType<NativeEmulationTools.EmulationReport>(collector.Value), null);
            }
            catch (ToolError e) { return ((string)e.Partial!, null, e); }
        }
        finally { NativeEmulationTools.RunsRoot = before; }
    }

    [RequiresRealDataFact("CORVUS_EMULATOR")]
    public Task The_fixture_writes_its_decoded_text_and_the_region_set_holds_it_at_the_allocation() => DecodedText(x64: false);

    [RequiresRealDataFact("CORVUS_EMULATOR")]
    public Task The_x64_fixture_writes_its_decoded_text_and_the_region_set_holds_it_at_the_allocation() => DecodedText(x64: true);

    private async Task DecodedText(bool x64)
    {
        var (text, report, error) = await Run(unmodelled: false, x64);
        Assert.Null(error);
        Assert.Equal(["kernel32.VirtualAlloc", "kernel32.CreateFileA", "kernel32.WriteFile", "kernel32.CloseHandle", "kernel32.ExitProcess"],
            report!.ApiCalls!.Select(c => c.Api));
        var file = Assert.Single(report.FilesWritten!);
        Assert.EndsWith(EmulatorFixture.FileName, file.Path);
        Assert.Equal(EmulatorFixture.Text, File.ReadAllText(file.SavedAs!));
        var allocation = Convert.ToUInt64(report.ApiCalls![0].Returned, 16);
        var set = RegionSetFile.Open(report.RegionSet!);
        var bytes = new byte[EmulatorFixture.Text.Length];
        Assert.Equal(bytes.Length, set.ReadMemory(allocation, bytes));
        Assert.Equal(EmulatorFixture.Text, Encoding.ASCII.GetString(bytes));
        Assert.Contains("ran to its end", text);
    }

    [RequiresRealDataFact("CORVUS_EMULATOR")]
    public async Task An_unmodelled_function_stops_the_run_by_name()
    {
        var (text, _, error) = await Run(unmodelled: true);
        Assert.Equal(ErrorCode.Unsupported, error!.Code);
        Assert.Contains(EmulatorFixture.MissingFunction, error.Message);
        Assert.Contains("unsupported_api", text);
    }
}
