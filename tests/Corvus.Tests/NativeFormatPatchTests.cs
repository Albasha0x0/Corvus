using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Native.MachO;
using Corvus.Services;
using Corvus.Tests.NativeFormats;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>patch_bytes, undo_native_edit and save_native on ELF and Mach-O images, thin and universal.</summary>
public sealed class NativeFormatPatchTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly Env _env = new();
    private readonly NativeEditTools _tools;

    public NativeFormatPatchTests()
    {
        var code = new NativeCodeService(_env.Workspace, _env.Options, null, new AnnotationStore(_dir.File("ann")));
        _tools = new NativeEditTools(_env.Workspace, code, new NativeEditService(_env.Workspace, code));
    }

    public void Dispose()
    {
        _env.Dispose();
        _dir.Dispose();
    }

    private string Write(string name, byte[] bytes)
    {
        var path = _dir.File(name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    /// <summary>x64 ELF: mov eax, 1; ret at the entry, and a relocated pointer (R_X86_64_RELATIVE) at the start of .data.</summary>
    private static byte[] Elf() => new ElfWriter
    {
        Machine = ElfWriter.EmX64, Type = 3, Entry = ElfWriter.TextRva, Text = [0xB8, 1, 0, 0, 0, 0xC3, 0xCC, 0xCC],
        Relocations = [new(ElfWriter.DataRva, 8, Addend: ElfWriter.TextRva)],
    }.Build();

    [Fact]
    public async Task Elf_patch_undo_and_save()
    {
        var path = Write("lib.so", Elf());
        var dry = await _tools.PatchBytes(path, $"rva:0x{ElfWriter.TextRva:X}", hex: "B8 02 00 00 00", dryRun: true);
        Assert.Contains("Dry run: would patch 5 byte(s)", dry);
        var done = await _tools.PatchBytes("lib.so", $"rva:0x{ElfWriter.TextRva:X}", hex: "B8 02 00 00 00", dryRun: false);
        Assert.Contains("Recorded as lib.so#1", done);
        var native = _env.Workspace.Read(() => _env.Workspace.GetNative("lib.so"));
        var read = new byte[2];
        native.Image.Read(ElfWriter.TextRva, read);
        Assert.Equal([0xB8, 0x02], read);

        var output = _dir.File("lib.patched.so");
        var saved = await _tools.SaveNative("lib.so", output);
        Assert.Contains("Verified: every byte outside the patched ranges", saved);
        Assert.DoesNotContain("checksum", saved, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Re-parsed as EM_X86_64 ELF64 shared object", saved);
        var written = File.ReadAllBytes(output);
        var original = File.ReadAllBytes(path);
        Assert.Equal(original.Length, written.Length);
        Assert.Equal(1, Enumerable.Range(0, original.Length).Count(i => original[i] != written[i]));

        Assert.Contains("Undid lib.so#", await _tools.UndoNativeEdit("lib.so"));
        native.Image.Read(ElfWriter.TextRva, read);
        Assert.Equal([0xB8, 0x01], read);
    }

    [Fact]
    public async Task Pointer_values_take_a_name()
    {
        var elf = new ElfWriter
        {
            Machine = ElfWriter.EmX64, Type = 2, Base = 0x400000, Entry = ElfWriter.TextRva, Text = [0x31, 0xC0, 0xC3, 0xCC, 0xC3],
            Symbols = [new("helper", ElfWriter.TextRva + 4, 1)], Hash = ElfWriter.HashKind.Gnu,
        };
        var path = Write("ptr", elf.Build());
        Assert.Contains("Recorded", await _tools.PatchBytes(path, $"rva:0x{ElfWriter.DataRva + 0x10:X}", value: "helper", type: "ptr", dryRun: false));
        Assert.Contains("Recorded", await _tools.PatchBytes("ptr", $"rva:0x{ElfWriter.DataRva + 0x20:X}", value: "0x401000", type: "ptr", dryRun: false));
        var native = _env.Workspace.Read(() => _env.Workspace.GetNative("ptr"));
        var read = new byte[8];
        native.Image.Read(ElfWriter.DataRva + 0x10, read);
        Assert.Equal(0x400000UL + ElfWriter.TextRva + 4, BitConverter.ToUInt64(read));
        native.Image.Read(ElfWriter.DataRva + 0x20, read);
        Assert.Equal(0x401000UL, BitConverter.ToUInt64(read));
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAnyAsync<ToolError>(() => _tools.PatchBytes("ptr", $"rva:0x{ElfWriter.DataRva + 0x30:X}", value: "no_such_name", type: "ptr", dryRun: false))).Code);
    }

    [Fact]
    public async Task Elf_bytes_the_loader_rewrites_are_refused()
    {
        var path = Write("rel.so", Elf());
        var error = await Assert.ThrowsAsync<ToolError>(() => _tools.PatchBytes(path, $"rva:0x{ElfWriter.DataRva + 4:X}", hex: "00 00", dryRun: false));
        Assert.Equal(ErrorCode.Conflict, error.Code);
        Assert.Contains("relocated_range: the loader writes the pointer at", error.Message);
        Assert.Contains("a dynamic relocation", error.Message);
        Assert.Contains("Recorded", await _tools.PatchBytes("rel.so", $"rva:0x{ElfWriter.DataRva + 4:X}", hex: "00 00", allowUnsafe: true, dryRun: false));
    }

    [Fact]
    public async Task MachO_signature_is_marked_invalid_and_encrypted_bytes_are_refused()
    {
        var signed = new MachOWriter { CodeSignature = new("com.example.sample", "ABCDE12345") };
        var path = Write("signed.dylib", signed.Build());
        var patched = await _tools.PatchBytes(path, $"rva:0x{MachOWriter.TextOffset:X}", hex: "1F 20 03 D5", dryRun: false);
        Assert.Contains("The Mach-O code signature no longer matches the patched bytes", patched);
        var saved = await _tools.SaveNative("signed.dylib", _dir.File("signed.out.dylib"));
        Assert.Contains("The Mach-O code signature no longer matches", saved);

        var encrypted = new MachOWriter { Encryption = (MachOWriter.TextOffset, 0x100, 1) };
        var enc = Write("enc.dylib", encrypted.Build());
        var error = await Assert.ThrowsAsync<ToolError>(() => _tools.PatchBytes(enc, $"rva:0x{MachOWriter.TextOffset:X}", hex: "1F 20 03 D5", allowUnsafe: true, dryRun: false));
        Assert.Contains("encrypted_range", error.Message);
    }

    [Fact]
    public async Task Universal_file_keeps_its_other_slices()
    {
        var x64 = new MachOWriter { CpuType = MachOWriter.CpuX64, CpuSubType = 3, Text = [0x90, 0x90, 0x90, 0xC3] }.Build();
        var arm64 = new MachOWriter().Build();
        var path = Write("fat.dylib", MachOWriter.Fat([(MachOWriter.CpuX64, 3, x64), (MachOWriter.CpuArm64, 0, arm64)]));
        _env.Workspace.LoadAny(path, slice: "x86_64");
        var id = _env.Workspace.Read(() => _env.Workspace.Natives.Single().Id);
        Assert.Contains("Recorded", await _tools.PatchBytes(id, $"rva:0x{MachOWriter.TextOffset:X}", hex: "CC", dryRun: false));
        Assert.Equal("x86_64", _env.Workspace.Read(() => _env.Workspace.GetNative(id).SliceName));
        var output = _dir.File("fat.out.dylib");
        Assert.Contains("Verified", await _tools.SaveNative(id, output));
        var original = File.ReadAllBytes(path);
        var written = File.ReadAllBytes(output);
        Assert.Equal(original.Length, written.Length);
        Assert.Equal(1, Enumerable.Range(0, original.Length).Count(i => original[i] != written[i]));
        Assert.Equal(0xCC, MachOFile.FromBytes(written, output, "x86_64").FileBytes.Span[(int)MachOWriter.TextOffset]);
    }
}
