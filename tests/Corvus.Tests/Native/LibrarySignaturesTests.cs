using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Diff;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>Library functions read from COFF objects the test writes and found in a headerless image that links their bytes.</summary>
public sealed class LibrarySignaturesTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const ushort Amd64 = 0x8664;

    // push rbx; sub rsp,20h; mov rbx,rcx; lea rcx,[rip+disp32]; call rel32; mov eax,[rbx+8]; add rsp,20h; pop rbx; ret.
    private static readonly byte[] ParseHeader =
        [0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x0D, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0x8B, 0x43, 0x08, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3];

    // xor eax,eax; loop over rdx bytes at rcx adding each; ret: no relocations.
    private static readonly byte[] ChecksumBlock =
        [0x33, 0xC0, 0x48, 0x85, 0xD2, 0x74, 0x10, 0x0F, 0xB6, 0x01, 0x03, 0xC0, 0x48, 0xFF, 0xC1, 0x48, 0xFF, 0xCA, 0x75, 0xF3, 0x01, 0xC0, 0x90, 0x90, 0xC3];

    // mov eax,1; ret: below the fixed-byte floor.
    private static readonly byte[] Tiny = [0xB8, 1, 0, 0, 0, 0xC3];

    /// <summary>
    /// An object with parse_header (two REL32 relocations) in its own section, and checksum_block then tiny in one
    /// section with int3 padding after each.
    /// </summary>
    private static byte[] Object() => CoffFixtures.Object(Amd64,
        [
            new(".text$mn", CoffFixtures.Code, ParseHeader, [(12, 3, 4), (17, 4, 4)]),
            new(".text$mn", CoffFixtures.Code, [.. ChecksumBlock, 0xCC, 0xCC, 0xCC, .. Tiny, 0xCC, 0xCC], []),
        ],
        [
            new("parse_header", 0, 1, 0x20, 2),
            new("checksum_block", 0, 2, 0x20, 2),
            new("tiny", (uint)ChecksumBlock.Length + 3, 2, 0x20, 2),
            new("header_format", 0, 0, 0, 2),
            new("log_header", 0, 0, 0x20, 2),
        ]);

    private static LibrarySignatureSet Set(params byte[][] objects) =>
        new("test.lib", NativeArch.X64, [.. objects.SelectMany((o, i) => LibrarySignatures.Functions(CoffObject.Read(o, out _)!, $"m{i}.obj"))], objects.Length, []);

    /// <summary>A headerless x64 image of 0x200 bytes of int3 with <paramref name="code"/> placed at each offset.</summary>
    private static RawCodeImage Image(params (int At, byte[] Code)[] code)
    {
        var bytes = Enumerable.Repeat((byte)0xCC, 0x200).ToArray();
        foreach (var (at, c) in code) c.CopyTo(bytes, at);
        return new RawCodeImage(bytes, "linked.bin", RawLayout.Parse("x64", "0x140000000", null, bytes.Length));
    }

    /// <summary>parse_header as a linker leaves it: the relocated fields hold this image's displacements.</summary>
    private static byte[] Linked(byte seed)
    {
        var b = (byte[])ParseHeader.Clone();
        for (int i = 0; i < 4; i++) { b[12 + i] = (byte)(seed + i); b[17 + i] = (byte)(seed * 3 + i); }
        return b;
    }

    [Fact]
    public void Each_function_keeps_its_bytes_with_relocated_fields_unfixed_and_padding_dropped()
    {
        var fs = LibrarySignatures.Functions(CoffObject.Read(Object(), out _)!, "m.obj").ToList();
        Assert.Equal(["parse_header", "checksum_block", "tiny"], fs.Select(f => f.Name));
        Assert.Equal(ParseHeader.Length - 8, fs[0].FixedCount);
        Assert.False(fs[0].Fixed[12] || fs[0].Fixed[15] || fs[0].Fixed[17] || fs[0].Fixed[20]);
        Assert.True(fs[0].Fixed[11] && fs[0].Fixed[16] && fs[0].Fixed[21]);
        Assert.Equal(ChecksumBlock, fs[1].Bytes);
        Assert.Equal(Tiny, fs[2].Bytes);
    }

    [Fact]
    public void Functions_are_named_at_their_starts_whatever_the_linker_wrote_into_relocated_fields()
    {
        var image = Image((0x20, Linked(0x41)), (0x80, ChecksumBlock), (0x100, Tiny));
        var (matches, ambiguous) = LibrarySignatures.Match(Set(Object()), image, [0x10, 0x20, 0x80, 0x100, 0x180], null, default);
        Assert.Equal([(0x20u, "parse_header"), (0x80u, "checksum_block")], matches.Select(m => (m.Rva, m.Name)));
        Assert.Equal(ParseHeader.Length - 8, matches[0].FixedBytes);
        Assert.Empty(ambiguous);
    }

    [Fact]
    public void A_start_two_library_functions_match_and_a_function_at_two_starts_name_nothing()
    {
        var copy = CoffFixtures.Object(Amd64, [new(".text$mn", CoffFixtures.Code, ChecksumBlock, [])], [new("checksum_block_copy", 0, 1, 0x20, 2)]);
        var (matches, ambiguous) = LibrarySignatures.Match(Set(Object(), copy), Image((0x80, ChecksumBlock)), [0x80], null, default);
        Assert.Empty(matches);
        Assert.Equal(["checksum_block", "checksum_block_copy"], Assert.Single(ambiguous).Names);

        (matches, ambiguous) = LibrarySignatures.Match(Set(Object()), Image((0x20, Linked(1)), (0x60, Linked(9))), [0x20, 0x60], null, default);
        Assert.Empty(matches);
        Assert.All(ambiguous, a => Assert.Equal("the function's bytes are at 2 starts", a.Reason));
    }

    [Fact]
    public void A_match_whose_call_reaches_a_function_of_another_name_is_refused()
    {
        // parse_header at 0x20 calls log_header; the linked call reaches 0x80 (field at 0x31, next instruction at 0x35).
        var linked = Linked(1);
        BitConverter.GetBytes(0x80 - 0x35).CopyTo(linked, 17);
        var image = Image((0x20, linked), (0x80, ChecksumBlock));
        var (matches, ambiguous) = LibrarySignatures.Match(Set(Object()), image, [0x20, 0x80], null, default);
        Assert.Equal([(0x80u, "checksum_block")], matches.Select(m => (m.Rva, m.Name)));
        var refused = Assert.Single(ambiguous);
        Assert.Equal((0x20u, "call_target_differs", "its call to 'log_header' reaches 'checksum_block'"), (refused.Rva, refused.Code, refused.Reason));

        (matches, ambiguous) = LibrarySignatures.Match(Set(Object()), Image((0x20, linked)), [0x20], rva => rva == 0x80 ? "log_header" : null, default);
        Assert.Equal("parse_header", Assert.Single(matches).Name);
        Assert.Empty(ambiguous);
    }

    [Fact]
    public void A_name_two_objects_define_with_alike_bytes_is_kept_when_one_of_them_calls_consistently()
    {
        // A second parse_header that calls log_header_wide; the image names the call's target log_header.
        var wide = CoffFixtures.Object(Amd64, [new(".text$mn", CoffFixtures.Code, ParseHeader, [(12, 1, 4), (17, 2, 4)])],
            [new("parse_header", 0, 1, 0x20, 2), new("header_format", 0, 0, 0, 2), new("log_header_wide", 0, 0, 0x20, 2)]);
        var linked = Linked(1);
        BitConverter.GetBytes(0x80 - 0x35).CopyTo(linked, 17);
        string? Names(uint rva) => rva == 0x80 ? "log_header" : null;
        var (matches, ambiguous) = LibrarySignatures.Match(Set(wide, Object()), Image((0x20, linked)), [0x20], Names, default);
        Assert.Equal("parse_header", Assert.Single(matches).Name);
        Assert.Empty(ambiguous);

        (_, ambiguous) = LibrarySignatures.Match(Set(wide), Image((0x20, linked)), [0x20], Names, default);
        Assert.Equal("its call to 'log_header_wide' reaches 'log_header'", Assert.Single(ambiguous).Reason);
    }

    [Fact]
    public void A_library_reads_its_coff_members_and_names_the_members_it_skipped()
    {
        var import = new byte[40];
        import[2] = 0xFF; import[3] = 0xFF;
        var path = _dir.File("sample.lib");
        File.WriteAllBytes(path, CoffFixtures.Library(("parse.obj", Object()), ("kernel32.dll", import), ("d:\\build\\objects\\elf_member.o", [0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1])));
        var set = LibrarySignatures.Read(path, default);
        Assert.Equal(NativeArch.X64, set.Arch);
        Assert.Equal(3, set.Members);
        Assert.Equal(["parse_header", "checksum_block", "tiny"], set.Functions.Select(f => f.Name));
        Assert.Contains("1 member(s) skipped: an import object (it names a DLL export; no code)", set.Notes);
        Assert.Contains("1 member(s) skipped: a malformed ELF object", set.Notes);
    }

    /// <summary>
    /// parse_header as gcc emits it: the lea a REX_GOTPCRELX the linker may relax (REX, opcode and ModRM too), the call a
    /// PLT32 to log_header.
    /// </summary>
    private static byte[] ElfObject() => ElfObjectFixtures.Write(62, ParseHeader, [(12, 42, 2, -4), (17, 4, 3, -4)],
        [
            new("parse_header", 0, (ulong)ParseHeader.Length, ElfObjectFixtures.Function, ElfObjectFixtures.Global, 1),
            new("header_format", 0, 0, ElfObjectFixtures.NoType, ElfObjectFixtures.Global, 0),
            new("log_header", 0, 0, ElfObjectFixtures.NoType, ElfObjectFixtures.Global, 0),
        ]);

    [Fact]
    public void An_elf_object_function_leaves_relaxable_and_relocated_bytes_unfixed_and_records_its_call()
    {
        var f = Assert.Single(LibrarySignatures.Functions(Corvus.Native.Elf.ElfFile.FromBytes(ElfObject()), "parse.o", out var reason)!);
        Assert.Null(reason);
        Assert.Equal("parse_header", f.Name);
        Assert.Equal(ParseHeader.Length - 7 - 4, f.FixedCount);
        Assert.False(f.Fixed[9] || f.Fixed[11] || f.Fixed[15] || f.Fixed[17] || f.Fixed[20]);
        Assert.True(f.Fixed[8] && f.Fixed[16] && f.Fixed[21]);
        Assert.Equal(new LibraryCall(17, 0, "log_header"), Assert.Single(f.Calls));
    }

    [Fact]
    public void Fuzzed_elf_objects_are_read_or_refused_with_a_reason()
    {
        var failures = FormatFuzz.Run(ElfObject(), b =>
        {
            Corvus.Native.Elf.ElfFile elf;
            try { elf = Corvus.Native.Elf.ElfFile.FromBytes(b); }
            catch (ToolError) { return; }
            if (LibrarySignatures.Functions(elf, "x.o", out var reason) == null && reason == null) throw new InvalidOperationException("refused without a reason");
        }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    [Fact]
    public void An_archive_of_elf_objects_names_the_start_holding_its_function()
    {
        var path = _dir.File("libparse.a");
        File.WriteAllBytes(path, CoffFixtures.Library(("parse.o", ElfObject())));
        var set = LibrarySignatures.Read(path, default);
        Assert.Equal(NativeArch.X64, set.Arch);
        var (matches, ambiguous) = LibrarySignatures.Match(set, Image((0x40, Linked(0x41))), [0x40], null, default);
        Assert.Equal((0x40u, "parse_header", "parse.o"), (Assert.Single(matches).Rva, matches[0].Name, matches[0].Member));
        Assert.Empty(ambiguous);
    }

    [Fact]
    public void A_file_that_is_neither_a_library_nor_an_object_is_refused_with_the_reason()
    {
        var path = _dir.File("notes.txt");
        File.WriteAllText(path, "plain text, not a COFF object");
        var e = Assert.Throws<ToolError>(() => LibrarySignatures.Read(path, default));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.Contains("is not a static library or object file", e.Message);
    }
}
