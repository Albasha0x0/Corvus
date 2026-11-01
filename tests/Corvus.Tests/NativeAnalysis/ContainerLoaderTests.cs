using Iced.Intel;
using ModelContextProtocol.Protocol;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>Checks that survey_features joins a container header to the cipher and entry ranges of its loader.</summary>
public sealed class ContainerLoaderTests : IDisposable
{
    private const ulong Base = 0x180000000;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private enum Cipher { None, Aes, Blowfish, Sm4 }

    private static readonly byte[] AesHead = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76];
    private static readonly byte[] BlowfishHead = [0x88, 0x6A, 0x3F, 0x24, 0xD3, 0x08, 0xA3, 0x85, 0x2E, 0x8A, 0x19, 0x13, 0x44, 0x73, 0x70, 0x03];
    private static readonly byte[] Sm4Head = [0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05];

    // A loader that compares the magic and steps a block routine over 16-byte
    // blocks; the block routine reads the cipher table named by cipher, and
    // compares a round count only when rounds is set.
    private string Image(Cipher cipher, bool rounds = true, bool referenced = true,
        uint[]? entries = null, uint? declaredOverride = null)
    {
        entries ??= [20, 20 + 512];
        byte[] Code(Dictionary<string, uint> slots)
        {
            var a = new Assembler(64);
            var block = a.CreateLabel();
            var again = a.CreateLabel();
            a.sub(rsp, 0x28);
            if (referenced) a.cmp(eax, BitConverter.ToInt32("XCNT"u8));
            a.mov(ecx, 0);
            a.Label(ref again);
            a.call(block);
            a.add(ecx, 0x10);
            a.cmp(ecx, 0x40);
            a.jl(again);
            a.add(rsp, 0x28);
            a.ret();
            for (int i = 0; i < 6; i++) a.int3();
            a.Label(ref block);
            if (cipher != Cipher.None)
                a.AddInstruction(Instruction.Create(Iced.Intel.Code.Mov_r32_rm32, Register.EAX,
                    new MemoryOperand(Register.RIP, (long)(Base + slots["sbox"]), 8)));
            if (rounds) a.cmp(edx, 0xA);
            a.ret();
            var stream = new MemoryStream();
            a.Assemble(new StreamCodeWriter(stream), Base + LinkedImages.Text);
            return stream.ToArray();
        }

        Dictionary<string, uint> Data(PeBlob blob, List<uint> relocations)
        {
            blob.Align(16);
            var table = new byte[256];
            (cipher switch { Cipher.Blowfish => BlowfishHead, Cipher.Sm4 => Sm4Head, _ => AesHead }).CopyTo(table, 0);
            uint sbox = blob.Bytes(table);
            blob.Align(16);
            var body = new byte[1024];
            new Random(7).NextBytes(body);
            uint declared = declaredOverride ?? 4 + 4 * (uint)entries.Length + 1024;
            uint container = blob.Bytes([.. "XCNT"u8, .. BitConverter.GetBytes(declared),
                .. BitConverter.GetBytes((uint)entries.Length),
                .. entries.SelectMany(BitConverter.GetBytes), .. body]);
            return new() { ["sbox"] = sbox, ["container"] = container };
        }

        var path = _dir.File($"loader{Guid.NewGuid():N}.dll");
        File.WriteAllBytes(path, LinkedImages.Build("loader.dll", [("Load", 0)], [("KERNEL32.dll", ["ExitProcess"])], Code, Data));
        return path;
    }

    // The file offset of the container header: its magic is the last match.
    private static int ContainerAt(string path) => ((ReadOnlySpan<byte>)File.ReadAllBytes(path)).LastIndexOf("XCNT"u8);

    private async Task<string> Survey(string path)
    {
        await using var server = await InProcessServer.StartAsync();
        var load = await server.Client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = path });
        var r = await server.Client.CallToolAsync("survey_features", new Dictionary<string, object?>
        {
            ["assembly"] = load.StructuredContent!.Value.GetProperty("ids")[0].GetString(),
            ["category"] = "crypto",
        });
        return string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
    }

    [Fact]
    public async Task An_AES_loader_names_its_cipher_and_the_exact_entry_0_range_to_verify()
    {
        var path = Image(Cipher.Aes);
        var text = await Survey(path);
        Assert.Contains("loader transform AES mode", text);
        Assert.Contains("entry ranges +0x14 length 512, +0x214 length", text);
        Assert.Contains($"Next: unpack_container path={path} algorithm=aes-128 mode=", text);
        Assert.Contains($"offset={ContainerAt(path) + 0x14}, length=512>", text);
    }

    [Fact]
    public async Task A_Blowfish_loader_names_its_cipher_and_the_exact_entry_0_range_to_verify()
    {
        var path = Image(Cipher.Blowfish);
        var text = await Survey(path);
        Assert.Contains("loader transform Blowfish mode", text);
        Assert.Contains($"algorithm=blowfish mode=", text);
        Assert.Contains($"offset={ContainerAt(path) + 0x14}, length=512>", text);
    }

    [Fact]
    public async Task An_AES_loader_with_no_round_count_names_no_verification_call()
    {
        var text = await Survey(Image(Cipher.Aes, rounds: false));
        Assert.Contains("loader transform AES", text);
        Assert.DoesNotContain("unpack_container", text);
    }

    [Fact]
    public async Task An_unsupported_cipher_is_named_without_a_verification_call()
    {
        var text = await Survey(Image(Cipher.Sm4));
        Assert.Contains("loader transform SM4", text);
        Assert.DoesNotContain("unpack_container", text);
    }

    [Fact]
    public async Task A_loader_without_a_cipher_table_adds_entry_ranges_and_no_verification_call()
    {
        var text = await Survey(Image(Cipher.None));
        Assert.Contains("entry ranges +0x14 length 512", text);
        Assert.DoesNotContain("loader transform", text);
        Assert.DoesNotContain("unpack_container", text);
    }

    [Fact]
    public async Task A_container_no_function_references_adds_entry_ranges_and_no_loader()
    {
        var text = await Survey(Image(Cipher.Aes, referenced: false));
        Assert.Contains("entry ranges +0x14 length 512", text);
        Assert.DoesNotContain("loader transform", text);
    }

    [Fact]
    public async Task Entry_ranges_list_three_entries_and_count_the_rest()
    {
        var text = await Survey(Image(Cipher.Aes, entries: [32, 160, 288, 416, 544]));
        Assert.Contains("entry ranges +0x20 length 128, +0xA0 length 128, +0x120 length 128 and 2 more", text);
    }

    [Fact]
    public async Task A_cut_container_labels_an_entry_outside_the_section_and_stays_partial()
    {
        var text = await Survey(Image(Cipher.Aes, entries: [24, 536, 0x100000], declaredOverride: 0x200000));
        Assert.Contains("+0x100000 outside the section", text);
        Assert.Contains("(partial:", text);
        Assert.DoesNotContain("length -", text);
    }
}
