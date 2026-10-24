using System.Buffers.Binary;
using System.Text;
using Iced.Intel;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Services.Analysis;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>Rust &amp;str lengths and Swift small strings in synthetic x64 and ARM64 code.</summary>
public class NativeStringFormsTests
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;
    private const uint Data = CodeTestImage.SyntheticDataRva;
    private const ulong Base64 = 0x140000000UL;
    private const ulong BaseArm = 0x10000000UL;
    private const uint Sink = Data + 0x300;

    // The standard library's source path that marks a Rust build.
    private static readonly byte[] RustcPath = Encoding.ASCII.GetBytes("/rustc/0123456789abcdef0123456789abcdef01234567/library/core/src/str/mod.rs\0");

    private static byte[] Assemble(Action<Assembler> build)
    {
        var a = new Assembler(64);
        build(a);
        var stream = new MemoryStream();
        a.Assemble(new StreamCodeWriter(stream), Base64 + Code);
        return stream.ToArray();
    }

    private static Instruction Lea(Register reg, uint rva) => Instruction.Create(Iced.Intel.Code.Lea_r64_m, reg, new MemoryOperand(Register.RIP, (long)(Base64 + rva), 8));

    private static Instruction CallSink() => Instruction.Create(Iced.Intel.Code.Call_rm64, new MemoryOperand(Register.RIP, (long)(Base64 + Sink), 8));

    private static byte[] DataWith(params (int At, byte[] Bytes)[] parts)
    {
        var data = new byte[0x400];
        foreach (var (at, bytes) in parts) bytes.CopyTo(data, at);
        return data;
    }

    private static List<(StringEncoding Encoding, string Text)> Strings(NativeCodeIndex index) =>
        [.. index.Strings.Select(s => (s.Encoding, index.ReadString(s)))];

    private static NativeImport SinkImport(string module = "app_support.dll") => new(module, "sink", null, 0, Sink, false);

    /// <summary>"helloworld!" then "xyz" and a NUL, read as two &amp;str through Win64 argument pairs.</summary>
    private static byte[] TwoLiteralsCode() => Assemble(a =>
    {
        a.sub(rsp, 0x28);
        a.AddInstruction(Lea(Register.RCX, Data + 0x10));
        a.mov(edx, 5);
        a.AddInstruction(CallSink());
        a.mov(edx, 6);
        a.AddInstruction(Lea(Register.RCX, Data + 0x15));
        a.AddInstruction(CallSink());
        a.add(rsp, 0x28);
        a.ret();
    });

    [Fact]
    public void Rust_literals_without_terminators_are_split_by_the_lengths_code_loads()
    {
        var data = DataWith((0x10, Encoding.ASCII.GetBytes("helloworld!xyz\0")), (0x100, RustcPath));
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, TwoLiteralsCode(), data, [SinkImport()], entry: Code));
        var strings = Strings(index);
        Assert.Contains((StringEncoding.Utf8, "hello"), strings);
        Assert.Contains((StringEncoding.Utf8, "world!"), strings);
        Assert.DoesNotContain(strings, s => s.Text.StartsWith("helloworld", StringComparison.Ordinal));
    }

    [Fact]
    public void Rust_literals_on_ARM64_take_the_length_in_the_next_argument_register()
    {
        var a = new A64(Code);
        a.Word(A64.Adrp(a.Here, Data + 0x10, 0, BaseArm)).Word(A64.AddImm(0, 0, (Data + 0x10) & 0xFFF)).Word(A64.MovW(1, 5)).Word(A64.Bl(a.Here, Code + 0x40));
        a.Word(A64.MovW(1, 6)).Word(A64.Adrp(a.Here, Data + 0x15, 0, BaseArm)).Word(A64.AddImm(0, 0, (Data + 0x15) & 0xFFF)).Word(A64.Bl(a.Here, Code + 0x40));
        while (a.Here < Code + 0x40) a.Word(A64.Ret);
        a.Word(A64.Ret);
        var data = DataWith((0x10, Encoding.ASCII.GetBytes("helloworld!xyz\0")), (0x100, RustcPath));
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.Arm64, a.Bytes(), data, entry: Code, format: ImageFormat.Elf));
        var strings = Strings(index);
        Assert.Contains((StringEncoding.Utf8, "hello"), strings);
        Assert.Contains((StringEncoding.Utf8, "world!"), strings);
    }

    [Fact]
    public void Rust_str_pairs_in_data_give_their_lengths()
    {
        // A relocated (pointer, length) pair at 0x40, as in a panic location or a format string's pieces.
        var pair = new byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(pair, Base64 + Data + 0x10);
        BinaryPrimitives.WriteUInt64LittleEndian(pair.AsSpan(8), 5);
        var data = DataWith((0x10, Encoding.ASCII.GetBytes("helloworld!xyz\0")), (0x40, pair), (0x100, RustcPath));
        var code = Assemble(a => a.ret());
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, code, data, relocations: [Data + 0x40], entry: Code));
        Assert.Contains((StringEncoding.Utf8, "hello"), Strings(index));
    }

    [Fact]
    public void Outside_Rust_builds_a_length_beside_a_C_string_keeps_its_terminator()
    {
        // Prefixes of a C string passed with their lengths, as memcpy takes them.
        var data = DataWith((0x10, Encoding.ASCII.GetBytes("helloworld!xyz\0")));
        var image = CodeTestImage.Synthetic(NativeArch.X64, TwoLiteralsCode(), data, [SinkImport()], entry: Code);
        Assert.False(StringForms.HasRustStrings(image));
        var strings = Strings(NativeCodeIndex.Build(image));
        Assert.Contains((StringEncoding.Ascii, "helloworld!xyz"), strings);
        Assert.DoesNotContain(strings, s => s.Encoding == StringEncoding.Utf8);
    }

    /// <summary>"/bin/sh" (7 bytes), "/usr/sbin/sshd" (14, split over both words) and "café" (5 UTF-8 bytes) as Swift passes them.</summary>
    private static byte[] SwiftCode() => Assemble(a =>
    {
        a.sub(rsp, 0x28);
        a.mov(rdi, Word("/bin/sh"));
        a.mov(rsi, 0xE7UL << 56);
        a.AddInstruction(CallSink());
        a.mov(rdi, Word("/usr/sbi"));
        a.mov(rsi, 0xEEUL << 56 | Word("n/sshd"));
        a.AddInstruction(CallSink());
        a.mov(rsi, 0xA5UL << 56);
        a.mov(rdi, Word("café"));
        a.AddInstruction(CallSink());
        a.add(rsp, 0x28);
        a.ret();
    });

    private static ulong Word(string text)
    {
        var bytes = new byte[8];
        Encoding.UTF8.GetBytes(text).CopyTo(bytes, 0);
        return BinaryPrimitives.ReadUInt64LittleEndian(bytes);
    }

    [Fact]
    public void Swift_small_strings_are_read_from_immediate_pairs()
    {
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, SwiftCode(), null, [SinkImport("swiftCore.dll")], entry: Code));
        var inline = Strings(index).Where(s => s.Encoding == StringEncoding.Inline).Select(s => s.Text);
        Assert.Equal(["/bin/sh", "/usr/sbin/sshd", "café"], inline);
        Assert.All(index.Strings.Where(s => s.Encoding == StringEncoding.Inline), s => Assert.Equal(Code, index.FunctionAt(s.Rva)?.Start));
    }

    [Fact]
    public void Swift_small_strings_on_ARM64_are_read_from_move_chains()
    {
        static uint MovzX(int rd, ulong imm, int hw) => 0xD2800000 | (uint)hw << 21 | (uint)(imm & 0xFFFF) << 5 | (uint)rd;
        static uint MovkX(int rd, ulong imm, int hw) => 0xF2800000 | (uint)hw << 21 | (uint)(imm & 0xFFFF) << 5 | (uint)rd;
        ulong first = Word("/bin/sh");
        var a = new A64(Code);
        a.Word(MovzX(0, first, 0)).Word(MovkX(0, first >> 16, 1)).Word(MovkX(0, first >> 32, 2)).Word(MovkX(0, first >> 48, 3));
        a.Word(MovzX(1, 0xE700, 3)).Word(A64.Bl(a.Here, Code + 0x40));
        while (a.Here < Code + 0x40) a.Word(A64.Ret);
        a.Word(A64.Ret);
        var image = CodeTestImage.Synthetic(NativeArch.Arm64, a.Bytes(), null, [new NativeImport("libswiftCore.so", "swift_bridgeObjectRelease", null, 0, Data + 0x10, false)],
            entry: Code, format: ImageFormat.Elf);
        Assert.Contains((StringEncoding.Inline, "/bin/sh"), Strings(NativeCodeIndex.Build(image)));
    }

    [Fact]
    public void Swift_small_strings_need_a_Swift_build()
    {
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, SwiftCode(), null, [SinkImport()], entry: Code));
        Assert.DoesNotContain(index.Strings, s => s.Encoding == StringEncoding.Inline);
    }

    /// <summary>Built from StringFormFixtures/literals.rs and literals.swift (build.ps1).</summary>
    [Theory]
    [InlineData("rust-x64.elf", "utf8", "opening configuration|config.toml|connection refused|retrying in 5 seconds")]
    [InlineData("rust-arm64.elf", "utf8", "opening configuration|config.toml|connection refused|retrying in 5 seconds")]
    [InlineData("swift-x64.exe", "inline", "/bin/sh|Content-Type|naïve|/etc/hosts")]
    [InlineData("swift-x64.elf", "inline", "/bin/sh|Content-Type|naïve|/etc/hosts")]
    [InlineData("swift-arm64.elf", "inline", "/bin/sh|Content-Type|naïve|/etc/hosts")]
    public void Compiled_literals_are_listed_one_by_one(string file, string encoding, string expected)
    {
        var index = NativeCodeIndex.Build(NativeImageLoader.Open(Path.Combine(AppContext.BaseDirectory, "NativeAnalysis", "StringFormFixtures", file)));
        var kind = encoding == "utf8" ? StringEncoding.Utf8 : StringEncoding.Inline;
        var found = Strings(index).Where(s => s.Encoding == kind).Select(s => s.Text).ToHashSet();
        Assert.Superset(expected.Split('|').ToHashSet(), found);
    }

    [Fact]
    public void A_saved_index_keeps_inline_string_text()
    {
        var image = CodeTestImage.Synthetic(NativeArch.X64, SwiftCode(), null, [SinkImport("swiftCore.dll")], entry: Code);
        var built = NativeCodeIndex.Build(image);
        var stream = new MemoryStream();
        using (var w = new PayloadWriter(b => stream.Write(b))) built.WritePayload(w);
        var loaded = NativeCodeIndex.ReadPayload(stream.ToArray(), image, null, default);
        Assert.Equal(Strings(built), Strings(loaded));
        Assert.Contains((StringEncoding.Inline, "/usr/sbin/sshd"), Strings(loaded));
    }

    [Fact]
    public void A_str_feature_rule_sees_an_inline_string()
    {
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, SwiftCode(), null, [SinkImport("swiftCore.dll")], entry: Code));
        Assert.NotNull(new NativeFeatureScan(index, default).Evaluate("str:^/usr/sbin/sshd$"));
    }
}
