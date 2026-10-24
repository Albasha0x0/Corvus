using System.Buffers.Binary;
using System.Diagnostics;
using Corvus.Native;
using Corvus.Native.Elf;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// RawCandidates over headerless images with a known instruction set and base: a public library's mapped image, relocated
/// to <see cref="Base"/> and its headers cleared.
/// </summary>
public sealed class RawCandidateTests(ITestOutputHelper output) : IDisposable
{
    private const ulong Base = 0x40000000;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static async Task<(string Text, bool IsError)> Call(InProcessServer server, string tool, Dictionary<string, object?> args)
    {
        var r = await server.Client.CallToolAsync(tool, args);
        return (string.Concat(r.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(b => b.Text)), r.IsError == true);
    }

    private static string Sqlite(string rid) => RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "runtimes", rid, "native",
        rid.StartsWith("win", StringComparison.Ordinal) ? "e_sqlite3.dll" : "libe_sqlite3.so");

    /// <summary>
    /// The image of <paramref name="path"/> as mapped at <paramref name="at"/>: relative relocations and the MIPS local GOT
    /// applied, then the relocation tables and the bytes before the first section cleared, as in an image linked there.
    /// </summary>
    internal static byte[] Relocated(string path, ulong at)
    {
        var image = NativeImageLoader.Open(path);
        var bytes = new byte[image.SizeOfImage];
        for (uint rva = 0; rva < bytes.Length; rva += 0x1000)
            image.Read(rva, bytes.AsSpan((int)rva, (int)Math.Min(0x1000, bytes.Length - rva)));
        int width = image.Is64Bit ? 8 : 4;
        ulong Read(uint rva, bool bigEndian)
        {
            var slot = bytes.AsSpan((int)rva, width);
            if (width == 8) return bigEndian ? BinaryPrimitives.ReadUInt64BigEndian(slot) : BinaryPrimitives.ReadUInt64LittleEndian(slot);
            return bigEndian ? BinaryPrimitives.ReadUInt32BigEndian(slot) : BinaryPrimitives.ReadUInt32LittleEndian(slot);
        }
        void Write(uint rva, ulong value, bool bigEndian)
        {
            var slot = bytes.AsSpan((int)rva, width);
            if (width == 8) { if (bigEndian) BinaryPrimitives.WriteUInt64BigEndian(slot, value); else BinaryPrimitives.WriteUInt64LittleEndian(slot, value); }
            else if (bigEndian) BinaryPrimitives.WriteUInt32BigEndian(slot, (uint)value);
            else BinaryPrimitives.WriteUInt32LittleEndian(slot, (uint)value);
        }
        if (image is ElfFile elf)
        {
            ulong delta = at - elf.ImageBase;
            foreach (var r in elf.Relocations)
                if (r.Kind == ElfRelocationKind.Relative && elf.TryVaToRva(r.Offset, out uint rva) && rva + width <= bytes.Length)
                    Write(rva, (r.ExplicitAddend ? (ulong)r.Addend : Read(rva, elf.BigEndian)) + delta, elf.BigEndian);
            // The MIPS dynamic linker relocates the local GOT without relocations and fills the global GOT from symbols;
            // entry 0 is its resolver, and entry 1 its module pointer when the top bit is set.
            ulong? Tag(long tag) => elf.DynamicEntries.Where(e => e.Tag == tag).Select(e => (ulong?)e.Value).FirstOrDefault();
            if (elf.Machine == ElfNames.EmMips && Tag(3) is { } got && Tag(0x7000000A) is { } local && Tag(0x70000013) is { } first)
            {
                for (ulong i = 1; i < local; i++)
                    if (elf.TryVaToRva(got + i * (ulong)width, out uint rva) && Read(rva, elf.BigEndian) is var value && (i > 1 || value >> (width * 8 - 1) == 0))
                        Write(rva, value + delta, elf.BigEndian);
                for (ulong i = first; i < (ulong)elf.DynamicSymbols.Count; i++)
                    if (elf.DynamicSymbols[(int)i] is { IsDefined: true } sym && elf.TryVaToRva(got + (local + i - first) * (ulong)width, out uint rva))
                        Write(rva, sym.Value + delta, elf.BigEndian);
            }
            foreach (var table in image.Sections.Where(s => s.Name.StartsWith(".rel", StringComparison.Ordinal)))
                bytes.AsSpan((int)table.Rva, (int)Math.Min(table.VirtualSize, (uint)bytes.Length - table.Rva)).Clear();
        }
        else
        {
            ulong delta = at - image.ImageBase;
            foreach (var rva in image.RelocationRvas)
            {
                var slot = bytes.AsSpan((int)rva, width);
                ulong value = width == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(slot) : BinaryPrimitives.ReadUInt32LittleEndian(slot);
                Write(rva, value + delta, false);
            }
        }
        bytes.AsSpan(0, (int)image.Sections.Where(s => s.Rva > 0).Min(s => s.Rva)).Clear();
        return bytes;
    }

    [Theory, Trait("Data", "Real")]
    [InlineData("linux-x86", "x86")]
    [InlineData("linux-x64", "x64")]
    [InlineData("linux-arm", "thumb")]
    [InlineData("linux-armel", "arm")]
    [InlineData("linux-arm64", "arm64")]
    [InlineData("linux-mips64", "mips64el")]
    [InlineData("linux-ppc64le", "ppc64le")]
    [InlineData("linux-riscv64", "riscv64")]
    [InlineData("win-x86", "x86")]
    [InlineData("win-x64", "x64")]
    [InlineData("win-arm64", "arm64")]
    [InlineData("win-arm", "thumb")]
    public void A_relocated_library_reads_as_its_instruction_set_at_its_base(string rid, string arch)
    {
        var data = Relocated(Sqlite(rid), Base);
        var isas = RawCandidates.Isas(data);
        output.WriteLine(string.Join("\n", isas.Select(c => $"{c.Arch} {c.Score}: {string.Join(", ", c.Evidence.Select(e => $"{e.Name} x{e.Hits}"))}")));
        Assert.Equal(arch, isas[0].Arch);
        Assert.True(isas.Count == 1 || isas[0].Score >= 2 * isas[1].Score, $"{isas[0].Score} vs {isas.ElementAtOrDefault(1)?.Score}");

        var bases = RawCandidates.Bases(data, RawArch.Find(arch));
        output.WriteLine($"{bases.Pointers:N0} pointers, {bases.Targets:N0} strings; " + string.Join("; ", bases.Bases.Select(b => $"0x{b.Base:X} {b.Votes} votes, {b.Strings} strings")) +
                         string.Concat(bases.Notes.Select(n => "\n" + n)));
        Assert.True(bases.Clear, string.Join("; ", bases.Notes));
        Assert.Equal(Base, bases.Bases[0].Base);
    }

    [Fact, Trait("Data", "Real")]
    public void An_instruction_set_without_a_signature_reads_as_none()
    {
        var data = Relocated(Sqlite("linux-s390x"), Base);
        var scored = RawCandidates.Score(data);
        output.WriteLine(string.Join(", ", scored.Take(3).Select(c => $"{c.Arch} {c.Score}")));
        Assert.Empty(RawCandidates.Isas(data));
    }

    [Fact]
    public void Random_bytes_and_text_read_as_no_instruction_set()
    {
        var random = new byte[1 << 20];
        new Random(7).NextBytes(random);
        Assert.Empty(RawCandidates.Isas(random));
        var text = System.Text.Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("The quick brown fox jumps over the lazy dog. 0123456789\n", 20000)));
        Assert.Empty(RawCandidates.Isas(text));
    }

    /// <summary>The Cortex-M fixture's vector table puts its handlers at 0x80001xx, so its base is 0x8000000.</summary>
    [Fact]
    public void A_cortex_m_vector_table_names_its_base()
    {
        var data = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Engines", "IsaFixtures", "cortexm.bin"));
        Assert.Equal(0x8000000UL, RawCandidates.VectorTableBase(data, RawArch.Find("thumb")));
        Assert.Null(RawCandidates.VectorTableBase(data, RawArch.Find("arm")));
        Assert.Equal("vector table", RawCandidates.Bases(data, RawArch.Find("thumb")).Bases[0].Source);
    }

    [Fact, Trait("Data", "Real"), Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public void Scoring_and_the_base_search_keep_their_rates()
    {
        // 12 relocated libraries back to back: 16 MiB of code and data, the largest region scored whole.
        var parts = new[] { "linux-x64", "linux-arm64", "win-x64", "linux-arm", "win-arm64", "linux-ppc64le", "linux-riscv64", "win-x86", "linux-x86", "linux-armel", "win-arm", "linux-mips64" }
            .Select(r => Relocated(Sqlite(r), Base)).ToList();
        var data = new byte[RawCandidates.ScoreWhole];
        for (int at = 0, i = 0; at < data.Length; i++)
        {
            var p = parts[i % parts.Count];
            int n = Math.Min(p.Length, data.Length - at);
            p.AsSpan(0, n).CopyTo(data.AsSpan(at));
            at += n;
        }
        RawCandidates.Score(data.AsSpan(0, 1 << 16));
        var clock = Stopwatch.StartNew();
        RawCandidates.Score(data);
        double rate = data.Length / clock.Elapsed.TotalSeconds / (1 << 20);
        var x64 = Relocated(Sqlite("linux-x64"), Base);
        var search = new byte[RawCandidates.ScoreWhole];
        for (int at = 0; at < search.Length; at += x64.Length) x64.AsSpan(0, Math.Min(x64.Length, search.Length - at)).CopyTo(search.AsSpan(at));
        clock.Restart();
        var bases = RawCandidates.Bases(search, RawArch.Find("x64"));
        var elapsed = clock.Elapsed;
        output.WriteLine($"score {rate:F0} MB/s; base search over 16 MiB {elapsed.TotalMilliseconds:F0} ms, {bases.Pointers:N0} pointers, {bases.Targets:N0} strings");
        PerfBudget.AtLeast("native/raw-isa-rate", rate, 20, "MB/s", output);
        PerfBudget.Time("native/raw-base-16mb", elapsed, TimeSpan.FromSeconds(1), output);
    }

    [Fact, Trait("Data", "Real"), Trait("Speed", "Slow")]
    public async Task A_headerless_file_gets_a_raw_view_and_a_load_hint_with_its_call()
    {
        var path = _dir.File("arm64.bin");
        File.WriteAllBytes(path, Relocated(Sqlite("linux-arm64"), Base));
        await using var server = await InProcessServer.StartAsync();
        var overview = await Call(server, "summarize_file", new() { ["path"] = path });
        output.WriteLine(overview.Text);
        Assert.Contains("Headerless code: reads as arm64", overview.Text);
        var view = await Call(server, "summarize_file", new() { ["path"] = path, ["view"] = "raw" });
        output.WriteLine(view.Text);
        Assert.Contains($"load_assembly path={path} format=raw arch=arm64 base=0x40000000", view.Text);
        var load = await Call(server, "load_assembly", new() { ["path"] = path, ["format"] = "raw" });
        Assert.True(load.IsError);
        Assert.Contains("needs arch; the bytes read as arm64", load.Text);
        Assert.Contains("arch=arm64 base=0x40000000", load.Text);
    }

    [Fact, Trait("Data", "Real"), Trait("Speed", "Slow")]
    public async Task A_code_region_before_a_signature_is_read_by_the_raw_view_and_named_by_the_firmware_view()
    {
        var code = Relocated(Sqlite("linux-riscv64"), Base);
        var path = _dir.File("image.bin");
        using (var zip = new MemoryStream())
        {
            using (var archive = new System.IO.Compression.ZipArchive(zip, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
                using (var w = new StreamWriter(archive.CreateEntry("config.txt").Open())) w.Write("mode=1\n");
            File.WriteAllBytes(path, [.. code, .. zip.ToArray()]);
        }
        await using var server = await InProcessServer.StartAsync();
        var firmware = await Call(server, "summarize_file", new() { ["path"] = path, ["view"] = "firmware" });
        output.WriteLine(firmware.Text);
        Assert.Contains($"0x0-0x{code.Length:X} ({code.Length:N0} bytes): no signature; view=raw reads it", firmware.Text);
        var raw = await Call(server, "summarize_file", new() { ["path"] = path, ["view"] = "raw" });
        output.WriteLine(raw.Text);
        Assert.Contains("riscv64", raw.Text);
        Assert.Contains($"bytes 0x0-0x{code.Length:X} are not a file of their own: saved as one, they load with load_assembly path=<file> format=raw arch=riscv64 base=0x40000000", raw.Text);
    }

    [Theory, Trait("Data", "Real")]
    [InlineData("linux-ppc64le", "ppc64le")]
    [InlineData("linux-mips64", "mips64el")]
    public async Task A_little_endian_64_bit_candidate_loads_with_its_call(string rid, string arch)
    {
        var path = _dir.File($"{arch}.bin");
        File.WriteAllBytes(path, Relocated(Sqlite(rid), Base));
        await using var server = await InProcessServer.StartAsync();
        var load = await Call(server, "load_assembly", new() { ["path"] = path, ["format"] = "raw", ["arch"] = arch, ["base"] = "0x40000000" });
        Assert.False(load.IsError, load.Text);
        Assert.Contains($"{arch}.bin[{arch}@0x40000000]", load.Text);
        Assert.Equal(arch, RawArch.Find(arch == "ppc64le" ? "powerpc64le" : "mips64le").Name);
    }
}
