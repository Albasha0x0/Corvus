using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Diff;
using Corvus.Native.Patching;
using Corvus.Native.Pe;
using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary>The file's bytes against an engine's memory: each kind of differing range named, with a scripted engine.</summary>
public sealed class EngineMemoryDiffTests
{
    private const ulong Base = 0x140000000;

    /// <summary>
    /// A PE with .text (3 pages), .data (0x200 file bytes, 0x2000 mapped) holding a pointer at 0x4010 that a base
    /// relocation covers, and .reloc. The engine holds no headers, not the last .text page and no zero fill.
    /// </summary>
    private static (INativeImage Image, byte[] File, byte[] Memory, bool[] Held) Fixture()
    {
        var b = new PeBuilder { ImageBase = Base };
        b.Add(".text", Enumerable.Range(0, 0x3000).Select(i => (byte)(i * 7)).ToArray(), 0x60000020);
        var data = new byte[0x200];
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(0x10), Base + 0x1000);
        b.Add(".data", data, 0xC0000040, virtualSize: 0x2000);
        var reloc = new byte[12];
        BinaryPrimitives.WriteUInt32LittleEndian(reloc, 0x4000);
        BinaryPrimitives.WriteUInt32LittleEndian(reloc.AsSpan(4), 12);
        BinaryPrimitives.WriteUInt16LittleEndian(reloc.AsSpan(8), 10 << 12 | 0x010);
        var r = b.Add(".reloc", reloc, 0x42000040);
        b.Directories[5] = (r.Rva, 12);
        var file = b.Build();
        var image = PeFile.FromBytes(file, "fixture.dll");
        var memory = new byte[image.SizeOfImage];
        image.Read(0, memory);
        var held = new bool[memory.Length];
        Array.Fill(held, true, 0x1000, 0x2000);
        Array.Fill(held, true, 0x4000, 0x200);
        Array.Fill(held, true, 0x6000, 0x1000);
        return (image, file, memory, held);
    }

    [Fact]
    public async Task Each_differing_range_is_named_by_what_wrote_it()
    {
        var (image, file, memory, held) = Fixture();
        memory[0x1010] = memory[0x1011] = 0x90;
        memory[0x1020] = 0xCC;
        for (int i = 0; i < 8; i++) memory[0x1040 + i] ^= 0xFF;
        memory[0x1080] = 0xEE;
        memory[0x4011] ^= 1;
        var engine = new ScriptedEngine(memory, held)
        {
            Fixups = new([new EngineFixup(0x1040, 8, "type 1, applied", "puts")], [new NativeByteRange(0x1020, [file[0x220]])], false),
        };
        var edit = new NativePatch(0x1010, 0x210, file[0x210..0x212], [0x90, 0x90], "test edit");

        var report = await EngineMemoryDiff.CompareAsync("ida", image, file, Base, engine, [edit], default);

        MemoryRange At(ulong va) => report.Ranges.Single(x => x.EngineAddress == $"0x{va:X}");
        Assert.Equal(("patched", 2u, "session edit: test edit"), (At(Base + 0x1010).Kind, At(Base + 0x1010).Length, At(Base + 0x1010).Detail));
        Assert.Equal(("patched", "patched in the database"), (At(Base + 0x1020).Kind, At(Base + 0x1020).Detail));
        Assert.Equal(("engine_fixup", 8u, "type 1, applied -> puts"), (At(Base + 0x1040).Kind, At(Base + 0x1040).Length, At(Base + 0x1040).Detail));
        var differs = report.Ranges.Single(x => x.Kind == "differs");
        Assert.Equal(($"0x{Base + 0x1080:X}", "0x280", "80", "EE"), (differs.EngineAddress, differs.FileOffset, differs.FileBytes, differs.EngineBytes));
        Assert.Equal(("unknown", 0x1000u), (At(Base + 0x3000).Kind, At(Base + 0x3000).Length));
        Assert.Equal(("relocation_applied", "base relocation at 0x4010, written by the engine's loader; the engine records no fixup there"),
            (At(Base + 0x4011).Kind, At(Base + 0x4011).Detail));
        Assert.Equal(("uninitialized", 0x1E00u, null), (At(Base + 0x4200).Kind, At(Base + 0x4200).Length, At(Base + 0x4200).FileOffset));
        Assert.Equal("unknown", At(Base).Kind); // the engine holds no headers
        var text = report.Sections.Single(s => s.Name == ".text");
        Assert.Equal((0x2000L, 0x2000L - 12, 0x1000L), (text.Compared, text.Equal, text.Unknown));
        Assert.True(report.FixupsListed);
        Assert.DoesNotContain(report.Notes, n => n.Contains("loaded the image at", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_rebased_pointer_is_a_relocation_and_without_fixups_the_rest_is_unclassified()
    {
        var (image, file, memory, held) = Fixture();
        const ulong engineBase = Base + 0x10000;
        BinaryPrimitives.WriteUInt64LittleEndian(memory.AsSpan(0x4010), engineBase + 0x1000);
        memory[0x1080] = 0xEE;
        var engine = new ScriptedEngine(memory, held);

        var report = await EngineMemoryDiff.CompareAsync("ghidra", image, file, engineBase, engine, [], default);

        var moved = report.Ranges.Single(x => x.Kind == "relocation_applied");
        Assert.Equal("base relocation at 0x4010 moved by 0x10000", moved.Detail);
        Assert.Equal($"0x{engineBase + 0x4012:X}", moved.EngineAddress);
        Assert.Equal($"0x{engineBase + 0x1080:X}", report.Ranges.Single(x => x.Kind == "unclassified").EngineAddress);
        Assert.DoesNotContain(report.Ranges, x => x.Kind is "differs" or "engine_fixup");
        Assert.False(report.FixupsListed);
        Assert.Contains(report.Notes, n => n.Contains("does not list its fixups", StringComparison.Ordinal));
        Assert.Contains(report.Notes, n => n.Contains($"loaded the image at 0x{engineBase:X}", StringComparison.Ordinal));
    }

    [Fact]
    public void Page_digests_of_runs_match_the_digest_of_the_same_bytes()
    {
        var bytes = Enumerable.Range(0, 0x2100).Select(i => (byte)i).ToArray();
        var pages = EngineControl.Digest([new NativeMemoryRun(0xF00, bytes)], 0x1000);
        Assert.Equal([(0xF00u, 0x100), (0x1000u, 0x1000), (0x2000u, 0x1000)], pages.Select(p => (p.Rva, p.Length)));
        Assert.Equal(NativeMemoryPage.Digest(bytes.AsSpan(0x100, 0x1000)), pages[1].Hash);
        Assert.Equal(16, pages[0].Hash.Length);
    }

    /// <summary>
    /// An engine holding <paramref name="memory"/> where <paramref name="held"/> is set; pages come from the interface's
    /// default (runs digested here, as with a worker without page digests) and fixups only when scripted.
    /// </summary>
    private sealed class ScriptedEngine(byte[] memory, bool[] held) : INativeEngineControl
    {
        public EngineFixupList? Fixups { get; init; }

        public Task<IReadOnlyList<NativeMemoryRun>> MemoryAsync(uint rva, uint length, CancellationToken cancellationToken = default)
        {
            var runs = new List<NativeMemoryRun>();
            long end = Math.Min(memory.Length, (long)rva + length);
            for (long i = rva; i < end;)
            {
                if (!held[i]) { i++; continue; }
                long j = i;
                while (j < end && held[j]) j++;
                runs.Add(new NativeMemoryRun((uint)i, memory[(int)i..(int)j]));
                i = j;
            }
            return Task.FromResult<IReadOnlyList<NativeMemoryRun>>(runs);
        }

        public Task<EngineFixupList> FixupsAsync(int max, CancellationToken cancellationToken = default) =>
            Fixups is { } f ? Task.FromResult(f) : throw new ToolError(ErrorCode.Unsupported, "This engine does not list its fixups.");

        public Task<IReadOnlyList<NativeAnalyzerOption>> AnalyzersAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<NativeReanalysis> ReanalyzeAsync(IReadOnlyList<KeyValuePair<string, string>> options, uint? start, uint? end, double seconds,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<NativeCandidateScan> FunctionCandidatesAsync(int maxInstructions, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<NativeMarkResult> SetMarksAsync(IReadOnlyList<NativeMark> marks, string stamp, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }
}
