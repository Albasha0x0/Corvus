using Corvus.Core;
using Corvus.Native.Elf;
using Corvus.Services;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

/// <summary>The Il2Cpp binary layout on damaged images: a layout, or a tool error naming why the binary is not read.</summary>
public sealed class Il2CppLayoutFuzzTests
{
    /// <summary>The PE as a loaded module lays it out: headers, then every section at its RVA.</summary>
    private static byte[] Mapped(byte[] pe)
    {
        var header = MappedPeLayout.Parse(pe)!;
        var mapped = new byte[header.SizeOfImage];
        pe.AsSpan(0, (int)header.SizeOfHeaders).CopyTo(mapped);
        foreach (var s in header.Sections)
            pe.AsSpan((int)s.RawOffset, (int)Math.Min(s.RawSize, s.VirtualSize)).CopyTo(mapped.AsSpan((int)s.Rva));
        return mapped;
    }

    [Fact]
    [FuzzEntry(typeof(MappedPeLayout))]
    public void Fuzzed_pe_headers_never_throw()
    {
        var pe = NativePeTests.KitchenSink(true);
        static void Read(byte[] b)
        {
            if (MappedPeLayout.Parse(b) is not { } h) return;
            foreach (var s in h.Sections) _ = (h.SectionAt(s.Rva), h.FileOffset(s.Rva));
            if (MappedPeLayout.IsMapped(b, h)) MappedPeLayout.Normalize(b, h);
        }
        var failures = FormatFuzz.Run(pe, Read, 1000);
        failures.AddRange(FormatFuzz.Run(Mapped(pe), Read, 1000));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }

    [Fact]
    [FuzzEntry(typeof(Il2CppBinaryLayout))]
    public void Fuzzed_il2cpp_binaries_never_throw_past_a_tool_error()
    {
        var pe = NativePeTests.KitchenSink(true);
        var seeds = new[] { pe, Mapped(pe), FormatWriterTests.SampleElf().Build(), FormatWriterTests.SampleElf(false, ElfWriter.EmArm).Build(), FormatWriterTests.SampleMachO().Build() };
        var failures = new List<string>();
        foreach (var seed in seeds)
            failures.AddRange(FormatFuzz.Run(seed, b =>
            {
                try
                {
                    var layout = Il2CppBinaryLayout.Open(b, "GameAssembly.bin").Layout;
                    foreach (var a in layout.Areas)
                        _ = (layout.FileOffset(a.Rva), layout.InCode(layout.ImageBase + a.Rva + 1), layout.AreaAt(a.Rva + a.Size / 2));
                }
                catch (ToolError) { }
            }, 300));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }
}
