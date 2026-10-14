using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Msvc;
using Corvus.Native.Pe;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// The code index and RTTI recovery give the same results on the real PE parser (<see cref="PeFile"/>, the reference for
/// loader semantics) and on the test-only adapters written before it (<see cref="CodeTestImage"/>, <see cref="MsvcTestImage"/>).
/// CORVUS_NATIVE_ADAPTER_SAMPLE sets the files per directory (default 60; 0 = all).
/// </summary>
[Trait("Speed", "Slow")]
public class NativeAdapterConsistencyTests(ITestOutputHelper output)
{
    private static int Limit => int.TryParse(Environment.GetEnvironmentVariable("CORVUS_NATIVE_ADAPTER_SAMPLE"), out var l) ? l : 60;

    public static IEnumerable<object[]> Directories() =>
    [
        [Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32")],
        [Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64")],
    ];

    [Theory]
    [MemberData(nameof(Directories))]
    public void SameFunctionsReferencesAndClasses(string directory)
    {
        if (!OperatingSystem.IsWindows() || !Directory.Exists(directory)) return;
        var files = NativeToolSweepTests.Sample(NativeToolHarness.NativeFiles(directory, maxSize: 30_000_000)
            .Where(f => f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)), Limit);
        var differences = new List<string>();
        int compared = 0, functions = 0, classes = 0;
        foreach (var path in files)
        {
            PeFile pe;
            CodeTestImage code;
            MsvcTestImage? msvc;
            try
            {
                pe = PeFile.Open(path);
                code = CodeTestImage.Load(path);
                msvc = MsvcTestImage.TryLoad(path);
            }
            catch (Exception ex) when (ex is BadImageFormatException or IOException or UnauthorizedAccessException or InvalidOperationException) { continue; }
            if (pe.Arch is not (NativeArch.X86 or NativeArch.X64) || msvc == null) continue;
            compared++;
            var name = Path.GetFileName(path);
            foreach (var d in ImageDifferences(pe, code)) differences.Add($"{name}: image: {d}");

            var a = NativeCodeIndex.Build(pe);
            var b = NativeCodeIndex.Build(code);
            functions += a.Functions.Count;
            var onlyA = a.Functions.Select(f => f.Start).Except(b.Functions.Select(f => f.Start)).ToList();
            var onlyB = b.Functions.Select(f => f.Start).Except(a.Functions.Select(f => f.Start)).ToList();
            if (onlyA.Count + onlyB.Count > 0)
                differences.Add($"{name}: functions {a.Functions.Count} vs {b.Functions.Count}; only PeFile {Hex(onlyA)}; only adapter {Hex(onlyB)}");
            if (a.Stats.Xrefs != b.Stats.Xrefs || a.Stats.Strings != b.Stats.Strings || a.Stats.Instructions != b.Stats.Instructions)
                differences.Add($"{name}: xrefs {a.Stats.Xrefs} vs {b.Stats.Xrefs}, strings {a.Stats.Strings} vs {b.Stats.Strings}, instructions {a.Stats.Instructions} vs {b.Stats.Instructions}");

            var ra = MsvcRtti.Analyze(pe);
            var rb = MsvcRtti.Analyze(msvc);
            classes += ra.Classes.Count;
            var ca = ra.Classes.Select(c => $"{c.Name}|{c.Vtables.Count}|{c.Bases.Count}").Order().ToList();
            var cb = rb.Classes.Select(c => $"{c.Name}|{c.Vtables.Count}|{c.Bases.Count}").Order().ToList();
            if (!ca.SequenceEqual(cb))
                differences.Add($"{name}: RTTI classes {ra.Classes.Count} vs {rb.Classes.Count}; only PeFile {string.Join(", ", ca.Except(cb).Take(3))}; only adapter {string.Join(", ", cb.Except(ca).Take(3))}");
        }
        output.WriteLine($"{directory}: {compared} images compared, {functions} functions, {classes} RTTI classes, {differences.Count} differences");
        foreach (var d in differences.Take(60)) output.WriteLine("DIFF " + d);
        Assert.Empty(differences);
    }

    private static string Hex(List<uint> rvas) => rvas.Count == 0 ? "none" : $"{rvas.Count}: " + string.Join(" ", rvas.Order().Take(5).Select(r => r.ToString("X")));

    /// <summary>What the code index reads from an image, compared field by field.</summary>
    internal static IEnumerable<string> ImageDifferences(INativeImage a, INativeImage b)
    {
        if (a.Arch != b.Arch || a.ImageBase != b.ImageBase || a.EntryPointRva != b.EntryPointRva || a.SizeOfImage != b.SizeOfImage)
            yield return $"headers {a.Arch}/{a.ImageBase:X}/{a.EntryPointRva:X}/{a.SizeOfImage:X} vs {b.Arch}/{b.ImageBase:X}/{b.EntryPointRva:X}/{b.SizeOfImage:X}";
        if (a.Sections.Count != b.Sections.Count || a.Sections.Zip(b.Sections).Any(p => p.First != p.Second))
            yield return "sections differ: " + string.Join("; ", a.Sections.Zip(b.Sections).Where(p => p.First != p.Second).Take(2).Select(p => $"{p.First} vs {p.Second}"));
        static string Imp(NativeImport i) => $"{i.Module.ToLowerInvariant()}!{i.Name ?? "#" + i.Ordinal}@{i.SlotRva:X}{(i.IsDelayLoad ? "d" : "")}";
        var ia = a.Imports.Select(Imp).ToHashSet();
        var ib = b.Imports.Select(Imp).ToHashSet();
        if (!ia.SetEquals(ib))
            yield return $"imports {ia.Count} vs {ib.Count}; only PeFile {string.Join(", ", ia.Except(ib).Take(3))}; only adapter {string.Join(", ", ib.Except(ia).Take(3))}";
        static string Exp(NativeExport e) => $"{e.Name}#{e.Ordinal}@{e.Rva:X}>{e.ForwardedTo}";
        var ea = a.Exports.Select(Exp).ToHashSet();
        var eb = b.Exports.Select(Exp).ToHashSet();
        if (!ea.SetEquals(eb))
            yield return $"exports {ea.Count} vs {eb.Count}; only PeFile {string.Join(", ", ea.Except(eb).Take(3))}; only adapter {string.Join(", ", eb.Except(ea).Take(3))}";
        if (!a.RuntimeFunctions.SequenceEqual(b.RuntimeFunctions)) yield return $".pdata {a.RuntimeFunctions.Count} vs {b.RuntimeFunctions.Count}";
        if (!a.RelocationRvas.SequenceEqual(b.RelocationRvas)) yield return $"relocations {a.RelocationRvas.Count} vs {b.RelocationRvas.Count}";
        if (!a.TlsCallbackRvas.SequenceEqual(b.TlsCallbackRvas)) yield return $"TLS callbacks {a.TlsCallbackRvas.Count} vs {b.TlsCallbackRvas.Count}";
    }
}
