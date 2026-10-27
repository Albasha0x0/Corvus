using System.Reflection;
using System.Runtime.CompilerServices;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>S12.5: every format reader has a quick fuzz entry ([FuzzEntry] on a test of the quick set).</summary>
public class FormatFuzzCoverageTests
{
    private static readonly Assembly Server = typeof(Providers).Assembly;

    /// <summary>Entry points that take a file's bytes: a non-private static method of one of these names whose first parameter is the bytes.</summary>
    private static readonly string[] EntryNames = ["FromBytes", "Read", "Parse", "Open", "TryRead", "TryParse"];

    private static readonly Type[] ByteInputs = [typeof(byte[]), typeof(ReadOnlySpan<byte>), typeof(ReadOnlyMemory<byte>), typeof(Stream)];

    /// <summary>Readers of structures inside an image already read, which the scan for byte entry points does not see.</summary>
    private static readonly Type[] ImageReaders =
    [
        typeof(Corvus.Native.Dwarf.DwarfReader), typeof(Corvus.Native.MachO.AppleObjcMetadata), typeof(Corvus.Native.MachO.AppleSwiftMetadata),
        typeof(Corvus.Native.NativeAot.NativeAotImage), typeof(Corvus.Native.NativeAot.NativeAotMetadata), typeof(Corvus.Native.ReadyToRun.R2RImage),
        typeof(Corvus.Native.Go.GoBuildInfo), typeof(Corvus.Native.Go.GoFunctionTable),
    ];

    /// <summary>The format readers of the server: container readers, summarize_file views, byte entry points and <see cref="ImageReaders"/>.</summary>
    internal static SortedDictionary<string, string> Readers()
    {
        var readers = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var t in Server.GetTypes())
        {
            if (t.IsDefined(typeof(CompilerGeneratedAttribute))) continue;
            if (t is { IsClass: true, IsAbstract: false } && (typeof(IContainerReader).IsAssignableFrom(t) || typeof(IFileSummaryView).IsAssignableFrom(t)))
                readers[Key(t)] = typeof(IContainerReader).IsAssignableFrom(t) ? "container reader" : "summarize_file view";
            foreach (var m in t.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
                if (!m.IsPrivate && EntryNames.Contains(m.Name) && m.GetParameters() is [var first, ..] && ByteInputs.Contains(first.ParameterType))
                    readers.TryAdd(Key(t), $"{m.Name}({first.ParameterType.Name})");
        }
        foreach (var t in ImageReaders) readers[Key(t)] = "image reader";
        return readers;
    }

    /// <summary>Each reader named by a [FuzzEntry] with the tests that name it, and the entries outside the quick set.</summary>
    private static (Dictionary<Type, List<string>> Covered, List<string> Slow) Entries()
    {
        var covered = new Dictionary<Type, List<string>>();
        var slow = new List<string>();
        foreach (var type in typeof(FormatFuzzCoverageTests).Assembly.GetTypes())
            foreach (var method in type.GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
            {
                var entries = method.GetCustomAttributes<FuzzEntryAttribute>().ToList();
                if (entries.Count == 0) continue;
                var name = $"{type.Name}.{method.Name}";
                if (!method.IsDefined(typeof(FactAttribute), true) || IsSlow(method)) slow.Add(name);
                foreach (var reader in entries.SelectMany(e => e.Readers))
                    (covered.TryGetValue(reader, out var list) ? list : covered[reader] = []).Add(name);
            }
        return (covered, slow);
    }

    private static bool IsSlow(MethodInfo method)
    {
        static bool Slow(MemberInfo m) => m.GetCustomAttributesData().Any(a => a.AttributeType == typeof(TraitAttribute)
            && a.ConstructorArguments is [{ Value: "Speed" }, { Value: "Slow" }]);
        if (Slow(method)) return true;
        for (var t = method.DeclaringType; t != null; t = t.DeclaringType)
            if (Slow(t)) return true;
        return false;
    }

    /// <summary>"Native.Pe.PeFile"; nested types keep their '+'.</summary>
    private static string Key(Type t) => t.FullName!.StartsWith("Corvus.", StringComparison.Ordinal) ? t.FullName["Corvus.".Length..] : t.FullName;

    [Fact]
    public void Every_reader_has_a_quick_fuzz_entry()
    {
        var (covered, slow) = Entries();
        Assert.True(slow.Count == 0, "[FuzzEntry] belongs on a quick test ([Fact] or [Theory], not Speed=Slow): " + string.Join(", ", slow));
        bool Covers(Type? t)
        {
            for (; t != null; t = t.DeclaringType)
                if (covered.ContainsKey(t)) return true;
            return false;
        }
        var types = Server.GetTypes().ToDictionary(Key, StringComparer.Ordinal);
        var violations = Readers().Where(r => !Covers(types[r.Key])).ToDictionary(r => r.Key, r => $"{r.Value}: no quick fuzz entry");
        Ratchet.Check("format-fuzz", "every format reader has a quick fuzz entry, a [FuzzEntry] test in the quick set (S12.5)", violations);
    }

    [Fact]
    public void The_scan_finds_the_known_readers()
    {
        var readers = Readers();
        Assert.All(new[] { "Native.Pe.PeFile", "Native.Elf.ElfFile", "Native.MachO.MachOFile", "Native.Dump.MinidumpFile", "Native.Pdb.PdbFile",
            "Core.Mobile.DexFile", "Core.Archives.ArchiveReader", "Services.Analysis.SqliteFileView", "Native.Dwarf.DwarfReader" },
            r => Assert.True(readers.ContainsKey(r), r));
    }
}
