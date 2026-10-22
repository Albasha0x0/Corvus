using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using Corvus.Native;
using Corvus.Native.Dwarf;
using Corvus.Native.Pdb;
using Corvus.Tests.NativeFormats;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// The DWARF reader against llvm-dwarfdump and llvm-symbolizer (CORVUS_LLVM_BIN) on 25 ELF and 5 Mach-O libraries of the
/// NativeAOT runtime packs; DWARF 2-5, type units, compressed sections, 32-bit and big-endian targets built with clang; and a
/// debug file of a gigabyte read within the memory budget.
/// </summary>
[Trait("Speed", "Slow")]
[Permit("reference-tool")]
public sealed partial class DwarfOracleTests(ITestOutputHelper output)
{
    private static readonly string[] Libraries =
        ["libSystem.Native", "libSystem.Globalization.Native", "libSystem.IO.Compression.Native", "libSystem.Net.Security.Native", "libSystem.Security.Cryptography.Native.OpenSsl"];
    private static readonly string[] LinuxTargets = ["linux-x64", "linux-arm64", "linux-arm", "linux-musl-x64", "linux-musl-arm64"];

    /// <summary>
    /// What llvm-dwarfdump shows: functions by address, and file- or namespace-scope structs by name and size with their members
    /// (byte offset, or -1 - bit offset for a bit field).
    /// </summary>
    private sealed record Dump(Dictionary<ulong, HashSet<string>> Functions, Dictionary<string, List<(string Name, long Offset)>> Structs);

    [GeneratedRegex(@"^(0x[0-9a-fA-F]+):(\s+)(DW_TAG_\w+)(?:\s+\[\d+\])?(?:\s+\*)?(?:\s+\((0x[0-9a-fA-F]+)\))?\s*$")]
    private static partial Regex TagLine();

    [GeneratedRegex(@"^\s+(DW_AT_\w+)(?:\s+\[[^\]]+\])?\s+\((.*)\)\s*$")]
    private static partial Regex AttributeLine();

    /// <summary>Reads llvm-dwarfdump --debug-info text (plain or --verbose): nesting from the parent offset when printed, else from the indentation.</summary>
    private static Dump Parse(string text)
    {
        var functions = new Dictionary<ulong, HashSet<string>>();
        var structs = new Dictionary<string, List<(string, long)>>();
        var dies = new Dictionary<string, (string Tag, string? Parent, Dictionary<string, string> Attrs)>();
        var order = new List<string>();
        var stack = new List<(int Indent, string Offset)>();
        string? current = null;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (TagLine().Match(line) is { Success: true } t)
            {
                int indent = t.Groups[2].Value.Length;
                string? parent = t.Groups[4].Success ? t.Groups[4].Value : null;
                if (parent == null)
                {
                    while (stack.Count > 0 && stack[^1].Indent >= indent) stack.RemoveAt(stack.Count - 1);
                    parent = stack.Count > 0 ? stack[^1].Offset : null;
                }
                current = Normalize(t.Groups[1].Value);
                stack.Add((indent, current));
                dies[current] = (t.Groups[3].Value, parent == null ? null : Normalize(parent), []);
                order.Add(current);
            }
            else if (current != null && AttributeLine().Match(line) is { Success: true } a)
                dies[current].Attrs.TryAdd(a.Groups[1].Value, a.Groups[2].Value);
        }
        static string Normalize(string offset) => Convert.ToUInt64(offset, 16).ToString("x");
        static string? Quoted(string? value) => value == null ? null : Regex.Match(value, "\"([^\"]*)\"\\s*\\)?$") is { Success: true } m ? m.Groups[1].Value : null;
        // the value's last hex number outside quotes: "(0x10)", "(indexed (0049) address = 0x2960)", "(cu + 0x3a => {0x0000003a} ...)"
        static ulong? Number(string? value) =>
            value == null ? null : Regex.Matches(Regex.Replace(value, "\"[^\"]*\"", ""), "0x[0-9a-fA-F]+") is { Count: > 0 } m ? Convert.ToUInt64(m[^1].Value, 16) : null;
        string? NameOf(string offset)
        {
            for (int hop = 0; hop < 8 && dies.TryGetValue(offset, out var d); hop++)
            {
                if (Quoted(d.Attrs.GetValueOrDefault("DW_AT_name")) is { } n) return n;
                var next = d.Attrs.GetValueOrDefault("DW_AT_specification") ?? d.Attrs.GetValueOrDefault("DW_AT_abstract_origin");
                if (next == null || Number(next) is not { } target) return null;
                offset = target.ToString("x");
            }
            return null;
        }
        foreach (var offset in order)
        {
            var (tag, parent, attrs) = dies[offset];
            if (tag == "DW_TAG_subprogram" && !attrs.ContainsKey("DW_AT_declaration") && Number(attrs.GetValueOrDefault("DW_AT_low_pc")) is { } low && low != 0
                && NameOf(offset) is { } name)
                (functions.TryGetValue(low, out var set) ? set : functions[low] = []).Add(name);
            if (tag is "DW_TAG_structure_type" or "DW_TAG_union_type" or "DW_TAG_class_type" && !attrs.ContainsKey("DW_AT_declaration")
                && Quoted(attrs.GetValueOrDefault("DW_AT_name")) is { } sname && parent != null && dies[parent].Tag is "DW_TAG_compile_unit" or "DW_TAG_namespace")
            {
                long size = (long)(Number(attrs.GetValueOrDefault("DW_AT_byte_size")) ?? 0);
                // a bit field by its bit offset (DWARF 4+), else a member by its byte offset
                var members = order.Where(o => dies[o].Parent == offset && dies[o].Tag == "DW_TAG_member" && !dies[o].Attrs.ContainsKey("DW_AT_declaration"))
                    .Select(o => (Quoted(dies[o].Attrs.GetValueOrDefault("DW_AT_name")) ?? "",
                        dies[o].Attrs.TryGetValue("DW_AT_data_bit_offset", out var bits) ? -1 - (long)(Number(bits) ?? 0)
                        : (long)(Number(dies[o].Attrs.GetValueOrDefault("DW_AT_data_member_location")) ?? 0)))
                    .ToList();
                structs.TryAdd($"{sname}:{size}", members);
            }
        }
        return new Dump(functions, structs);
    }

    /// <summary>Our reading of a debug file for its image: functions, structs and lines compared with the tools; returns a summary line.</summary>
    private string Compare(string imagePath, string debugPath, List<string> problems)
    {
        var image = NativeImageLoader.Open(imagePath);
        var clock = Stopwatch.StartNew();
        using var container = DebugContainer.Open(debugPath, image.BuildId);
        var pdb = DwarfDebugInfo.Read(container, image, () => DebugContainer.Open(debugPath, image.BuildId));
        var read = clock.Elapsed;
        var label = $"{Path.GetFileName(Path.GetDirectoryName(Path.GetDirectoryName(imagePath)))}/{Path.GetFileName(imagePath)}";
        var ours = pdb.Symbols.Where(s => s.IsFunction && s.Rva != null).GroupBy(s => image.ImageBase + s.Rva!.Value)
            .ToDictionary(g => g.Key, g => g.Select(s => s.Name.Split("::")[^1]).ToHashSet());
        Assert.NotEmpty(ours);
        var model = PdbTypeModel.Of(pdb, image.Is64Bit ? 8 : 4);
        string summary = $"{label}: {ours.Count} function addresses, {model.Records} type records, read in {read.TotalMilliseconds:0} ms";
        if (LlvmOracle.Run("llvm-dwarfdump", LlvmOracle.Options.DwarfDebugInfo, debugPath) is { } text)
        {
            var dump = Parse(text);
            foreach (var (address, names) in dump.Functions)
                if (!ours.TryGetValue(address, out var mine) || !names.IsSubsetOf(mine))
                    problems.Add($"{label} 0x{address:X}: llvm-dwarfdump {string.Join("/", names)}, ours {(mine == null ? "none" : string.Join("/", mine))}");
            if (ours.Count != dump.Functions.Count) problems.Add($"{label}: {ours.Count} function addresses, llvm-dwarfdump {dump.Functions.Count}");
            foreach (var (key, members) in dump.Structs)
            {
                var parts = key.Split(':');
                var node = model.Named(parts[0]).Select(model.Node).FirstOrDefault(n => n?.Size.ToString() == parts[1]);
                var mine = node?.Members.Where(m => m.Kind == PdbMemberKind.Data)
                    .Select(m => (m.Name, m.BitLength >= 0 && members.Any(x => x.Name == m.Name && x.Offset < 0) ? -1 - (m.Offset * 8 + m.BitPosition) : m.Offset)).ToList();
                if (mine == null || !mine.SequenceEqual(members)) problems.Add($"{label} struct {key}: llvm-dwarfdump {string.Join(",", members)}, ours {(mine == null ? "none" : string.Join(",", mine))}");
            }
            summary += $"; llvm-dwarfdump: {dump.Functions.Count} functions, {dump.Structs.Count} structs";
        }
        var sample = pdb.Symbols.Where(s => s.IsFunction && s.Rva != null && s.Size > 0)
            .SelectMany(s => new[] { s.Rva!.Value, s.Rva!.Value + s.Size / 2 }).Distinct().ToList();
        if (LlvmOracle.Symbolize(debugPath, sample.Select(r => image.ImageBase + r).ToList()) is { } expected)
        {
            var mine = pdb.Source!.Lookup(sample);
            int same = 0;
            for (int i = 0; i < expected.Count; i++)
            {
                var want = expected[i].Select(f => $"{f.Function}@{f.File}:{f.Line}");
                var got = mine[i]?.Frames.Select(f => $"{f.Function.Split("::")[^1]}@{Path.GetFileName(f.File ?? "??")}:{f.Line}") ?? [];
                if (want.SequenceEqual(got)) same++;
                else if (problems.Count < 200) problems.Add($"{label} line 0x{image.ImageBase + sample[i]:X}: llvm-symbolizer {string.Join(" <- ", want)}, ours {string.Join(" <- ", got)}");
            }
            summary += $"; lines: {same} of {expected.Count} equal llvm-symbolizer";
        }
        return summary;
    }

    [Fact]
    public void Corpus_names_types_and_lines_equal_llvm()
    {
        var problems = new List<string>();
        foreach (var rid in LinuxTargets)
            foreach (var lib in Libraries)
                output.WriteLine(Compare(NativeFixtures.NativeAotLib(rid, lib + ".so"), NativeFixtures.NativeAotLib(rid, lib + ".so.dbg"), problems));
        foreach (var lib in Libraries.Where(l => !l.EndsWith("OpenSsl", StringComparison.Ordinal)).Append("libSystem.Security.Cryptography.Native.Apple"))
            output.WriteLine(Compare(NativeFixtures.NativeAotLib("osx-arm64", lib + ".dylib"), NativeFixtures.NativeAotLib("osx-arm64", lib + ".dylib.dwarf"), problems));
        if (LlvmOracle.Bin == null) output.WriteLine($"{LlvmOracle.Variable} is not set: read only, not compared");
        foreach (var p in problems.Take(40)) output.WriteLine(p);
        Assert.Empty(problems);
    }

    private const string VariantSource = """
        namespace geo {
        struct Flags { unsigned ready : 1; unsigned level : 3; signed delta : 5; unsigned long long wide : 40; };
        enum Kind : int { KindNone = 0, KindBig = 0x7fffffff, KindNeg = -3 };
        typedef struct { int x, y; } Point;
        union Value { int i; float f; void* p; };
        class Shape { public: virtual ~Shape() {} virtual int area() const { return kind; } int kind; Point origin; };
        class Square : public Shape { public: int area() const override { return side * side; } int side; Value extra[2][3]; };
        template <typename T> struct Box { T value; T get() const { return value; } };
        static inline int twice(int v) { return v * 2; }
        int use(Square* s, Flags* f, Box<long>* b, Kind k, int (*cb)(Point*)) {
            Point p = { (int)f->level, twice(s->side) };
            return s->area() + (int)f->wide + (int)b->get() + (int)k + cb(&p) + twice(f->delta);
        }
        }
        geo::Square g_square;
        """;

    /// <summary>
    /// One C++ source built as DWARF 2, 3, 4 and 5, with type units, for 64- and 32-bit and a big-endian target (clang and lld
    /// from CORVUS_LLVM_BIN): the same qualified names, layouts, bit fields, enums and inlined calls from each.
    /// </summary>
    [Fact]
    public void Dwarf_versions_type_units_and_targets_read_alike()
    {
        if (LlvmOracle.Bin == null) { output.WriteLine($"{LlvmOracle.Variable} is not set"); return; }
        using var dir = new TempDir();
        (string Target, string Flags, int Pointer)[] variants =
        [
            ("x86_64-linux-gnu", LlvmOracle.Options.DwarfVersion + "2", 8),
            ("armv7a-linux-gnueabihf", LlvmOracle.Options.DwarfVersion + "3", 4),
            ("x86_64-linux-gnu", LlvmOracle.Options.DwarfVersion + "4 " + LlvmOracle.Options.TypeUnits, 8),
            ("i386-linux-gnu", LlvmOracle.Options.DwarfVersion + "4", 4),
            ("x86_64-linux-gnu", LlvmOracle.Options.DwarfVersion + "5", 8),
            ("x86_64-linux-gnu", LlvmOracle.Options.DwarfVersion + "5 " + LlvmOracle.Options.TypeUnits, 8),
            ("aarch64_be-linux-gnu", LlvmOracle.Options.DwarfVersion + "5", 8),
        ];
        foreach (var (target, flags, pointer) in variants)
        {
            var path = dir.File($"{target}{flags.Replace(' ', '_')}.so");
            var failure = LlvmOracle.Compile(VariantSource, path,
                $"{LlvmOracle.Options.Target}{target} {LlvmOracle.Options.ClangSharedObject} {flags} {LlvmOracle.Options.CPlusPlus}");
            Assert.True(failure == null, failure);
            var image = NativeImageLoader.Open(path);
            using var container = DebugContainer.FromMemory(path, File.ReadAllBytes(path));
            var pdb = DwarfDebugInfo.Read(container, image, () => DebugContainer.FromMemory(path, File.ReadAllBytes(path)));
            var model = PdbTypeModel.Of(pdb, pointer);
            var label = $"{target} {flags}";
            output.WriteLine($"{label}: {pdb.Symbols.Count} symbols, {model.Records} type records, {pdb.Source!.InlinedInstances} inlined; " +
                             string.Join("; ", pdb.Issues.Select(i => i.Message)));
            Assert.Empty(pdb.Issues);
            Assert.Contains(pdb.Symbols, s => s.Name == "geo::use" && s.IsFunction && s.LinkageName == "_ZN3geo3useEPNS_6SquareEPNS_5FlagsEPNS_3BoxIlEENS_4KindEPFiPNS_5PointEE");
            Assert.Contains(pdb.Symbols, s => s.Name == "geo::Square::area" && s.IsFunction);
            Assert.Contains(pdb.Symbols, s => s.Name == "g_square" && s.Kind == PdbSymbolKind.GlobalData && model.Spell(s.TypeIndex) == "geo::Square");
            Assert.True(pdb.Source.InlinedInstances > 0, label);

            var flagsType = model.Node(Assert.Single(model.Named("geo::Flags")))!;
            var bits = flagsType.Members.Select(m => (m.Name, Bit: m.Offset * 8 + (image is Native.Elf.ElfFile { BigEndian: true } ? Msb(m) : m.BitPosition), m.BitLength)).ToList();
            Assert.Equal([("ready", 0L, 1), ("level", 1L, 3), ("delta", 4L, 5), ("wide", 9L, 40)], bits);
            var kind = model.Node(Assert.Single(model.Named("geo::Kind")))!;
            Assert.Equal([("KindNone", 0L), ("KindBig", 0x7fffffffL), ("KindNeg", -3L)], kind.Enumerators.Select(e => (e.Name, e.Value)));
            var square = model.Node(Assert.Single(model.Named("geo::Square")))!;
            Assert.Contains(square.Members, m => m.Kind == PdbMemberKind.Base && model.Spell(m.Type) == "geo::Shape" && m.Offset == 0);
            var extra = square.Members.Single(m => m.Name == "extra");
            Assert.Equal("geo::Value[2][3]", model.Spell(extra.Type));
            Assert.Equal(pointer == 8 ? 48 : 24, model.SizeOf(extra.Type));
            Assert.Equal(PdbTypeKind.Struct, model.Node(Assert.Single(model.Named("geo::Point")))!.Kind);
            Assert.Equal(pointer, model.Node(Assert.Single(model.Named("geo::Box<long>")))!.Size);
        }

        // a big-endian bit field counted from the storage unit's most significant bit, as the declaration order lays it out
        static long Msb(PdbTypeMember m) => (m.BitLength == 40 ? 64 : 32) - m.BitPosition - m.BitLength;
    }
}

/// <summary>A debug file of a gigabyte read with a bounded working set (no other test runs meanwhile: the working set is the process's).</summary>
[Collection(nameof(SerialTimingTests))]
public sealed class DwarfMemoryTests(ITestOutputHelper output)
{
    /// <summary>One DWARF 4 unit of about 64 KB: a long producer string, a struct of 50 members, one function.</summary>
    private static (byte[] Abbrev, byte[] Unit) Unit()
    {
        byte[] abbrev =
        [
            1, 0x11, 1, 0x25, 0x08, 0x03, 0x08, 0x11, 0x01, 0x12, 0x06, 0, 0, // compile unit: producer, name, low_pc, high_pc
            2, 0x13, 1, 0x03, 0x08, 0x0b, 0x05, 0, 0, // struct: name, byte_size
            3, 0x0d, 0, 0x03, 0x08, 0x49, 0x13, 0x38, 0x05, 0, 0, // member: name, type, location
            4, 0x24, 0, 0x03, 0x08, 0x0b, 0x0b, 0x3e, 0x0b, 0, 0, // base type: name, size, encoding
            5, 0x2e, 0, 0x03, 0x08, 0x11, 0x01, 0x12, 0x06, 0x3f, 0x19, 0, 0, // function: name, low_pc, high_pc, external
            0,
        ];
        var body = new MemoryStream();
        var w = new BinaryWriter(body);
        void Text(string s) { w.Write(System.Text.Encoding.ASCII.GetBytes(s)); w.Write((byte)0); }
        w.Write((ushort)4); w.Write(0u); w.Write((byte)8);
        w.Write((byte)1); Text(new string('p', 64_000)); Text("big.c"); w.Write(0xD7A0UL); w.Write(0x100u);
        int intAt = (int)body.Position + 4;
        w.Write((byte)4); Text("int"); w.Write((byte)4); w.Write((byte)5);
        w.Write((byte)2); Text("Big"); w.Write((ushort)200);
        for (int i = 0; i < 50; i++) { w.Write((byte)3); Text($"m{i}"); w.Write(intAt); w.Write((ushort)(4 * i)); }
        w.Write((byte)0);
        w.Write((byte)5); Text("f"); w.Write(0xD7A0UL); w.Write(0x40u);
        w.Write((byte)0);
        w.Flush();
        var unit = new byte[4 + body.Length];
        BitConverter.GetBytes((uint)body.Length).CopyTo(unit, 0);
        body.ToArray().CopyTo(unit, 4);
        return (abbrev, unit);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_gigabyte_debug_file_reads_within_the_memory_budget()
    {
        if (ChildTest.Rerun(this, output)) return;
        using var dir = new TempDir();
        var image = NativeImageLoader.Open(NativeFixtures.NativeAotLib("linux-x64", "libSystem.Native.so"));
        var (abbrev, unit) = Unit();
        int copies = (int)((1L << 30) / unit.Length) + 1;
        var path = dir.File("large.debug");
        DebugFileWriter.Write(path,
        [
            DebugFileWriter.BuildId(image.BuildId!), DebugFileWriter.Bytes(".debug_abbrev", abbrev),
            new DebugFileWriter.Section(".debug_info", 1, s => { for (int i = 0; i < copies; i++) s.Write(unit); }),
        ]);
        GC.Collect();
        GC.WaitForPendingFinalizers();
        long baseline = Environment.WorkingSet, peak = baseline;
        using var done = new ManualResetEventSlim();
        var sampler = new Thread(() => { while (!done.Wait(20)) peak = Math.Max(peak, Environment.WorkingSet); }) { IsBackground = true };
        sampler.Start();
        var clock = Stopwatch.StartNew();
        PdbFile pdb;
        using (var container = DebugContainer.Open(path, image.BuildId)) pdb = DwarfDebugInfo.Read(container, image, () => DebugContainer.Open(path, image.BuildId));
        clock.Stop();
        done.Set();
        sampler.Join();
        peak = Math.Max(peak, Environment.WorkingSet);
        long length = new FileInfo(path).Length;
        output.WriteLine($"{length:N0} bytes, {copies:N0} units in {clock.Elapsed.TotalSeconds:F1} s; working set {baseline >> 20} MB before, peak {peak >> 20} MB (+{(peak - baseline) >> 20} MB)");
        Assert.True(length > 1L << 30);
        Assert.Equal(copies, pdb.Symbols.Count(s => s.Name == "f"));
        var model = PdbTypeModel.Of(pdb, 8);
        Assert.Equal(200, model.Node(Assert.Single(model.Named("Big")))!.Size);
        Assert.True(peak - baseline < 200L << 20, $"working set grew by {(peak - baseline) >> 20} MB");
    }
}
