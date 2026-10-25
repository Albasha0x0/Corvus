using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests.NativeFormats;

/// <summary>
/// Code names read from snapshots the Dart SDK (CORVUS_DART), earlier Dart releases (CORVUS_DART_RELEASES) and Flutter's
/// gen_snapshot (CORVUS_FLUTTER; earlier releases in CORVUS_FLUTTER_RELEASES) compile, compared with the debug symbols
/// the compiler writes beside them (--save-debugging-info), which name each code address as the VM prints it.
/// </summary>
[Trait("Speed", "Slow")]
[Permit("reference-tool")]
public sealed class DartSdkProgramTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private const string Source = """
        // A ledger with classes, methods, getters, closures and a top-level function.
        class LedgerEntry {
          final String account;
          final int cents;
          LedgerEntry(this.account, this.cents);
          bool get isCredit => cents > 0;
          String describe() => '$account:${cents ~/ 100}.${(cents % 100).abs()}';
        }

        class Ledger {
          final List<LedgerEntry> entries = [];
          void post(String account, int cents) => entries.add(LedgerEntry(account, cents));
          int balanceOf(String account) =>
              entries.where((e) => e.account == account).fold(0, (sum, e) => sum + e.cents);
          Map<String, int> totals() {
            final out = <String, int>{};
            for (final e in entries) {
              out.update(e.account, (v) => v + e.cents, ifAbsent: () => e.cents);
            }
            return out;
          }
        }

        int checksumOrders(List<int> values) {
          var h = 17;
          for (final v in values) {
            h = (h * 31 + v) & 0x7fffffff;
          }
          return h;
        }

        void main(List<String> args) {
          final ledger = Ledger();
          for (var i = 0; i < 10 + args.length; i++) {
            ledger.post(i.isEven ? 'cash' : 'bank', (i * 1234) - 5000);
          }
          print(ledger.totals());
          print(ledger.balanceOf('cash'));
          print(checksumOrders([for (final e in ledger.entries) e.cents]));
          print(ledger.entries.where((e) => e.isCredit).map((e) => e.describe()).join(','));
        }
        """;

    /// <summary>
    /// Compiles <see cref="Source"/> with <paramref name="op"/> and returns the read program, its instructions' RVA and the
    /// debug symbols by address.
    /// </summary>
    private (DartProgram Program, uint Text, Dictionary<uint, HashSet<string>> Symbols) Compile(string op, string? dart = null, string name = "ledger")
    {
        var source = _dir.File($"{name}-{op}.dart");
        File.WriteAllText(source, Source);
        string snapshot = _dir.File($"{name}-{op}.aot"), debug = _dir.File($"{name}-{op}.debug");
        var tool = ExternalTools.DartSdk;
        var run = ExternalTools.Run(dart ?? ExternalTools.Locate(tool)!.Value.Path, ExternalTools.Arguments(tool, op, ("output", snapshot), ("debug", debug), ("source", source)),
            TimeSpan.FromMinutes(5), 1 << 20, default);
        Assert.True(run.ExitCode == 0, run.Stderr + run.Text);
        var (program, text) = DartNames.Read(NativeImageLoader.FromBytes(File.ReadAllBytes(snapshot), snapshot))!.Value;
        var symbols = new Dictionary<uint, HashSet<string>>();
        foreach (var s in NativeImageLoader.FromBytes(File.ReadAllBytes(debug), debug).Symbols.Where(s => s.Kind == ImageSymbolKind.Function))
            (symbols.TryGetValue(s.Rva, out var set) ? set : symbols[s.Rva] = []).Add(s.Name);
        return (program, text, symbols);
    }

    /// <summary>
    /// Compiles <see cref="Source"/> as Flutter's build does (frontend server, then gen_snapshot for the Android release of
    /// <paramref name="arch"/>, which compresses pointers) and returns the read program, its instructions' RVA and the debug
    /// symbols by address.
    /// </summary>
    private (DartProgram Program, uint Text, Dictionary<uint, HashSet<string>> Symbols) CompileCompressed(string arch, string? sdk = null, string name = "flutter")
    {
        var source = _dir.File($"{name}-{arch}.dart");
        File.WriteAllText(source, Source);
        string kernel = _dir.File($"{name}-{arch}.dill"), elf = _dir.File($"{name}-{arch}.so"), debug = _dir.File($"{name}-{arch}.debug");
        var tool = ExternalTools.FlutterSdk;
        var exe = OperatingSystem.IsWindows() ? ".exe" : "";
        // dartaotruntime sits in <root>/bin/cache/dart-sdk/bin.
        var root = sdk ?? Path.GetFullPath(Path.Combine(Path.GetDirectoryName(ExternalTools.Locate(tool)!.Value.Path)!, "..", "..", "..", ".."));
        var bin = Path.Combine(root, "bin", "cache", "dart-sdk", "bin");
        // Releases before the AOT frontend server snapshot run the JIT one in dart.
        bool aot = File.Exists(Path.Combine(bin, "snapshots", "frontend_server_aot.dart.snapshot"));
        var runtime = Path.Combine(bin, (aot ? "dartaotruntime" : "dart") + exe);
        var host = OperatingSystem.IsWindows() ? "windows-x64" : OperatingSystem.IsMacOS() ? "darwin-x64" : "linux-x64";
        var genSnapshot = Path.Combine(root, "bin", "cache", "artifacts", "engine", $"android-{arch}-release", host, "gen_snapshot" + (OperatingSystem.IsWindows() ? ".exe" : ""));
        var run = ExternalTools.Run(runtime, ExternalTools.Arguments(tool, aot ? "kernel" : "kernel-jit", ("root", root), ("output", kernel), ("source", source)), TimeSpan.FromMinutes(5), 1 << 20, default);
        Assert.True(run.ExitCode == 0, run.Stderr + run.Text);
        run = ExternalTools.Run(genSnapshot, ExternalTools.Arguments(tool, "aot-elf", ("output", elf), ("debug", debug), ("kernel", kernel)), TimeSpan.FromMinutes(5), 1 << 20, default);
        Assert.True(run.ExitCode == 0, run.Stderr + run.Text);
        var image = NativeImageLoader.FromBytes(File.ReadAllBytes(elf), elf);
        // Releases before 3.13 write a VM and an isolate snapshot.
        Assert.All(DartScan.Snapshots(File.ReadAllBytes(elf)).Where(s => s.Kind == "full-aot"), s => Assert.Contains("compressed-pointers", s.Features));
        var (program, text) = DartNames.Read(image)!.Value;
        var symbols = new Dictionary<uint, HashSet<string>>();
        foreach (var s in NativeImageLoader.FromBytes(File.ReadAllBytes(debug), debug).Symbols.Where(s => s.Kind == ImageSymbolKind.Function))
            (symbols.TryGetValue(s.Rva, out var set) ? set : symbols[s.Rva] = []).Add(s.Name);
        return (program, text, symbols);
    }

    /// <summary>Matching names and differing ones (address, ours, the symbols'); an address without a symbol fails.</summary>
    private (int Same, List<string> Differ) Compare(DartProgram program, uint text, Dictionary<uint, HashSet<string>> symbols)
    {
        Assert.Null(program.Unsupported);
        int same = 0;
        var differ = new List<string>();
        foreach (var c in program.Code)
        {
            Assert.True(symbols.TryGetValue(text + c.Offset, out var names), $"no debug symbol at 0x{text + c.Offset:X} ({c.Name})");
            if (names.Contains(c.Name)) same++;
            else differ.Add($"0x{text + c.Offset:X} {c.Name} / {string.Join(" | ", names)}");
        }
        output.WriteLine($"{same} of {program.Code.Count} names equal the debug symbols; {program.Functions} functions, {program.Unnamed} stubs unnamed");
        foreach (var d in differ.Take(30)) output.WriteLine(d);
        return (same, differ);
    }

    // Differences left: code shared by several functions (the symbols name another of them) and mixin names.
    [RequiresRealDataFact("CORVUS_DART")]
    public void Names_equal_the_compilers_debug_symbols()
    {
        var (program, text, symbols) = Compile("aot");
        var (same, _) = Compare(program, text, symbols);
        Assert.True(same * 100 >= program.Code.Count * 99, $"{same} of {program.Code.Count}");
        // A constructor and its class's allocation stub both print "new <class>"; Ledger.post is inlined, with no code.
        var at = program.Code.ToLookup(c => c.Name, c => text + c.Offset);
        foreach (var name in new[] { "main", "checksumOrders", "Ledger.balanceOf", "Ledger.totals", "LedgerEntry.describe", "new Ledger", "new LedgerEntry" })
            Assert.True(at[name].Any(address => symbols[address].Contains(name)), name);
    }

    // Each folder dart-<version>/dart-sdk holds one release; releases before 3.13 write VM and isolate snapshots.
    [RequiresRealDataFact("CORVUS_DART_RELEASES")]
    public void Earlier_releases_name_their_code_as_their_debug_symbols_do()
    {
        var sdks = Directory.GetDirectories(Environment.GetEnvironmentVariable("CORVUS_DART_RELEASES")!, "dart-*").Order().ToList();
        Assert.NotEmpty(sdks);
        var problems = new List<string>();
        foreach (var sdk in sdks)
        {
            var release = Path.GetFileName(sdk)[5..];
            var dart = Path.Combine(sdk, "dart-sdk", "bin", "dart" + (OperatingSystem.IsWindows() ? ".exe" : ""));
            var (program, text, symbols) = Compile("aot", dart, release);
            int same = program.Code.Count(c => symbols.TryGetValue(text + c.Offset, out var names) && names.Contains(c.Name));
            output.WriteLine($"Dart {release}: layout {program.Layout ?? program.Unsupported}, {same} of {program.Code.Count} names equal");
            foreach (var c in program.Code.Where(c => !(symbols.TryGetValue(text + c.Offset, out var names) && names.Contains(c.Name))).Take(30))
                output.WriteLine($"  0x{text + c.Offset:X} {c.Name} / {string.Join(" | ", symbols.GetValueOrDefault(text + c.Offset) ?? [])}");
            if (program.Unsupported != null || same * 100 < program.Code.Count * 99) problems.Add($"Dart {release}: {same} of {program.Code.Count}");
            var at = program.Code.ToLookup(c => c.Name, c => text + c.Offset);
            foreach (var name in new[] { "main", "checksumOrders", "Ledger.balanceOf", "Ledger.totals", "LedgerEntry.describe" })
                if (!at[name].Any(address => symbols.TryGetValue(address, out var names) && names.Contains(name))) problems.Add($"Dart {release}: {name}");
        }
        Assert.True(problems.Count == 0, string.Join("; ", problems));
    }

    // The VM writes no read-only data image with compressed pointers: strings and code metadata are read from the stream.
    [RequiresRealDataTheory("CORVUS_FLUTTER")]
    [InlineData("x64")]
    [InlineData("arm64")]
    public void A_compressed_pointer_build_names_equal_its_debug_symbols(string arch)
    {
        var (program, text, symbols) = CompileCompressed(arch);
        var (same, _) = Compare(program, text, symbols);
        Assert.True(same * 100 >= program.Code.Count * 99, $"{same} of {program.Code.Count}");
        var at = program.Code.ToLookup(c => c.Name, c => text + c.Offset);
        foreach (var name in new[] { "main", "checksumOrders", "Ledger.balanceOf", "Ledger.totals", "LedgerEntry.describe" })
            Assert.True(at[name].Any(address => symbols[address].Contains(name)), name);
    }

    // Each folder flutter-<version> holds one release's Dart SDK, patched SDK and Android gen_snapshot, as Flutter caches them.
    [RequiresRealDataFact("CORVUS_FLUTTER_RELEASES")]
    public void Earlier_compressed_pointer_releases_name_their_code_as_their_debug_symbols_do()
    {
        var sdks = Directory.GetDirectories(Environment.GetEnvironmentVariable("CORVUS_FLUTTER_RELEASES")!, "flutter-*").Order().ToList();
        Assert.NotEmpty(sdks);
        var problems = new List<string>();
        foreach (var sdk in sdks)
            foreach (var arch in new[] { "x64", "arm64" })
            {
                var release = $"Flutter {Path.GetFileName(sdk)[8..]} {arch}";
                var (program, text, symbols) = CompileCompressed(arch, sdk, Path.GetFileName(sdk));
                int same = program.Code.Count(c => symbols.TryGetValue(text + c.Offset, out var names) && names.Contains(c.Name));
                output.WriteLine($"{release}: layout {program.Layout ?? program.Unsupported}, {same} of {program.Code.Count} names equal");
                foreach (var c in program.Code.Where(c => !(symbols.TryGetValue(text + c.Offset, out var names) && names.Contains(c.Name))).Take(30))
                    output.WriteLine($"  0x{text + c.Offset:X} {c.Name} / {string.Join(" | ", symbols.GetValueOrDefault(text + c.Offset) ?? [])}");
                if (program.Unsupported != null || same * 100 < program.Code.Count * 99) problems.Add($"{release}: {same} of {program.Code.Count}");
            }
        Assert.True(problems.Count == 0, string.Join("; ", problems));
    }

    // DWARF stack traces drop the Function objects of most code; closures whose parent is gone print "<optimized out>".
    [RequiresRealDataFact("CORVUS_DART")]
    public void A_build_with_separate_debug_information_names_what_its_snapshot_keeps()
    {
        var (program, text, symbols) = Compile("aot-split");
        var (same, _) = Compare(program, text, symbols);
        Assert.True(same * 100 >= program.Code.Count * 89, $"{same} of {program.Code.Count}");
        Assert.Contains(program.Code, c => c.Name == "main");
    }
}
