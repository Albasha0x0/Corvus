using System.Diagnostics;
using System.Text.RegularExpressions;
using Corvus.Native.Code;
using Corvus.Native.Msvc;
using Corvus.Native.Pdb;
using Corvus.Native.Pe;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>The PDB reader against real PDBs: a C++ sample built with /Zi (checked against its linker map) and system DLLs whose PDBs are in a local cache.</summary>
public class PdbOracleTests(ITestOutputHelper output)
{
    private const string SampleSource = """
        #include <cstdio>
        namespace geo {
            struct Vec { int x, y; Vec operator+(const Vec& o) const; int dot(const Vec& o) const; };
            Vec Vec::operator+(const Vec& o) const { return { x + o.x, y + o.y }; }
            int Vec::dot(const Vec& o) const { return x * o.x + y * o.y; }
        }
        class Shape {
        public:
            Shape(int k) : kind(k) {}
            virtual ~Shape() {}
            virtual int area() const { return kind; }
            int kind;
        };
        class Square : public Shape {
        public:
            Square(int s) : Shape(2), side(s) {}
            int area() const override { return side * side; }
            int side;
        };
        template <typename T> struct Box { T value; __declspec(noinline) T get() const { return value; } };
        static __declspec(noinline) int helper(int v) { return v * 3 + 1; }
        int overloaded(int a) { return a + helper(a); }
        int overloaded(double a) { return (int)a * 2; }
        extern "C" __declspec(dllexport) int c_export(int a) { return a ^ 0x5A; }
        int g_counter = 7;
        static int s_hidden = 9;
        const char* g_name = "sample";
        __declspec(dllexport) int use_all(int n) {
            geo::Vec a{ n, 2 }, b{ 3, n };
            Square sq(n);
            Shape* s = &sq;
            Box<int> bi{ n }; Box<double> bd{ 1.5 };
            s_hidden += n;
            return (a + b).dot(a) + s->area() + bi.get() + (int)bd.get() + overloaded(n) + overloaded(2.0) + g_counter + s_hidden + (int)g_name[0];
        }
        """;

    private sealed record MapSymbol(string Name, uint Rva, bool Function, string Object);

    private static List<MapSymbol> ReadMap(string path, ulong imageBase)
    {
        var list = new List<MapSymbol>();
        var line = new Regex(@"^\s*[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{8,16})\s+(f\s+)?(i\s+)?(\S+)\s*$");
        foreach (var l in File.ReadLines(path))
        {
            var m = line.Match(l);
            if (!m.Success) continue;
            ulong va = Convert.ToUInt64(m.Groups[2].Value, 16);
            if (va >= imageBase) list.Add(new MapSymbol(m.Groups[1].Value, (uint)(va - imageBase), m.Groups[3].Success, m.Groups[5].Value));
        }
        return list;
    }

    [Theory]
    [Trait("Speed", "Slow")]
    [InlineData("x64")]
    [InlineData("x86")]
    public void CompiledSampleMatchesItsLinkerMap(string arch)
    {
        var vcvars = VisualStudio.VcVarsAll();
        if (vcvars == null) return; // no Visual C++ build tools
        using var dir = new TempDir();
        File.WriteAllText(dir.File("sample.cpp"), SampleSource);
        var psi = new ProcessStartInfo("cmd.exe")
        {
            WorkingDirectory = dir.Path,
            Arguments = $"/s /c \"\"{vcvars}\" {arch} >nul && cl /nologo /c /Zi /O1 /GR /EHsc sample.cpp"
                + " && link /nologo /DLL /DEBUG /INCREMENTAL:NO /OPT:NOICF /MAP:sample.map /PDB:sample.pdb /OUT:sample.dll sample.obj\"",
        };
        var (code, log) = Tools.Run(psi, 300_000);
        Assert.True(code == 0 && File.Exists(dir.File("sample.pdb")), log);

        var image = PeFile.Open(dir.File("sample.dll"));
        var location = PdbLocator.Locate(image, symbolPath: "");
        Assert.Equal(dir.File("sample.pdb"), location.Path);
        var sw = Stopwatch.StartNew();
        var pdb = PdbFile.Open(location.Path!, image.Sections);
        var names = PdbNaming.Choose(pdb, image.SizeOfImage).ToDictionary(n => n.Rva);
        output.WriteLine($"{arch}: {pdb.Symbols.Count} symbols, {pdb.Modules.Count} modules, {names.Count} names in {sw.ElapsedMilliseconds} ms; issues: {string.Join("; ", pdb.Issues.Select(i => i.Message))}");
        Assert.Empty(pdb.Issues);
        Assert.True(pdb.Matches(image.CodeView!));

        var map = ReadMap(dir.File("sample.map"), image.ImageBase);
        // compiler-generated exception-handling labels ($unwind$f, __ehhandler$f, ...) are in the map only
        var ours = map.Where(m => m.Object == "sample.obj" && !(m.Name.Contains('$') && !m.Name.StartsWith('?'))).ToList();
        Assert.Contains(ours, m => m.Name.Contains("helper"));
        var publics = pdb.Symbols.Where(s => s.IsPublic).Select(s => (s.Name, s.Rva)).ToHashSet();
        var errors = new List<string>();
        foreach (var m in ours)
        {
            // every symbol of the map is at the same address in the PDB: externals as publics, statics as procedures or data
            bool isPublic = publics.Contains((m.Name, m.Rva));
            if (!names.TryGetValue(m.Rva, out var n)) { errors.Add($"{m.Name} @ {m.Rva:X}: no PDB name"); continue; }
            if (m.Function != n.IsFunction) errors.Add($"{m.Name} @ {m.Rva:X}: function {m.Function} in the map, {n.IsFunction} in the PDB");
            string plain = MsvcDemangler.Undecorate(m.Name, MsvcNameStyle.NameOnly) ?? (arch == "x86" && m.Name.StartsWith('_') ? m.Name[1..] : m.Name);
            if (n.Name != plain && n.Name != m.Name && !isPublic) errors.Add($"{m.Name} @ {m.Rva:X}: PDB name '{n.Name}', expected '{plain}'");
            if (m.Name.StartsWith('?') && n.Decorated != null && n.Decorated != m.Name && !isPublic) errors.Add($"{m.Name} @ {m.Rva:X}: decorated '{n.Decorated}'");
        }
        foreach (var expect in new[] { "geo::Vec::operator+", "geo::Vec::dot", "Square::area", "Box<int>::get", "Box<double>::get", "helper", "overloaded", "c_export", "use_all", "g_counter", "s_hidden" })
            if (!names.Values.Any(n => n.Name == expect)) errors.Add($"no PDB name '{expect}'");
        Assert.True(errors.Count == 0, string.Join("\n", errors));

        // with the PDB's functions as roots, the code index has a function at every function of the map
        var starts = names.Values.Where(n => n.IsFunction).Select(n => n.Rva).ToArray();
        var index = NativeCodeIndex.Build(image, new CodeIndexOptions { SymbolStarts = starts });
        var missing = ours.Where(m => m.Function && index.FunctionByStart(m.Rva) == null).Select(m => m.Name).ToList();
        Assert.True(missing.Count == 0, string.Join(", ", missing));
    }

    /// <summary>Downloads the PDB of a system DLL from Microsoft's symbol server; runs only with CORVUS_NETWORK_TESTS=1.</summary>
    [OptInFact("CORVUS_NETWORK_TESTS")]
    [Trait("Speed", "Slow")]
    public async Task DownloadsASystemPdbWhenNetworkTestsAreOn()
    {
        var dll = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll");
        if (!File.Exists(dll)) return;
        var image = PeFile.Open(dll);
        using var dir = new TempDir();
        var path = await PdbLocator.DownloadAsync(image.CodeView!, PdbLocator.DefaultServer, TimeSpan.FromMinutes(2), 256L << 20, null, dir.File("cache"));
        var pdb = PdbFile.Open(path, image.Sections);
        Assert.True(pdb.Matches(image.CodeView!));
        var names = PdbNaming.Choose(pdb, image.SizeOfImage).Select(n => n.Name).ToHashSet();
        Assert.Contains("CreateFileW", names);
    }

    /// <summary>Every PDB in the local symbol caches (up to 400): read without exception; the issues and the slowest read are reported.</summary>
    [Fact]
    [Trait("Speed", "Slow")]
    public void EveryCachedPdbReads()
    {
        var files = PdbLocator.LocalStores([])
            .Where(Directory.Exists)
            .SelectMany(d => { try { return Directory.EnumerateFiles(d, "*.pdb", SearchOption.AllDirectories).Take(400).ToList(); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; } })
            .Distinct(StringComparer.OrdinalIgnoreCase).Take(400).ToList();
        int read = 0, withIssues = 0, symbols = 0;
        long slowestMs = 0, bytes = 0, readMs = 0, namingMs = 0;
        string slowest = "";
        var total = Stopwatch.StartNew();
        foreach (var f in files)
        {
            var sw = Stopwatch.StartNew();
            PdbFile pdb;
            try { pdb = PdbFile.Open(f); }
            catch (Corvus.Core.ToolError e) { output.WriteLine($"{f}: {e.Code} {e.Message}"); continue; }
            readMs += sw.ElapsedMilliseconds;
            long naming = sw.ElapsedMilliseconds;
            PdbNaming.Choose(pdb);
            namingMs += sw.ElapsedMilliseconds - naming;
            read++;
            symbols += pdb.Symbols.Count;
            bytes += pdb.FileSize;
            if (pdb.Issues.Count > 0) { withIssues++; output.WriteLine($"{f}: {string.Join("; ", pdb.Issues.Take(3).Select(i => i.Message))}"); }
            if (sw.ElapsedMilliseconds > slowestMs) (slowestMs, slowest) = (sw.ElapsedMilliseconds, $"{f} ({pdb.FileSize:N0} bytes, {pdb.Symbols.Count} symbols)");
        }
        output.WriteLine($"{read} of {files.Count} PDBs read ({bytes:N0} bytes, {symbols:N0} symbols) in {total.ElapsedMilliseconds} ms (reading {readMs} ms, naming {namingMs} ms), {withIssues} with issues; slowest {slowestMs} ms: {slowest}");
    }

    /// <summary>System DLLs whose matching PDB is in a local symbol cache (_NT_SYMBOL_PATH, C:\symbols, ...): every named export has a PDB symbol at its address.</summary>
    [Fact]
    [Trait("Speed", "Slow")]
    public void SystemDllsWithCachedPdbsAgreeWithTheirExports()
    {
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        if (system.Length == 0 || !Directory.Exists(system)) return;
        int checkedImages = 0, exportsChecked = 0;
        var errors = new List<string>();
        long slowestMs = 0;
        string slowest = "";
        foreach (var path in Directory.EnumerateFiles(system, "*.dll").OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
        {
            if (checkedImages >= 40) break;
            PeFile image;
            try { image = PeFile.Open(path); }
            catch (Corvus.Core.ToolError) { continue; }
            if (image.CodeView is not { Format: "RSDS" } || image.Exports.Count == 0) continue;
            var location = PdbLocator.Locate(image);
            if (location.Path == null) continue;
            var sw = Stopwatch.StartNew();
            var pdb = PdbFile.Open(location.Path, image.Sections);
            var names = PdbNaming.Choose(pdb, image.SizeOfImage);
            if (sw.ElapsedMilliseconds > slowestMs) (slowestMs, slowest) = (sw.ElapsedMilliseconds, $"{Path.GetFileName(location.Path)} ({new FileInfo(location.Path).Length:N0} bytes, {pdb.Symbols.Count} symbols)");
            checkedImages++;
            if (pdb.Issues.Count > 0) errors.Add($"{Path.GetFileName(path)}: {string.Join("; ", pdb.Issues.Select(i => i.Message))}");
            var at = names.Select(n => n.Rva).ToHashSet();
            var exports = image.Exports.Where(e => e.ForwardedTo == null && e.Name != null && image.SectionAt(e.Rva) is { IsExecutable: true }).ToList();
            int missing = exports.Count(e => !at.Contains(e.Rva));
            exportsChecked += exports.Count;
            // a handful of exports may be aliases the PDB does not record; most must be there
            if (missing > Math.Max(2, exports.Count / 100)) errors.Add($"{Path.GetFileName(path)}: {missing} of {exports.Count} exports have no PDB symbol");
        }
        output.WriteLine($"{checkedImages} DLLs with cached PDBs, {exportsChecked} exports checked; slowest read {slowestMs} ms: {slowest}");
        Assert.True(errors.Count == 0, string.Join("\n", errors));
    }
}
