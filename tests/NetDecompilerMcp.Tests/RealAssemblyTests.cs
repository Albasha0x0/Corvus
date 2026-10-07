using System.Collections.Concurrent;
using System.Diagnostics;
using dnlib.DotNet;
using NetDecompilerMcp.Core;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Robustness on large real-world assemblies (dnlib, the ILSpy engine itself) and, when present on this machine,
/// on a real Il2CppDumper DummyDll folder.
/// </summary>
public class RealAssemblyTests(ITestOutputHelper output)
{
    private static readonly string DnlibPath = typeof(ModuleDefMD).Assembly.Location;
    private static readonly string IlSpyPath = typeof(ICSharpCode.Decompiler.CSharp.CSharpDecompiler).Assembly.Location;

    [Fact]
    public void DecompilesEveryTopLevelTypeOfDnlibConcurrently()
    {
        using var env = new Env(DnlibPath);
        var types = env.Fixture.Module.Types.Where(t => t.FullName != "<Module>").ToList();
        var failures = new ConcurrentBag<string>();
        int fallbacks = 0;
        var sw = Stopwatch.StartNew();
        Parallel.ForEach(types, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, t =>
        {
            try
            {
                var code = env.Workspace.Read(() => env.Decompiler.DecompileType(env.Fixture, t, default));
                if (code.Contains("Whole-type decompilation failed")) Interlocked.Increment(ref fallbacks);
                if (code.Length < 20) failures.Add($"{t.FullName}: empty output");
            }
            catch (Exception ex)
            {
                failures.Add($"{t.FullName}: {ex.GetType().Name}: {ex.Message}");
            }
        });
        output.WriteLine($"{types.Count} types in {sw.Elapsed.TotalSeconds:F1}s, {fallbacks} needed member-by-member fallback");
        Assert.Empty(failures);
    }

    [Fact]
    public void SearchAndCrossReferencesScaleOnTheIlSpyEngine()
    {
        using var env = new Env(IlSpyPath);
        env.Workspace.Load(DnlibPath);
        var all = env.Workspace.Assemblies;
        var sw = Stopwatch.StartNew();

        var strings = env.Search.SearchStrings("cannot", false, all, 50, default);
        var symbols = env.Search.SearchSymbols("Visit*", false, SymbolKind.Method, all, null, 50, default);
        var il = env.Search.SearchIL("newobj *Exception::.ctor*; throw", all, 50, default);
        var constant = env.Search.SearchConstants("0x7FFFFFFF", all, 50, default);
        output.WriteLine($"searches: {sw.ElapsedMilliseconds} ms (strings {strings.Total}, symbols {symbols.Total}, il {il.Total}, constants {constant.Total})");
        Assert.True(strings.Total > 0 && symbols.Total > 0 && il.Total > 0 && constant.Total > 0);

        sw.Restart();
        var settings = env.One("ICSharpCode.Decompiler.DecompilerSettings", SymbolKind.Type);
        var refs = env.References.FindReferences(settings, true, 500, default);
        var hierarchy = env.References.GetHierarchy((TypeDef)env.One("ICSharpCode.Decompiler.IL.ILInstruction", SymbolKind.Type).Member, 500, default);
        output.WriteLine($"xrefs: {sw.ElapsedMilliseconds} ms (DecompilerSettings used {refs.Total}x, ILInstruction has {hierarchy.DerivedTotal} direct subclasses)");
        Assert.True(refs.Total > 50);
        Assert.True(hierarchy.DerivedTotal > 5);
    }

    [Fact]
    public void CSharpPatchOfRealCodeRunsAfterSave()
    {
        using var env = new Env(DnlibPath);
        env.Edit(() => env.Edits.PatchMethodCSharp(env.One("dnlib.DotNet.UTF8String::ToString()"), "return \"patched:\" + String;", false, default));
        using var dir = new TempDir();
        var path = dir.File("dnlib.dll");
        env.Edits.Save(env.Fixture, path, false);

        var context = new System.Runtime.Loader.AssemblyLoadContext("patched-dnlib", isCollectible: true);
        try
        {
            var asm = context.LoadFromStream(new MemoryStream(File.ReadAllBytes(path)));
            var type = asm.GetType("dnlib.DotNet.UTF8String")!;
            var value = Activator.CreateInstance(type, "abc")!;
            Assert.Equal("patched:abc", value.ToString());
        }
        finally
        {
            context.Unload();
        }
    }

    [Fact]
    public void ExportsDnlibAsProject()
    {
        using var env = new Env(DnlibPath);
        using var dir = new TempDir();
        var sw = Stopwatch.StartNew();
        var result = env.Decompiler.ExportProject(env.Fixture, dir.Path, null, default);
        output.WriteLine($"export: {result.FileCount} files in {sw.Elapsed.TotalSeconds:F1}s, {result.FailedTypes.Count} failed types");
        Assert.True(result.FileCount > 300);
        Assert.NotNull(result.ProjectFile);
    }

    /// <summary>A real app's assemblies (NDM_MONO_GAME_DIR): decompile, search, cross-reference and patch its own code.</summary>
    [RequiresRealDataFact(RealData.MonoGameDir)]
    public void RealGameAssembliesEndToEnd()
    {
        using var ws = new AssemblyWorkspace();
        var options = new ServerOptions();
        var decompiler = new Services.DecompilerService(ws, options);
        var search = new Services.SearchService();
        var references = new Services.ReferenceService(ws);
        var sw = Stopwatch.StartNew();
        var report = ws.LoadDirectory(RealData.Path(RealData.MonoGameDir), false);
        output.WriteLine($"load: {report.Loaded.Count} assemblies, {ws.Assemblies.Sum(a => a.Module.GetTypes().Count())} types in {sw.ElapsedMilliseconds} ms");
        Assert.NotEmpty(report.Loaded);

        // Decompile every top-level type of the app's own assemblies (not the bundled framework / engine) concurrently.
        var game = ws.Assemblies.Where(RealData.IsAppAssembly).ToList();
        Assert.NotEmpty(game);
        var types = game.SelectMany(a => a.Module.Types.Where(t => t.FullName != "<Module>").Select(t => (a, t))).ToList();
        var failures = new ConcurrentBag<string>();
        int fallbacks = 0;
        sw.Restart();
        Parallel.ForEach(types, x =>
        {
            try
            {
                var code = ws.Read(() => decompiler.DecompileType(x.a, x.t, default));
                if (code.Contains("Whole-type decompilation failed")) Interlocked.Increment(ref fallbacks);
            }
            catch (Exception ex) { failures.Add($"{x.t.FullName}: {ex.GetType().Name}: {ex.Message}"); }
        });
        output.WriteLine($"decompiled {types.Count} game types in {sw.Elapsed.TotalSeconds:F1}s; {fallbacks} used member fallback; {failures.Count} failed");
        Assert.Empty(failures);

        sw.Restart();
        var strings = search.SearchStrings("http", false, ws.Assemblies, 20, default);
        var symbols = search.SearchSymbols("*Manager*", false, SymbolKind.Type, game, null, 20, default);
        output.WriteLine($"search: {sw.ElapsedMilliseconds} ms (strings {strings.Total}, *Manager* types {symbols.Total})");

        sw.Restart();
        var target = symbols.Items.FirstOrDefault() ?? search.SearchSymbols("*", false, SymbolKind.Type, game, null, 1, default).Items[0];
        var refs = ws.Read(() => references.FindReferences(target, true, 200, default));
        output.WriteLine($"xrefs to {target.Label}: {refs.Total} in {sw.ElapsedMilliseconds} ms");

        // C# patch dry run on a real method: the first bool method without out / ref parameters ("return true;" must be
        // a valid body for it). In a typical game folder that is in a bundled library with internal types in signatures.
        var method = game.SelectMany(a => a.Module.GetTypes()).SelectMany(t => t.Methods)
            .First(m => m.HasBody && !m.IsConstructor && m.ReturnType.ElementType == ElementType.Boolean && !m.DeclaringType.Name.String.Contains('<')
                        && !m.DeclaringType.HasGenericParameters && !m.Name.String.Contains('.') && !m.IsGetter && !m.IsSetter
                        && m.Parameters.All(p => p.Type is not ByRefSig));
        var asm = ws.Assemblies.First(a => a.Module == method.Module);
        var patcher = new Services.CSharpPatcher(ws, decompiler);
        sw.Restart();
        using var scratch = ModuleDefMD.Load(asm.GetImageBytes(), ws.DnlibContext);
        var compiled = ws.Read(() => patcher.PatchMethod(new ResolvedSymbol(asm, method), "return true;", scratch, default));
        output.WriteLine($"C# patch dry run of {Format.MemberLabel(method)}: {compiled.Listing.Split('\n').Length} instructions in {sw.ElapsedMilliseconds} ms");
        Assert.Contains("ret", compiled.Listing);
    }

    /// <summary>A real Il2CppDumper / Cpp2IL DummyDll folder (NDM_IL2CPP_DUMMY_DIR).</summary>
    [RequiresRealDataFact(RealData.Il2CppDummyDir)]
    public void Il2CppDummyDllFolder()
    {
        using var ws = new AssemblyWorkspace();
        var sw = Stopwatch.StartNew();
        var report = ws.LoadDirectory(RealData.Path(RealData.Il2CppDummyDir), false);
        output.WriteLine($"loaded {report.Loaded.Count} assemblies in {sw.ElapsedMilliseconds} ms");
        Assert.NotEmpty(report.Loaded);

        var il2cpp = new Services.Il2CppService(ws);
        var index = ws.Assemblies.SelectMany(il2cpp.GetIndex).Where(e => e.Rva != null).ToList();
        Assert.NotEmpty(index);

        // Round-trip a sample of real RVAs: every exact start maps back to a method sharing that RVA.
        var rng = new Random(42);
        foreach (var entry in Enumerable.Range(0, 300).Select(_ => index[rng.Next(index.Count)]))
        {
            var matches = il2cpp.FindByAddress(entry.Rva!.Value, "rva", ws.Assemblies);
            Assert.Contains(matches, m => m.Relation == "exact start" && m.Entry.Rva == entry.Rva);
        }

        var options = new ServerOptions();
        var decompiler = new Services.DecompilerService(ws, options);
        var sample = ws.Assemblies.SelectMany(a => a.Module.Types.Skip(1).Take(3).Select(t => (a, t))).Take(60).ToList();
        foreach (var (asm, t) in sample)
            Assert.False(string.IsNullOrWhiteSpace(decompiler.DecompileType(asm, t, default)));
    }
}
