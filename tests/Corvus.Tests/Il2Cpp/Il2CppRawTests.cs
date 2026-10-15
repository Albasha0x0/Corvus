using System.Diagnostics;
using dnlib.DotNet;
using Corvus.Core;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// The built-in Il2Cpp metadata reader: header checks and typed errors, game file discovery, memory-image layouts,
/// and the model's round trip into the script the navigator uses (quick); on a real game, agreement with an
/// Il2CppDumper dump of the same files (slow, CORVUS_IL2CPP_GAME and CORVUS_IL2CPP_GAME_DUMP).
/// </summary>
public sealed class Il2CppRawTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private string Metadata(string name, uint magic, int version, int size = 0x100)
    {
        var bytes = new byte[size];
        BitConverter.TryWriteBytes(bytes.AsSpan(0), magic);
        BitConverter.TryWriteBytes(bytes.AsSpan(4), version);
        var path = _dir.File(name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    [Fact]
    public void UnreadableMetadataIsATypedErrorWithAReason()
    {
        var encrypted = Assert.Throws<ToolError>(() => Il2CppMetadataReader.CheckHeader(Metadata("enc.dat", 0x12345678, 29)));
        Assert.Equal(ErrorCode.MalformedInput, encrypted.Code);
        Assert.Contains("encrypted_or_obfuscated", encrypted.Message);
        foreach (var version in new[] { 23, 40 })
        {
            var old = Assert.Throws<ToolError>(() => Il2CppMetadataReader.CheckHeader(Metadata($"v{version}.dat", 0xFAB11BAF, version)));
            Assert.Equal(ErrorCode.Unsupported, old.Code);
            Assert.Contains("unsupported_version", old.Message);
        }
        Assert.Contains("truncated", Assert.Throws<ToolError>(() => Il2CppMetadataReader.CheckHeader(Metadata("short.dat", 0xFAB11BAF, 29, 6))).Message);
        Assert.Equal(31, Il2CppMetadataReader.CheckHeader(Metadata("ok.dat", 0xFAB11BAF, 31)));

        // A valid header over nothing, with a binary that is no Il2Cpp build: every layout fails, reported as such.
        Directory.CreateDirectory(_dir.File("game"));
        var metadata = Metadata(Path.Combine("game", "global-metadata.dat"), 0xFAB11BAF, 29, 0x400);
        File.Copy(McpProtocolTests.NativeSample(_dir), _dir.File(Path.Combine("game", "GameAssembly.dll")));
        var files = Assert.IsType<Il2CppGameFiles>(Il2CppGameFiles.Find(metadata));
        var error = Assert.Throws<ToolError>(() => Il2CppMetadataReader.Read(files, _dir.File("out"), null, default));
        Assert.Equal(ErrorCode.MalformedInput, error.Code);
        Assert.Contains("Tried: Unity", error.Message);
    }

    [Fact]
    public async Task LoadAssemblyReadsAGameFolderAndReportsWhyNot()
    {
        var game = _dir.File("enc");
        Directory.CreateDirectory(Path.Combine(game, "G_Data", "il2cpp_data", "Metadata"));
        Metadata(Path.Combine("enc", "G_Data", "il2cpp_data", "Metadata", "global-metadata.dat"), 0xDEADBEEF, 29);
        File.Copy(McpProtocolTests.NativeSample(_dir), Path.Combine(game, "GameAssembly.dll"));
        using var ws = new AssemblyWorkspace();
        var options = new ServerOptions { BackgroundIndexing = false, WatchFiles = false };
        var il2cpp = new Il2CppService(ws);
        var tools = new Corvus.Tools.WorkspaceTools(ws, il2cpp, new IndexingService(ws, new CallGraphService(ws), options), new Corvus.Services.Analysis.UnpackService(ws));
        var error = await Assert.ThrowsAsync<ToolError>(() => tools.LoadAssembly(game));
        Assert.Contains("encrypted_or_obfuscated", error.Message);
        Assert.Empty(ws.Assemblies); // nothing half-loaded
        // GameAssembly.dll alone still loads as a native image, with the way to its metadata.
        Assert.Contains("Il2Cpp game: its metadata is", await tools.LoadAssembly(Path.Combine(game, "GameAssembly.dll")));
        // A package without Il2Cpp metadata says so, not that it is no PE file.
        var apk = _dir.File("plain.apk");
        using (var zip = System.IO.Compression.ZipFile.Open(apk, System.IO.Compression.ZipArchiveMode.Create)) zip.CreateEntry("classes.dex");
        var previousCache = Environment.GetEnvironmentVariable(Il2CppRawLoader.RootVariable);
        Environment.SetEnvironmentVariable(Il2CppRawLoader.RootVariable, _dir.File("cache"));
        try { Assert.Contains("reason no_il2cpp_metadata", (await Assert.ThrowsAsync<ToolError>(() => tools.LoadAssembly(apk))).Message); }
        finally { Environment.SetEnvironmentVariable(Il2CppRawLoader.RootVariable, previousCache); }
    }

    [Fact]
    public void GameFilesAreFoundFromTheFolderTheMetadataOrTheBinary()
    {
        var game = _dir.File("Game");
        var meta = Path.Combine(game, "Game_Data", "il2cpp_data", "Metadata");
        Directory.CreateDirectory(meta);
        var metadata = Metadata(Path.Combine("Game", "Game_Data", "il2cpp_data", "Metadata", "global-metadata.dat"), 0xFAB11BAF, 24);
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => Il2CppGameFiles.Find(metadata)).Code); // no binary yet
        var binary = Path.Combine(game, "GameAssembly.dll");
        File.WriteAllBytes(binary, [0x4D, 0x5A]);
        foreach (var path in new[] { game, metadata, binary })
        {
            var files = Assert.IsType<Il2CppGameFiles>(Il2CppGameFiles.Find(path));
            Assert.Equal(Path.GetFullPath(binary), files.Binary, ignoreCase: true);
            Assert.Equal(Path.GetFullPath(metadata), files.Metadata, ignoreCase: true);
            Assert.EndsWith("Game_Data", files.DataDirectory);
        }
        Assert.Null(Il2CppGameFiles.Find(Env.FixturePath)); // an ordinary assembly
    }

    [Fact]
    public void MemoryImagesAreReadAtTheirRvas()
    {
        var bytes = NativePeTests.KitchenSink(is64: true);
        var header = MappedPeLayout.Parse(bytes)!;
        Assert.False(MappedPeLayout.IsMapped(bytes, header));
        // The loaded-module layout: headers, then every section at its RVA, SizeOfImage long.
        var mapped = new byte[header.SizeOfImage];
        bytes.AsSpan(0, (int)header.SizeOfHeaders).CopyTo(mapped);
        foreach (var s in header.Sections)
            bytes.AsSpan((int)s.RawOffset, (int)Math.Min(s.RawSize, s.VirtualSize)).CopyTo(mapped.AsSpan((int)s.Rva));
        Assert.True(MappedPeLayout.IsMapped(mapped, header));
        var path = _dir.File("mapped.dll");
        File.WriteAllBytes(path, mapped);
        Assert.All(NativeCodeScanner.Sections(path), s => Assert.Equal(s.Rva, s.RawOffset));
        Assert.Contains(NativeCodeScanner.Sections(McpProtocolTests.NativeSample(_dir)), s => s.Rva != s.RawOffset);
    }

    [Fact]
    public void ModelRoundTripsIntoTheNavigatorsScript()
    {
        var model = new Il2CppGameModel
        {
            BinaryPath = "b", MetadataPath = "m", MetadataVersion = 29.1f, HeaderVersion = 29, UnityVersion = "2022.1.0f1", UnityVersionSource = "test",
            ImageBase = 0x180000000, MemoryImage = false,
            LiteralValues = ["hello", "unslotted"], LiteralSlots = [0x3000, 0],
            Methods =
            [
                new(0x1000, "Ns.Box<int>$$Put", "Asm.dll", 0x06000002),
                new(0x1000, "Ns.Box<uint>$$Put", "Asm.dll", 0x06000002),
                new(0x1100, "Ns.Plain$$Run", "Asm.dll", 0x06000005),
            ],
            Metadata = [new(0x5000, "Ns.Plain_TypeInfo", "Ns_Plain_c*"), new(0x5008, "Ns.Plain_var", "Il2CppType*")],
            MethodInfos = [new(0x5010, "Method$Ns.Plain.Run()", 0x1100)],
            Addresses = [0x1200],
            Unreadables = [new("method X::Y", "pointer_outside_image", "detail")],
        };
        var path = _dir.File(Il2CppGameModel.FileName);
        model.Write(path);
        var back = Il2CppGameModel.Read(path);
        Assert.Equal(model.Methods, back.Methods);
        Assert.Equal(model.LiteralSlots, back.LiteralSlots);
        Assert.Equal("pointer_outside_image", Assert.Single(back.Unreadables).Reason);

        var script = Il2CppScript.FromModel(back, path);
        Assert.True(script.FromMetadata);
        Assert.Equal(new uint[] { 0x1000, 0x1100, 0x1200 }, script.FunctionStarts);
        var (first, count) = script.MethodRange(0x1000);
        Assert.Equal(2, count);
        Assert.Equal(("Asm.dll", 0x06000002u), script.Definition(first));
        Assert.Equal("Ns.Box<int>$$Put", script.ReadMethod(first).Name);
        Assert.Equal("Il2CppType*", script.ReadMetadata(Assert.Single(script.MetadataNamed("Ns.Plain_var"))).Signature);
        var info = Assert.Single(script.MethodInfosNamed("Method$Ns.Plain.Run()"));
        Assert.Equal(0x1100u, script.MethodInfoTarget(info));
        int seen = 0;
        script.ForEachMethodInfo(_ => seen++, default);
        Assert.Equal(1, seen);
        Assert.Throws<IOException>(() => Il2CppGameModel.Read(Env.FixturePath));
    }

    /// <summary>script.json names built-in types by their C# keyword ("string_TypeInfo"); either spelling finds the slot.</summary>
    [Fact]
    public void BuiltInTypesAreFoundByEitherSpelling()
    {
        var model = new Il2CppGameModel
        {
            BinaryPath = "b", MetadataPath = "m", MetadataVersion = 29, HeaderVersion = 29, UnityVersion = "2022.1.0f1", UnityVersionSource = "test",
            ImageBase = 0x180000000, MemoryImage = false, LiteralValues = [], LiteralSlots = [], Methods = [], MethodInfos = [], Addresses = [], Unreadables = [],
            Metadata = [new(0x5000, "string_TypeInfo", "System_String_c*"), new(0x5008, "System.Collections.Generic.List<string>_TypeInfo", "x")],
        };
        var path = _dir.File("alias-" + Il2CppGameModel.FileName);
        model.Write(path);
        var script = Il2CppScript.FromModel(Il2CppGameModel.Read(path), path);
        Assert.Single(Il2CppNavigator.FindSlots(script, "System.String_TypeInfo").Metadata);
        Assert.Single(Il2CppNavigator.FindSlots(script, "string_TypeInfo").Metadata);
        Assert.Empty(Il2CppNavigator.FindSlots(script, "System.Strin_TypeInfo").Metadata);
        Assert.Equal(("string", "System.String", "Ns.Type"), (Il2CppNames.OtherSpelling("System.String"), Il2CppNames.FullTypeKey("string"), Il2CppNames.FullTypeKey("Ns.Type")));
    }

    /// <summary>
    /// A raw game (CORVUS_IL2CPP_GAME: game folder or global-metadata.dat) read by the built-in reader, against an
    /// Il2CppDumper dump of the same files (CORVUS_IL2CPP_GAME_DUMP: its DummyDll folder, script.json and stringliteral.json
    /// beside it or in its parent). Methods, types and fields are paired by assembly and metadata token ([Token]);
    /// reports the agreement of method addresses, field offsets, ScriptMethod / metadata slots and string literals,
    /// and the timings. Without the dump, reports the read alone.
    /// </summary>
    [RequiresRealDataFact(GameVariable)]
    [Trait("Speed", "Slow")]
    public void RawGameMatchesTheDump()
    {
        var files = Il2CppGameFiles.Find(RealData.Path(GameVariable)) ?? throw new InvalidOperationException("not an Il2Cpp game");
        using var raw = new AssemblyWorkspace(new ServerOptions { WatchFiles = false });
        var cache = Environment.GetEnvironmentVariable(Il2CppRawLoader.RootVariable) is { Length: > 0 } c ? c : _dir.File("il2cpp-cache");
        var watch = Stopwatch.StartNew();
        var result = new Il2CppRawLoader(raw).Load(files, loadBinary: false, m => output.WriteLine($"  [{watch.Elapsed.TotalSeconds:0.0} s] {m}"), default, cache);
        output.WriteLine(Il2CppRawLoader.Describe(result));
        output.WriteLine($"first load {watch.Elapsed.TotalSeconds:0.0} s");
        watch.Restart();
        using (var again = new AssemblyWorkspace(new ServerOptions { WatchFiles = false }))
        {
            var cached = new Il2CppRawLoader(again).Load(files, loadBinary: false, null, default, cache);
            Assert.True(cached.FromCache);
            output.WriteLine($"second load (cache) {watch.Elapsed.TotalSeconds:0.0} s");
        }
        Assert.True(result.Model.MethodsWithCode > 0);
        Assert.Empty(result.Load.Skipped);

        // apply_il2cpp_names on the bare binary reads the metadata beside it first (from the cache here).
        var previousCache = Environment.GetEnvironmentVariable(Il2CppRawLoader.RootVariable);
        Environment.SetEnvironmentVariable(Il2CppRawLoader.RootVariable, cache);
        try
        {
            using var bare = new AssemblyWorkspace(new ServerOptions { WatchFiles = false });
            var bareIl2cpp = new Il2CppService(bare);
            var bareNavigator = new Il2CppNavigator(bare, bareIl2cpp, new Il2CppStringService(bare, bareIl2cpp));
            var code = new NativeCodeService(bare, new ServerOptions { BackgroundIndexing = false }, annotations: new Corvus.Native.Annotations.AnnotationStore(_dir.File("ann-bare")));
            bare.LoadAny(files.Binary);
            watch.Restart();
            var text = new Corvus.Tools.Il2CppNativeTools(bare, code, new Il2CppNativeNames(bareIl2cpp, bareNavigator, code))
                .ApplyIl2CppNames(Path.GetFileName(files.Binary)).GetAwaiter().GetResult();
            output.WriteLine($"apply_il2cpp_names on the bare binary ({watch.Elapsed.TotalSeconds:0.0} s, with the index):\n{text}");
            Assert.Contains("from the cache", text);
            Assert.Contains("functions named:", text);
        }
        finally { Environment.SetEnvironmentVariable(Il2CppRawLoader.RootVariable, previousCache); }

        var rawIl2cpp = new Il2CppService(raw);
        var rawStrings = new Il2CppStringService(raw, rawIl2cpp);
        var rawNavigator = new Il2CppNavigator(raw, rawIl2cpp, rawStrings);
        var rawImage = Assert.Single(raw.Read(() => rawNavigator.ImagesFor(raw.Assemblies)));
        Assert.NotNull(rawImage.Script);
        output.WriteLine($"raw: {rawImage.Script!.MethodCount} ScriptMethod, {rawImage.Script.FunctionStarts.Length} function starts, {rawImage.Dump!.Values.Length} literals with slots");

        if (RealData.Get(DumpVariable) is not { } dumpDir) return;
        using var dump = new AssemblyWorkspace(new ServerOptions { WatchFiles = false });
        watch.Restart();
        dump.LoadDirectory(dumpDir, false);
        var dumpIl2cpp = new Il2CppService(dump);
        var dumpStrings = new Il2CppStringService(dump, dumpIl2cpp);
        var dumpImage = Assert.Single(dump.Read(() => new Il2CppNavigator(dump, dumpIl2cpp, dumpStrings).ImagesFor(dump.Assemblies)), i => i.Dump != null);
        output.WriteLine($"dump loaded in {watch.Elapsed.TotalSeconds:0.0} s");

        // Methods, fields and types by (assembly, token).
        var (rawMethods, rawFields, rawTypes) = Members(raw);
        var (dumpMethods, dumpFields, dumpTypes) = Members(dump);
        Report("types", dumpTypes.Keys.Count(rawTypes.ContainsKey), dumpTypes.Count, rawTypes.Count);
        int methodsBoth = 0, rvaSame = 0, offsetSame = 0, slotSame = 0, addressBoth = 0, onlyDump = 0, onlyRaw = 0;
        var mismatches = new List<string>();
        foreach (var (key, d) in dumpMethods)
        {
            if (!rawMethods.TryGetValue(key, out var r)) continue;
            methodsBoth++;
            if (d.Rva == null && r.Rva == null) continue;
            if (d.Rva == null) { onlyRaw++; continue; }
            if (r.Rva == null) { onlyDump++; if (mismatches.Count < 10) mismatches.Add($"no address: {key} (dump {d.Rva:X})"); continue; }
            addressBoth++;
            if (d.Rva == r.Rva) rvaSame++;
            else if (mismatches.Count < 10) mismatches.Add($"{key}: dump 0x{d.Rva:X}, raw 0x{r.Rva:X}");
            if (d.Offset == r.Offset) offsetSame++;
            if (d.Slot == r.Slot) slotSame++;
        }
        Report("methods paired by token", methodsBoth, dumpMethods.Count, rawMethods.Count);
        Report("method RVA agreement", rvaSame, addressBoth, addressBoth);
        Report("method file offset agreement", offsetSame, addressBoth, addressBoth);
        Report("vtable slot agreement", slotSame, addressBoth, addressBoth);
        output.WriteLine($"addresses only in the dump: {onlyDump}; only in the raw read: {onlyRaw}");
        foreach (var m in mismatches) output.WriteLine("  " + m);
        int fieldsBoth = 0, offsetsBoth = 0, offsetsSame = 0;
        var fieldMismatches = new List<string>();
        foreach (var (key, d) in dumpFields)
        {
            if (!rawFields.TryGetValue(key, out var r)) continue;
            fieldsBoth++;
            if (d == null && r == null) continue;
            offsetsBoth++;
            if (d == r) offsetsSame++;
            else if (fieldMismatches.Count < 10) fieldMismatches.Add($"{key}: dump {d}, raw {r}");
        }
        Report("fields paired by token", fieldsBoth, dumpFields.Count, rawFields.Count);
        Report("field offset agreement", offsetsSame, offsetsBoth, offsetsBoth);
        foreach (var m in fieldMismatches) output.WriteLine("  " + m);

        // script.json and stringliteral.json against the model.
        var rawScript = rawImage.Script!;
        if (dumpImage.Script is { } dumpScript)
        {
            var dumpEntries = Enumerable.Range(0, dumpScript.MethodCount).Select(e => (dumpScript.MethodAddress(e), dumpScript.MethodName(e))).ToHashSet();
            var rawEntries = Enumerable.Range(0, rawScript.MethodCount).Select(e => (rawScript.MethodAddress(e), rawScript.MethodName(e))).ToHashSet();
            Report("ScriptMethod (address, name) agreement", dumpEntries.Count(rawEntries.Contains), dumpEntries.Count, rawEntries.Count);
            var dumpAddresses = dumpEntries.Select(e => e.Item1).ToHashSet();
            Report("ScriptMethod address agreement", dumpAddresses.Count(rawEntries.Select(e => e.Item1).ToHashSet().Contains), dumpAddresses.Count, rawEntries.Select(e => e.Item1).Distinct().Count());
            foreach (var e in dumpEntries.Where(e => !rawEntries.Contains(e)).Take(8)) output.WriteLine($"  dump only: 0x{e.Item1:X} {e.Item2}");
            foreach (var e in rawEntries.Where(e => !dumpEntries.Contains(e)).Take(8)) output.WriteLine($"  raw only: 0x{e.Item1:X} {e.Item2}");
            var dumpStarts = dumpScript.FunctionStarts.ToHashSet();
            Report("function start agreement", rawScript.FunctionStarts.Count(dumpStarts.Contains), dumpStarts.Count, rawScript.FunctionStarts.Length);
            var dumpSlots = Enumerable.Range(0, dumpScript.MetadataCount).Select(e => (dumpScript.MetadataAddress(e), dumpScript.MetadataName(e))).ToHashSet();
            var rawSlots = Enumerable.Range(0, rawScript.MetadataCount).Select(e => (rawScript.MetadataAddress(e), rawScript.MetadataName(e))).ToHashSet();
            Report("ScriptMetadata (address, name) agreement", dumpSlots.Count(rawSlots.Contains), dumpSlots.Count, rawSlots.Count);
            foreach (var e in dumpSlots.Where(e => !rawSlots.Contains(e)).Take(5)) output.WriteLine($"  dump only: 0x{e.Item1:X} {e.Item2}");
            var dumpInfos = Enumerable.Range(0, dumpScript.MethodInfoCount).Select(e => (dumpScript.MethodInfoAddress(e), dumpScript.MethodInfoTarget(e))).ToHashSet();
            var rawInfos = Enumerable.Range(0, rawScript.MethodInfoCount).Select(e => (rawScript.MethodInfoAddress(e), rawScript.MethodInfoTarget(e))).ToHashSet();
            Report("ScriptMetadataMethod (address, target) agreement", dumpInfos.Count(rawInfos.Contains), dumpInfos.Count, rawInfos.Count);
        }
        if (dumpImage.Dump is { } dumpLiterals && dumpLiterals.Files.HasLiterals)
        {
            var dumpSet = dumpLiterals.Values.Zip(dumpLiterals.Addresses).ToHashSet();
            var rawSet = rawImage.Dump.Values.Zip(rawImage.Dump.Addresses).ToHashSet();
            Report("string literal (slot, value) agreement", dumpSet.Count(rawSet.Contains), dumpSet.Count, rawSet.Count);
            Report("string literal value agreement", dumpSet.Select(s => s.First).Distinct().Count(new HashSet<string>(result.Model.LiteralValues).Contains),
                dumpSet.Select(s => s.First).Distinct().Count(), result.Model.LiteralValues.Length);
        }
        Assert.True(rvaSame >= 0.99 * addressBoth, "method RVAs disagree");

        // The tools' paths end to end, on both: literal references, navigation, native names, export, decompilation.
        var rawRun = EndToEnd(raw, files, "raw");
        var dumpRun = EndToEnd(dump, files, "dump");
        foreach (var key in rawRun.Keys)
            output.WriteLine($"  {key}: raw {rawRun[key]}, dump {dumpRun.GetValueOrDefault(key)}");
    }

    private Dictionary<string, string> EndToEnd(AssemblyWorkspace ws, Il2CppGameFiles files, string label)
    {
        var result = new Dictionary<string, string>();
        var il2cpp = new Il2CppService(ws);
        var strings = new Il2CppStringService(ws, il2cpp);
        var navigator = new Il2CppNavigator(ws, il2cpp, strings);
        var watch = Stopwatch.StartNew();
        var image = ws.Read(() => navigator.ImagesFor(ws.Assemblies)).First(i => i.Dump != null);
        var refs = image.Dump!.References;
        result["literal references"] = refs == null ? $"none ({image.Dump.ReferenceProblem})"
            : $"{refs.Sites.Length} loads of {refs.ReferencedLiterals} literals in {refs.Functions} functions ({watch.Elapsed.TotalSeconds:0.0} s)";

        var rng = new Random(7);
        var methods = ws.Assemblies.SelectMany(il2cpp.GetIndex).Where(e => e.Rva is <= uint.MaxValue).ToList();
        int trips = 0;
        watch.Restart();
        foreach (var e in Enumerable.Range(0, 500).Select(_ => methods[rng.Next(methods.Count)]))
            if (ws.Read(() => navigator.Locate(e.Rva!.Value, "rva", ws.Assemblies)) is [{ Function.IsExactStart: true } r] && r.Methods.Any(m => m.Method == e.Method)) trips++;
        result["method -> RVA -> method"] = $"{trips}/500 ({watch.ElapsedMilliseconds} ms)";

        watch.Restart();
        var native = ws.LoadAny(files.Binary).Native!;
        var code = new NativeCodeService(ws, new ServerOptions { BackgroundIndexing = false }, annotations: new Corvus.Native.Annotations.AnnotationStore(_dir.File($"ann-{label}")));
        var names = ws.Read(() => new Il2CppNativeNames(il2cpp, navigator, code).Apply(native, null, ws.Assemblies, default));
        result["apply_il2cpp_names"] = $"{names.Functions} functions, {names.SharedFunctions} shared, {names.Strings} literals, {names.MetadataSlots} metadata and {names.MethodInfoSlots} MethodInfo slots ({watch.Elapsed.TotalSeconds:0.0} s)";

        watch.Restart();
        var export = new Il2CppExporter(il2cpp).Export(ws.Assemblies, _dir.File($"export-{label}"), "all", "il2cpp", default);
        result["export_il2cpp_symbols"] = $"{export.Methods} functions, {export.Structs} structs ({watch.Elapsed.TotalSeconds:0.0} s)";

        var decompiler = new DecompilerService(ws, new ServerOptions());
        var app = ws.Assemblies.FirstOrDefault(a => a.AssemblyName == "Assembly-CSharp") ?? ws.Assemblies.OrderByDescending(a => a.Module.Types.Count).First();
        var types = app.Module.Types.Where(t => !t.IsGlobalModuleType).ToList();
        int ok = 0, tried = 0;
        watch.Restart();
        foreach (var t in Enumerable.Range(0, 20).Select(_ => types[rng.Next(types.Count)]).Distinct())
        {
            tried++;
            try { if (ws.Read(() => decompiler.DecompileMembers(app, [t], default)).Contains(t.Name.String.Split('`')[0], StringComparison.Ordinal)) ok++; }
            catch (Exception ex) { output.WriteLine($"  {label}: decompiling {t.FullName} failed: {ex.Message}"); }
        }
        result["decompile_type"] = $"{ok}/{tried} of {app.Id} ({watch.ElapsedMilliseconds} ms)";
        return result;
    }

    [Fact]
    public void MetadataAloneIsTakenWithoutABinary_AndAnUnreadableOneSaysWhy()
    {
        Directory.CreateDirectory(_dir.File("alone"));
        var path = Metadata(Path.Combine("alone", "global-metadata.dat"), 0xFAB11BAF, 29, 0x400);
        Assert.Throws<ToolError>(() => Il2CppGameFiles.Find(path));
        var files = Assert.IsType<Il2CppGameFiles>(Il2CppGameFiles.Find(path, metadataOnly: true));
        Assert.Equal("", files.Binary);
        using var ws = new AssemblyWorkspace(new ServerOptions { WatchFiles = false });
        var error = Assert.Throws<ToolError>(() => new Il2CppRawLoader(ws).Load(files, loadBinary: true, null, default, _dir.File("cache")));
        Assert.Equal(ErrorCode.MalformedInput, error.Code);
        Assert.Contains("could not be read without the binary", error.Message);
        Assert.Contains("Tried: Unity", error.Message);
        Assert.Empty(ws.Assemblies);
    }

    /// <summary>The real game's metadata copied alone: the same images, types, methods and fields as the read with the binary.</summary>
    [RequiresRealDataFact(GameVariable)]
    [Trait("Speed", "Slow")]
    public void RealMetadataAloneMatchesTheReadWithTheBinary()
    {
        var files = Il2CppGameFiles.Find(RealData.Path(GameVariable)) ?? throw new InvalidOperationException("not an Il2Cpp game");
        var alone = _dir.File(Path.Combine("alone-real", Il2CppGameFiles.MetadataFileName));
        Directory.CreateDirectory(Path.GetDirectoryName(alone)!);
        File.Copy(files.Metadata, alone);
        var cache = _dir.File("il2cpp-cache");
        using var metaWs = new AssemblyWorkspace(new ServerOptions { WatchFiles = false });
        var watch = Stopwatch.StartNew();
        var meta = new Il2CppRawLoader(metaWs).Load(Il2CppGameFiles.Find(alone, metadataOnly: true)!, loadBinary: true, null, default, cache);
        output.WriteLine($"metadata alone: {watch.Elapsed.TotalSeconds:0.0} s\n{Il2CppRawLoader.Describe(meta)}");
        using var fullWs = new AssemblyWorkspace(new ServerOptions { WatchFiles = false });
        var full = new Il2CppRawLoader(fullWs).Load(files, loadBinary: false, null, default, cache);
        Assert.Null(meta.Binary);
        Assert.Empty(meta.Model.Unreadables);
        Assert.Equal((full.Model.Images, full.Model.Types, full.Model.MethodDefinitions, full.Model.Fields),
            (meta.Model.Images, meta.Model.Types, meta.Model.MethodDefinitions, meta.Model.Fields));
        Assert.Equal(full.Model.LiteralValues.Length, meta.Model.LiteralValues.Length);
        // Simple names: nesting comes from the declaring type index with the binary and from the nestedTypes section without it.
        List<string> Names(AssemblyWorkspace ws, bool full) => ws.Read(() => ws.Assemblies.Where(a => a.Module.Assembly?.Name != Il2CppDummyBuilder.AttributeAssembly)
            .SelectMany(a => a.Module.GetTypes()).Select(t => full ? t.FullName : t.Name.String).Order(StringComparer.Ordinal).ToList());
        Assert.Equal(Names(fullWs, false), Names(metaWs, false));
        output.WriteLine("nested differently: " + string.Join(", ", Names(fullWs, true).Except(Names(metaWs, true)).Take(10)));
    }

    private const string GameVariable = "CORVUS_IL2CPP_GAME";
    private const string DumpVariable = "CORVUS_IL2CPP_GAME_DUMP";

    private void Report(string what, int same, int dumpCount, int rawCount) =>
        output.WriteLine($"{what}: {same} of {dumpCount} ({(dumpCount == 0 ? 0 : 100.0 * same / dumpCount):0.00} %); raw has {rawCount}");

    private static (Dictionary<string, (ulong? Rva, ulong? Offset, ulong? Va, string? Slot)> Methods, Dictionary<string, string?> Fields, Dictionary<string, bool> Types) Members(AssemblyWorkspace ws)
    {
        var methods = new Dictionary<string, (ulong?, ulong?, ulong?, string?)>();
        var fields = new Dictionary<string, string?>();
        var types = new Dictionary<string, bool>();
        foreach (var asm in ws.Assemblies)
            foreach (var t in asm.Module.GetTypes())
            {
                if (Il2CppNavigator.TokenOf(t) is not { } typeToken) continue;
                types[$"{asm.AssemblyName}|{typeToken:X}"] = true;
                foreach (var m in t.Methods)
                {
                    if (Il2CppNavigator.TokenOf(m) is not { } token) continue;
                    var a = Il2CppService.GetAttributes(m).FirstOrDefault(x => x.Name == "AddressAttribute" && !x.InvalidAddress);
                    methods[$"{asm.AssemblyName}|{token:X}"] = a == null ? (null, null, null, null)
                        : (Il2CppService.ParseNumber(a.Values.GetValueOrDefault("RVA")), Il2CppService.ParseNumber(a.Values.GetValueOrDefault("Offset")),
                           Il2CppService.ParseNumber(a.Values.GetValueOrDefault("VA")), a.Values.GetValueOrDefault("Slot"));
                }
                foreach (var f in t.Fields)
                    if (Il2CppNavigator.TokenOf(f) is { } token)
                        fields[$"{asm.AssemblyName}|{token:X}"] = Il2CppService.GetAttributes(f).FirstOrDefault(x => x.Name == "FieldOffsetAttribute")?.Values.GetValueOrDefault("Offset");
            }
        return (methods, fields, types);
    }
}
