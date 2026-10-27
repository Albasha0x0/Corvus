using System.Diagnostics;
using dnlib.DotNet;
using Corvus.Core;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>The built-in metadata reader: headers, file discovery, layouts and model round trip; real builds via CORVUS_AOT_BUILD.</summary>
public sealed class AotBuildTests(ITestOutputHelper output) : IDisposable
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
    public void Unreadable_metadata_is_a_typed_error_with_a_reason()
    {
        var encrypted = Assert.Throws<ToolError>(() => AotMetadataReader.CheckHeader(Metadata("enc.dat", 0x12345678, 29)));
        Assert.Equal(ErrorCode.MalformedInput, encrypted.Code);
        Assert.Contains("encrypted_or_transformed", encrypted.Message);
        foreach (var version in new[] { 23, 40 })
        {
            var old = Assert.Throws<ToolError>(() => AotMetadataReader.CheckHeader(Metadata($"v{version}.dat", 0xFAB11BAF, version)));
            Assert.Equal(ErrorCode.Unsupported, old.Code);
            Assert.Contains("unsupported_version", old.Message);
        }
        Assert.Contains("truncated", Assert.Throws<ToolError>(() => AotMetadataReader.CheckHeader(Metadata("short.dat", 0xFAB11BAF, 29, 6))).Message);
        Assert.Equal(31, AotMetadataReader.CheckHeader(Metadata("ok.dat", 0xFAB11BAF, 31)));

        // A valid header over nothing, with a binary that is no AOT build: every layout fails, reported as such.
        Directory.CreateDirectory(_dir.File("app"));
        var metadata = Metadata(Path.Combine("app", "global-metadata.dat"), 0xFAB11BAF, 29, 0x400);
        File.Copy(McpProtocolTests.NativeSample(_dir), _dir.File(Path.Combine("app", "GameAssembly.dll")));
        var files = Assert.IsType<AotBuildFiles>(AotBuildFiles.Find(metadata));
        var error = Assert.Throws<ToolError>(() => AotMetadataReader.Read(files, _dir.File("out"), null, default));
        Assert.Equal(ErrorCode.MalformedInput, error.Code);
        Assert.Contains("Tried: engine", error.Message);
    }

    [Fact]
    public async Task Load_assembly_reads_a_build_folder_and_reports_why_not()
    {
        var folder = _dir.File("enc");
        Directory.CreateDirectory(Path.Combine(folder, "G_Data", "il2cpp_data", "Metadata"));
        Metadata(Path.Combine("enc", "G_Data", "il2cpp_data", "Metadata", "global-metadata.dat"), 0xDEADBEEF, 29);
        File.Copy(McpProtocolTests.NativeSample(_dir), Path.Combine(folder, "GameAssembly.dll"));
        using var ws = new AssemblyWorkspace();
        var options = new ServerOptions { BackgroundIndexing = false, WatchFiles = false };
        var aot = new AotMetadataService(ws);
        var tools = new Corvus.Tools.WorkspaceTools(ws, aot, new IndexingService(ws, new CallGraphService(ws), options), new Corvus.Services.Analysis.UnpackService(ws));
        var error = await Assert.ThrowsAsync<ToolError>(() => tools.LoadAssembly(folder));
        Assert.Contains("encrypted_or_transformed", error.Message);
        // Nothing half-loaded.
        Assert.Empty(ws.Assemblies);
        // GameAssembly.dll alone still loads as a native image, with the way to its metadata.
        Assert.Contains("AOT metadata: ", await tools.LoadAssembly(Path.Combine(folder, "GameAssembly.dll")));
        // A package without AOT metadata says so, not that it is no PE file.
        var apk = _dir.File("plain.apk");
        using (var zip = System.IO.Compression.ZipFile.Open(apk, System.IO.Compression.ZipArchiveMode.Create)) zip.CreateEntry("classes.dex");
        Assert.Contains("reason no_metadata", (await Assert.ThrowsAsync<ToolError>(() => tools.LoadAssembly(apk))).Message);
    }

    [Fact]
    public void Build_files_are_found_from_the_folder_the_metadata_or_the_binary()
    {
        var folder = _dir.File("App");
        var meta = Path.Combine(folder, "App_Data", "il2cpp_data", "Metadata");
        Directory.CreateDirectory(meta);
        var metadata = Metadata(Path.Combine("App", "App_Data", "il2cpp_data", "Metadata", "global-metadata.dat"), 0xFAB11BAF, 24);
        // No binary yet.
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => AotBuildFiles.Find(metadata)).Code);
        var binary = Path.Combine(folder, "GameAssembly.dll");
        File.WriteAllBytes(binary, [0x4D, 0x5A]);
        foreach (var path in new[] { folder, metadata, binary })
        {
            var files = Assert.IsType<AotBuildFiles>(AotBuildFiles.Find(path));
            Assert.Equal(Path.GetFullPath(binary), files.Binary, ignoreCase: true);
            Assert.Equal(Path.GetFullPath(metadata), files.Metadata, ignoreCase: true);
            Assert.EndsWith("App_Data", files.DataDirectory);
        }
        // An ordinary assembly.
        Assert.Null(AotBuildFiles.Find(Env.FixturePath));
    }

    [Fact]
    public void Memory_images_are_read_at_their_RVAs()
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
    public void Model_round_trips_into_the_navigators_script()
    {
        var model = new AotBuildModel
        {
            BinaryPath = "b", MetadataPath = "m", MetadataVersion = 29.1f, HeaderVersion = 29, EngineVersion = "2022.1.0f1", EngineVersionSource = "test",
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
        var path = _dir.File(AotBuildModel.FileName);
        model.Write(path);
        var back = AotBuildModel.Read(path);
        Assert.Equal(model.Methods, back.Methods);
        Assert.Equal(model.LiteralSlots, back.LiteralSlots);
        Assert.Equal("pointer_outside_image", Assert.Single(back.Unreadables).Reason);

        var script = AotScript.FromModel(back, path);
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
        Assert.Throws<IOException>(() => AotBuildModel.Read(Env.FixturePath));
    }

    /// <summary>script.json names built-in types by their C# keyword ("string_TypeInfo"); either spelling finds the slot.</summary>
    [Fact]
    public void Built_in_types_are_found_by_either_spelling()
    {
        var model = new AotBuildModel
        {
            BinaryPath = "b", MetadataPath = "m", MetadataVersion = 29, HeaderVersion = 29, EngineVersion = "2022.1.0f1", EngineVersionSource = "test",
            ImageBase = 0x180000000, MemoryImage = false, LiteralValues = [], LiteralSlots = [], Methods = [], MethodInfos = [], Addresses = [], Unreadables = [],
            Metadata = [new(0x5000, "string_TypeInfo", "System_String_c*"), new(0x5008, "System.Collections.Generic.List<string>_TypeInfo", "x")],
        };
        var path = _dir.File("alias-" + AotBuildModel.FileName);
        model.Write(path);
        var script = AotScript.FromModel(AotBuildModel.Read(path), path);
        Assert.Single(AotNavigator.FindSlots(script, "System.String_TypeInfo").Metadata);
        Assert.Single(AotNavigator.FindSlots(script, "string_TypeInfo").Metadata);
        Assert.Empty(AotNavigator.FindSlots(script, "System.Strin_TypeInfo").Metadata);
        Assert.Equal(("string", "System.String", "Ns.Type"), (AotNames.OtherSpelling("System.String"), AotNames.FullTypeKey("string"), AotNames.FullTypeKey("Ns.Type")));
    }

    /// <summary>
    /// A raw build (CORVUS_AOT_BUILD: build folder or global-metadata.dat) read by the built-in reader, against dummy
    /// assemblies of the same files (CORVUS_AOT_BUILD_DUMP: their DummyDll folder, script.json and stringliteral.json
    /// beside it or in its parent). Methods, types and fields are paired by assembly and metadata token ([Token]);
    /// reports the agreement of method addresses, field offsets, ScriptMethod / metadata slots and string literals,
    /// and the timings. Without the dump, reports the read alone.
    /// </summary>
    [RequiresRealDataFact(BuildVariable)]
    [Trait("Speed", "Slow")]
    public void Raw_build_matches_the_dump()
    {
        var files = AotBuildFiles.Find(RealData.Path(BuildVariable)) ?? throw new InvalidOperationException("not an AOT build");
        using var raw = new AssemblyWorkspace(new ServerOptions { WatchFiles = false });
        // apply_metadata_names below reads the default cache.
        var cache = AotBuildLoader.DefaultRoot;
        var watch = Stopwatch.StartNew();
        var result = new AotBuildLoader(raw).Load(files, loadBinary: false, m => output.WriteLine($"  [{watch.Elapsed.TotalSeconds:0.0} s] {m}"), default, cache);
        output.WriteLine(AotBuildLoader.Describe(result));
        output.WriteLine($"first load {watch.Elapsed.TotalSeconds:0.0} s");
        watch.Restart();
        using (var again = new AssemblyWorkspace(new ServerOptions { WatchFiles = false }))
        {
            var cached = new AotBuildLoader(again).Load(files, loadBinary: false, null, default, cache);
            Assert.True(cached.FromCache);
            output.WriteLine($"second load (cache) {watch.Elapsed.TotalSeconds:0.0} s");
        }
        Assert.True(result.Model.MethodsWithCode > 0);
        Assert.Empty(result.Load.Skipped);

        // apply_metadata_names on the bare binary reads the metadata beside it first (from the cache here).
        {
            using var bare = new AssemblyWorkspace(new ServerOptions { WatchFiles = false });
            var bareAot = new AotMetadataService(bare);
            var bareNavigator = new AotNavigator(bare, bareAot, new AotStringService(bare, bareAot));
            var code = new NativeCodeService(bare, new ServerOptions { BackgroundIndexing = false }, annotations: new Corvus.Native.Annotations.AnnotationStore(_dir.File("ann-bare")));
            bare.LoadAny(files.Binary);
            watch.Restart();
            var text = new Corvus.Tools.MetadataNameTools(bare, code, new AotNativeNames(bareAot, bareNavigator, code))
                .ApplyMetadataNames(Path.GetFileName(files.Binary)).GetAwaiter().GetResult();
            output.WriteLine($"apply_metadata_names on the bare binary ({watch.Elapsed.TotalSeconds:0.0} s, with the index):\n{text}");
            Assert.Contains("from the cache", text);
            Assert.Contains("functions named:", text);
        }

        var rawAot = new AotMetadataService(raw);
        var rawStrings = new AotStringService(raw, rawAot);
        var rawNavigator = new AotNavigator(raw, rawAot, rawStrings);
        var rawImage = Assert.Single(raw.Read(() => rawNavigator.ImagesFor(raw.Assemblies)));
        Assert.NotNull(rawImage.Script);
        output.WriteLine($"raw: {rawImage.Script!.MethodCount} ScriptMethod, {rawImage.Script.FunctionStarts.Length} function starts, {rawImage.Dump!.Values.Length} literals with slots");

        if (RealData.Get(DumpVariable) is not { } dumpDir) return;
        using var dump = new AssemblyWorkspace(new ServerOptions { WatchFiles = false });
        watch.Restart();
        dump.LoadDirectory(dumpDir, false);
        var dumpAot = new AotMetadataService(dump);
        var dumpStrings = new AotStringService(dump, dumpAot);
        var dumpImage = Assert.Single(dump.Read(() => new AotNavigator(dump, dumpAot, dumpStrings).ImagesFor(dump.Assemblies)), i => i.Dump != null);
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

    private Dictionary<string, string> EndToEnd(AssemblyWorkspace ws, AotBuildFiles files, string label)
    {
        var result = new Dictionary<string, string>();
        var aot = new AotMetadataService(ws);
        var strings = new AotStringService(ws, aot);
        var navigator = new AotNavigator(ws, aot, strings);
        var watch = Stopwatch.StartNew();
        var image = ws.Read(() => navigator.ImagesFor(ws.Assemblies)).First(i => i.Dump != null);
        var refs = image.Dump!.References;
        result["literal references"] = refs == null ? $"none ({image.Dump.ReferenceProblem})"
            : $"{refs.Sites.Length} loads of {refs.ReferencedLiterals} literals in {refs.Functions} functions ({watch.Elapsed.TotalSeconds:0.0} s)";

        var rng = new Random(7);
        var methods = ws.Assemblies.SelectMany(aot.GetIndex).Where(e => e.Rva is <= uint.MaxValue).ToList();
        int trips = 0;
        watch.Restart();
        foreach (var e in Enumerable.Range(0, 500).Select(_ => methods[rng.Next(methods.Count)]))
            if (ws.Read(() => navigator.Locate(e.Rva!.Value, "rva", ws.Assemblies)) is [{ Function.IsExactStart: true } r] && r.Methods.Any(m => m.Method == e.Method)) trips++;
        result["method -> RVA -> method"] = $"{trips}/500 ({watch.ElapsedMilliseconds} ms)";

        watch.Restart();
        var native = ws.LoadAny(files.Binary).Native!;
        var code = new NativeCodeService(ws, new ServerOptions { BackgroundIndexing = false }, annotations: new Corvus.Native.Annotations.AnnotationStore(_dir.File($"ann-{label}")));
        var names = ws.Read(() => new AotNativeNames(aot, navigator, code).Apply(native, null, ws.Assemblies, default));
        result["apply_metadata_names"] = $"{names.Functions} functions, {names.SharedFunctions} shared, {names.Strings} literals, {names.MetadataSlots} metadata and {names.MethodInfoSlots} MethodInfo slots ({watch.Elapsed.TotalSeconds:0.0} s)";

        watch.Restart();
        var export = new AotExporter(aot).Export(ws.Assemblies, _dir.File($"export-{label}"), "all", "aot", default);
        result["export_method_symbols"] = $"{export.Methods} functions, {export.Structs} structs ({watch.Elapsed.TotalSeconds:0.0} s)";

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
    public void Metadata_alone_is_taken_without_a_binary_and_an_unreadable_one_says_why()
    {
        Directory.CreateDirectory(_dir.File("alone"));
        var path = Metadata(Path.Combine("alone", "global-metadata.dat"), 0xFAB11BAF, 29, 0x400);
        Assert.Throws<ToolError>(() => AotBuildFiles.Find(path));
        var files = Assert.IsType<AotBuildFiles>(AotBuildFiles.Find(path, metadataOnly: true));
        Assert.Equal("", files.Binary);
        using var ws = new AssemblyWorkspace(new ServerOptions { WatchFiles = false });
        var error = Assert.Throws<ToolError>(() => new AotBuildLoader(ws).Load(files, loadBinary: true, null, default, _dir.File("cache")));
        Assert.Equal(ErrorCode.MalformedInput, error.Code);
        Assert.Contains("could not be read without the binary", error.Message);
        Assert.Contains("Tried: engine", error.Message);
        Assert.Empty(ws.Assemblies);
    }

    /// <summary>The real build's metadata copied alone: the same images, types, methods and fields as the read with the binary.</summary>
    [RequiresRealDataFact(BuildVariable)]
    [Trait("Speed", "Slow")]
    public void Real_metadata_alone_matches_the_read_with_the_binary()
    {
        var files = AotBuildFiles.Find(RealData.Path(BuildVariable)) ?? throw new InvalidOperationException("not an AOT build");
        var alone = _dir.File(Path.Combine("alone-real", AotBuildFiles.MetadataFileName));
        Directory.CreateDirectory(Path.GetDirectoryName(alone)!);
        File.Copy(files.Metadata, alone);
        var cache = _dir.File("aot-cache");
        using var metaWs = new AssemblyWorkspace(new ServerOptions { WatchFiles = false });
        var watch = Stopwatch.StartNew();
        var meta = new AotBuildLoader(metaWs).Load(AotBuildFiles.Find(alone, metadataOnly: true)!, loadBinary: true, null, default, cache);
        output.WriteLine($"metadata alone: {watch.Elapsed.TotalSeconds:0.0} s\n{AotBuildLoader.Describe(meta)}");
        using var fullWs = new AssemblyWorkspace(new ServerOptions { WatchFiles = false });
        var full = new AotBuildLoader(fullWs).Load(files, loadBinary: false, null, default, cache);
        Assert.Null(meta.Binary);
        Assert.Empty(meta.Model.Unreadables);
        Assert.Equal((full.Model.Images, full.Model.Types, full.Model.MethodDefinitions, full.Model.Fields),
            (meta.Model.Images, meta.Model.Types, meta.Model.MethodDefinitions, meta.Model.Fields));
        Assert.Equal(full.Model.LiteralValues.Length, meta.Model.LiteralValues.Length);
        // Full names: both reads nest from the nestedTypes section.
        List<string> Names(AssemblyWorkspace ws) => ws.Read(() => ws.Assemblies.Where(a => a.Module.Assembly?.Name != AotDummyBuilder.AttributeAssembly)
            .SelectMany(a => a.Module.GetTypes()).Select(t => t.FullName).Order(StringComparer.Ordinal).ToList());
        Assert.Equal(Names(fullWs), Names(metaWs));
    }

    /// <summary>The real build's dummy assemblies, with the binary and from the metadata alone, are byte-identical on a second build.</summary>
    [RequiresRealDataFact(BuildVariable)]
    [Trait("Speed", "Slow")]
    public void Real_dummy_assemblies_are_the_same_bytes_on_every_build()
    {
        var files = AotBuildFiles.Find(RealData.Path(BuildVariable)) ?? throw new InvalidOperationException("not an AOT build");
        var alone = _dir.File(Path.Combine("alone-twice", AotBuildFiles.MetadataFileName));
        Directory.CreateDirectory(Path.GetDirectoryName(alone)!);
        File.Copy(files.Metadata, alone);
        var metadataOnly = AotBuildFiles.Find(alone, metadataOnly: true)!;
        foreach (var (name, build) in new (string, Action<string>)[]
                 {
                     ("binary", dir => AotMetadataReader.Read(files, dir, null, default)),
                     ("metadata", dir => AotMetadataOnly.Read(metadataOnly, dir, null, default)),
                 })
        {
            string first = _dir.File($"{name}-1"), second = _dir.File($"{name}-2");
            build(first);
            build(second);
            var written = Directory.GetFiles(first, "*.dll").Select(Path.GetFileName).Order(StringComparer.Ordinal).ToList();
            Assert.NotEmpty(written);
            Assert.Equal(written, Directory.GetFiles(second, "*.dll").Select(Path.GetFileName).Order(StringComparer.Ordinal).ToList());
            Assert.All(written, f => Assert.True(File.ReadAllBytes(Path.Combine(first, f!)).AsSpan().SequenceEqual(File.ReadAllBytes(Path.Combine(second, f!))), $"{name}: {f} differs"));
        }
    }

    /// <summary>
    /// A real build (CORVUS_AOT_GENERICS_BUILD: a Windows build folder) copied with its code registration's module fields
    /// cleared, as in builds that fill the registration at run time: the copy reads every ScriptMethod entry of the
    /// original, generic instances (from the generic method pointer array found in the data) included, and its function
    /// starts from the invoker, attribute generator and unresolved call tables found there.
    /// </summary>
    [RequiresRealDataFact(GenericsVariable)]
    [Trait("Speed", "Slow")]
    public void Runtime_filled_registration_keeps_the_generic_instances()
    {
        var files = AotBuildFiles.Find(RealData.Path(GenericsVariable)) ?? throw new InvalidOperationException("not an AOT build");
        var original = AotMetadataReader.Read(files, _dir.File("dummy-original"), null, default).Model;

        var bytes = File.ReadAllBytes(files.Binary);
        var image = Corvus.Native.NativeImageLoader.FromBytes(bytes, files.Binary);
        int ptr = image.Is64Bit ? 8 : 4;
        var registration = Assert.Single(AotRegistrationSearch.CodeRegistration(image));
        Assert.True(image.TryRvaToFileOffset((uint)(registration.FieldVa - image.ImageBase) - (uint)ptr, out long at));
        Array.Clear(bytes, (int)at, 2 * ptr);
        var copy = _dir.File(Path.Combine("cleared", Path.GetFileName(files.Binary)));
        Directory.CreateDirectory(Path.GetDirectoryName(copy)!);
        File.WriteAllBytes(copy, bytes);
        var cleared = AotMetadataReader.Read(files with { Binary = copy }, _dir.File("dummy-cleared"), null, default);
        foreach (var note in cleared.Notes) output.WriteLine(note);

        Assert.Contains(cleared.Notes, n => n.Contains("filled at run time") && n.Contains("generic method pointers ("));
        var expected = original.Methods.Select(e => (e.Address, e.Name)).ToHashSet();
        var actual = cleared.Model.Methods.Select(e => (e.Address, e.Name)).ToHashSet();
        int generic = expected.Count(e => e.Name.Contains('<'));
        output.WriteLine($"ScriptMethod entries {actual.Count(expected.Contains)} of {expected.Count} ({generic} with generic arguments); copy has {actual.Count}");
        Assert.True(expected.SetEquals(actual));
        var starts = cleared.Model.Addresses.ToHashSet();
        output.WriteLine($"function starts {original.Addresses.Count(starts.Contains)} of {original.Addresses.Length}; copy has {starts.Count}");
        Assert.Superset(starts, original.Addresses.ToHashSet());
        // Only the reverse P/Invoke wrappers stay unmapped: their count is kept in the registration alone.
        Assert.True(original.Addresses.Length - starts.Count <= original.Addresses.Length / 1000, "more than 0.1 % of the function starts are missing");
    }

    private const string BuildVariable = "CORVUS_AOT_BUILD";
    private const string DumpVariable = "CORVUS_AOT_BUILD_DUMP";
    private const string GenericsVariable = "CORVUS_AOT_GENERICS_BUILD";

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
                if (AotNavigator.TokenOf(t) is not { } typeToken) continue;
                types[$"{asm.AssemblyName}|{typeToken:X}"] = true;
                foreach (var m in t.Methods)
                {
                    if (AotNavigator.TokenOf(m) is not { } token) continue;
                    var a = AotMetadataService.GetAttributes(m).FirstOrDefault(x => x.Name == "AddressAttribute" && !x.InvalidAddress);
                    methods[$"{asm.AssemblyName}|{token:X}"] = a == null ? (null, null, null, null)
                        : (AotMetadataService.ParseNumber(a.Values.GetValueOrDefault("RVA")), AotMetadataService.ParseNumber(a.Values.GetValueOrDefault("Offset")),
                           AotMetadataService.ParseNumber(a.Values.GetValueOrDefault("VA")), a.Values.GetValueOrDefault("Slot"));
                }
                foreach (var f in t.Fields)
                    if (AotNavigator.TokenOf(f) is { } token)
                        fields[$"{asm.AssemblyName}|{token:X}"] = AotMetadataService.GetAttributes(f).FirstOrDefault(x => x.Name == "FieldOffsetAttribute")?.Values.GetValueOrDefault("Offset");
            }
        return (methods, fields, types);
    }
}
