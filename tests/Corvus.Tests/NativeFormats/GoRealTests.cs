using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Go;
using Xunit.Abstractions;

namespace Corvus.Tests.NativeFormats;

/// <summary>Go function tables of real Go programs: every file of the CORVUS_GO_SAMPLES folder (ELF, PE, Mach-O; never run).</summary>
[Trait("Speed", "Slow")]
public sealed class GoRealTests(ITestOutputHelper output)
{
    public const string Variable = "CORVUS_GO_SAMPLES";

    private static IEnumerable<(string Name, INativeImage Image)> Samples()
    {
        foreach (var path in Directory.EnumerateFiles(RealData.Path(Variable)).Order(StringComparer.Ordinal))
        {
            INativeImage image;
            try { image = NativeImageLoader.Open(path); }
            catch (Exception ex) when (ex is IOException or InvalidOperationException or ArgumentException) { continue; }
            if (GoFunctionTable.Of(image) != null) yield return (Path.GetFileName(path), image);
        }
    }

    [RequiresRealDataFact(Variable)]
    public void Function_sizes_are_their_own_code_not_the_gap_to_the_next()
    {
        int files = 0;
        foreach (var (name, image) in Samples())
        {
            files++;
            var go = GoFunctionTable.Of(image)!;
            int own = go.Functions.Count(f => f.OwnSize);
            // symbol sizes, where the linker kept its symbol table, are the code without alignment padding
            var symbols = image.Symbols.Where(s => s.Kind == ImageSymbolKind.Function && s.Size > 0).GroupBy(s => s.Rva).ToDictionary(g => g.Key, g => g.First().Size);
            int compared = 0, agree = 0, gapAgree = 0;
            for (int i = 0; i < go.Functions.Count; i++)
            {
                var f = go.Functions[i];
                if (!symbols.TryGetValue(f.Rva, out var size)) continue;
                compared++;
                if (Math.Abs((long)size - f.Size) <= 1) agree++;
                if (i + 1 < go.Functions.Count && Math.Abs((long)size - (go.Functions[i + 1].Rva - f.Rva)) <= 1) gapAgree++;
            }
            output.WriteLine($"{name}: {go.VersionText}, {go.Functions.Count} functions, {own} own sizes; symbol sizes matched {agree}/{compared} (gap to the next entry: {gapAgree})");
            Assert.True(own >= go.Functions.Count * 995L / 1000, $"{name}: {own} of {go.Functions.Count} sizes from the function's own tables");
            if (compared > 0) Assert.True(agree >= compared * 995L / 1000, $"{name}: {agree} of {compared} sizes match the symbol table");
        }
        Assert.True(files > 0, "no Go programs in the samples folder");
    }

    [RequiresRealDataFact(Variable)]
    public void Code_walks_stay_inside_the_tables_extents()
    {
        foreach (var (name, image) in Samples())
        {
            var go = GoFunctionTable.Of(image)!;
            var index = NativeCodeIndex.Build(image);
            // walks may end short (padding, literal pools, code after noreturn calls), never past
            int same = go.Functions.Count(g => g.OwnSize && index.FunctionByStart(g.Rva) is { } f && f.End == g.Rva + g.Size);
            output.WriteLine($"{name}: {same} of {go.Functions.Count} walks end where the table does; {string.Join("; ", index.Issues)}");
            int over = index.Issues.Count == 0 ? 0 : int.Parse(index.Issues.Single().Split(' ')[3]);
            Assert.True(over <= go.Functions.Count / 200, $"{name}: {over} functions decode past their end");
        }
    }

    [RequiresRealDataFact(Variable)]
    public void Build_info_names_the_toolchain_module_and_settings()
    {
        foreach (var (name, image) in Samples())
        {
            var build = GoBuildInfo.Of(image);
            Assert.NotNull(build);
            output.WriteLine($"{name}: {build.GoVersion}; path {build.Path}; main {build.Main}; {build.Dependencies.Count} deps; " +
                             string.Join(", ", build.Settings.Select(s => $"{s.Key}={s.Value}")));
            Assert.StartsWith("go1.", build.GoVersion);
        }
    }

    /// <summary>The image with its relocations hidden.</summary>
    private sealed class Unrelocated(INativeImage inner) : INativeImage
    {
        public ImageFormat Format => inner.Format;
        public string Path => inner.Path;
        public string Sha256 => inner.Sha256;
        public NativeArch Arch => inner.Arch;
        public bool Is64Bit => inner.Is64Bit;
        public bool IsDll => inner.IsDll;
        public ulong ImageBase => inner.ImageBase;
        public uint EntryPointRva => inner.EntryPointRva;
        public uint SizeOfImage => inner.SizeOfImage;
        public IReadOnlyList<NativeSection> Sections => inner.Sections;
        public IReadOnlyList<NativeImport> Imports => inner.Imports;
        public IReadOnlyList<NativeExport> Exports => inner.Exports;
        public IReadOnlyList<RuntimeFunction> RuntimeFunctions => inner.RuntimeFunctions;
        public IReadOnlyList<uint> RelocationRvas => [];
        public IReadOnlyList<uint> TlsCallbackRvas => inner.TlsCallbackRvas;
        public IReadOnlyList<ParseIssue> Issues => inner.Issues;
        public IReadOnlyList<ImageSymbol> Symbols => inner.Symbols;
        public IReadOnlyList<DeclaredFunction> DeclaredFunctions => inner.DeclaredFunctions;
        public int Read(uint rva, Span<byte> destination) => inner.Read(rva, destination);
        public bool TryRvaToFileOffset(uint rva, out long fileOffset) => inner.TryRvaToFileOffset(rva, out fileOffset);
        public bool TryFileOffsetToRva(long fileOffset, out uint rva) => inner.TryFileOffsetToRva(fileOffset, out rva);
        public NativeSection? SectionAt(uint rva) => inner.SectionAt(rva);
    }

    private static List<CodeXref> Pointers(NativeCodeIndex index) =>
        [.. index.Functions.SelectMany(f => index.RefsTo(f.Start)).Where(x => x.Kind == XrefKind.Pointer)];

    [RequiresRealDataFact(Variable)]
    public void Pointer_references_without_relocations_are_the_relocated_slots()
    {
        foreach (var (name, image) in Samples())
        {
            if (image.RelocationRvas.Count == 0)
            {
                var index = NativeCodeIndex.Build(image);
                output.WriteLine($"{name}: no relocations; {Pointers(index).Count} unconfirmed pointer references");
                continue;
            }
            // with the relocations hidden, every pointer reference found must be a relocated slot
            var ctx = new CodeContext(image, new ImageCode(image), new CodeIndexOptions());
            var relocated = ctx.Relocations.Where(r => image.SectionAt(r) is { IsExecutable: false } && ctx.TryReadPointer(r, out uint t) && ctx.Code.IsCode(t)).ToHashSet();
            var found = Pointers(NativeCodeIndex.Build(new Unrelocated(image)));
            int hit = found.Count(x => relocated.Contains(x.From));
            // the Go linker leaves itab slots of dead methods unrebased: real pointers to runtime.unreachableMethod
            var unreachable = GoFunctionTable.Of(image)!.Functions.Where(f => f.Name == "runtime.unreachableMethod").Select(f => f.Rva).ToHashSet();
            int dead = found.Count(x => !relocated.Contains(x.From) && unreachable.Contains(x.To));
            output.WriteLine($"{name}: relocations hidden; {found.Count} unconfirmed pointer references, {hit} relocated, {dead} unrebased dead methods, " +
                             $"{found.Count - hit - dead} false; with relocations {Pointers(NativeCodeIndex.Build(image)).Count}");
            Assert.Equal(found.Count, hit + dead);
        }
    }
}
