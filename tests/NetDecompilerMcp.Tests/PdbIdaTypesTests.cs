using System.Diagnostics;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Pdb;
using NetDecompilerMcp.Native.Pe;
using NetDecompilerMcp.Native.Providers.Ida;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>PDB types (structs, enums, prototypes) reaching IDA's database and the pseudocode, through IDA's PDB loader and the own reader.</summary>
public sealed class PdbIdaTypesTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    internal const string Source = """
        #include <stdio.h>
        #include <stdlib.h>
        typedef enum PacketKind { PK_HELLO = 1, PK_DATA = 2, PK_BYE = 7 } PacketKind;
        typedef struct Header { unsigned short magic; unsigned char version; PacketKind kind; unsigned int urgent : 1, retries : 3; } Header;
        typedef struct Packet {
            Header header;
            int sequence_number;
            double payload_weight;
            char sender_name[16];
            struct Packet* next_packet;
            int (*checksum)(const struct Packet*);
        } Packet, *PPacket;
        __declspec(noinline) int score_packet(PPacket p, int bias)
        {
            int s = bias;
            while (p) {
                if (p->header.kind == PK_DATA) s += p->sequence_number * 3;
                else if (p->header.kind == PK_BYE) s -= (int)p->payload_weight;
                s ^= p->sender_name[2] + p->header.version + p->header.retries;
                p = p->next_packet;
            }
            return s;
        }
        static int sum(const Packet* p) { return p->sequence_number; }
        int main(int argc, char** argv)
        {
            Packet a = { { 0xBEEF, 2, PK_DATA, 1, 2 }, argc, 1.5, "alice", NULL, sum };
            Packet b = { { 0xBEEF, 2, PK_BYE, 0, 5 }, 7, 2.5, "bob", &a, sum };
            printf("%d\n", score_packet(argc > 1 ? &b : &a, atoi(argv[0])) + a.checksum(&b));
            return 0;
        }
        """;

    /// <summary>The fixture built with /Zi into <paramref name="dir"/>: (exe, pdb), or null without MSVC build tools.</summary>
    internal static (string Exe, string Pdb)? Build(TempDir dir, string arch = "x64")
    {
        var vcvars = VisualStudio.VcVarsAll();
        if (vcvars == null) return null;
        File.WriteAllText(dir.File("fixture.c"), Source);
        var psi = new ProcessStartInfo("cmd.exe")
        {
            WorkingDirectory = dir.Path,
            Arguments = $"/s /c \"\"{vcvars}\" {arch} >nul && cl /nologo /O2 /GS- /Zi /MD fixture.c /link /DEBUG /INCREMENTAL:NO /OUT:fixture.exe /PDB:fixture.pdb\"",
        };
        var (code, log) = Tools.Run(psi, 300_000);
        Assert.True(code == 0 && File.Exists(dir.File("fixture.pdb")), log);
        return (dir.File("fixture.exe"), dir.File("fixture.pdb"));
    }

    private sealed record Rig(AssemblyWorkspace Workspace, NativeCodeService Code, NativeAnalysisTools Analysis, NativeEngineService Engines, PdbService Pdbs);

    private Rig Setup(string cache)
    {
        var options = new ServerOptions { TimeoutSeconds = 300, BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = cache }, code, workspace, options);
        _owned.Add(engines);
        var names = new NativeNamePush(code);
        return new Rig(workspace, code, new NativeAnalysisTools(workspace, engines, new OutputPager(options), names, code, new NativeTypePush()), engines, new PdbService(code));
    }

    /// <summary>A synthetic TPI stream (struct Node with a pointer to itself, an array, a procedure type), then mangled copies of it.</summary>
    [Fact]
    public void Own_reader_writes_a_synthetic_type_stream_and_survives_damage()
    {
        static byte[] Field(Action<List<byte>> body)
        {
            var b = new List<byte>();
            body(b);
            while (b.Count % 4 != 0) b.Add((byte)(0xF0 | (4 - b.Count % 4))); // LF_PAD
            return [.. b];
        }
        static void U16(List<byte> b, int v) => b.AddRange(BitConverter.GetBytes((ushort)v));
        static void U32(List<byte> b, uint v) => b.AddRange(BitConverter.GetBytes(v));
        static void Name(List<byte> b, string s) { b.AddRange(System.Text.Encoding.UTF8.GetBytes(s)); b.Add(0); }
        static byte[] Member(uint type, int offset, string name) => Field(b => { U16(b, 0x150D); U16(b, 3); U32(b, type); U16(b, offset); Name(b, name); });

        var records = new List<byte[]>
        {
            PdbBuilder.Record(0x1201, b => { U32(b, 2); U32(b, 0x1003); U32(b, 0x74); }),                       // 0x1000 arglist (Node*, int)
            PdbBuilder.Record(0x1008, b => { U32(b, 0x74); b.Add(0); b.Add(0); U16(b, 2); U32(b, 0x1000); }),    // 0x1001 int (Node*, int)
            PdbBuilder.Record(0x1203, b => { b.AddRange(Member(0x74, 0, "a")); b.AddRange(Member(0x1003, 8, "next")); b.AddRange(Member(0x1004, 16, "private")); }),
            PdbBuilder.Record(0x1002, b => { U32(b, 0x1005); U32(b, 0x0C | (8 << 13)); }),                      // 0x1003 Node*
            PdbBuilder.Record(0x1503, b => { U32(b, 0x70); U32(b, 0x23); U16(b, 8); Name(b, ""); }),             // 0x1004 char[8]
            PdbBuilder.Record(0x1505, b => { U16(b, 3); U16(b, 0); U32(b, 0x1002); U32(b, 0); U32(b, 0); U16(b, 24); Name(b, "Node"); }),
        };
        var tpi = new List<byte>();
        U32(tpi, 20040203); U32(tpi, 56); U32(tpi, 0x1000); U32(tpi, 0x1000 + (uint)records.Count); U32(tpi, (uint)records.Sum(r => r.Length));
        tpi.AddRange(new byte[56 - tpi.Count]);
        foreach (var r in records) tpi.AddRange(r);
        var pdb = PdbBuilder.Sample();
        pdb.GlobalRecords.Add(PdbBuilder.Record(0x1108, b => { U32(b, 0x1003); Name(b, "PNode"); }));
        var msf = pdb.Msf();
        msf.Streams[2] = [.. tpi];
        var path = _dir.File("synthetic.pdb");
        File.WriteAllBytes(path, msf.Build());

        var decls = PdbTypes.Build(PdbFile.Open(path), 8);
        output.WriteLine(decls.Declarations);
        Assert.Contains("struct Node\n{\n  int a;\n  unsigned char __pad0[4];\n  struct Node *next;\n  char private_[8];\n};\n", decls.Declarations);
        Assert.Contains("typedef struct Node *PNode;", decls.Declarations);
        Assert.Equal(2, decls.Prototypes.Count);
        Assert.All(decls.Prototypes, p => Assert.Equal("int __cdecl f(struct Node *, int);", p.Declaration));

        // damaged type records: counted or noted, never thrown
        var random = new Random(5);
        var file = File.ReadAllBytes(path);
        int tpiAt = FindTpi(file); // one block: the stream is contiguous in the file
        for (int i = 0; i < 60; i++)
        {
            var copy = (byte[])file.Clone();
            for (int k = 0; k < 4; k++) copy[tpiAt + random.Next(tpi.Count)] = (byte)random.Next(256);
            File.WriteAllBytes(path, copy);
            var damaged = PdbTypes.Build(PdbFile.Open(path), 8);
            Assert.NotNull(damaged.Declarations);
        }

        int FindTpi(byte[] f)
        {
            var head = tpi.Take(16).ToArray();
            for (int at = 0; at + head.Length <= f.Length; at++)
                if (f.AsSpan(at, head.Length).SequenceEqual(head)) return at;
            throw new InvalidOperationException("TPI stream not found");
        }
    }

    /// <summary>The own reader's declarations for the fixture: every struct member at the PDB's offset, prototypes for the procedures.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void Own_reader_writes_the_fixture_types()
    {
        if (Build(_dir) is not { } built) { output.WriteLine("no MSVC build tools"); return; }
        var image = PeFile.Open(built.Exe);
        var pdb = PdbFile.Open(built.Pdb, image.Sections);
        var decls = PdbTypes.Build(pdb, 8);
        output.WriteLine($"{decls.Records} records: {decls.Structs} structs, {decls.Unions} unions, {decls.Enums} enums, {decls.Typedefs} typedefs, " +
                         $"{decls.Prototypes.Count} prototypes; skipped {string.Join(", ", decls.Skipped.Select(kv => $"{kv.Value} {kv.Key}"))}");
        var text = decls.Declarations;        Assert.Contains("struct Packet\n{\n  struct Header header;\n  int sequence_number;\n", text);
        Assert.Contains("  double payload_weight;\n  char sender_name[16];\n  struct Packet *next_packet;\n  int (__cdecl *checksum)(const struct Packet *);\n", text);
        Assert.Contains("enum PacketKind : int", text);
        Assert.Contains("  unsigned int urgent : 1;\n  unsigned int retries : 3;\n  unsigned int : 28;\n", text);
        Assert.Contains("typedef struct Packet *PPacket;", text);
        Assert.Contains(decls.Prototypes, p => p.Declaration == "int __cdecl f(struct Packet *, int);");
        // Header: magic(2) version(1) pad(1) kind(4) bit fields(4) = 12 bytes, all explicit under pack(1)
        Assert.Contains("struct Header\n{\n  unsigned short magic;\n  unsigned char version;\n  unsigned char __pad0[1];\n  enum PacketKind kind;\n", text);
    }

    /// <summary>
    /// A real image shipped with its PDB, named by NDM_PDB_SAMPLE ("image path|function name|function name..."; skipped when
    /// unset): each function decompiled without the PDB's types (a copy of the image away from its PDB), then through IDA's
    /// PDB loader and through the own reader. Prints the snippets and timings.
    /// </summary>
    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task Real_image_with_its_pdb()
    {
        if (Environment.GetEnvironmentVariable("NDM_PDB_SAMPLE") is not { Length: > 0 } sample) { output.WriteLine("NDM_PDB_SAMPLE is not set"); return; }
        var parts = sample.Split('|');
        var original = parts[0];
        var pdbPath = Path.ChangeExtension(original, ".pdb");
        var copy = Directory.CreateDirectory(_dir.File("bare")).FullName;
        var image = Path.Combine(copy, Path.GetFileName(original));
        File.Copy(original, image);
        var pe = PeFile.Open(image);
        var symbols = PdbFile.Open(pdbPath, pe.Sections).Symbols;
        foreach (var route in new[] { NativePdbTypes.RouteIda, NativePdbTypes.RouteOwn })
        {
            var rig = Setup(_dir.File("cache-" + route));
            rig.Engines.PdbTypes.PreferOwnReader = route == NativePdbTypes.RouteOwn;
            var native = rig.Workspace.LoadAny(image).Native!;
            var clock = Stopwatch.StartNew();
            await rig.Analysis.DecompileNative(native.Id, $"rva:0x{pe.EntryPointRva:X}");
            output.WriteLine($"== {route}: first analysis without the PDB {clock.Elapsed.TotalSeconds:0.0} s");
            var bare = new Dictionary<string, string>();
            foreach (var name in parts.Skip(1))
            {
                var rva = symbols.First(s => s.Name == name && s.IsFunction).Rva!.Value;
                bare[name] = await rig.Analysis.DecompileNative(native.Id, $"rva:0x{rva:X}");
            }
            await rig.Pdbs.Load(native, pdbPath, false, null, false, TimeSpan.FromSeconds(30), 1 << 30, default);
            foreach (var name in parts.Skip(1))
            {
                var rva = symbols.First(s => s.Name == name && s.IsFunction).Rva!.Value;
                clock.Restart();
                var typed = await rig.Analysis.DecompileNative(native.Id, $"rva:0x{rva:X}");
                output.WriteLine($"-- {name} before:\n{bare[name]}\n-- {name} after ({clock.Elapsed.TotalSeconds:0.0} s):\n{typed}");
            }
            rig.Engines.Dispose();
        }
    }

    /// <summary>
    /// An image analyzed without its PDB, then given one with load_pdb: the next decompile_native loads it through IDA's
    /// PDB loader into the saved database (once: a later session finds the stamp), and the pseudocode shows its types.
    /// The same through the own reader on a fresh database.
    /// </summary>
    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task Pdb_types_reach_the_pseudocode_through_IDAs_loader_and_the_own_reader()
    {
        if (Build(_dir) is not { } built) { output.WriteLine("no MSVC build tools"); return; }
        // the PDB away from the image and from the path recorded in it: the first analysis has no symbols
        var symbols = Directory.CreateDirectory(_dir.File("symbols")).FullName;
        var pdbPath = Path.Combine(symbols, "fixture.pdb");
        File.Move(built.Pdb, pdbPath);

        var rig = Setup(_dir.File("cache"));
        var image = PeFile.Open(built.Exe);
        var scoreRva = PdbFile.Open(pdbPath, image.Sections).Symbols.First(s => s.Name == "score_packet" && s.IsFunction).Rva!.Value;
        var before = await rig.Analysis.DecompileNative(built.Exe, $"rva:0x{scoreRva:X}");
        var native = rig.Workspace.Read(() => rig.Workspace.Natives[0]);
        output.WriteLine(before);
        Assert.DoesNotContain("types: PDB", before);
        var session = await rig.Engines.Session(native, null, null, default);
        Assert.Null(NativePdbTypes.Current(session));

        var load = await rig.Pdbs.Load(native, pdbPath, false, null, false, TimeSpan.FromSeconds(30), 1 << 30, default);
        Assert.NotNull(load.State);
        var clock = Stopwatch.StartNew();
        var after = await rig.Analysis.DecompileNative(native.Id, $"rva:0x{scoreRva:X}");
        output.WriteLine($"after load_pdb ({clock.Elapsed.TotalSeconds:0.0} s):\n{after}");
        Assert.Contains("types: PDB fixture.pdb via IDA's PDB loader: loaded", after);
        Assert.Contains("Packet *", after);
        Assert.Contains("->sequence_number", after);
        Assert.Contains("->next_packet", after);
        Assert.Contains("PK_DATA", after);
        var source = NativePdbTypes.Current(session)!;
        Assert.Equal(NativePdbTypes.RouteIda, source.Route);

        // idempotent: the next call does not load again; a new session on the saved database finds the stamp
        Assert.Contains("(already in the database)", (await rig.Analysis.DecompileNative(native.Id, $"rva:0x{scoreRva:X}")).Split('\n')[0]);
        rig.Engines.Dispose();
        var rig2 = Setup(_dir.File("cache"));
        await rig2.Pdbs.Load(rig2.Workspace.LoadAny(built.Exe).Native!, pdbPath, false, null, false, TimeSpan.FromSeconds(30), 1 << 30, default);
        var reopened = await rig2.Analysis.DecompileNative(built.Exe, $"rva:0x{scoreRva:X}");
        output.WriteLine(reopened.Split('\n')[0]);
        Assert.Contains("(already in the database)", reopened);
        Assert.Contains("->sequence_number", reopened);
        rig2.Engines.Dispose();

        // the own reader, on a fresh database analyzed without the PDB
        var rig3 = Setup(_dir.File("cache3"));
        rig3.Engines.PdbTypes.PreferOwnReader = true;
        var native3 = rig3.Workspace.LoadAny(built.Exe).Native!;
        await rig3.Analysis.DecompileNative(native3.Id, "rva:0x" + native3.Image.EntryPointRva.ToString("X"));
        await rig3.Pdbs.Load(native3, pdbPath, false, null, false, TimeSpan.FromSeconds(30), 1 << 30, default);
        var own = await rig3.Analysis.DecompileNative(native3.Id, $"rva:0x{scoreRva:X}");
        output.WriteLine($"own reader:\n{own}");
        var applied = NativePdbTypes.Current(await rig3.Engines.Session(native3, null, null, default))!;
        output.WriteLine("rejected prototypes: " + string.Join("; ", applied.OwnApplied!.Failures));
        Assert.Equal(0, applied.OwnApplied.DeclarationErrors);
        Assert.Equal(applied.Own!.Prototypes.Count, applied.OwnApplied.Typed);
        Assert.Contains("via the server's PDB type reader", own);
        Assert.DoesNotContain("declaration errors", own.Split('\n')[0]);
        Assert.Contains("Packet *", own);
        Assert.Contains("->sequence_number", own);
        Assert.Contains("->next_packet", own);
    }
}
