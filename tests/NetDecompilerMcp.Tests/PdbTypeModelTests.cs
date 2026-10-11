using NetDecompilerMcp.Native.Pdb;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>The PDB type model over a synthetic TPI stream, and the C writer on top of it.</summary>
public sealed class PdbTypeModelTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private PdbFile Fixture()
    {
        var path = _dir.File("typed.pdb");
        if (!File.Exists(path)) File.WriteAllBytes(path, PdbTypeFixture.Pdb());
        return PdbFile.Open(path);
    }

    private static PdbTypeNode Named(PdbTypeModel model, string name) => model.Node(Assert.Single(model.Named(name)))!;

    [Fact]
    public void Nodes_carry_members_bit_fields_and_spellings()
    {
        var model = PdbTypeModel.Read(Fixture(), 8);
        Assert.DoesNotContain(model.Notes, n => n.Contains("TPI", StringComparison.Ordinal));

        var player = Named(model, "Player");
        Assert.Equal((PdbTypeKind.Struct, 0x40L, false), (player.Kind, player.Size, player.Forward));
        Assert.Equal(["header +0x0 Header", "pos +0xC Vec", "val +0x18 Value", "scores +0x24 int[4]", "next +0x38 Player *"],
            player.Members.Select(m => $"{m.Name} +0x{m.Offset:X} {model.Spell(m.Type)}"));
        var scores = model.Node(player.Members[3].Type)!;
        Assert.Equal((PdbTypeKind.Array, 4L, 16L, 0x74u), (scores.Kind, scores.Count, scores.Size, scores.Element));
        // the pointer names the forward record, which resolves to the definition
        var next = model.Node(player.Members[4].Type)!;
        Assert.Equal(player.Index, model.DefinitionOf(next.Element));

        var header = Named(model, "Header");
        Assert.Equal([("urgent", 1, 0), ("retries", 3, 1)], header.Members.Where(m => m.BitLength >= 0).Select(m => (m.Name, m.BitLength, m.BitPosition)));
        Assert.Equal("unsigned int", model.Spell(header.Members[3].Type));

        var color = Named(model, "Color");
        Assert.Equal((PdbTypeKind.Enum, 4L), (color.Kind, color.Size));
        Assert.Equal(["Blue=4", "Red=1", "Green=2"], color.Enumerators.Select(e => $"{e.Name}={e.Value}"));

        var game = Named(model, "Game");
        Assert.Equal(PdbMemberKind.Static, game.Members.Single(m => m.Name == "instances").Kind);
        Assert.Equal("Player[4]", model.Spell(game.Members[1].Type));

        var baseClass = Named(model, "Base");
        Assert.Equal(PdbTypeKind.Class, baseClass.Kind);
        Assert.Equal((PdbMemberKind.Vfptr, 0L), (baseClass.Members[0].Kind, baseClass.Members[0].Offset));
        var derived = Named(model, "Derived");
        Assert.Equal((PdbMemberKind.Base, "Base"), (derived.Members[0].Kind, model.Spell(derived.Members[0].Type)));

        Assert.Equal(2, model.Named("Dup").Count);
        var opaque = model.Node(Assert.Single(model.Named("Opaque")))!;
        Assert.True(opaque.Forward);
        Assert.Equal(0u, model.DefinitionOf(opaque.Index));

        var proc = model.Node(0x1001)!;
        Assert.Equal(PdbTypeKind.Procedure, proc.Kind);
        Assert.Equal("int __cdecl(Player *, int)", proc.Name);
        Assert.Equal((0x74u, 2, "__cdecl"), (proc.Function!.Return, proc.Function.Parameters.Count, proc.Function.Convention));
        var method = model.Node(model.FunctionTypeOf(Enumerable.Range(0x1000, model.Records).Select(i => (uint)i)
            .First(i => model.Node(i)?.Kind == PdbTypeKind.MemberFunction)))!;
        Assert.Equal("__thiscall", method.Function!.Convention);
        Assert.Equal("Base *", model.Spell(method.Function.This));
        Assert.Equal((PdbTypeKind.Simple, "int", 4L), (model.Node(0x74)!.Kind, model.Node(0x74)!.Name, model.Node(0x74)!.Size));
        Assert.Equal("void *", model.Spell(0x603));
    }

    [Fact]
    public void Model_is_cached_per_pdb_and_pointer_size()
    {
        var pdb = Fixture();
        Assert.Same(PdbTypeModel.Of(pdb, 8), PdbTypeModel.Of(pdb, 8));
        Assert.NotSame(PdbTypeModel.Of(pdb, 8), PdbTypeModel.Of(pdb, 4));
        Assert.Equal(0x403u, Named(PdbTypeModel.Of(pdb, 4), "Base").Members[0].Type); // the vftable pointer: T_32PVOID
    }

    /// <summary>The writer's output for the fixture, pinned: the model refactor must leave it byte for byte.</summary>
    [Fact]
    public void Writer_output_is_unchanged()
    {
        var decls = PdbTypes.Build(Fixture(), 8);
        output.WriteLine(decls.Declarations);
        Assert.Equal(Golden, decls.Declarations);
        Assert.Equal(["int __cdecl f(struct Player *, int);", "int __cdecl f(struct Player *, int);"], decls.Prototypes.Select(p => p.Declaration));
        Assert.Equal(["typedef_unwritable=1"], decls.Skipped.Select(k => $"{k.Key}={k.Value}")); // Opaque: forward only
    }

    private static readonly string Golden = """
        #pragma pack(push, 1)
        struct Player;
        struct Game;
        struct Derived;
        struct Dup;
        struct Dup_2;
        struct Header;
        struct Vec;
        union Value;
        struct Base;
        enum Color : int
        {
          Blue = 4,
          Red = 1,
          Green = 2,
        };
        struct Header
        {
          unsigned short magic;
          unsigned char version;
          unsigned char __pad0[1];
          enum Color kind;
          unsigned int urgent : 1;
          unsigned int retries : 3;
          unsigned int : 28;
        };
        struct Vec
        {
          float x;
          float y;
          float z;
        };
        union Value
        {
          int i;
          float f;
          struct Vec v;
        };
        struct Player
        {
          struct Header header;
          struct Vec pos;
          union Value val;
          int scores[4];
          unsigned char __pad0[4];
          struct Player *next;
        };
        struct Game
        {
          int count;
          unsigned char __pad0[4];
          struct Player players[4];
        };
        struct Base
        {
          void *__vftable;
          int a;
          unsigned char __pad0[4];
        };
        struct Derived
        {
          struct Base baseclass_0;
          int b;
          unsigned char __pad0[4];
        };
        struct Dup
        {
          int a;
        };
        struct Dup_2
        {
          __int64 b;
        };
        typedef struct Player *PPlayer;
        #pragma pack(pop)
        """ + "\n";
}
