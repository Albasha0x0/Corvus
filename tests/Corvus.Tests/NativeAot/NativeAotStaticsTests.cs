using System.Buffers.Binary;
using Corvus.Native.NativeAot;
using Corvus.Services;
using B = Corvus.Tests.NativeAotBuilder;
using static Corvus.Tests.NativeAotNameMapTests;

namespace Corvus.Tests;

public class NativeAotStaticsTests
{
    private const uint Cctor = B.TextRva + 0x20;

    private sealed record Fixture(NativeAotImage Aot, uint GcSlot, uint NonGc, uint ThreadCell, uint Unowned);

    /// <summary>
    /// .NET 10 x64: Dog::.cctor (named by the stack-trace map) loads Dog's GC statics slot and its thread statics cell; its
    /// class constructor context precedes the non-GC statics; a second GC slot nothing references. Dog's metadata keeps
    /// static string Name, const int Max, static int Count and the instance field legs.
    /// </summary>
    private static Fixture Build()
    {
        var m = NativeAotMetadataTests.Model(16, statics: true);
        var b = new B { Major = 16 };
        b.Blob(BlobId.EmbeddedMetadata, m.Blob);

        // GC statics: the GCStaticEEType (object of header, MethodTable pointer and 8 bytes of fields), the slots and the region.
        b.Data.Align(8);
        uint eeType = b.Data.U32(0);
        b.Data.U32(0x18);
        b.Data.Zero(16);
        uint gcSlot = b.Data.U32(0);
        b.Data.Patch32(gcSlot, eeType - gcSlot | 1); // uninitialized
        b.Data.U32(0);
        uint unowned = b.Data.U32(0);
        b.Data.Patch32(unowned, eeType - unowned | 1);
        b.Data.U32(0);
        uint region = b.Data.Here;
        b.Data.U32(gcSlot - b.Data.Here);
        b.Data.U32(unowned - b.Data.Here);
        b.Row(201, region, b.Data.Here);
        // Non-GC statics behind the class constructor context; the thread statics cell: TypeManager indirection, -(8 + 8).
        b.Pointer(b.Data, Cctor);
        uint nonGc = b.Data.Zero(8);
        uint typeManager = b.Data.Zero(8);
        b.Row(204, typeManager, 0, flags: 0);
        uint cell = b.Data.Here;
        b.Pointer(b.Data, typeManager);
        b.Data.U64(unchecked((ulong)-16L));

        // Dog::.cctor: mov rax, [rip + slot]; lea rcx, [rip + cell]; ret. Other: an unnamed function.
        var text = new byte[0x100];
        void RipRelative(int at, byte[] opcode, uint target)
        {
            opcode.CopyTo(text, at);
            int next = at + opcode.Length + 4;
            BinaryPrimitives.WriteInt32LittleEndian(text.AsSpan(at + opcode.Length), (int)(target - (B.TextRva + (uint)next)));
        }
        RipRelative(0x20, [0x48, 0x8B, 0x05], gcSlot);
        RipRelative(0x27, [0x48, 0x8D, 0x0D], cell);
        text[0x2E] = 0xC3;
        text[0x80] = 0xC3;
        b.Text = text;

        // Stack-trace map: owner Dog, name ".cctor", at the cctor.
        b.Rdata.Align(4);
        uint st = b.Rdata.Here;
        byte[] name = [.. Unsigned(m.CctorName.Offset)];
        var map = new byte[4 + 1 + 4 + name.Length + 4];
        map[0] = 1;
        map[4] = 0x03;
        BinaryPrimitives.WriteUInt32LittleEndian(map.AsSpan(5), m.Writer.Token(m.Dog));
        name.CopyTo(map, 9);
        int code = 9 + name.Length;
        BinaryPrimitives.WriteInt32LittleEndian(map.AsSpan(code), (int)(Cctor - (st + (uint)code)));
        Assert.Equal(st, b.Blob(BlobId.StackTraceMethodRvaToTokenMapping, map));
        return new Fixture(NativeAotImage.Open(b.Image())!, gcSlot, nonGc, cell, unowned);
    }

    [Fact]
    public void Statics_name_their_owners_and_fields()
    {
        var f = Build();
        var statics = f.Aot.Statics;
        Assert.Equal(NativeAotStage.Complete, statics.Stage.Status);
        Assert.Equal(4, statics.Bases.Count);

        var gc = statics.At(f.GcSlot)!;
        Assert.Equal((NativeAotStaticsKind.Gc, "Sample.Zoo.Dog", "code", 8u), (gc.Kind, gc.Owner, gc.Origin, gc.Size));
        Assert.Equal([new NativeAotStaticField("Name", "string", 0)], gc.Fields);

        var nonGc = statics.At(f.NonGc)!;
        Assert.Equal((NativeAotStaticsKind.NonGc, "Sample.Zoo.Dog", "class constructor context", 4u), (nonGc.Kind, nonGc.Owner, nonGc.Origin, nonGc.Size));
        Assert.Equal([new NativeAotStaticField("Count", "int", 0)], nonGc.Fields);
        Assert.Same(nonGc, statics.At(f.NonGc + 2));
        Assert.Null(statics.At(f.NonGc + 4));

        var thread = statics.At(f.ThreadCell)!;
        Assert.Equal((NativeAotStaticsKind.Thread, "Sample.Zoo.Dog", 8L), (thread.Kind, thread.Owner, thread.ThreadIndex));
        Assert.Null(statics.At(f.Unowned)!.Owner);
    }

    /// <summary>Bytes just past an owned non-GC statics base that has no field metadata read as Owner::field_0xN; never past the next base.</summary>
    [Fact]
    public void Statics_without_field_names_keep_their_owner()
    {
        NativeAotStaticBase[] bases =
        [
            new(NativeAotStaticsKind.NonGc, 0x1000, "App.Settings", "code", 0, []),
            new(NativeAotStaticsKind.NonGc, 0x1010, null, null, 0, []),
            new(NativeAotStaticsKind.NonGc, 0x2000, "App.Known", "code", 8, [new NativeAotStaticField("Count", "int", 0)]),
        ];
        Assert.Equal(0x1000u, NativeAotNames.UnnamedStatic(bases, 0x1008)!.Rva);
        Assert.Null(NativeAotNames.UnnamedStatic(bases, 0x1000)); // the base itself is named
        Assert.Null(NativeAotNames.UnnamedStatic(bases, 0x1014)); // past the next base, which has no owner
        Assert.Null(NativeAotNames.UnnamedStatic(bases, 0x2004)); // field metadata names those
    }

    /// <summary>The name layer gains Owner__field_0xN where code uses a static the metadata keeps no name for; never past the next base, never over a name.</summary>
    [Fact]
    public void Statics_without_field_names_are_named_from_their_code_references()
    {
        NativeAotStaticBase[] bases =
        [
            new(NativeAotStaticsKind.NonGc, 0x1000, "App.Settings", "code", 0, []),
            new(NativeAotStaticsKind.NonGc, 0x1010, null, null, 0, []),
            new(NativeAotStaticsKind.NonGc, 0x2000, "App.Known", "code", 8, [new NativeAotStaticField("Count", "int", 0)]),
        ];
        uint[] refs = [0x1000, 0x1004, 0x1008, 0x1008, 0x1014, 0x2004];
        var asked = new List<(uint, uint)>();
        IEnumerable<uint> Referenced(uint start, uint end)
        {
            asked.Add((start, end));
            return refs.Where(r => r >= start && r < end);
        }
        var existing = new Dictionary<uint, string> { [0x1000] = "App_Settings__Statics", [0x1004] = "already_named" };
        var (names, comments, added) = NativeAotNames.StaticFieldNames(bases, existing, new Dictionary<uint, string>(), Referenced, default);
        Assert.Equal(1, added);
        Assert.Equal("App_Settings__field_0x8", names[0x1008]);
        Assert.Contains("static of App.Settings at +0x8", comments[0x1008]);
        Assert.Equal("already_named", names[0x1004]);
        Assert.Equal([(0x1001u, 0x1010u)], asked); // only the owned block without field metadata, up to the next base
    }

    [Fact]
    public void Statics_are_named_in_the_layer_and_described()
    {
        var f = Build();
        var built = NativeAotNames.Build(f.Aot);
        Assert.Equal("Sample_Zoo_Dog__GCStatics", built.Names[f.GcSlot]);
        Assert.Equal("Sample_Zoo_Dog__Statics", built.Names[f.NonGc]);
        Assert.Equal("Sample_Zoo_Dog__ThreadStaticsIndex", built.Names[f.ThreadCell]);
        Assert.Equal("GCStatics_0", built.Names[f.Unowned]);
        Assert.Contains("GC statics of Sample.Zoo.Dog (inferred from the code that references it)", built.Comments[f.GcSlot]);
        Assert.Contains("fields: string Name +0x0", built.Comments[f.GcSlot]);
        Assert.Contains("offset 0x8 in the module's thread-local block", built.Comments[f.ThreadCell]);
        Assert.Equal(4, built.Report.Statics);

        using var dir = new TempDir();
        using var env = new Env();
        File.WriteAllBytes(dir.File("app.exe"), ((Native.Pe.PeFile)f.Aot.Image).FileBytes.ToArray());
        var native = env.Workspace.LoadAny(dir.File("app.exe")).Native!;
        Assert.Contains("NativeAOT static Sample.Zoo.Dog::Count (+0x2) in the non-GC statics", string.Join("\n", NativeAotNames.Describe(native, f.NonGc + 2)));
        Assert.Contains("NativeAOT GC statics of Sample.Zoo.Dog", string.Join("\n", NativeAotNames.Describe(native, f.GcSlot)));
    }
}
