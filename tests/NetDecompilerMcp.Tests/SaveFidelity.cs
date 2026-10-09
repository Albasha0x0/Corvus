using System.Buffers.Binary;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;
using static NetDecompilerMcp.Tests.IlLab;

namespace NetDecompilerMcp.Tests;

/// <summary>Invalid shapes injected into a module that dnlib writes cleanly, by patching the written bytes.</summary>
public enum InvalidShape
{
    EmptyBody,
    BranchPastEnd,
    BranchIntoInstruction,
    TruncatedHandler,
    OverlappingHandler,
    LocalOutOfRange,
    MalformedSignature,
    UnreadableBody,
}

/// <summary>
/// Test images for save fidelity: valid methods (with member references, string literals, locals and exception
/// handlers, so tokens and heaps are exercised), an edit target, and one method per <see cref="InvalidShape"/>, each
/// named after its shape. Also an independent comparison of two images, read with System.Reflection.Metadata only.
/// </summary>
internal static class SaveFidelity
{
    public const string Type = "Lab.P";
    public const string EditTarget = "Lab.P::Target";

    public static string Method(InvalidShape shape) => $"{Type}::{shape}";

    /// <summary>The report code an invalid shape is listed with (after an edit; an unmodified save lists every shape as kept).</summary>
    public static string Code(InvalidShape shape, bool edited) => shape switch
    {
        InvalidShape.MalformedSignature => "malformed-signature",
        InvalidShape.UnreadableBody when edited => "unreadable-body",
        _ => "invalid-body",
    };

    public static byte[] Build(params InvalidShape[] shapes)
    {
        var lab = new IlLab("Fidelity");
        var t = lab.T;
        var max = new MemberRefUser(lab.Module, "Max", MethodSig.CreateStatic(t.Int32, t.Int32, t.Int32),
            new TypeRefUser(lab.Module, "System", "Math", t.AssemblyRef));
        var concat = new MemberRefUser(lab.Module, "Concat", MethodSig.CreateStatic(t.String, t.String, t.String), t.String.TypeDefOrRef);

        lab.Method("Valid", t.Int32, [t.Int32], [Op(OpCodes.Ldarg_0), Ldc(7), OpCodes.Call.ToInstruction(max), Ret()]);
        lab.Method("Text", t.String, [t.String],
            [OpCodes.Ldstr.ToInstruction("hello "), Op(OpCodes.Ldarg_0), OpCodes.Call.ToInstruction(concat), Ret()]);
        lab.Method("Target", t.Int32, [], [Ldc(5), Ret()]);
        {
            var ret = Ret();
            var leave = OpCodes.Leave.ToInstruction(ret);
            var handlerStart = Op(OpCodes.Pop);
            var handlerLeave = OpCodes.Leave.ToInstruction(ret);
            var tryStart = Op(OpCodes.Ldarg_0);
            var local = new Local(t.Int32);
            var m = lab.Method("Guarded", t.Void, [t.Int32],
                [tryStart, OpCodes.Stloc.ToInstruction(local), leave, handlerStart, handlerLeave, ret]);
            m.Body.Variables.Add(local);
            m.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart, TryEnd = handlerStart, HandlerStart = handlerStart, HandlerEnd = ret, CatchType = t.Object.TypeDefOrRef,
            });
        }

        foreach (var shape in shapes.Distinct())
        {
            var name = shape.ToString();
            MethodDef m;
            switch (shape)
            {
                case InvalidShape.EmptyBody:
                case InvalidShape.UnreadableBody:
                    m = lab.Method(name, t.Void, Ret());
                    break;
                case InvalidShape.BranchPastEnd:
                {
                    var ret = Ret();
                    m = lab.Method(name, t.Void, Op(OpCodes.Nop), OpCodes.Br_S.ToInstruction(ret), ret);
                    break;
                }
                case InvalidShape.BranchIntoInstruction:
                {
                    var target = OpCodes.Ldc_I4.ToInstruction(0x11223344);
                    m = lab.Method(name, t.Void, OpCodes.Br_S.ToInstruction(target), target, Op(OpCodes.Pop), Ret());
                    break;
                }
                case InvalidShape.TruncatedHandler:
                case InvalidShape.OverlappingHandler:
                {
                    // nop; leave.s RET; endfinally; RET: ret   with try [0, 3) finally [3, 4)
                    var ret = Ret();
                    var nop = Op(OpCodes.Nop);
                    var end = Op(OpCodes.Endfinally);
                    m = lab.Method(name, t.Void, nop, OpCodes.Leave_S.ToInstruction(ret), end, ret);
                    m.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally) { TryStart = nop, TryEnd = end, HandlerStart = end, HandlerEnd = ret });
                    break;
                }
                case InvalidShape.LocalOutOfRange:
                {
                    var local = new Local(t.Int32);
                    m = lab.Method(name, t.Int32, Op(OpCodes.Ldc_I4_0), OpCodes.Stloc_S.ToInstruction(local), OpCodes.Ldloc_S.ToInstruction(local), Ret());
                    m.Body.Variables.Add(local);
                    break;
                }
                case InvalidShape.MalformedSignature:
                    // A signature no other member shares: (char, char, char, char) -> void.
                    m = lab.Method(name, t.Void, [t.Char, t.Char, t.Char, t.Char], [Ret()]);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(shapes));
            }
            // Unreachable, distinct tails: dnlib shares identical bodies, and each shape must patch its own.
            foreach (var i in new[] { Ldc(1000 + (int)shape), Op(OpCodes.Pop), Ret() }) m.Body.Instructions.Add(i);
        }

        var image = lab.Write();
        foreach (var shape in shapes.Distinct()) Inject(image, shape);
        return image;
    }

    /// <summary>Patches the written bytes of the method named after <paramref name="shape"/>.</summary>
    private static void Inject(byte[] image, InvalidShape shape)
    {
        int body, code, rowRva, sig;
        using (var pe = new PEReader(new MemoryStream(image.ToArray())))
        {
            var md = pe.GetMetadataReader();
            var handle = md.MethodDefinitions.Single(h => md.GetString(md.GetMethodDefinition(h).Name) == shape.ToString());
            var def = md.GetMethodDefinition(handle);
            body = Offset(pe, def.RelativeVirtualAddress);
            code = body + ((image[body] & 3) == 2 ? 1 : 12);
            int metadata = pe.PEHeaders.MetadataStartOffset;
            rowRva = metadata + md.GetTableMetadataOffset(TableIndex.MethodDef) + (MetadataTokens.GetRowNumber(handle) - 1) * md.GetTableRowSize(TableIndex.MethodDef);
            sig = metadata + md.GetHeapMetadataOffset(HeapIndex.Blob) + MetadataTokens.GetHeapOffset(def.Signature) + 1; // after the 1-byte length
        }
        switch (shape)
        {
            case InvalidShape.EmptyBody:
                image[body] = 0x02; // tiny header, 0 bytes of code
                break;
            case InvalidShape.BranchPastEnd:
                Assert.Equal(0x2B, image[code + 1]); // br.s
                image[code + 2] = 0x10;
                break;
            case InvalidShape.BranchIntoInstruction:
                Assert.Equal(0x2B, image[code]); // br.s +0 -> +1: into ldc.i4's operand
                image[code + 1] = 0x01;
                break;
            case InvalidShape.TruncatedHandler:
            case InvalidShape.OverlappingHandler:
            {
                int codeSize = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(body + 4));
                int section = code + codeSize;
                section += (4 - (section - body) % 4) % 4;
                Assert.Equal(0x01, image[section] & 0x7F); // small EH table
                int clause = section + 4;
                if (shape == InvalidShape.TruncatedHandler)
                    image[clause + 4] = 0x40; // try length past the end of the code
                else
                {
                    BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(clause + 5), 1); // handler [1, 3) inside the try [0, 3)
                    image[clause + 7] = 2;
                }
                break;
            }
            case InvalidShape.LocalOutOfRange:
                Assert.Equal(0x11, image[code + 3]); // ldloc.s 0 -> ldloc.s 9
                image[code + 4] = 0x09;
                break;
            case InvalidShape.MalformedSignature:
                Assert.Equal(0x04, image[sig + 1]); // 4 parameters -> 9: the blob ends before them
                image[sig + 1] = 0x09;
                break;
            case InvalidShape.UnreadableBody:
                BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(rowRva), 0x7FFF0000u);
                break;
        }
    }

    private static int Offset(PEReader pe, int rva)
    {
        foreach (var s in pe.PEHeaders.SectionHeaders)
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.SizeOfRawData) return rva - s.VirtualAddress + s.PointerToRawData;
        throw new InvalidOperationException($"RVA 0x{rva:X} not in a section");
    }

    /// <summary>
    /// Members of <paramref name="original"/> whose stored bytes differ in <paramref name="written"/>: method bodies
    /// (header, IL and exception sections) and signature blobs of rows that keep their rids. Tokens; read with
    /// System.Reflection.Metadata, independently of the writer's own check.
    /// </summary>
    public static HashSet<uint> Differences(byte[] original, byte[] written)
    {
        var differ = new HashSet<uint>();
        using var a = new PEReader(new MemoryStream(original));
        using var b = new PEReader(new MemoryStream(written));
        var ma = a.GetMetadataReader();
        var mb = b.GetMetadataReader();
        foreach (var handle in ma.MethodDefinitions)
        {
            int rid = MetadataTokens.GetRowNumber(handle);
            try
            {
                var da = ma.GetMethodDefinition(handle);
                if (da.RelativeVirtualAddress == 0 || (da.ImplAttributes & System.Reflection.MethodImplAttributes.CodeTypeMask) != System.Reflection.MethodImplAttributes.IL) continue;
                var ba = BodyBytes(a, da.RelativeVirtualAddress);
                byte[]? bb = null;
                if (rid <= mb.GetTableRowCount(TableIndex.MethodDef))
                {
                    var db = mb.GetMethodDefinition(MetadataTokens.MethodDefinitionHandle(rid));
                    if (db.RelativeVirtualAddress != 0) bb = BodyBytes(b, db.RelativeVirtualAddress);
                }
                if (ba == null || bb == null || !ba.AsSpan().SequenceEqual(bb)) differ.Add((uint)MetadataTokens.GetToken(handle));
            }
            catch (BadImageFormatException)
            {
                differ.Add((uint)MetadataTokens.GetToken(handle)); // unreadable (an RVA above 2 GB): must be reported
            }
        }
        foreach (var (table, signature) in new (TableIndex, Func<MetadataReader, int, BlobHandle>)[]
        {
            (TableIndex.MethodDef, (m, r) => m.GetMethodDefinition(MetadataTokens.MethodDefinitionHandle(r)).Signature),
            (TableIndex.Field, (m, r) => m.GetFieldDefinition(MetadataTokens.FieldDefinitionHandle(r)).Signature),
            (TableIndex.MemberRef, (m, r) => m.GetMemberReference(MetadataTokens.MemberReferenceHandle(r)).Signature),
            (TableIndex.StandAloneSig, (m, r) => m.GetStandaloneSignature(MetadataTokens.StandaloneSignatureHandle(r)).Signature),
            (TableIndex.TypeSpec, (m, r) => m.GetTypeSpecification(MetadataTokens.TypeSpecificationHandle(r)).Signature),
            (TableIndex.MethodSpec, (m, r) => m.GetMethodSpecification(MetadataTokens.MethodSpecificationHandle(r)).Signature),
            (TableIndex.Property, (m, r) => m.GetPropertyDefinition(MetadataTokens.PropertyDefinitionHandle(r)).Signature),
        })
        {
            for (int rid = 1; rid <= ma.GetTableRowCount(table); rid++)
            {
                uint token = (uint)MetadataTokens.GetToken(MetadataTokens.EntityHandle(table, rid));
                if (rid > mb.GetTableRowCount(table)) { differ.Add(token); continue; }
                if (!Blob(ma, signature(ma, rid)).AsSpan().SequenceEqual(Blob(mb, signature(mb, rid)))) differ.Add(token);
            }
        }
        return differ;
    }

    private static byte[] Blob(MetadataReader md, BlobHandle h)
    {
        try { return h.IsNil ? [] : md.GetBlobBytes(h); }
        catch (BadImageFormatException) { return [0xBA, 0xD0]; }
    }

    /// <summary>
    /// A body's stored bytes as the runtime reads them (header of the size its size field declares, code, exception
    /// sections; padding excluded), or null when they lie outside the image.
    /// </summary>
    private static byte[]? BodyBytes(PEReader pe, int rva)
    {
        try
        {
            // Read in place: copying the rest of the section for every body made large modules quadratic.
            var data = pe.GetSectionData(rva).GetReader();
            int length = data.Length;
            byte At(long i) { data.Offset = (int)i; return data.ReadByte(); }
            byte[] Range(long start, long count) { data.Offset = (int)start; return data.ReadBytes((int)count); }
            if (length == 0) return null;
            byte first = At(0);
            if ((first & 3) == 2) return length > first >> 2 ? Range(0, 1 + (first >> 2)) : null;
            if ((first & 3) != 3 || length < 12) return null;
            int header = (At(1) >> 4) * 4;
            long end = header + (long)BinaryPrimitives.ReadUInt32LittleEndian(Range(4, 4));
            if (header < 12 || end > length) return null;
            var bytes = Range(0, end).ToList();
            if ((first & 0x08) == 0) return [.. bytes];
            long pos = (rva + end + 3 & ~3L) - rva;
            while (true)
            {
                if (pos + 4 > length) return null;
                byte kind = At(pos);
                int size = (kind & 0x40) != 0 ? At(pos + 1) | At(pos + 2) << 8 | At(pos + 3) << 16 : At(pos + 1);
                if (size < 4 || pos + size > length) return null;
                bytes.AddRange(Range(pos, size));
                pos += size;
                if ((kind & 0x80) == 0) return [.. bytes];
                pos = (rva + pos + 3 & ~3L) - rva;
            }
        }
        catch (Exception ex) when (ex is BadImageFormatException or ArgumentOutOfRangeException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>The tokens a save report lists.</summary>
    public static HashSet<uint> Listed(SaveReport report, bool changesBytes) => report.Issues.Where(i => i.ChangesBytes == changesBytes).Select(i => i.Token).ToHashSet();
}
