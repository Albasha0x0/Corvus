using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using dnlib.DotNet.Emit;
using OperandType = dnlib.DotNet.Emit.OperandType;

namespace NetDecompilerMcp.Core;

/// <summary>
/// Method bodies and signature blobs of an image exactly as stored, read with System.Reflection.Metadata. Used to keep
/// what an edit did not touch byte-for-byte when the module is written again, and to check that it was.
/// </summary>
internal sealed class RawImage : IDisposable
{
    /// <summary>A method body as stored: header and IL, and the exception sections that follow (padding excluded).</summary>
    public sealed record Body(byte[] Code, byte[]? Sections, uint LocalVarSigToken, int HeaderSize)
    {
        public int CodeSize => Code.Length - HeaderSize;
        public ReadOnlySpan<byte> IL => Code.AsSpan(HeaderSize);

        public bool SameBytes(byte[] code, byte[]? sections) =>
            Code.AsSpan().SequenceEqual(code) && (Sections ?? []).AsSpan().SequenceEqual(sections ?? []);

        public bool SameBytes(Body other) => SameBytes(other.Code, other.Sections);

        public int Length => Code.Length + (Sections?.Length ?? 0);
    }

    public readonly record struct MethodRow(int Rva, System.Reflection.MethodImplAttributes ImplAttributes)
    {
        public bool IsIL => (ImplAttributes & System.Reflection.MethodImplAttributes.CodeTypeMask) == System.Reflection.MethodImplAttributes.IL;
    }

    /// <summary>Tables whose rows keep their rids when dnlib writes with PreserveAll, with the blob column checked.</summary>
    public static readonly TableIndex[] SignatureTables =
    [
        TableIndex.MethodDef, TableIndex.Field, TableIndex.MemberRef, TableIndex.StandAloneSig, TableIndex.TypeSpec,
        TableIndex.MethodSpec, TableIndex.Property,
    ];

    private readonly byte[] _image;
    private readonly PEReader _pe;
    private readonly SectionHeader[] _sections;
    private readonly ImmutableArray<byte> _metadata;

    public MetadataReader Metadata { get; }

    public RawImage(byte[] image)
    {
        _image = image;
        _pe = new PEReader(new MemoryStream(image, writable: false), PEStreamOptions.PrefetchEntireImage);
        _sections = _pe.PEHeaders.SectionHeaders.ToArray();
        Metadata = _pe.GetMetadataReader();
        _metadata = _pe.GetMetadata().GetContent();
    }

    public int MethodCount => Metadata.GetTableRowCount(TableIndex.MethodDef);

    public MethodRow Method(int rid)
    {
        var def = Metadata.GetMethodDefinition(MetadataTokens.MethodDefinitionHandle(rid));
        int rva;
        try { rva = def.RelativeVirtualAddress; }
        catch (BadImageFormatException) { rva = -1; } // above 2 GB: no image is that large
        return new MethodRow(rva, def.ImplAttributes);
    }

    /// <summary>The body stored at <paramref name="rva"/>, or null with the reason it cannot be read.</summary>
    public Body? ReadBody(int rva, out string? error)
    {
        error = null;
        if (rva < 0)
        {
            error = "the RVA lies above 2 GB, outside the image";
            return null;
        }
        if (!TryOffset(rva, out int offset, out int available))
        {
            error = $"RVA 0x{rva:X8} is outside the image's sections";
            return null;
        }
        var data = _image.AsSpan(offset, available);
        byte first = data[0];
        if ((first & 3) == 2)
        {
            int size = first >> 2;
            if (1 + size > data.Length) { error = $"the {size}-byte code at RVA 0x{rva:X8} runs past the end of its section"; return null; }
            return new Body(data[..(1 + size)].ToArray(), null, 0, 1);
        }
        if ((first & 3) != 3) { error = $"invalid body header 0x{first:X2} at RVA 0x{rva:X8}"; return null; }
        if (data.Length < 12) { error = $"the body header at RVA 0x{rva:X8} runs past the end of its section"; return null; }
        ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(data);
        int headerSize = (flags >> 12) * 4;
        uint codeSize = BinaryPrimitives.ReadUInt32LittleEndian(data[4..]);
        uint localSig = BinaryPrimitives.ReadUInt32LittleEndian(data[8..]);
        if (headerSize < 12) { error = $"invalid fat header size {headerSize} at RVA 0x{rva:X8}"; return null; }
        if (codeSize > (uint)(data.Length - headerSize)) { error = $"the {codeSize}-byte code at RVA 0x{rva:X8} runs past the end of its section"; return null; }
        int end = headerSize + (int)codeSize;
        var code = data[..end].ToArray();
        if ((flags & 0x08) == 0) return new Body(code, null, localSig, headerSize);

        // Exception sections: 4-byte aligned after the code, chained by the MoreSects bit; kept as one span.
        int start = (int)(((uint)(rva + end) + 3 & ~3u) - (uint)rva);
        int pos = start;
        while (true)
        {
            if (pos + 4 > data.Length) { error = $"the exception sections of the body at RVA 0x{rva:X8} run past the end of its section"; return null; }
            byte kind = data[pos];
            int size = (kind & 0x40) != 0 ? data[pos + 1] | data[pos + 2] << 8 | data[pos + 3] << 16 : data[pos + 1];
            if (size < 4 || pos + size > data.Length) { error = $"invalid exception section (size {size}) in the body at RVA 0x{rva:X8}"; return null; }
            pos += size;
            if ((kind & 0x80) == 0) break;
            pos = (int)(((uint)(rva + pos) + 3 & ~3u) - (uint)rva);
        }
        return new Body(code, data[start..pos].ToArray(), localSig, headerSize);
    }

    private bool TryOffset(int rva, out int offset, out int available)
    {
        foreach (var s in _sections)
        {
            if ((uint)rva < (uint)s.VirtualAddress || (uint)rva >= (uint)s.VirtualAddress + (uint)Math.Max(s.VirtualSize, s.SizeOfRawData)) continue;
            long delta = (uint)rva - (uint)s.VirtualAddress;
            long rawEnd = Math.Min((long)s.PointerToRawData + s.SizeOfRawData, _image.Length);
            offset = (int)(s.PointerToRawData + delta);
            available = (int)(rawEnd - offset);
            return available > 0;
        }
        offset = available = 0;
        return false;
    }

    /// <summary>The blob column of a row of one of the <see cref="SignatureTables"/>.</summary>
    public BlobHandle Signature(TableIndex table, int rid) => table switch
    {
        TableIndex.MethodDef => Metadata.GetMethodDefinition(MetadataTokens.MethodDefinitionHandle(rid)).Signature,
        TableIndex.Field => Metadata.GetFieldDefinition(MetadataTokens.FieldDefinitionHandle(rid)).Signature,
        TableIndex.MemberRef => Metadata.GetMemberReference(MetadataTokens.MemberReferenceHandle(rid)).Signature,
        TableIndex.StandAloneSig => Metadata.GetStandaloneSignature(MetadataTokens.StandaloneSignatureHandle(rid)).Signature,
        TableIndex.TypeSpec => Metadata.GetTypeSpecification(MetadataTokens.TypeSpecificationHandle(rid)).Signature,
        TableIndex.MethodSpec => Metadata.GetMethodSpecification(MetadataTokens.MethodSpecificationHandle(rid)).Signature,
        TableIndex.Property => Metadata.GetPropertyDefinition(MetadataTokens.PropertyDefinitionHandle(rid)).Signature,
        _ => throw new ArgumentOutOfRangeException(nameof(table)),
    };

    public byte[] Blob(BlobHandle handle) => handle.IsNil ? [] : Metadata.GetBlobBytes(handle);

    /// <summary>The raw bytes of a heap (#Blob, #US, ...).</summary>
    public ReadOnlySpan<byte> Heap(HeapIndex heap)
    {
        int size = Metadata.GetHeapSize(heap);
        return size == 0 ? [] : _metadata.AsSpan().Slice(Metadata.GetHeapMetadataOffset(heap), size);
    }

    /// <summary>The number of locals declared by a body's local signature, or null when it cannot be read.</summary>
    public int? LocalCount(uint localVarSigToken)
    {
        if (localVarSigToken == 0) return 0;
        if (localVarSigToken >> 24 != 0x11) return null;
        int rid = (int)(localVarSigToken & 0xFFFFFF);
        if (rid == 0 || rid > Metadata.GetTableRowCount(TableIndex.StandAloneSig)) return null;
        try
        {
            var reader = Metadata.GetBlobReader(Metadata.GetStandaloneSignature(MetadataTokens.StandaloneSignatureHandle(rid)).Signature);
            if (reader.ReadByte() != 0x07) return null;
            return reader.ReadCompressedInteger();
        }
        catch (BadImageFormatException) { return null; }
    }

    /// <summary>The number of arguments of a method, <c>this</c> included, or null when its signature cannot be read.</summary>
    public int? ArgumentCount(int methodRid)
    {
        try
        {
            var reader = Metadata.GetBlobReader(Metadata.GetMethodDefinition(MetadataTokens.MethodDefinitionHandle(methodRid)).Signature);
            byte header = reader.ReadByte();
            if ((header & 0x10) != 0) reader.ReadCompressedInteger();
            return reader.ReadCompressedInteger() + ((header & 0x20) != 0 ? 1 : 0);
        }
        catch (BadImageFormatException) { return null; }
    }

    /// <summary>Why a stored body is not valid IL, or null when it is.</summary>
    public string? Problem(Body body, int methodRid)
    {
        var il = body.IL;
        if (body.HeaderSize > 12) return $"the fat header declares {body.HeaderSize} bytes (12 is the only valid size)";
        if (il.Length == 0) return "empty body (no instructions)";
        int? locals = LocalCount(body.LocalVarSigToken);
        int? args = ArgumentCount(methodRid);
        var starts = new HashSet<int>();
        var branches = new List<(int At, long Target)>();
        OpCode? last = null;
        int pos = 0;
        while (pos < il.Length)
        {
            int at = pos;
            starts.Add(at);
            byte first = il[pos++];
            if (first == 0xFE && pos == il.Length) return $"truncated instruction at IL_{at:X4}";
            var op = first == 0xFE ? OpCodes.TwoByteOpCodes[il[pos++]] : OpCodes.OneByteOpCodes[first];
            if (op.Code is Code.UNKNOWN1 or Code.UNKNOWN2) return $"unknown opcode 0x{(first == 0xFE ? 0xFE00 | il[pos - 1] : first):X2} at IL_{at:X4}";
            if (op.OperandType == OperandType.InlineSwitch)
            {
                if (il.Length - pos < 4) return $"the switch at IL_{at:X4} runs past the end of the code";
                uint count = BinaryPrimitives.ReadUInt32LittleEndian(il[pos..]);
                pos += 4;
                if (count > (uint)(il.Length - pos) / 4) return $"the switch at IL_{at:X4} runs past the end of the code";
                int next = pos + (int)count * 4;
                for (int k = 0; k < count; k++) branches.Add((at, (long)next + BinaryPrimitives.ReadInt32LittleEndian(il[(pos + 4 * k)..])));
                pos = next;
                last = op;
                continue;
            }
            int size = op.OperandType switch
            {
                OperandType.InlineNone or OperandType.InlinePhi => 0,
                OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
                OperandType.InlineVar => 2,
                OperandType.InlineI8 or OperandType.InlineR => 8,
                _ => 4,
            };
            if (il.Length - pos < size) return $"the instruction at IL_{at:X4} runs past the end of the code";
            var operand = il.Slice(pos, size);
            pos += size;
            if (op.OperandType == OperandType.ShortInlineBrTarget) branches.Add((at, (long)pos + (sbyte)operand[0]));
            else if (op.OperandType == OperandType.InlineBrTarget) branches.Add((at, (long)pos + BinaryPrimitives.ReadInt32LittleEndian(operand)));
            else if (op.OperandType is OperandType.ShortInlineVar or OperandType.InlineVar)
            {
                int index = size == 1 ? operand[0] : BinaryPrimitives.ReadUInt16LittleEndian(operand);
                bool isLocal = op.Code is Code.Ldloc or Code.Ldloc_S or Code.Stloc or Code.Stloc_S or Code.Ldloca or Code.Ldloca_S;
                if (isLocal && locals is { } l && index >= l) return $"IL_{at:X4} uses local {index}; the body declares {l}";
                if (!isLocal && args is { } a && index >= a) return $"IL_{at:X4} uses argument {index}; the method has {a}";
            }
            else if (op.Code is Code.Ldloc_0 or Code.Ldloc_1 or Code.Ldloc_2 or Code.Ldloc_3 or Code.Stloc_0 or Code.Stloc_1 or Code.Stloc_2 or Code.Stloc_3)
            {
                int index = op.Code switch { Code.Ldloc_0 or Code.Stloc_0 => 0, Code.Ldloc_1 or Code.Stloc_1 => 1, Code.Ldloc_2 or Code.Stloc_2 => 2, _ => 3 };
                if (locals is { } l && index >= l) return $"IL_{at:X4} uses local {index}; the body declares {l}";
            }
            last = op;
        }
        foreach (var (at, target) in branches)
        {
            if (target < 0 || target >= il.Length) return $"the branch at IL_{at:X4} targets IL_{target:X4}, outside the code ({il.Length} bytes)";
            if (!starts.Contains((int)target)) return $"the branch at IL_{at:X4} targets IL_{target:X4}, inside an instruction";
        }
        if (body.Sections != null && ClauseProblem(body.Sections, il.Length, starts) is { } clause) return clause;
        if (last is not { } end || !(end.FlowControl is FlowControl.Return or FlowControl.Throw or FlowControl.Branch || end.Code is Code.Jmp or Code.Endfinally))
            return "the code runs past its end";
        return null;
    }

    /// <summary>Exception clauses out of range, off instruction boundaries, or overlapping without nesting.</summary>
    private static string? ClauseProblem(byte[] sections, int codeSize, HashSet<int> starts)
    {
        var clauses = new List<(int Kind, int TryStart, int TryEnd, int HandlerStart, int HandlerEnd, int Filter)>();
        int pos = 0;
        while (pos + 4 <= sections.Length)
        {
            byte kind = sections[pos];
            bool fat = (kind & 0x40) != 0;
            int size = fat ? sections[pos + 1] | sections[pos + 2] << 8 | sections[pos + 3] << 16 : sections[pos + 1];
            if ((kind & 0x3F) == 0x01)
            {
                int clauseSize = fat ? 24 : 12;
                for (int c = pos + 4; c + clauseSize <= pos + size && c + clauseSize <= sections.Length; c += clauseSize)
                {
                    var s = sections.AsSpan(c);
                    if (fat)
                        clauses.Add(((int)BinaryPrimitives.ReadUInt32LittleEndian(s), (int)BinaryPrimitives.ReadUInt32LittleEndian(s[4..]),
                            (int)(BinaryPrimitives.ReadUInt32LittleEndian(s[4..]) + BinaryPrimitives.ReadUInt32LittleEndian(s[8..])),
                            (int)BinaryPrimitives.ReadUInt32LittleEndian(s[12..]),
                            (int)(BinaryPrimitives.ReadUInt32LittleEndian(s[12..]) + BinaryPrimitives.ReadUInt32LittleEndian(s[16..])),
                            (int)BinaryPrimitives.ReadUInt32LittleEndian(s[20..])));
                    else
                        clauses.Add((BinaryPrimitives.ReadUInt16LittleEndian(s), BinaryPrimitives.ReadUInt16LittleEndian(s[2..]),
                            BinaryPrimitives.ReadUInt16LittleEndian(s[2..]) + s[4], BinaryPrimitives.ReadUInt16LittleEndian(s[5..]),
                            BinaryPrimitives.ReadUInt16LittleEndian(s[5..]) + s[7], (int)BinaryPrimitives.ReadUInt32LittleEndian(s[8..])));
                }
            }
            if (size < 4) break;
            pos += size;
            pos = (pos + 3) & ~3;
        }

        bool Boundary(int offset) => offset == codeSize || starts.Contains(offset);
        for (int i = 0; i < clauses.Count; i++)
        {
            var c = clauses[i];
            if (c.TryStart < 0 || c.TryEnd > codeSize || c.HandlerStart < 0 || c.HandlerEnd > codeSize || c.TryEnd <= c.TryStart || c.HandlerEnd <= c.HandlerStart)
                return $"exception clause {i} (try IL_{c.TryStart:X4}-IL_{c.TryEnd:X4}, handler IL_{c.HandlerStart:X4}-IL_{c.HandlerEnd:X4}) lies outside the code ({codeSize} bytes)";
            if (!Boundary(c.TryStart) || !Boundary(c.TryEnd) || !Boundary(c.HandlerStart) || !Boundary(c.HandlerEnd) || (c.Kind & 1) != 0 && !Boundary(c.Filter))
                return $"exception clause {i} starts or ends inside an instruction";
            if (!(c.TryEnd <= c.HandlerStart || c.HandlerEnd <= c.TryStart))
                return $"exception clause {i}: the try block IL_{c.TryStart:X4}-IL_{c.TryEnd:X4} overlaps its handler IL_{c.HandlerStart:X4}-IL_{c.HandlerEnd:X4}";
            for (int j = 0; j < i; j++)
            {
                var d = clauses[j];
                foreach (var (a0, a1) in new[] { (c.TryStart, c.TryEnd), (c.HandlerStart, c.HandlerEnd) })
                foreach (var (b0, b1) in new[] { (d.TryStart, d.TryEnd), (d.HandlerStart, d.HandlerEnd) })
                {
                    bool disjoint = a1 <= b0 || b1 <= a0;
                    bool nested = a0 >= b0 && a1 <= b1 || b0 >= a0 && b1 <= a1;
                    if (!disjoint && !nested) return $"exception clauses {j} and {i} overlap without nesting";
                }
            }
        }
        return null;
    }

    public void Dispose() => _pe.Dispose();
}
