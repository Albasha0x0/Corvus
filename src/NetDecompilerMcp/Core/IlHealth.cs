using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using dnlib.DotNet.Emit;
using OperandType = dnlib.DotNet.Emit.OperandType;

namespace NetDecompilerMcp.Core;

/// <summary>
/// Whether method bodies hold valid IL. A body is invalid when it contains an unknown opcode, an operand runs past the
/// end of the code, or the code does not end in a return / throw / branch. Bodies of a runtime-decrypted assembly
/// dumped from memory (or an encrypted one on disk) fail this, and decompiling them yields "Unknown opcode" noise.
/// Exception clauses of valid bodies are checked as well (<see cref="ClauseIssues"/>).
/// Reads the PE image directly; never throws.
/// </summary>
public static class IlHealth
{
    /// <summary>
    /// Bodies counted, the metadata tokens of the invalid ones, and per method token the problems of its invalid
    /// exception clauses (one per clause).
    /// </summary>
    public sealed record Result(int Bodies, IReadOnlySet<int> InvalidTokens)
    {
        public static readonly Result None = new(0, new HashSet<int>());
        public int Invalid => InvalidTokens.Count;

        public IReadOnlyDictionary<int, IReadOnlyList<string>> InvalidClauses { get; init; } = new Dictionary<int, IReadOnlyList<string>>();

        /// <summary>Invalid exception clauses over all bodies.</summary>
        public int InvalidClauseCount => InvalidClauses.Values.Sum(c => c.Count);

        /// <summary>Whether the method's body (as loaded from the file) is not valid IL.</summary>
        public bool IsInvalid(dnlib.DotNet.MethodDef method) => InvalidTokens.Count > 0 && InvalidTokens.Contains(method.MDToken.ToInt32());

        /// <summary>The problems of the method's invalid exception clauses (as loaded from the file); empty when there are none.</summary>
        public IReadOnlyList<string> ClauseIssues(dnlib.DotNet.MethodDef method) =>
            InvalidClauses.Count > 0 && InvalidClauses.TryGetValue(method.MDToken.ToInt32(), out var issues) ? issues : [];

        /// <summary>Most bodies invalid (at least 5 and 30%): the IL is encrypted or the image is not usable as is.</summary>
        public bool MostlyInvalid => Invalid >= 5 && Invalid >= Bodies * 0.3;

        public string Describe() =>
            $"{Invalid} of {Bodies} method bodies are not valid IL (encrypted, or a memory dump of an image whose IL is decrypted at run time): " +
            "decompiled code and body comparisons for them are meaningless.";
    }

    /// <summary>An exception clause as stored: Flags 0 catch, 1 filter, 2 finally, 4 fault; offsets and lengths in IL bytes.</summary>
    public readonly record struct Clause(int Flags, int TryOffset, int TryLength, int HandlerOffset, int HandlerLength, int FilterOffset, bool HasCatchType);

    public static Result Assess(byte[] image, CancellationToken ct = default)
    {
        try
        {
            using var pe = new PEReader(new MemoryStream(image, writable: false));
            if (!pe.HasMetadata) return Result.None;
            var md = pe.GetMetadataReader();
            int bodies = 0;
            var invalid = new HashSet<int>();
            var clauses = new Dictionary<int, IReadOnlyList<string>>();
            foreach (var handle in md.MethodDefinitions)
            {
                ct.ThrowIfCancellationRequested();
                var def = md.GetMethodDefinition(handle);
                int rva = def.RelativeVirtualAddress;
                if (rva == 0) continue;
                // native (C++/CLI) and runtime-implemented methods: the RVA points at machine code, not IL
                if ((def.ImplAttributes & System.Reflection.MethodImplAttributes.CodeTypeMask) != System.Reflection.MethodImplAttributes.IL) continue;
                bodies++;
                MethodBodyBlock body;
                try { body = pe.GetMethodBody(rva); }
                catch (Exception)
                {
                    invalid.Add(MetadataTokens.GetToken(handle)); // unreadable body header or exception sections
                    continue;
                }
                var il = body.GetILContent().AsSpan();
                if (!IsValid(il))
                {
                    invalid.Add(MetadataTokens.GetToken(handle));
                    continue;
                }
                if (body.ExceptionRegions.Length == 0) continue;
                var issues = ClauseIssues(il, body.ExceptionRegions.Select(Of).ToList());
                if (issues.Count > 0) clauses[MetadataTokens.GetToken(handle)] = issues;
            }
            return new Result(bodies, invalid) { InvalidClauses = clauses };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Result.None;
        }
    }

    private static Clause Of(ExceptionRegion r) =>
        new((int)r.Kind, r.TryOffset, r.TryLength, r.HandlerOffset, r.HandlerLength, r.FilterOffset, !r.CatchType.IsNil);

    /// <summary>Whether the body at <paramref name="rva"/> decodes completely and ends with a flow-ending instruction.</summary>
    public static bool IsValid(PEReader pe, int rva)
    {
        try { return IsValid(pe.GetMethodBody(rva).GetILContent().AsSpan()); }
        catch (Exception) { return false; } // unreadable body header
    }

    /// <summary>Whether the code bytes decode completely and end with a flow-ending instruction.</summary>
    public static bool IsValid(ReadOnlySpan<byte> il) => Decode(il, null);

    /// <summary>
    /// One problem per invalid clause of a valid IL body (ECMA-335 II.25.4.6, II.19): flags other than catch, filter,
    /// finally or fault; a try or handler range outside the code; a range start or end that is not an instruction
    /// boundary (a prefix and the instruction it modifies are one instruction); a filter that does not start on an
    /// instruction before its handler; a catch clause without a type.
    /// </summary>
    public static List<string> ClauseIssues(ReadOnlySpan<byte> il, IReadOnlyList<Clause> clauses)
    {
        var boundaries = new HashSet<int>();
        var issues = new List<string>();
        if (!Decode(il, boundaries)) return issues;
        int size = il.Length;
        boundaries.Add(size);
        for (int i = 0; i < clauses.Count; i++)
        {
            var c = clauses[i];
            string kind = c.Flags switch { 0 => "catch", 1 => "filter", 2 => "finally", 4 => "fault", _ => $"flags 0x{c.Flags:X}" };
            var problem = c.Flags is not (0 or 1 or 2 or 4) ? "flags are not catch (0), filter (1), finally (2) or fault (4)"
                : Range("try", c.TryOffset, c.TryLength) ?? Range("handler", c.HandlerOffset, c.HandlerLength)
                ?? (c.Flags == 1 && (!boundaries.Contains(c.FilterOffset) || c.FilterOffset >= c.HandlerOffset)
                    ? $"filter at IL_{c.FilterOffset:X4} does not start on an instruction before its handler (IL_{c.HandlerOffset:X4})" : null)
                ?? (c.Flags == 0 && !c.HasCatchType ? "catch clause without a catch type" : null);
            if (problem != null) issues.Add($"clause {i} ({kind}): {problem}");
        }
        return issues;

        string? Range(string name, int start, int length)
        {
            if (start < 0 || length < 0 || start > size || length > size - start)
                return $"{name} range IL_{start:X4}+0x{length:X} leaves the code (0x{size:X} bytes)";
            if (!boundaries.Contains(start)) return $"{name} range starts inside an instruction (IL_{start:X4})";
            if (!boundaries.Contains(start + length)) return $"{name} range ends inside an instruction (IL_{start + length:X4})";
            return null;
        }
    }

    /// <summary>Decodes the code; collects the offsets where an instruction (with its prefixes) starts.</summary>
    private static bool Decode(ReadOnlySpan<byte> il, HashSet<int>? boundaries)
    {
        if (il.Length == 0) return false;
        OpCode? last = null;
        int pos = 0;
        while (pos < il.Length)
        {
            if (last?.OpCodeType != OpCodeType.Prefix) boundaries?.Add(pos);
            byte first = il[pos++];
            if (first == 0xFE && pos == il.Length) return false;
            var op = first == 0xFE ? OpCodes.TwoByteOpCodes[il[pos++]] : OpCodes.OneByteOpCodes[first];
            if (op.Code is Code.UNKNOWN1 or Code.UNKNOWN2) return false;
            if (op.OperandType == OperandType.InlineSwitch)
            {
                if (il.Length - pos < 4) return false;
                uint count = BitConverter.ToUInt32(il.Slice(pos, 4));
                pos += 4;
                if (count > (uint)(il.Length - pos) / 4) return false;
                pos += (int)count * 4;
            }
            else
            {
                int size = op.OperandType switch
                {
                    OperandType.InlineNone or OperandType.InlinePhi => 0,
                    OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
                    OperandType.InlineVar => 2,
                    OperandType.InlineI8 or OperandType.InlineR => 8,
                    _ => 4,
                };
                if (il.Length - pos < size) return false;
                pos += size;
            }
            last = op;
        }
        return last is { } end && (end.FlowControl is FlowControl.Return or FlowControl.Throw or FlowControl.Branch || end.Code == Code.Jmp);
    }

    /// <summary>One method's body, from an assembly's image (null: no body).</summary>
    public static bool? IsValid(byte[] image, int rva)
    {
        if (rva == 0) return null;
        try
        {
            using var pe = new PEReader(new MemoryStream(image, writable: false));
            return IsValid(pe, rva);
        }
        catch (Exception) { return false; }
    }
}
