using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using dnlib.DotNet.Emit;
using OperandType = dnlib.DotNet.Emit.OperandType;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Whether method bodies hold valid IL. A body is invalid when it contains an unknown opcode, an operand runs past the
/// end of the code, or the code does not end in a return / throw / branch. Bodies of a runtime-decrypted assembly
/// dumped from memory (or an encrypted one on disk) fail this, and decompiling them yields "Unknown opcode" noise.
/// Reads the PE image directly; never throws.
/// </summary>
public static class IlHealth
{
    /// <summary>Bodies counted, and the metadata tokens of the invalid ones.</summary>
    public sealed record Result(int Bodies, IReadOnlySet<int> InvalidTokens)
    {
        public static readonly Result None = new(0, new HashSet<int>());
        public int Invalid => InvalidTokens.Count;

        /// <summary>Whether the method's body (as loaded from the file) is not valid IL.</summary>
        public bool IsInvalid(dnlib.DotNet.MethodDef method) => InvalidTokens.Count > 0 && InvalidTokens.Contains(method.MDToken.ToInt32());

        /// <summary>Most bodies invalid (at least 5 and 30%): the IL is encrypted or the image is not usable as is.</summary>
        public bool MostlyInvalid => Invalid >= 5 && Invalid >= Bodies * 0.3;

        public string Describe() =>
            $"{Invalid} of {Bodies} method bodies are not valid IL (encrypted, or a memory dump of an image whose IL is decrypted at run time): " +
            "decompiled code and body comparisons for them are meaningless.";
    }

    public static Result Assess(byte[] image, CancellationToken ct = default)
    {
        try
        {
            using var pe = new PEReader(new MemoryStream(image, writable: false));
            if (!pe.HasMetadata) return Result.None;
            var md = pe.GetMetadataReader();
            int bodies = 0;
            var invalid = new HashSet<int>();
            foreach (var handle in md.MethodDefinitions)
            {
                ct.ThrowIfCancellationRequested();
                int rva = md.GetMethodDefinition(handle).RelativeVirtualAddress;
                if (rva == 0) continue;
                bodies++;
                if (!IsValid(pe, rva)) invalid.Add(MetadataTokens.GetToken(handle));
            }
            return new Result(bodies, invalid);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Result.None;
        }
    }

    /// <summary>Whether the body at <paramref name="rva"/> decodes completely and ends with a flow-ending instruction.</summary>
    public static bool IsValid(PEReader pe, int rva)
    {
        try { return IsValid(pe.GetMethodBody(rva).GetILContent().AsSpan()); }
        catch (Exception) { return false; } // unreadable body header
    }

    /// <summary>Whether the code bytes decode completely and end with a flow-ending instruction.</summary>
    public static bool IsValid(ReadOnlySpan<byte> il)
    {
        if (il.Length == 0) return false;
        OpCode? last = null;
        int pos = 0;
        while (pos < il.Length)
        {
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
