using Iced.Intel;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Native.Diff;

/// <summary>How an instruction operand that names an address is encoded.</summary>
public enum AddressOperand : byte
{
    None,
    /// <summary>Branch or call displacement relative to the next instruction.</summary>
    Relative,
    /// <summary>RIP-relative memory displacement (x64).</summary>
    RipRelative,
    /// <summary>Absolute address in a displacement or immediate (relocated, or inside the image).</summary>
    Absolute,
}

/// <summary>
/// One decoded instruction with the bytes that change when code moves masked: branch displacements, RIP-relative
/// displacements, relocated or in-image absolute addresses in displacements and immediates. Addresses are RVAs.
/// </summary>
public sealed class MaskedInsn
{
    public uint Rva { get; init; }
    public byte[] Bytes { get; init; } = [];
    /// <summary>Bit i set: byte i varies between builds (a wildcard in a pattern).</summary>
    public ushort Wild { get; init; }
    public Mnemonic Mnemonic { get; init; }
    public FlowControl Flow { get; init; }
    /// <summary>Opcode and operand shape (operand kinds and sizes, no registers or values): stable under register and address changes.</summary>
    public int Token { get; init; }
    /// <summary>Where the address operand sits in <see cref="Bytes"/>, its size and kind (the first one when several).</summary>
    public byte OperandOffset { get; init; }
    public byte OperandSize { get; init; }
    public AddressOperand OperandKind { get; init; }
    /// <summary>The address the operand names (branch target, memory or immediate address), when inside the image.</summary>
    public uint? Target { get; init; }
    /// <summary>Immediate that is not an address (non-trivial values only: see <see cref="MaskedDecoder"/>).</summary>
    public ulong? Constant { get; init; }

    public int Length => Bytes.Length;
    public uint End => Rva + (uint)Bytes.Length;
    public bool IsWild(int i) => (Wild >> i & 1) != 0;
}

/// <summary>Decodes x86 / x64 code of an image into <see cref="MaskedInsn"/>. Not thread-safe; one per thread.</summary>
public sealed class MaskedDecoder
{
    private readonly INativeImage _image;
    private readonly uint[] _relocs;
    private readonly int _bitness;
    private readonly ulong _base;
    private readonly ulong _limit;
    private byte[] _buffer = new byte[4096];

    public MaskedDecoder(INativeImage image)
    {
        if (image.Arch is not (NativeArch.X86 or NativeArch.X64))
            throw new NotSupportedException(InstructionSets.For(image.Arch).Reason);
        _image = image;
        _relocs = image.RelocationRvas as uint[] ?? image.RelocationRvas.ToArray();
        if (!IsSorted(_relocs)) { _relocs = (uint[])_relocs.Clone(); Array.Sort(_relocs); }
        _bitness = image.Arch == NativeArch.X64 ? 64 : 32;
        _base = image.ImageBase;
        _limit = image.ImageBase + image.SizeOfImage;
    }

    private static bool IsSorted(uint[] a)
    {
        for (int i = 1; i < a.Length; i++) if (a[i] < a[i - 1]) return false;
        return true;
    }

    public INativeImage Image => _image;

    /// <summary>
    /// Linear decode of [<paramref name="start"/>, <paramref name="end"/>), at most <paramref name="max"/> instructions;
    /// stops at bytes that do not decode or are not mapped.
    /// </summary>
    public int Decode(uint start, uint end, List<MaskedInsn> output, int max = int.MaxValue)
    {
        if (end <= start) return 0;
        long want = Math.Min((long)end - start, 1L << 24);
        if (_buffer.Length < want) _buffer = new byte[Math.Max(want, _buffer.Length * 2L)];
        int read = _image.Read(start, _buffer.AsSpan(0, (int)want));
        if (read <= 0) return 0;
        var reader = new ByteArrayCodeReader(_buffer, 0, read);
        var decoder = Decoder.Create(_bitness, reader, _base + start, DecoderOptions.None);
        int count = 0;
        while (count < max && reader.CanReadByte)
        {
            uint rva = start + (uint)reader.Position;
            decoder.Decode(out var instr);
            if (instr.IsInvalid || instr.Length == 0) break;
            output.Add(Build(in instr, decoder.GetConstantOffsets(in instr), rva, _buffer.AsSpan((int)(rva - start), instr.Length)));
            count++;
        }
        return count;
    }

    /// <summary>The instruction at <paramref name="rva"/>, or null when it does not decode.</summary>
    public MaskedInsn? DecodeOne(uint rva)
    {
        var list = new List<MaskedInsn>(1);
        return Decode(rva, rva + 15, list, 1) == 1 ? list[0] : null;
    }

    private bool InImage(ulong va) => va >= _base && va < _limit;
    private bool Relocated(uint rva) => Array.BinarySearch(_relocs, rva) >= 0;

    private MaskedInsn Build(in Instruction instr, ConstantOffsets co, uint rva, ReadOnlySpan<byte> bytes)
    {
        ushort wild = 0;
        byte opOffset = 0, opSize = 0;
        var opKind = AddressOperand.None;
        uint? target = null;
        ulong? constant = null;

        void Mark(int offset, int size, AddressOperand kind, ulong va)
        {
            for (int i = 0; i < size && offset + i < 16; i++) wild |= (ushort)(1 << (offset + i));
            if (opKind != AddressOperand.None) return;
            opOffset = (byte)offset;
            opSize = (byte)size;
            opKind = kind;
            if (InImage(va)) target = (uint)(va - _base);
        }

        bool branch = false;
        for (int i = 0; i < instr.OpCount; i++)
        {
            switch (instr.GetOpKind(i))
            {
                case OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64:
                    branch = true;
                    if (co.HasImmediate) Mark(co.ImmediateOffset, co.ImmediateSize, AddressOperand.Relative, instr.NearBranchTarget);
                    break;
                case OpKind.FarBranch16 or OpKind.FarBranch32:
                    branch = true;
                    if (co.HasImmediate) Mark(co.ImmediateOffset, co.ImmediateSize, AddressOperand.Absolute, 0);
                    if (co.HasImmediate2) Mark(co.ImmediateOffset2, co.ImmediateSize2, AddressOperand.Absolute, 0);
                    break;
            }
        }

        if (instr.IsIPRelativeMemoryOperand)
        {
            if (co.HasDisplacement) Mark(co.DisplacementOffset, co.DisplacementSize, AddressOperand.RipRelative, instr.IPRelativeMemoryAddress);
        }
        else if (co.HasDisplacement && co.DisplacementSize >= 4)
        {
            ulong disp = _bitness == 64 ? instr.MemoryDisplacement64 : instr.MemoryDisplacement32;
            if (Relocated(rva + co.DisplacementOffset) || InImage(disp)) Mark(co.DisplacementOffset, co.DisplacementSize, AddressOperand.Absolute, disp);
        }

        if (!branch && co.HasImmediate)
        {
            ulong imm = Immediate(in instr);
            if (co.ImmediateSize >= 4 && (Relocated(rva + co.ImmediateOffset) || InImage(imm)))
                Mark(co.ImmediateOffset, co.ImmediateSize, AddressOperand.Absolute, imm);
            else if (IsInteresting(in instr, imm)) constant = imm;
        }

        return new MaskedInsn
        {
            Rva = rva,
            Bytes = bytes.ToArray(),
            Wild = wild,
            Mnemonic = instr.Mnemonic,
            Flow = instr.FlowControl,
            Token = Token(in instr),
            OperandOffset = opOffset,
            OperandSize = opSize,
            OperandKind = opKind,
            Target = target,
            Constant = constant,
        };
    }

    private static ulong Immediate(in Instruction instr)
    {
        for (int i = 0; i < instr.OpCount; i++)
            if (instr.GetOpKind(i) is OpKind.Immediate8 or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate64 or OpKind.Immediate8to16
                or OpKind.Immediate8to32 or OpKind.Immediate8to64 or OpKind.Immediate32to64)
                return instr.GetImmediate(i);
        return 0;
    }

    /// <summary>Constants worth matching on: magic numbers, not small counts, masks of all ones, or stack frame sizes.</summary>
    private static bool IsInteresting(in Instruction instr, ulong imm)
    {
        if (instr.Op0Kind == OpKind.Register && instr.Op0Register is Register.RSP or Register.ESP) return false;
        long signed = (long)imm;
        if (signed is > -0x100 and < 0x100) return false;
        if (imm is 0xFFFFFFFF or 0xFFFF or 0xFFFFFFFF_FFFFFFFF or 0x7FFFFFFF or 0x80000000) return false;
        return true;
    }

    /// <summary>Mnemonic and operand shapes: kind, register class and size, memory size.</summary>
    private static int Token(in Instruction instr)
    {
        uint h = 2166136261;
        void Mix(int v) { h = (h ^ (uint)v) * 16777619; }
        Mix((int)instr.Mnemonic);
        Mix(instr.OpCount);
        for (int i = 0; i < instr.OpCount; i++)
        {
            var kind = instr.GetOpKind(i);
            switch (kind)
            {
                case OpKind.Register:
                    var reg = instr.GetOpRegister(i);
                    Mix(1000 + reg.GetSize() * 4 + (reg.IsGPR() ? 0 : reg.IsVectorRegister() ? 1 : 2));
                    break;
                case OpKind.Memory:
                    Mix(2000 + (int)instr.MemorySize);
                    break;
                case OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64:
                    Mix(3000);
                    break;
                default:
                    Mix(4000 + (int)kind);
                    break;
            }
        }
        return (int)h;
    }
}

/// <summary>Instruction listings of functions in address order (each byte decoded once).</summary>
public static class FunctionCode
{
    public const int MaxInstructions = 200_000;

    /// <summary>The instructions of <paramref name="f"/>'s blocks in address order; overlapping code is listed once.</summary>
    public static List<MaskedInsn> Instructions(NativeCodeIndex index, MaskedDecoder decoder, NativeFunction f, CancellationToken ct, out FunctionGraph graph)
    {
        graph = index.GetGraph(f, ct);
        var result = new List<MaskedInsn>(Math.Max(4, f.InstructionCount));
        uint covered = 0;
        foreach (var b in graph.Blocks)
        {
            if (b.End <= covered) continue;
            uint from = Math.Max(b.Start, covered);
            decoder.Decode(from, b.End, result, MaxInstructions - result.Count);
            covered = b.End;
            if (result.Count >= MaxInstructions) break;
        }
        return result;
    }

    /// <summary>Index of the instruction containing <paramref name="rva"/>, or -1.</summary>
    public static int IndexOf(List<MaskedInsn> code, uint rva)
    {
        int lo = 0, hi = code.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (rva < code[mid].Rva) hi = mid - 1;
            else if (rva >= code[mid].End) lo = mid + 1;
            else return mid;
        }
        return -1;
    }
}
