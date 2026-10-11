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
/// displacements, relocated or in-image absolute addresses in displacements and immediates; on ARM64 branch and literal
/// offsets, ADRP / ADR pages and the low 12 bits ADD / LDR / STR add to a page. Addresses are RVAs.
/// </summary>
public sealed class MaskedInsn
{
    public uint Rva { get; init; }
    public byte[] Bytes { get; init; } = [];
    /// <summary>Bit i set: byte i varies between builds (a wildcard in a pattern).</summary>
    public ushort Wild { get; init; }
    /// <summary>The instruction's mnemonic (Iced on x86, AsmArm64 plus <see cref="MaskedDecoder.Arm64Mnemonics"/> on ARM64).</summary>
    public int Mnemonic { get; init; }
    public FlowKind Flow { get; init; }
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

/// <summary>Decodes x86 / x64 and ARM64 code of an image into <see cref="MaskedInsn"/>. Not thread-safe; one per thread.</summary>
public sealed class MaskedDecoder
{
    /// <summary>ARM64 mnemonics are numbered from here, apart from x86 ones.</summary>
    public const int Arm64Mnemonics = 0x10000;

    private readonly INativeImage _image;
    private readonly uint[] _relocs;
    private readonly int _bitness;
    private readonly ulong _base;
    private readonly ulong _limit;
    private byte[] _buffer = new byte[4096];
    private readonly Arm64Decoder? _arm;
    private readonly Arm32Decoder? _arm32;
    // ARM: the address after the last decoded instruction; decoding on from there keeps address-forming pairs
    private uint _armNext = uint.MaxValue;

    /// <summary>ARM32 mnemonics are numbered from here.</summary>
    public const int Arm32Mnemonics = 0x20000;

    /// <param name="index">32-bit ARM: the code index whose function states decide ARM or Thumb (else read from the image).</param>
    public MaskedDecoder(INativeImage image, NativeCodeIndex? index = null)
    {
        if (image.Arch is not (NativeArch.X86 or NativeArch.X64 or NativeArch.Arm64 or NativeArch.Arm))
            throw new NotSupportedException(InstructionSets.For(image.Arch).Reason);
        _image = image;
        _relocs = image.RelocationRvas as uint[] ?? image.RelocationRvas.ToArray();
        if (!IsSorted(_relocs)) { _relocs = (uint[])_relocs.Clone(); Array.Sort(_relocs); }
        if (image.Arch == NativeArch.Arm64) _arm = new Arm64Decoder(image, null, _relocs);
        if (image.Arch == NativeArch.Arm) _arm32 = new Arm32Decoder(image, null, _relocs, index?.ArmModes ?? new Arm32Modes(image));
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
        if (_arm != null) return DecodeArm64(start, end, output, max);
        if (_arm32 != null) return DecodeArm32(start, end, output, max);
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
        return Decode(rva, rva + (_arm != null || _arm32 != null ? 4u : 15u), list, 1) == 1 ? list[0] : null;
    }

    private int DecodeArm32(uint start, uint end, List<MaskedInsn> output, int max)
    {
        var arm = _arm32!;
        if (start != _armNext)
        {
            arm.BeginRun(IndexBound.None);
            arm.Pin(arm.Modes.At(start));
        }
        int count = 0;
        var bytes = new byte[4];
        for (uint rva = start; rva < end && count < max;)
        {
            if (!arm.DecodeMapped(rva, out var insn) || insn.Flow == FlowKind.Invalid || rva + (uint)insn.Length > end
                || _image.Read(rva, bytes.AsSpan(0, insn.Length)) < insn.Length) { _armNext = uint.MaxValue; break; }
            output.Add(BuildArm32(arm.Last, in insn, bytes.AsSpan(0, insn.Length)));
            count++;
            rva += (uint)insn.Length;
            _armNext = rva;
        }
        return count;
    }

    /// <summary>Masks the bytes of an A32 / T32 instruction whose fields hold a branch, literal or ADR offset, or a relocated MOVW / MOVT address.</summary>
    private static MaskedInsn BuildArm32(in ArmInstruction i, in Insn insn, ReadOnlySpan<byte> bytes)
    {
        ushort wild = 0;
        void Bytes(params int[] which) { foreach (int b in which) wild |= (ushort)(1 << b); }
        bool pcRelative = false;
        for (int k = 0; k < i.OperandCount; k++)
            if (i.Operands[k].Kind == ArmOperandKind.Label || i.Operands[k].Kind == ArmOperandKind.Memory && i.Operands[k].Reg == 15) pcRelative = true;
        bool address = pcRelative || i.Mnemonic is "movw" or "movt" && insn.HasImm;
        if (address)
        {
            if (!i.Thumb) Bytes(0, 1, 2);
            else if (i.Length == 2) Bytes(0, 1);
            else Bytes(0, 1, 2, 3);
            // keep the opcode byte of a 16-bit conditional branch and of a literal load
            if (i.Thumb && i.Length == 2 && (i.Mnemonic == "b" && i.IsConditional || i.Mnemonic == "ldr")) wild &= 1;
        }
        long? constant = null;
        if (!address)
            for (int k = 0; k < i.OperandCount; k++)
                if (i.Operands[k].Kind == ArmOperandKind.Immediate && i.Operands[k].Value is var v and (>= 0x100 or <= -0x100)) { constant = v; break; }
        return new MaskedInsn
        {
            Rva = insn.Rva,
            Bytes = bytes.ToArray(),
            Wild = wild,
            Mnemonic = Arm32Mnemonics + (int)(Hash(i.Mnemonic) & 0xFFFF),
            Flow = insn.Flow,
            Token = Arm32Token(in i),
            OperandOffset = 0,
            OperandSize = 0,
            OperandKind = AddressOperand.None,
            Target = insn.HasTarget ? insn.Target : insn.HasMem ? insn.MemTarget : insn.HasImm ? insn.ImmTarget : null,
            Constant = constant is { } c ? (ulong)c : null,
        };
    }

    private static uint Hash(string s)
    {
        uint h = 2166136261;
        foreach (char ch in s) h = (h ^ ch) * 16777619;
        return h;
    }

    /// <summary>Mnemonic, encoding width, condition and operand shapes (no register numbers or values).</summary>
    private static int Arm32Token(in ArmInstruction i)
    {
        uint h = Hash(i.Mnemonic);
        void Mix(int v) { h = (h ^ (uint)v) * 16777619; }
        Mix(i.Length + (i.Thumb ? 10 : 0));
        Mix(i.Cond);
        for (int k = 0; k < i.OperandCount; k++) Mix((int)i.Operands[k].Kind * 10 + (int)i.Operands[k].Vector);
        return (int)h;
    }

    private int DecodeArm64(uint start, uint end, List<MaskedInsn> output, int max)
    {
        var arm = _arm!;
        if (start != _armNext) arm.BeginRun(IndexBound.None);
        int count = 0;
        var bytes = new byte[4];
        for (uint rva = start; rva + 4 <= end && count < max; rva += 4)
        {
            if (!arm.DecodeMapped(rva, out var insn) || insn.Flow == FlowKind.Invalid || _image.Read(rva, bytes) < 4) { _armNext = uint.MaxValue; break; }
            output.Add(BuildArm64(arm.Last, in insn, bytes));
            count++;
            _armNext = rva + 4;
        }
        return count;
    }

    /// <summary>Masks the fields of an ARM64 instruction that hold addresses, byte by byte (a field touching a byte makes it wild).</summary>
    private static MaskedInsn BuildArm64(AsmArm64.Arm64Instruction i, in Insn insn, byte[] bytes)
    {
        ushort wild = 0;
        uint? target = null;
        var kind = AddressOperand.None;
        void Bits(int low, int high) { for (int b = low / 8; b <= high / 8; b++) wild |= (ushort)(1 << b); }
        bool label = (i.Flags & AsmArm64.Arm64InstructionFlags.HasLabel) != 0;
        if (label)
        {
            switch (i.Id)
            {
                case AsmArm64.Arm64InstructionId.B_only_branch_imm or AsmArm64.Arm64InstructionId.BL_only_branch_imm: Bits(0, 25); break;
                case AsmArm64.Arm64InstructionId.ADRP_only_pcreladdr or AsmArm64.Arm64InstructionId.ADR_only_pcreladdr: Bits(5, 30); break;
                default: Bits(5, 23); break; // imm19 of b.cond, cbz / cbnz, literal loads; imm14 of tbz / tbnz
            }
            kind = AddressOperand.Relative;
            target = insn.HasTarget ? insn.Target : insn.HasMem ? insn.MemTarget : insn.HasImm ? insn.ImmTarget : null;
        }
        else if (insn.HasImm || insn.HasMem)
        {
            // the low 12 bits added to an ADRP page (add #imm12; ldr / str / ldp offsets): bits 10-21 at most
            Bits(10, 21);
            kind = AddressOperand.RipRelative;
            target = insn.HasImm ? insn.ImmTarget : insn.MemTarget;
        }
        ulong? constant = null;
        if (!label && kind == AddressOperand.None)
            for (int k = 0; k < i.OperandCount; k++)
                if (i.GetOperand(k).Kind == AsmArm64.Arm64OperandKind.Immediate && ((AsmArm64.Arm64ImmediateOperand)i.GetOperand(k)).Value is var v and (>= 0x100 or <= -0x100))
                {
                    constant = (ulong)v;
                    break;
                }
        return new MaskedInsn
        {
            Rva = insn.Rva,
            Bytes = (byte[])bytes.Clone(),
            Wild = wild,
            Mnemonic = Arm64Mnemonics + (int)i.Mnemonic,
            Flow = insn.Flow,
            Token = Arm64Token(i),
            // ARM64 address fields are not whole bytes: no operand position to read the address back from
            OperandOffset = 0,
            OperandSize = 0,
            OperandKind = AddressOperand.None,
            Target = target,
            Constant = constant,
        };
    }

    /// <summary>Instruction form and operand shapes (register classes, no register numbers or values).</summary>
    private static int Arm64Token(AsmArm64.Arm64Instruction i)
    {
        uint h = 2166136261;
        void Mix(int v) { h = (h ^ (uint)v) * 16777619; }
        Mix((int)i.Id);
        for (int k = 0; k < i.OperandCount; k++)
        {
            var op = i.GetOperand(k);
            Mix((int)op.Kind * 100 + (op.Kind == AsmArm64.Arm64OperandKind.Register ? (int)((AsmArm64.Arm64RegisterOperand)op).Value.Kind : 0));
        }
        return (int)h;
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
            Mnemonic = (int)instr.Mnemonic,
            Flow = instr.FlowControl switch
            {
                FlowControl.Return => FlowKind.Return,
                FlowControl.Call => FlowKind.Call,
                FlowControl.IndirectCall => FlowKind.IndirectCall,
                FlowControl.UnconditionalBranch => FlowKind.Jump,
                FlowControl.IndirectBranch => FlowKind.IndirectJump,
                FlowControl.ConditionalBranch => FlowKind.ConditionalJump,
                FlowControl.Exception or FlowControl.Interrupt => FlowKind.Trap,
                _ => FlowKind.Next,
            },
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
