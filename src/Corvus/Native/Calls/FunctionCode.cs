using Iced.Intel;
using Corvus.Native.Code;

namespace Corvus.Native.Calls;

/// <summary>One decoded instruction with the facts the value resolver needs.</summary>
internal struct Decoded
{
    public Instruction I;
    public uint Rva;
    /// <summary>Confirmed data address of the memory operand (RIP-relative, or absolute and relocated), else 0 with <see cref="HasMem"/> false.</summary>
    public uint MemRva;
    public bool HasMem;
    /// <summary>Confirmed address in an immediate operand.</summary>
    public uint ImmRva;
    public bool HasImm;
    /// <summary>Full registers this instruction writes (bit per register, <see cref="FunctionCode.Bit"/>); calls excluded.</summary>
    public ulong Writes;
}

/// <summary>
/// The decoded basic blocks of one function (Iced instructions plus confirmed addresses and written registers), the
/// unit the call-argument resolver walks backward over.
/// </summary>
internal sealed class FunctionCode
{
    public required NativeFunction Function { get; init; }
    public required FunctionGraph Graph { get; init; }
    public required Decoded[][] Blocks { get; init; }
    private Dictionary<uint, int>? _blockIndex;
    private Dictionary<uint, (int Block, int Index)>? _positions;

    private HashSet<int>? _stackTaken, _frameTaken;
    private bool? _framePointer;

    /// <summary>The prologue sets ebp / rbp from the stack pointer (mov ebp, esp / lea rbp, [rsp+n]): [rbp+n] are locals.</summary>
    public bool HasFramePointer => _framePointer ??= FindFramePointer();

    private bool FindFramePointer()
    {
        int entry = BlockIndexOf(Function.Start);
        if (entry < 0) return false;
        var insns = Blocks[entry];
        for (int i = 0; i < Math.Min(insns.Length, 12); i++)
        {
            ref readonly var x = ref insns[i].I;
            if (x.Op0Kind != OpKind.Register || x.Op0Register.GetFullRegister() != Register.RBP || x.Mnemonic == Mnemonic.Push) continue;
            return x.Mnemonic == Mnemonic.Mov && x.Op1Kind == OpKind.Register && x.Op1Register.GetFullRegister() == Register.RSP
                   || x.Mnemonic == Mnemonic.Lea && x.MemoryBase.GetFullRegister() == Register.RSP && x.MemoryIndex == Register.None;
        }
        return false;
    }

    /// <summary>Code takes the address of [rsp + <paramref name="offset"/>] (lea) somewhere in the function.</summary>
    public bool StackAddressTaken(int offset) => (_stackTaken ??= Taken(Register.RSP)).Contains(offset);

    /// <summary>Code takes the address of [rbp + <paramref name="offset"/>] (lea) somewhere in the function.</summary>
    public bool FrameAddressTaken(int offset) => (_frameTaken ??= Taken(Register.RBP)).Contains(offset);

    private HashSet<int> Taken(Register full)
    {
        var set = new HashSet<int>();
        foreach (var block in Blocks)
            foreach (var d in block)
                if (d.I.Mnemonic == Mnemonic.Lea && d.I.MemoryBase.GetFullRegister() == full && d.I.MemoryIndex == Register.None)
                    set.Add((int)(long)d.I.MemoryDisplacement64);
        return set;
    }

    public int BlockIndexOf(uint start)
    {
        _blockIndex ??= BuildBlockIndex();
        return _blockIndex.TryGetValue(start, out int i) ? i : -1;
    }

    private Dictionary<uint, int> BuildBlockIndex()
    {
        var d = new Dictionary<uint, int>(Graph.Blocks.Count);
        for (int i = 0; i < Graph.Blocks.Count; i++) d.TryAdd(Graph.Blocks[i].Start, i);
        return d;
    }

    /// <summary>Block and index of the instruction at <paramref name="rva"/>, or (-1, -1).</summary>
    public (int Block, int Index) Position(uint rva)
    {
        if (_positions == null)
        {
            var p = new Dictionary<uint, (int, int)>();
            for (int b = 0; b < Blocks.Length; b++)
                for (int i = 0; i < Blocks[b].Length; i++) p.TryAdd(Blocks[b][i].Rva, (b, i));
            _positions = p;
        }
        return _positions.TryGetValue(rva, out var pos) ? pos : (-1, -1);
    }

    /// <summary>Bit of a full register: RAX..R15 = 0..15, ZMM0..ZMM31 = 16..47; -1 otherwise.</summary>
    public static int Bit(Register full)
    {
        if (full >= Register.RAX && full <= Register.R15) return full - Register.RAX;
        if (full >= Register.ZMM0 && full <= Register.ZMM31) return 16 + (full - Register.ZMM0);
        return -1;
    }

    /// <summary>Decodes the blocks of <paramref name="graph"/>; at most <paramref name="maxInstructions"/> in total.</summary>
    public static FunctionCode Decode(NativeCodeIndex index, FunctionGraph graph, uint[] relocations, int maxInstructions, CancellationToken ct)
    {
        var image = index.Image;
        bool is64 = image.Arch == NativeArch.X64;
        var info = new InstructionInfoFactory();
        var blocks = new Decoded[graph.Blocks.Count][];
        int total = 0;
        for (int b = 0; b < graph.Blocks.Count; b++)
        {
            ct.ThrowIfCancellationRequested();
            var block = graph.Blocks[b];
            uint length = block.End > block.Start ? Math.Min(block.End - block.Start, 1u << 20) : 0;
            var bytes = new byte[length];
            int read = image.Read(block.Start, bytes);
            var decoder = Iced.Intel.Decoder.Create(is64 ? 64 : 32, new ByteArrayCodeReader(bytes, 0, read), image.ImageBase + block.Start, DecoderOptions.None);
            var list = new List<Decoded>(Math.Max(1, block.InstructionCount));
            while (decoder.IP < image.ImageBase + block.Start + (ulong)read && total < maxInstructions)
            {
                uint rva = (uint)(decoder.IP - image.ImageBase);
                decoder.Decode(out var insn);
                if (insn.IsInvalid) break;
                var d = new Decoded { I = insn, Rva = rva };
                Facts(image, is64, relocations, decoder, ref d);
                if (insn.FlowControl is not (FlowControl.Call or FlowControl.IndirectCall))
                {
                    var used = info.GetInfo(in insn);
                    foreach (var r in used.GetUsedRegisters())
                    {
                        if (r.Access is not (OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite)) continue;
                        int bit = Bit(r.Register.GetFullRegister());
                        if (bit >= 0) d.Writes |= 1UL << bit;
                    }
                }
                list.Add(d);
                total++;
            }
            blocks[b] = list.ToArray();
        }
        return new FunctionCode { Function = graph.Function, Graph = graph, Blocks = blocks };
    }

    private static void Facts(INativeImage image, bool is64, uint[] relocations, Iced.Intel.Decoder decoder, ref Decoded d)
    {
        ref readonly var i = ref d.I;
        bool hasMemory = false, hasImmediate = false;
        for (int k = 0; k < i.OpCount; k++)
        {
            var kind = i.GetOpKind(k);
            if (kind == OpKind.Memory) hasMemory = true;
            else if (kind is OpKind.Immediate32 or OpKind.Immediate64) hasImmediate = true;
        }
        if (hasMemory)
        {
            if (i.IsIPRelativeMemoryOperand)
            {
                if (TryRva(image, is64, i.IPRelativeMemoryAddress, out uint t)) { d.MemRva = t; d.HasMem = true; }
            }
            else if (i.MemoryBase == Register.None && i.MemoryIndex == Register.None && i.MemoryDisplSize >= 4
                     && TryRva(image, is64, i.MemoryDisplacement64, out uint t))
            {
                if (relocations.Length > 0)
                {
                    var o = decoder.GetConstantOffsets(in i);
                    if (o.HasDisplacement && Array.BinarySearch(relocations, d.Rva + o.DisplacementOffset) >= 0) { d.MemRva = t; d.HasMem = true; }
                }
                else if (!is64 && image.SectionAt(t) != null) { d.MemRva = t; d.HasMem = true; }
            }
        }
        if (hasImmediate)
        {
            for (int k = 0; k < i.OpCount; k++)
            {
                var kind = i.GetOpKind(k);
                if (kind is not (OpKind.Immediate32 or OpKind.Immediate64) || (kind == OpKind.Immediate32 && is64)) continue;
                if (!TryRva(image, is64, i.GetImmediate(k), out uint t)) break;
                if (relocations.Length > 0)
                {
                    var o = decoder.GetConstantOffsets(in i);
                    if (o.HasImmediate && Array.BinarySearch(relocations, d.Rva + o.ImmediateOffset) >= 0) { d.ImmRva = t; d.HasImm = true; }
                }
                else if (!is64 && i.Mnemonic is Mnemonic.Push or Mnemonic.Mov && image.SectionAt(t) != null) { d.ImmRva = t; d.HasImm = true; }
                break;
            }
        }
    }

    public static bool TryRva(INativeImage image, bool is64, ulong va, out uint rva)
    {
        rva = 0;
        if (!is64) va &= 0xFFFFFFFF;
        if (va < image.ImageBase || va - image.ImageBase >= image.SizeOfImage) return false;
        rva = (uint)(va - image.ImageBase);
        return true;
    }
}
