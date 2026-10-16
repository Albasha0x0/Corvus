namespace Corvus.Core.WebAssembly;

/// <summary>
/// One decoded instruction: its file offset and length, the opcode (prefixed ones as prefix &lt;&lt; 16 | sub) and its
/// immediates. <see cref="A"/> and <see cref="B"/> hold indexes (function, type and table, local, label, data and memory...);
/// <see cref="Value"/> a constant's bits; variable-length immediates (br_table, typed select, v128, shuffle, try_table)
/// are read again from <see cref="ImmStart"/>.
/// </summary>
internal struct WasmInstr
{
    public int Offset, Length;
    public int Op;
    public uint A, B;
    public long Value;
    /// <summary>
    /// Block type: -0x40 empty, a negative one-byte value type code (-0x01 for i32 = 0x7F...), a type index, or at or below
    /// <see cref="WasmCode.TypedBlock"/> a reference type with a heap type (<see cref="WasmBinary.BlockResult"/>). br_on_cast
    /// keeps its second heap type here, its first in <see cref="Value"/> and its flags in <see cref="Lane"/>.
    /// </summary>
    public long BlockType;
    public uint Align, Memory;
    public ulong MemOffset;
    public byte Lane;
    public int ImmStart, Count;
    public WasmOp Info;
}

/// <summary>Decodes instructions one at a time from a range of a module; a malformed instruction stops it with <see cref="Error"/>.</summary>
internal struct WasmCode(byte[] bytes, int pos, int end)
{
    /// <summary>Block types at or below this hold a reference type: TypedBlock - (int)type.</summary>
    public const long TypedBlock = -(1L << 33);

    private WasmReader _r = new(bytes, pos, end);

    public readonly int Pos => _r.Pos;
    public readonly int End => _r.End;
    public string? Error { get; private set; }

    public bool Next(out WasmInstr ins)
    {
        ins = default;
        if (Error != null || _r.Pos >= _r.End) return false;
        int start = _r.Pos;
        try
        {
            int op = _r.Byte();
            if (op is 0xFB or 0xFC or 0xFD or 0xFE) op = op << 16 | (int)_r.U32();
            var info = WasmOps.Get(op);
            if (info == null) { Error = $"unknown opcode {Describe(op)} at 0x{start:X}"; _r.Pos = start; return false; }
            ins.Op = op;
            ins.Info = info;
            ins.Offset = start;
            Immediates(ref ins);
            ins.Length = _r.Pos - start;
            return true;
        }
        catch (WasmFormatException ex)
        {
            Error = $"{ex.Message} at 0x{start:X}";
            _r.Pos = start;
            return false;
        }
    }

    public static string Describe(int op) => op > 0xFFFF ? $"0x{op >> 16:X2} {op & 0xFFFF}" : $"0x{op:X2}";

    private void Immediates(ref WasmInstr ins)
    {
        switch (ins.Info.Imm)
        {
            case WasmImm.None: break;
            case WasmImm.BlockType: ins.BlockType = ReadBlockType(); break;
            case WasmImm.Label or WasmImm.Func or WasmImm.TypeIndex or WasmImm.Local or WasmImm.Global or WasmImm.Table or WasmImm.Tag
                or WasmImm.Data or WasmImm.Elem:
                ins.A = _r.U32();
                break;
            case WasmImm.BrTable:
                {
                    uint n = _r.U32();
                    if (n > _r.End - _r.Pos) throw new WasmFormatException("br_table runs past the body");
                    ins.ImmStart = _r.Pos;
                    ins.Count = (int)n;
                    for (uint i = 0; i < n; i++) _r.U32();
                    ins.A = _r.U32(); // default
                    break;
                }
            case WasmImm.CallIndirect: ins.A = _r.U32(); ins.B = _r.U32(); break;
            case WasmImm.MemArg: MemArg(ref ins); break;
            case WasmImm.MemArgLane: MemArg(ref ins); ins.Lane = _r.Byte(); break;
            case WasmImm.Memory: ins.Memory = _r.U32(); break;
            case WasmImm.I32: ins.Value = _r.S32(); break;
            case WasmImm.I64: ins.Value = _r.S64(); break;
            case WasmImm.F32:
                if (_r.End - _r.Pos < 4) throw new WasmFormatException("unexpected end");
                ins.Value = BitConverter.ToUInt32(_r.Bytes, _r.Pos);
                _r.Pos += 4;
                break;
            case WasmImm.F64:
                if (_r.End - _r.Pos < 8) throw new WasmFormatException("unexpected end");
                ins.Value = BitConverter.ToInt64(_r.Bytes, _r.Pos);
                _r.Pos += 8;
                break;
            case WasmImm.HeapType: ins.Value = _r.S33(); break;
            case WasmImm.SelectTypes:
                {
                    uint n = _r.U32();
                    if (n > _r.End - _r.Pos) throw new WasmFormatException("select types run past the body");
                    ins.ImmStart = _r.Pos;
                    ins.Count = (int)n;
                    for (uint i = 0; i < n; i++) WasmBinary.ReadValType(ref _r);
                    break;
                }
            case WasmImm.TryTable:
                {
                    ins.BlockType = ReadBlockType();
                    uint n = _r.U32();
                    if (n > _r.End - _r.Pos) throw new WasmFormatException("try_table runs past the body");
                    ins.ImmStart = _r.Pos;
                    ins.Count = (int)n;
                    for (uint i = 0; i < n; i++)
                    {
                        byte kind = _r.Byte();
                        if (kind > 3) throw new WasmFormatException($"catch kind {kind}");
                        if (kind < 2) _r.U32();
                        _r.U32();
                    }
                    break;
                }
            case WasmImm.Lane: ins.Lane = _r.Byte(); break;
            case WasmImm.V128 or WasmImm.Shuffle:
                if (_r.End - _r.Pos < 16) throw new WasmFormatException("unexpected end");
                ins.ImmStart = _r.Pos;
                _r.Pos += 16;
                break;
            case WasmImm.DataMemory: ins.A = _r.U32(); ins.Memory = _r.U32(); break;
            case WasmImm.TwoMemories: ins.A = _r.U32(); ins.B = _r.U32(); break;
            case WasmImm.ElemTable: ins.A = _r.U32(); ins.B = _r.U32(); break;
            case WasmImm.TwoTables: ins.A = _r.U32(); ins.B = _r.U32(); break;
            case WasmImm.TypeField or WasmImm.TypeCount or WasmImm.TypeData or WasmImm.TypeElem or WasmImm.TwoTypes:
                ins.A = _r.U32();
                ins.B = _r.U32();
                break;
            case WasmImm.BrOnCast:
                ins.Lane = _r.Byte();
                if (ins.Lane > 3) throw new WasmFormatException($"br_on_cast flags {ins.Lane}");
                ins.A = _r.U32();
                ins.Value = _r.S33();
                ins.BlockType = _r.S33();
                break;
            case WasmImm.Fence:
                if (_r.Byte() != 0) throw new WasmFormatException("atomic.fence reserved byte is not 0");
                break;
        }
    }

    /// <summary>A block type: 0x40, a value type (0x63 / 0x64 with its heap type too), or an s33 type index.</summary>
    private long ReadBlockType()
    {
        if (_r.Peek() is 0x63 or 0x64) return TypedBlock - (int)WasmBinary.ReadValType(ref _r);
        return _r.S33();
    }

    /// <summary>alignment (bit 6 flags a memory index) and offset; memory64 offsets are 64-bit.</summary>
    private void MemArg(ref WasmInstr ins)
    {
        uint align = _r.U32();
        if ((align & 0x40) != 0)
        {
            ins.Memory = _r.U32();
            align &= ~0x40u;
        }
        ins.Align = align;
        ins.MemOffset = _r.U64();
    }

    /// <summary>The br_table targets of <paramref name="ins"/>, the default last.</summary>
    public static uint[] Targets(byte[] bytes, in WasmInstr ins)
    {
        var r = new WasmReader(bytes, ins.ImmStart, ins.Offset + ins.Length);
        var targets = new uint[ins.Count + 1];
        for (int i = 0; i < ins.Count; i++) targets[i] = r.U32();
        targets[ins.Count] = ins.A;
        return targets;
    }
}
