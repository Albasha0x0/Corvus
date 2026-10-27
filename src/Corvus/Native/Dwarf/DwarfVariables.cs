using Corvus.Native.Pdb;

namespace Corvus.Native.Dwarf;

/// <summary>The parameters and locals in scope at an address, with their location there in register names ("rdi", "[rbp-0x14]").</summary>
internal static class DwarfVariables
{
    private const int MaxVariables = 64;
    private const int MaxListEntries = 4096;

    public static List<DebugVariable> At(DwarfReader reader, DwarfUnit unit, IReadOnlyList<DwarfDie> chain, ulong address, NativeArch arch)
    {
        var result = new List<DebugVariable>();
        if (chain.Count == 0) return result;
        var function = chain[0];
        int start = unit.IndexOf(function);
        if (start < 0) return result;
        var frameBase = function.FrameBase;
        for (int i = start + 1; i < unit.Dies.Count && result.Count < MaxVariables; i++)
        {
            var d = unit.Dies[i];
            if (!Inside(unit, d, function)) break;
            if (d.Tag is not (Dw.TagFormalParameter or Dw.TagVariable)) continue;
            if (!InScope(reader, unit, d, function, address)) continue;
            var (name, type) = NameAndType(reader, unit, d);
            if (name == null) continue;
            var scope = unit.ParentOf(d) is { Tag: Dw.TagInlinedSubroutine } inl ? DwarfDebugInfo.Naming(reader, unit, inl).Name : null;
            result.Add(new DebugVariable(name, type is { } t ? TypeName(reader, unit, t, 0) : null, Location(reader, unit, d, address, arch, frameBase),
                d.Tag == Dw.TagFormalParameter, scope));
        }
        return result;
    }

    private static bool Inside(DwarfUnit unit, DwarfDie d, DwarfDie ancestor)
    {
        for (var p = unit.ParentOf(d); p != null; p = unit.ParentOf(p))
            if (ReferenceEquals(p, ancestor)) return true;
        return false;
    }

    /// <summary>Every lexical block and inlined call between the entry and the function holds the address.</summary>
    private static bool InScope(DwarfReader reader, DwarfUnit unit, DwarfDie d, DwarfDie function, ulong address)
    {
        for (var p = unit.ParentOf(d); p != null && !ReferenceEquals(p, function); p = unit.ParentOf(p))
        {
            if (p.Tag is not (Dw.TagLexicalBlock or Dw.TagInlinedSubroutine)) continue;
            var ranges = reader.RangesOf(unit, p);
            if (ranges.Count > 0 && !ranges.Any(r => address >= r.Low && address < r.High)) return false;
        }
        return true;
    }

    private static (string? Name, long? Type) NameAndType(DwarfReader reader, DwarfUnit unit, DwarfDie d)
    {
        string? name = d.Name;
        long type = d.Type;
        var (u, e) = (unit, d);
        for (int hop = 0; hop < 4 && (name == null || type < 0) && e.AbstractOrigin >= 0 && reader.Entry(e.AbstractOrigin, u) is { } o; hop++)
        {
            (u, e) = o;
            name ??= e.Name;
            if (type < 0) type = e.Type;
        }
        return (name, type >= 0 ? type : null);
    }

    /// <summary>A short C spelling of a type entry: names, pointers, const, arrays.</summary>
    private static string TypeName(DwarfReader reader, DwarfUnit unit, long offset, int depth)
    {
        if (depth > 8 || reader.Entry(offset, unit) is not { } entry) return "?";
        var (u, d) = entry;
        string Inner() => d.Type >= 0 ? TypeName(reader, u, d.Type, depth + 1) : "void";
        return d.Tag switch
        {
            Dw.TagPointerType => Inner() + "*",
            Dw.TagReferenceType => Inner() + "&",
            Dw.TagRvalueReferenceType => Inner() + "&&",
            Dw.TagConstType => "const " + Inner(),
            Dw.TagVolatileType => "volatile " + Inner(),
            Dw.TagRestrictType or Dw.TagAtomicType => Inner(),
            Dw.TagArrayType => Inner() + "[]",
            Dw.TagSubroutineType => "function",
            Dw.TagStructureType or Dw.TagClassType or Dw.TagUnionType or Dw.TagEnumerationType when d.Name != null => DwarfTypes.Qualify(u, d, d.Name, reader),
            _ => d.Name ?? "?",
        };
    }

    private static string Location(DwarfReader reader, DwarfUnit unit, DwarfDie d, ulong address, NativeArch arch, byte[]? frameBase)
    {
        if (d.LocationExpr is { } expr) return Describe(expr, unit, reader, arch, frameBase);
        if (d.LocationList < 0) return "no location (optimized out)";
        return ListEntry(reader, unit, d, address) is { } found ? Describe(found, unit, reader, arch, frameBase) : "not available here (location list)";
    }

    /// <summary>The expression of the location list entry that covers <paramref name="address"/>, or null.</summary>
    private static byte[]? ListEntry(DwarfReader reader, DwarfUnit unit, DwarfDie d, ulong address)
    {
        if (unit.Version >= 5)
        {
            if (reader.Loclists is not { } lists) return null;
            long offset = d.LocationList;
            if (d.LocationListIndexed)
            {
                long b = unit.LoclistsBase >= 0 ? unit.LoclistsBase : unit.OffsetSize == 8 ? 20 : 12;
                var ic = new DwarfCursor(lists.Slice(b + offset * unit.OffsetSize, unit.OffsetSize).Span, reader.BigEndian);
                offset = b + (long)ic.Sized(unit.OffsetSize);
                if (ic.Overrun) return null;
            }
            var c = new DwarfCursor(lists.From(offset, 1 << 20).Span, reader.BigEndian);
            ulong baseAddress = unit.BaseAddress;
            for (int n = 0; n < MaxListEntries && !c.AtEnd; n++)
            {
                ulong lo = 0, hi = 0;
                bool range = true;
                switch (c.U8())
                {
                    case 0: return null;
                    case 1: baseAddress = reader.Address(unit, c.Uleb()); range = false; break;
                    case 2: lo = reader.Address(unit, c.Uleb()); hi = reader.Address(unit, c.Uleb()); break;
                    case 3: lo = reader.Address(unit, c.Uleb()); hi = lo + c.Uleb(); break;
                    case 4: lo = baseAddress + c.Uleb(); hi = baseAddress + c.Uleb(); break;
                    case 5: lo = 0; hi = ulong.MaxValue; break; // default location
                    case 6: baseAddress = c.Sized(unit.AddressSize); range = false; break;
                    case 7: lo = c.Sized(unit.AddressSize); hi = c.Sized(unit.AddressSize); break;
                    case 8: lo = c.Sized(unit.AddressSize); hi = lo + c.Uleb(); break;
                    default: return null;
                }
                if (!range) continue;
                int length = (int)Math.Min(c.Uleb(), int.MaxValue);
                int at = c.Pos;
                c.Advance(length);
                if (c.Overrun) return null;
                if (address >= lo && address < hi) return c.Span(at, length).ToArray();
            }
            return null;
        }
        if (reader.Loc is not { } loc) return null;
        var lc = new DwarfCursor(loc.From(d.LocationList, 1 << 20).Span, reader.BigEndian);
        ulong max = unit.AddressSize == 8 ? ulong.MaxValue : uint.MaxValue, b4 = unit.BaseAddress;
        for (int n = 0; n < MaxListEntries && !lc.AtEnd; n++)
        {
            ulong lo = lc.Sized(unit.AddressSize), hi = lc.Sized(unit.AddressSize);
            if (lc.Overrun || lo == 0 && hi == 0) return null;
            if (lo == max) { b4 = hi; continue; }
            int length = lc.U16(), at = lc.Pos;
            lc.Advance(length);
            if (lc.Overrun) return null;
            if (address >= lo + b4 && address < hi + b4) return lc.Span(at, length).ToArray();
        }
        return null;
    }

    /// <summary>A location expression as text: registers, register-relative and frame-base-relative slots, addresses, values, pieces.</summary>
    public static string Describe(ReadOnlySpan<byte> expr, DwarfUnit unit, DwarfReader reader, NativeArch arch, byte[]? frameBase)
    {
        var parts = new List<string>();
        var c = new DwarfCursor(expr, reader.BigEndian);
        static string Offset(long v) => v == 0 ? "" : v < 0 ? $"-0x{-v:X}" : $"+0x{v:X}";
        string? value = null;
        while (!c.AtEnd)
        {
            byte op = c.U8();
            switch (op)
            {
                case >= 0x50 and <= 0x6F: value = DwarfRegisters.Name(arch, op - 0x50); break;
                case 0x90: value = DwarfRegisters.Name(arch, (int)c.Uleb()); break;
                case >= 0x70 and <= 0x8F: { int reg = op - 0x70; value = $"[{DwarfRegisters.Name(arch, reg)}{Offset(c.Sleb())}]"; break; }
                case 0x92: { int reg = (int)c.Uleb(); value = $"[{DwarfRegisters.Name(arch, reg)}{Offset(c.Sleb())}]"; break; }
                case 0x91: value = $"[{FrameBase(frameBase, unit, reader, arch)}{Offset(c.Sleb())}]"; break;
                case 0x03: value = $"0x{c.Sized(unit.AddressSize):X}"; break;
                case 0xA1 or 0xFB: value = $"0x{reader.Address(unit, c.Uleb()):X}"; break;
                case >= 0x30 and <= 0x4F: value = $"{op - 0x30}"; break;
                case 0x08: value = $"{c.U8()}"; break;
                case 0x09: value = $"{(sbyte)c.U8()}"; break;
                case 0x0A: value = $"{c.U16()}"; break;
                case 0x0B: value = $"{(short)c.U16()}"; break;
                case 0x0C: value = $"{c.U32()}"; break;
                case 0x0D: value = $"{(int)c.U32()}"; break;
                case 0x0E or 0x0F: value = $"0x{c.U64():X}"; break;
                case 0x10: value = $"{c.Uleb()}"; break;
                case 0x11: value = $"{c.Sleb()}"; break;
                case 0x23 when value != null: value = $"{value}+0x{c.Uleb():X}"; break;
                case 0x06 when value != null: value = $"[{value}]"; break;
                case 0x9F when value != null: value = $"value {value}"; break;
                case 0xA3 or 0xF3: // entry_value
                {
                    int length = (int)Math.Min(c.Uleb(), int.MaxValue), at = c.Pos;
                    c.Advance(length);
                    value = $"entry value of {Describe(c.Span(at, length), unit, reader, arch, frameBase)}";
                    break;
                }
                case 0x93: // piece
                    parts.Add($"{value ?? "?"}:{c.Uleb()}");
                    value = null;
                    break;
                case 0x9C: value = "CFA"; break;
                case 0x96: break;
                default: return $"expression ({expr.Length} bytes)";
            }
            if (c.Overrun) return $"expression ({expr.Length} bytes)";
        }
        if (value != null && parts.Count > 0) parts.Add(value);
        if (parts.Count > 0) return string.Join(" + ", parts);
        return value ?? "empty";
    }

    private static string FrameBase(byte[]? expr, DwarfUnit unit, DwarfReader reader, NativeArch arch) => expr switch
    {
        null => "frame base",
        [0x9C] => "CFA",
        [>= 0x50 and <= 0x6F] => DwarfRegisters.Name(arch, expr[0] - 0x50),
        _ => $"frame base {Describe(expr, unit, reader, arch, null)}",
    };
}

/// <summary>DWARF register numbers to the names each architecture's ABI uses.</summary>
internal static class DwarfRegisters
{
    private static readonly string[] X64 = ["rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"];
    private static readonly string[] X86 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip"];
    private static readonly string[] RiscV = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
        "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"];

    public static string Name(NativeArch arch, int reg) => arch switch
    {
        NativeArch.X64 when reg < X64.Length => X64[reg],
        NativeArch.X64 when reg is >= 17 and <= 32 => $"xmm{reg - 17}",
        NativeArch.X86 when reg < X86.Length => X86[reg],
        NativeArch.X86 when reg is >= 21 and <= 28 => $"xmm{reg - 21}",
        NativeArch.Arm64 when reg <= 30 => reg == 29 ? "fp" : reg == 30 ? "lr" : $"x{reg}",
        NativeArch.Arm64 when reg == 31 => "sp",
        NativeArch.Arm64 when reg is >= 64 and <= 95 => $"v{reg - 64}",
        NativeArch.Arm when reg <= 15 => reg switch { 11 => "fp", 13 => "sp", 14 => "lr", 15 => "pc", _ => $"r{reg}" },
        NativeArch.Arm when reg is >= 256 and <= 287 => $"d{reg - 256}",
        NativeArch.RiscV when reg < RiscV.Length => RiscV[reg],
        NativeArch.RiscV when reg is >= 32 and <= 63 => $"f{reg - 32}",
        NativeArch.PowerPc when reg <= 31 => $"r{reg}",
        NativeArch.PowerPc when reg == 65 => "lr",
        _ => $"reg{reg}",
    };
}
