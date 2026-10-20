using System.Buffers.Binary;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump;

/// <summary>How a frame's instruction address was found.</summary>
public static class FrameMethod
{
    /// <summary>The thread's (or the exception's) register context.</summary>
    public const string Context = "context";
    /// <summary>x64 virtual unwind through the caller's .pdata / UNWIND_INFO.</summary>
    public const string UnwindInfo = "unwind_info";
    /// <summary>x64 unwind of the top frame from inside an epilog (instructions emulated).</summary>
    public const string Epilog = "epilog";
    /// <summary>x64 function without .pdata (a leaf), or x86 after a call to an address that is not code: the return address at the stack pointer.</summary>
    public const string Leaf = "leaf";
    /// <summary>x64 UWOP_PUSH_MACHFRAME: an interrupt or exception frame.</summary>
    public const string MachineFrame = "machine_frame";
    /// <summary>x86 saved frame pointer chain (EBP).</summary>
    public const string FramePointer = "frame_pointer";
    /// <summary>x86 without a frame pointer: the nearest stack slot holding a return address whose call targets this function.</summary>
    public const string CallTarget = "call_target";
    /// <summary>Stack scan for a value that looks like a return address: heuristic.</summary>
    public const string Scan = "scan";
}

/// <summary>One frame of a walk: the instruction address and the stack pointer at it.</summary>
public sealed record WalkFrame(ulong Ip, ulong Sp, string Method, bool Heuristic, bool IsReturnAddress, string? Note)
{
    /// <summary>The address to look the code up by: one byte back for a return address (the call may end its function).</summary>
    public ulong LookupAddress => IsReturnAddress && Ip > 0 ? Ip - 1 : Ip;
}

/// <summary>The frames of one walk and why it ended.</summary>
public sealed record WalkResult(IReadOnlyList<WalkFrame> Frames, string Stop, IReadOnlyList<string> Notes);

/// <summary>
/// Walks a thread's stack in a dump. x64: virtual unwind with the modules' exception data (.pdata RUNTIME_FUNCTION,
/// UNWIND_INFO codes: push nonvol, alloc small / large, set frame register, save nonvol / xmm128 (near and far),
/// machine frame, chained info; epilog emulation for the top frame; leaf functions), falling back to a stack scan
/// (frames marked heuristic) where no unwind data is available (no image, JIT code) or it leads nowhere. x86: a return
/// address whose call instruction targets the current function (frames that omit the frame pointer), the EBP chain, then a scan. Unwind data and code bytes come from the module images the caller supplies (a matching file
/// from disk, or the image rebuilt from dump memory) and from captured memory. Every loop is bounded.
/// </summary>
public sealed class StackWalker
{
    public const int MaxFramesLimit = 1024;
    private const int MaxChain = 32;
    private const int MaxScanSlots = 0x4000;
    /// <summary>Stack slots examined by all the scans of one walk.</summary>
    private const int MaxScanSlotsPerWalk = 0x10000;
    private int _scanBudget;
    /// <summary>Slots the x86 caller searches may examine: a budget of their own, so many frames without a frame pointer leave the scan its share.</summary>
    private int _callerBudget;
    private ulong _stackLow, _stackHigh;

    private readonly IProcessMemory _dump;
    private readonly Func<DumpModule, PeFile?> _image;
    private readonly Func<ulong, ulong?>? _functionStart;
    private readonly int _ptr;

    /// <param name="image">The module's image (or null when there is none); called once per module, cache it.</param>
    /// <param name="functionStart">x86: the start address of the function holding an address (PDB or export names), or null.</param>
    public StackWalker(IProcessMemory dump, Func<DumpModule, PeFile?> image, Func<ulong, ulong?>? functionStart = null)
    {
        _dump = dump;
        _image = image;
        _functionStart = functionStart;
        _ptr = dump.Is64Bit ? 8 : 4;
    }

    public WalkResult Walk(DumpContext start, ulong stackLow, ulong stackHigh, int maxFrames, CancellationToken ct = default)
    {
        maxFrames = Math.Clamp(maxFrames, 1, MaxFramesLimit);
        var frames = new List<WalkFrame>();
        var notes = new List<string>();
        if (_dump.Arch is not (NativeArch.X64 or NativeArch.X86))
            return new WalkResult([new WalkFrame(start.Ip, start.Sp, FrameMethod.Context, false, false, null)],
                "unsupported_architecture", [$"stacks are walked for x64 and x86 dumps; this one is {_dump.Arch}"]);
        var ctx = start.Clone();
        (_scanBudget, _callerBudget) = (MaxScanSlotsPerWalk, MaxScanSlotsPerWalk);
        (_stackLow, _stackHigh) = (stackLow, stackHigh);
        frames.Add(new WalkFrame(ctx.Ip, ctx.Sp, FrameMethod.Context, false, false, start.Complete ? null : "register context is incomplete in the dump"));
        bool top = true, guessedFp = false;
        string stop = "max_frames";
        while (frames.Count < maxFrames)
        {
            ct.ThrowIfCancellationRequested();
            var (next, method, heuristic, note) = _dump.Arch == NativeArch.X64 ? StepX64(ctx, top) : StepX86(ctx, top);
            if (next == null)
            {
                stop = note ?? "end";
                break;
            }
            if (next.Ip == 0)
            {
                // after a scan EBP is a guess, and so is every frame chained from it: a zero return address read through it does not end the stack
                if (method == FrameMethod.FramePointer && guessedFp && Scan(ctx.Sp, stackHigh, ctx) is { } above)
                    (next, method, heuristic, note) = (above, FrameMethod.Scan, true, "the guessed frame pointer gave a zero return address; scanned the stack");
                else
                {
                    stop = "end_of_stack";
                    break;
                }
            }
            if (next.Sp <= ctx.Sp && !(method == FrameMethod.MachineFrame && next.Sp != ctx.Sp))
            {
                // no progress: try a scan once before giving up
                var scanned = Scan(ctx.Sp + (ulong)_ptr, stackHigh, ctx);
                if (scanned == null || scanned.Sp <= ctx.Sp) { stop = "stack_pointer_did_not_advance"; break; }
                (next, method, heuristic) = (scanned, FrameMethod.Scan, true);
                note = "the unwind did not advance the stack pointer; continued with a scan";
            }
            if (stackHigh > stackLow && (next.Sp < stackLow || next.Sp > stackHigh))
            {
                stop = "left_the_stack";
                notes.Add($"the next frame's stack pointer 0x{next.Sp:X} is outside the thread's stack 0x{stackLow:X}-0x{stackHigh:X}");
                break;
            }
            frames.Add(new WalkFrame(next.Ip, next.Sp, method, heuristic, method != FrameMethod.MachineFrame, note));
            guessedFp = method == FrameMethod.Scan || method == FrameMethod.FramePointer && guessedFp;
            ctx = next;
            top = method == FrameMethod.MachineFrame; // after a machine frame the address is an interrupted instruction
        }
        if (frames.Count >= maxFrames && stop == "max_frames") notes.Add($"stopped after {maxFrames} frames (maxFrames)");
        return new WalkResult(frames, stop, notes);
    }

    private (DumpContext? Next, string Method, bool Heuristic, string? Note) StepX64(DumpContext ctx, bool top)
    {
        ulong lookup = top ? ctx.Ip : ctx.Ip - 1;
        var module = _dump.ModuleAt(lookup);
        var image = module != null ? _image(module) : null;
        if (image is { Arch: NativeArch.X64 })
        {
            uint rva = (uint)(lookup - module!.Base);
            var rf = Lookup(image.RuntimeFunctions, rva);
            if (rf == null)
            {
                // a leaf function: no stack allocation, the return address is at the stack pointer
                if (!_dump.TryReadU64(ctx.Sp, out ulong ra)) return (null, "", false, "stack_not_captured");
                var leaf = ctx.Clone();
                leaf.Ip = ra;
                leaf.Sp = ctx.Sp + 8;
                if (ra == 0 || IsPlausibleReturn(ra, strict: false)) return (leaf, FrameMethod.Leaf, false, null);
                var s = Scan(ctx.Sp, ulong.MaxValue, ctx);
                return s != null ? (s, FrameMethod.Scan, true, $"no unwind data at {module.FileName}+0x{rva:X} and no return address at the stack pointer; scanned")
                    : (null, "", false, "no_return_address");
            }
            var unwound = VirtualUnwind(image, module.Base, rf, (uint)(ctx.Ip - module.Base), ctx, top, out bool machine, out bool epilog, out string? failure);
            // a frame a scan found can be stale, so its unwind reads a return address from the wrong slot
            if (unwound != null && !machine && unwound.Ip != 0 && !IsCode(unwound.Ip, ctx.Sp))
            {
                var rescan = Scan(ctx.Sp, ulong.MaxValue, ctx);
                return rescan != null ? (rescan, FrameMethod.Scan, true, $"the unwind at {module.FileName}+0x{rva:X} gave 0x{unwound.Ip:X}, which is not code; scanned")
                    : (null, "", false, "unwind_failed");
            }
            if (unwound != null) return (unwound, machine ? FrameMethod.MachineFrame : epilog ? FrameMethod.Epilog : FrameMethod.UnwindInfo, false, null);
            var scan = Scan(ctx.Sp, ulong.MaxValue, ctx);
            return scan != null ? (scan, FrameMethod.Scan, true, $"unwind failed at {module.FileName}+0x{rva:X} ({failure}); scanned")
                : (null, "", false, "unwind_failed");
        }
        // a call to a bad address (the null page, or memory known not to be code) left its return address on top
        if (top && module == null && (ctx.Ip < 0x10000 || _dump.RegionAt(ctx.Ip) is { IsExecutable: false })
            && _dump.TryReadU64(ctx.Sp, out ulong returned) && IsPlausibleReturn(returned, strict: true))
        {
            var called = ctx.Clone();
            called.Ip = returned;
            called.Sp = ctx.Sp + 8;
            return (called, FrameMethod.Leaf, false, "the instruction address is not code (a call to a bad address): return address read at the stack pointer");
        }
        var fallback = Scan(ctx.Sp, ulong.MaxValue, ctx);
        string why = module == null ? $"0x{ctx.Ip:X} is not in a module (JIT-compiled or generated code has no unwind data here)"
            : $"no image of {module.FileName} (not found on disk with a matching timestamp and size, not captured in the dump)";
        return fallback != null ? (fallback, FrameMethod.Scan, true, why + "; scanned the stack") : (null, "", false, "no_unwind_data");
    }

    private static RuntimeFunction? Lookup(IReadOnlyList<RuntimeFunction> table, uint rva)
    {
        int lo = 0, hi = table.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            var f = table[mid];
            if (rva < f.BeginRva) hi = mid - 1;
            else if (rva >= f.EndRva) lo = mid + 1;
            else return f;
        }
        return null;
    }

    private sealed record UnwindInfo(byte Version, byte Flags, byte PrologSize, byte FrameRegister, byte FrameOffset, ushort[] Codes, RuntimeFunction? Chained);

    private static UnwindInfo? ReadUnwindInfo(PeFile image, uint rva)
    {
        Span<byte> head = stackalloc byte[4];
        if (image.Read(rva, head) < 4) return null;
        int count = head[2];
        var body = new byte[4 + (count + 1) / 2 * 4 + 12];
        int n = image.Read(rva, body);
        if (n < 4 + count * 2) return null;
        var codes = new ushort[count];
        for (int i = 0; i < count; i++) codes[i] = BinaryPrimitives.ReadUInt16LittleEndian(body.AsSpan(4 + i * 2));
        byte flags = (byte)(head[0] >> 3);
        RuntimeFunction? chained = null;
        if ((flags & 4) != 0)
        {
            int at = 4 + ((count + 1) & ~1) * 2;
            if (n < at + 12) return null;
            chained = new RuntimeFunction(BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(at)), BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(at + 4)),
                BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(at + 8)));
        }
        return new UnwindInfo((byte)(head[0] & 7), flags, head[1], (byte)(head[3] & 0xF), (byte)(head[3] >> 4), codes, chained);
    }

    /// <summary>Slots an unwind code occupies (llvm-readobj's table).</summary>
    private static int CodeSlots(int op, int info) => op switch
    {
        1 => info == 0 ? 2 : 3,
        4 or 8 or 6 => 2,
        5 or 9 or 7 => 3,
        _ => 1,
    };

    private DumpContext? VirtualUnwind(PeFile image, ulong imageBase, RuntimeFunction function, uint ipRva, DumpContext ctx, bool top,
        out bool machine, out bool epilog, out string? failure)
    {
        machine = epilog = false;
        failure = null;
        var c = ctx.Clone();
        if (top && TryEpilog(c, image, imageBase, function))
        {
            epilog = true;
            return c;
        }
        var fn = function;
        for (int level = 0; level < MaxChain; level++)
        {
            var info = ReadUnwindInfo(image, fn.UnwindInfoRva);
            if (info == null) { failure = $"unwind info at RVA 0x{fn.UnwindInfoRva:X} is unreadable"; return null; }
            if (info.Version is not (1 or 2)) { failure = $"unwind info version {info.Version}"; return null; }
            uint prologOffset = level == 0 && ipRva >= fn.BeginRva && ipRva - fn.BeginRva < info.PrologSize ? ipRva - fn.BeginRva : uint.MaxValue;
            ulong frame = c.Sp;
            if (info.FrameRegister != 0)
            {
                bool established = prologOffset == uint.MaxValue || SetFpregOffset(info) is not { } at || at <= prologOffset;
                if (established) frame = c.Gpr[info.FrameRegister] - info.FrameOffset * 16UL;
            }
            var codes = info.Codes;
            for (int i = 0; i < codes.Length;)
            {
                int offset = codes[i] & 0xFF, op = (codes[i] >> 8) & 0xF, opInfo = codes[i] >> 12;
                int slots = CodeSlots(op, opInfo);
                if (i + slots > codes.Length) { failure = "unwind codes are truncated"; return null; }
                if (prologOffset != uint.MaxValue && offset > prologOffset)
                {
                    i += slots;
                    continue; // not executed yet
                }
                switch (op)
                {
                    case 0: // UWOP_PUSH_NONVOL
                        if (!_dump.TryReadU64(c.Sp, out ulong pushed)) { failure = $"stack at 0x{c.Sp:X} not captured"; return null; }
                        c.Gpr[opInfo] = pushed;
                        c.Sp += 8;
                        break;
                    case 1: // UWOP_ALLOC_LARGE
                        c.Sp += opInfo == 0 ? codes[i + 1] * 8UL : codes[i + 1] | (ulong)codes[i + 2] << 16;
                        break;
                    case 2: // UWOP_ALLOC_SMALL
                        c.Sp += (ulong)opInfo * 8 + 8;
                        break;
                    case 3: // UWOP_SET_FPREG
                        c.Sp = frame;
                        break;
                    case 4: // UWOP_SAVE_NONVOL
                    case 5: // UWOP_SAVE_NONVOL_FAR
                    {
                        ulong at = frame + (op == 4 ? codes[i + 1] * 8UL : codes[i + 1] | (ulong)codes[i + 2] << 16);
                        if (!_dump.TryReadU64(at, out ulong saved)) { failure = $"saved register slot 0x{at:X} not captured"; return null; }
                        c.Gpr[opInfo] = saved;
                        break;
                    }
                    case 8: // UWOP_SAVE_XMM128
                    case 9: // UWOP_SAVE_XMM128_FAR
                    {
                        ulong at = frame + (op == 8 ? codes[i + 1] * 16UL : codes[i + 1] | (ulong)codes[i + 2] << 16);
                        _dump.ReadMemory(at, c.Xmm.AsSpan(opInfo * 16, 16));
                        break;
                    }
                    case 10: // UWOP_PUSH_MACHFRAME
                    {
                        ulong sp = c.Sp + (opInfo != 0 ? 8UL : 0);
                        if (!_dump.TryReadU64(sp, out ulong rip) || !_dump.TryReadU64(sp + 24, out ulong oldSp))
                        {
                            failure = $"machine frame at 0x{sp:X} not captured";
                            return null;
                        }
                        c.Ip = rip;
                        c.Sp = oldSp;
                        machine = true;
                        break;
                    }
                    case 6: // UWOP_EPILOG (version 2): describes epilogs, nothing to undo
                    case 7:
                        break;
                    default:
                        failure = $"unknown unwind code {op}";
                        return null;
                }
                i += slots;
            }
            if ((info.Flags & 4) == 0 || info.Chained == null) break;
            fn = info.Chained;
            if (level == MaxChain - 1) { failure = "chained unwind info is deeper than 32 levels"; return null; }
        }
        if (!machine)
        {
            if (!_dump.TryReadU64(c.Sp, out ulong ra)) { failure = $"return address slot 0x{c.Sp:X} not captured"; return null; }
            c.Ip = ra;
            c.Sp += 8;
        }
        return c;
    }

    private static int? SetFpregOffset(UnwindInfo info)
    {
        for (int i = 0; i < info.Codes.Length; i += CodeSlots((info.Codes[i] >> 8) & 0xF, info.Codes[i] >> 12))
            if (((info.Codes[i] >> 8) & 0xF) == 3) return info.Codes[i] & 0xFF;
        return null;
    }

    /// <summary>
    /// Top frame inside an epilog (add rsp / lea rsp, pops, then ret or a jump out of the function): emulates the rest of
    /// it, as RtlVirtualUnwind does, since the unwind codes describe the frame before the epilog started.
    /// </summary>
    private bool TryEpilog(DumpContext c, PeFile image, ulong imageBase, RuntimeFunction function)
    {
        var code = new byte[64];
        int n = ReadCode(c.Ip, code, image, imageBase);
        if (n < 1) return false;
        int p = 0;
        ulong sp = c.Sp;
        var regs = (ulong[])c.Gpr.Clone();
        // optional stack adjustment
        if (p + 4 <= n && code[p] == 0x48 && code[p + 1] == 0x83 && code[p + 2] == 0xC4) { sp += code[p + 3]; p += 4; }
        else if (p + 7 <= n && code[p] == 0x48 && code[p + 1] == 0x81 && code[p + 2] == 0xC4) { sp += BinaryPrimitives.ReadUInt32LittleEndian(code.AsSpan(p + 3)); p += 7; }
        else if (p + 3 <= n && (code[p] & 0xFE) == 0x48 && code[p + 1] == 0x8D && ((code[p + 2] >> 3) & 7) == 4 && (code[p + 2] >> 6) is 1 or 2)
        {
            // lea rsp, [frame + disp]
            int mod = code[p + 2] >> 6, rm = (code[p + 2] & 7) | ((code[p] & 1) << 3);
            if ((code[p + 2] & 7) == 4) return false; // SIB form is not a legal epilog
            int len = mod == 1 ? 4 : 7;
            if (p + len > n) return false;
            long disp = mod == 1 ? (sbyte)code[p + 3] : BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(p + 3));
            sp = (ulong)((long)regs[rm] + disp);
            p += len;
        }
        // pops
        int pops = 0;
        while (p < n && pops < 16)
        {
            int reg;
            if (code[p] is >= 0x58 and <= 0x5F) { reg = code[p] - 0x58; p += 1; }
            else if (p + 1 < n && code[p] == 0x41 && code[p + 1] is >= 0x58 and <= 0x5F) { reg = code[p + 1] - 0x58 + 8; p += 2; }
            else break;
            if (!_dump.TryReadU64(sp, out ulong v)) return false;
            regs[reg] = v;
            sp += 8;
            pops++;
        }
        if (p >= n) return false;
        bool ends = code[p] == 0xC3 || (code[p] == 0xF3 && p + 1 < n && code[p + 1] == 0xC3) || (code[p] == 0xC2)
            || (code[p] == 0xFF && p + 1 < n && code[p + 1] == 0x25) || (code[p] == 0x48 && p + 2 < n && code[p + 1] == 0xFF && code[p + 2] == 0x25);
        if (!ends && code[p] == 0xE9 && p + 5 <= n)
        {
            // a tail jump out of the function
            ulong target = (ulong)((long)c.Ip + p + 5 + BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(p + 1)));
            ends = target < imageBase + function.BeginRva || target >= imageBase + function.EndRva;
        }
        if (!ends || p == 0 && code[0] == 0xE9) return false;
        if (!_dump.TryReadU64(sp, out ulong ra)) return false;
        regs.CopyTo(c.Gpr, 0);
        c.Ip = ra;
        c.Sp = sp + 8;
        return true;
    }

    private (DumpContext? Next, string Method, bool Heuristic, string? Note) StepX86(DumpContext ctx, bool top)
    {
        if (top)
        {
            // at the first instruction(s) of a standard prolog the caller's frame pointer is still live
            var code = new byte[3];
            var m = _dump.ModuleAt(ctx.Ip);
            int n = ReadCode(ctx.Ip, code, m != null ? _image(m) : null, m?.Base ?? 0);
            int? raAt = n >= 1 && code[0] == 0x55 || n >= 2 && code[0] == 0x8B && code[1] == 0xFF ? 0 // push ebp not executed
                : n >= 2 && code[0] == 0x8B && code[1] == 0xEC ? 4 // push ebp done, mov ebp, esp not
                : null;
            if (raAt is { } at && _dump.TryReadU32(ctx.Sp + (ulong)at, out uint ra0) && IsPlausibleReturn(ra0, strict: false))
            {
                var p = ctx.Clone();
                p.Ip = ra0;
                p.Sp = ctx.Sp + (ulong)at + 4;
                if (at == 4 && _dump.TryReadU32(ctx.Sp, out uint savedEbp)) p.Fp = savedEbp;
                return (p, FrameMethod.FramePointer, false, "in the prolog: return address read at the stack pointer");
            }
            // a call to a bad address (the null page, or memory known not to be code) left its return address on top
            if ((ctx.Ip < 0x10000 || _dump.ModuleAt(ctx.Ip) == null && _dump.RegionAt(ctx.Ip) is { IsExecutable: false })
                && _dump.TryReadU32(ctx.Sp, out uint ra1) && IsPlausibleReturn(ra1, strict: true))
            {
                var p = ctx.Clone();
                p.Ip = ra1;
                p.Sp = ctx.Sp + 4;
                return (p, FrameMethod.Leaf, false, "the instruction address is not code (a call to a bad address): return address read at the stack pointer");
            }
        }
        ulong ebp = ctx.Fp;
        uint nextEbp = 0, ret = 0;
        // a saved EBP off the thread's stack is not a frame (code that uses EBP freely, such as a hook's, left it)
        bool chain = ebp >= ctx.Sp && ebp != 0 && (_stackHigh <= _stackLow || ebp < _stackHigh) && _dump.TryReadU32(ebp, out nextEbp) && _dump.TryReadU32(ebp + 4, out ret)
                     && (ret == 0 || IsPlausibleReturn(ret, strict: false));
        // A function without a frame pointer leaves EBP to an outer frame: its own return address lies below that frame.
        if (_functionStart?.Invoke(top ? ctx.Ip : ctx.Ip - 1) is { } function
            && CallerOf(function, ctx.Sp, chain ? ebp + 4 : ctx.Sp + MaxScanSlots * 4UL) is { } found && (!chain || found.Slot < ebp + 4))
        {
            _dump.TryReadU32(found.Slot, out uint ra);
            var caller = ctx.Clone();
            caller.Ip = ra;
            caller.Sp = found.Slot + 4;
            return (caller, FrameMethod.CallTarget, false, found.Via is { } via ? $"the caller called 0x{via:X}, which tail-jumps here: its frame is gone" : null);
        }
        if (chain)
        {
            var next = ctx.Clone();
            next.Ip = ret;
            next.Sp = ebp + 8;
            next.Fp = nextEbp;
            return (next, FrameMethod.FramePointer, false, null);
        }
        var scanned = Scan(ctx.Sp, ulong.MaxValue, ctx);
        return scanned != null ? (scanned, FrameMethod.Scan, true, "the EBP chain ends here (frame pointer omitted or not captured); scanned the stack")
            : (null, "", false, "no_return_address");
    }

    /// <summary>
    /// The first x86 stack slot in [<paramref name="from"/>, <paramref name="limit"/>] holding a return address whose call
    /// (call rel32, call [abs32], or through a jmp thunk) targets <paramref name="function"/>, or a function that tail-jumps
    /// to it (<c>Via</c>); null when none.
    /// </summary>
    private (ulong Slot, ulong? Via)? CallerOf(ulong function, ulong from, ulong limit)
    {
        var buffer = new byte[0x400];
        var code = new byte[6];
        for (ulong at = from & ~3UL; at <= limit && _callerBudget > 0;)
        {
            int n = _dump.ReadMemory(at, buffer.AsSpan(0, (int)Math.Min((ulong)buffer.Length, limit - at + 4)));
            if (n < 4) return null;
            for (int i = 0; i + 4 <= n && _callerBudget > 0; i += 4, _callerBudget--)
            {
                uint v = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(i));
                if (v < 0x10000 || v - 6 < 0x10000) continue;
                var m = _dump.ModuleAt(v - 1);
                var image = m != null ? _image(m) : null;
                if (ReadCode(v - 6, code, image, m?.Base ?? 0) < 6) continue;
                bool calls;
                ulong? via = null;
                if (code[1] == 0xE8)
                {
                    ulong t = (uint)(v + BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(2)));
                    calls = t == function || JumpTarget(t) == function;
                    if (!calls && TailJumps(t, function)) (calls, via) = (true, t);
                }
                else if (code[0] == 0xFF && code[1] == 0x15)
                {
                    uint slot = BinaryPrimitives.ReadUInt32LittleEndian(code.AsSpan(2));
                    // a bound slot holds the target; one the dump does not hold (or holds unbound) is matched by the import's name
                    calls = _dump.TryReadU32(slot, out uint bound) && bound == function || ImportName(slot) is { } imported && imported == ExportName(function);
                }
                else continue;
                if (calls && IsPlausibleReturn(v, strict: true)) return (at + (ulong)i, via);
            }
            at += (ulong)n;
        }
        return null;
    }

    /// <summary>The name of the import whose IAT slot is at <paramref name="slot"/>, from its module's image.</summary>
    private string? ImportName(ulong slot) =>
        _dump.ModuleAt(slot) is { } m && _image(m) is { } image ? image.Imports.FirstOrDefault(i => i.SlotRva == slot - m.Base)?.Name : null;

    /// <summary>The name a module exports <paramref name="function"/> under, or null.</summary>
    private string? ExportName(ulong function) =>
        _dump.ModuleAt(function) is { } m && _image(m) is { } image ? image.Exports.FirstOrDefault(e => e.Rva == function - m.Base && e.ForwardedTo == null)?.Name : null;

    /// <summary>The target of a jmp rel32 at <paramref name="address"/> (an incremental-linking thunk), or null.</summary>
    private ulong? JumpTarget(ulong address)
    {
        var m = _dump.ModuleAt(address);
        Span<byte> b = stackalloc byte[5];
        if (ReadCode(address, b, m != null ? _image(m) : null, m?.Base ?? 0) < 5 || b[0] != 0xE9) return null;
        return (uint)(address + 5 + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(b[1..]));
    }

    private readonly Dictionary<(ulong, ulong), bool> _tailJumps = [];

    /// <summary>
    /// Whether the code of the function at <paramref name="start"/> holds a jmp rel32 to <paramref name="target"/> within
    /// its first <see cref="TailWindow"/> bytes: a tail call, whose frame the callee replaced.
    /// </summary>
    private bool TailJumps(ulong start, ulong target)
    {
        if (_tailJumps.TryGetValue((start, target), out var known)) return known;
        var m = _dump.ModuleAt(start);
        var code = new byte[TailWindow];
        int n = ReadCode(start, code, m != null ? _image(m) : null, m?.Base ?? 0);
        bool found = false;
        for (int i = 0; i + 5 <= n && !found; i++)
            found = code[i] == 0xE9 && (uint)(start + (ulong)i + 5 + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(i + 1))) == target;
        return _tailJumps[(start, target)] = found;
    }

    private const int TailWindow = 512;

    /// <summary>The first stack slot at or above <paramref name="from"/> holding a plausible return address.</summary>
    private DumpContext? Scan(ulong from, ulong limit, DumpContext basis)
    {
        var buffer = new byte[0x1000];
        ulong at = from & ~((ulong)_ptr - 1);
        int slots = 0;
        while (slots < MaxScanSlots && _scanBudget > 0 && at < limit)
        {
            int n = _dump.ReadMemory(at, buffer);
            if (n < _ptr) return null;
            for (int i = 0; i + _ptr <= n && slots < MaxScanSlots && _scanBudget > 0; i += _ptr, slots++, _scanBudget--)
            {
                ulong v = _ptr == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(i)) : BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(i));
                if (v < 0x10000 || !IsPlausibleReturn(v, strict: true)) continue;
                var c = basis.Clone();
                c.Ip = v;
                c.Sp = at + (ulong)i + (ulong)_ptr;
                // the frame pointer is unknown after a scan; x86 keeps looking for a chain from the slot below the return address
                if (_dump.Arch == NativeArch.X86) c.Fp = _dump.TryReadU32(at + (ulong)i - 4, out uint fp) && fp > c.Sp ? fp : 0;
                return c;
            }
            at += (ulong)n;
        }
        return null;
    }

    /// <summary>
    /// Whether <paramref name="address"/> can be a return address: inside executable code (a module's code section,
    /// or an executable region of the dump) and, when the bytes are available, right after a call instruction.
    /// Strict (scans) requires the call check whenever the code bytes are readable.
    /// </summary>
    /// <summary>
    /// <paramref name="address"/> can be code: canonical, and executable where the dump says (an image section, or a region
    /// when the dump has a memory list, which <paramref name="stackPointer"/>'s region shows).
    /// </summary>
    private bool IsCode(ulong address, ulong stackPointer)
    {
        if (address < 0x10000 || (_dump.Is64Bit && (long)address >> 47 is not (0 or -1))) return false;
        if (_dump.ModuleAt(address) is { } module && _image(module) is { } image)
            return image.SectionAt((uint)(address - module.Base)) is { IsExecutable: true };
        return _dump.RegionAt(address) is { } r ? r.IsExecutable : _dump.RegionAt(stackPointer) == null;
    }

    public bool IsPlausibleReturn(ulong address, bool strict)
    {
        var module = _dump.ModuleAt(address);
        PeFile? image = null;
        if (module != null)
        {
            image = _image(module);
            if (image != null)
            {
                var section = image.SectionAt((uint)(address - module.Base));
                if (section is not { IsExecutable: true }) return false;
            }
            else if (_dump.RegionAt(address) is { } r && !r.IsExecutable) return false;
        }
        else
        {
            if (_dump.RegionAt(address) is not { IsExecutable: true }) return false;
        }
        var before = new byte[8];
        int n = ReadCode(address - 8, before, image, module?.Base ?? 0);
        if (n < 8) return !strict || module != null;
        return FollowsCall(before);
    }

    /// <summary>The 8 bytes before a return address end with a call (E8 rel32, FF /2 in its register / memory forms).</summary>
    internal static bool FollowsCall(ReadOnlySpan<byte> b)
    {
        if (b[3] == 0xE8) return true; // call rel32
        if (b[6] == 0xFF && (b[7] & 0x38) == 0x10 && (b[7] >> 6) == 3) return true; // call reg
        if (b[6] == 0xFF && (b[7] & 0x38) == 0x10 && (b[7] >> 6) == 0 && (b[7] & 7) is not (4 or 5)) return true; // call [reg]
        if (Ff2(b, 5, 1, false)) return true; // call [reg+disp8]
        if (Ff2(b, 4, 1, true)) return true; // call [sib+disp8]
        if (b[2] == 0xFF && b[3] == 0x15) return true; // call [rip+disp32] / [disp32]
        if (Ff2(b, 2, 2, false)) return true; // call [reg+disp32]
        if (Ff2(b, 1, 2, true)) return true; // call [sib+disp32]
        if (Ff2(b, 5, 0, true)) return true; // call [sib]
        return false;
    }

    private static bool Ff2(ReadOnlySpan<byte> b, int at, int mod, bool sib)
    {
        if (b[at] != 0xFF) return false;
        byte modrm = b[at + 1];
        if (((modrm >> 3) & 7) != 2 || (modrm >> 6) != mod) return false;
        return ((modrm & 7) == 4) == sib;
    }

    /// <summary>Code bytes: captured memory first, then the module image.</summary>
    private int ReadCode(ulong address, Span<byte> destination, PeFile? image, ulong imageBase)
    {
        int n = _dump.ReadMemory(address, destination);
        if (n == destination.Length || image == null || address < imageBase) return n;
        ulong rva = address - imageBase;
        if (rva > uint.MaxValue) return n;
        var fromImage = new byte[destination.Length];
        int m = image.Read((uint)rva, fromImage);
        if (m <= n) return n;
        fromImage.AsSpan(0, m).CopyTo(destination);
        return m;
    }
}
