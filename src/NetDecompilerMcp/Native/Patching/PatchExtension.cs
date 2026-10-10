using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Native.Patching;

/// <summary>How the new code and the displaced original instructions run in the stub.</summary>
public enum StubMode
{
    /// <summary>The site's instructions are replaced: the stub runs only the new code, then jumps back.</summary>
    Replace,
    /// <summary>The new code runs before the displaced original instructions.</summary>
    Before,
    /// <summary>The new code runs after the displaced original instructions.</summary>
    After,
}

/// <summary>
/// Patch-site extension. When a patch needs more bytes than its site provides, the site is turned into a 5-byte near
/// jump to a stub placed in slack space (a file-backed code cave in an executable section); the stub holds the new
/// code and, unless the mode is <see cref="StubMode.Replace"/>, the site's displaced instructions re-encoded for the
/// stub address (relative branches / calls and RIP-relative operands recomputed by the block encoder), and ends with a
/// jump back to the instruction after the site. Leftover site bytes are padded with int3. The whole thing is one
/// <see cref="NativePatch"/> (site region plus <see cref="NativeStub"/>), so undo, export and save treat it as a unit.
///
/// Refused (with a reason code in the message) when it would be unsafe: a branch targets inside the displaced range
/// (code-index xrefs), a displaced instruction cannot be relocated, no slack space is found, an x64 prologue described
/// by unwind data would be split, or the architecture is not x86/x64.
/// </summary>
public static class PatchExtension
{
    /// <summary>The site must hold at least a 5-byte near jmp (E9 rel32).</summary>
    private const int JmpSize = 5;
    private const int MaxCaveScanBytes = 64 * 1024 * 1024;
    private static readonly byte[] FillerBytes = [0xCC, 0x00, 0x90];

    public static StubMode ParseMode(string? text) => (text ?? "").Trim().ToLowerInvariant() switch
    {
        "" or "replace" => StubMode.Replace,
        "before" => StubMode.Before,
        "after" => StubMode.After,
        _ => throw new ToolError(ErrorCode.InvalidArgument, $"stubMode must be replace, before or after, not '{text}'."),
    };

    /// <summary>The built extension: the recorded patch, the stub disassembly for the report, and placement facts.</summary>
    public sealed record Result(NativePatch Patch, string StubDisasm, string Placement, int SitePad);

    /// <summary>
    /// Builds a stub-extended patch at <paramref name="siteRva"/>. <paramref name="newAssembly"/> (patch_asm) is the
    /// new code assembled at the stub address; when it is null the raw <paramref name="newBytes"/> are emitted verbatim
    /// in the stub (patch_bytes). <paramref name="resolve"/> resolves symbols in the new assembly to VAs.
    /// </summary>
    public static Result Build(NativeCodeIndex index, uint siteRva, byte[] newBytes, string? newAssembly,
        StubMode mode, string description, Func<string, ulong?>? resolve)
    {
        var image = index.Image;
        if (image.Arch is NativeArch.Arm64)
            throw new ToolError(ErrorCode.Unsupported, "arm64_unsupported: patch-site extension is implemented for x86 and x64 only.",
                "use an x86/x64 image, or patch in place without extend");
        if (image.Arch is not (NativeArch.X86 or NativeArch.X64))
            throw new ToolError(ErrorCode.Unsupported, $"unsupported_arch: patch-site extension needs x86 or x64 code, not {image.Arch}.");
        if (index.Support != CodeSupport.Full)
            throw new ToolError(ErrorCode.Unsupported, "no_code: the image has no analyzable x86/x64 code for a stub.");
        if (!image.TryRvaToFileOffset(siteRva, out long siteFileOffset))
            throw new ToolError(ErrorCode.InvalidArgument, $"{NativeAddress.Va(image, siteRva)} is not backed by file bytes; there is nothing to patch there.");
        if (image.SectionAt(siteRva) is not { IsExecutable: true })
            throw new ToolError(ErrorCode.InvalidArgument, $"{NativeAddress.Va(image, siteRva)} is not in an executable section; a stub extends code only.");

        var owner = index.FunctionAt(siteRva);
        if (owner is { } fn && fn.Start != siteRva)
        {
            // The site must begin on an instruction boundary of its function.
            uint scan = fn.Start;
            while (scan < siteRva && index.Decode(scan) is { Length: > 0 } s) scan += (uint)s.Length;
            if (scan != siteRva)
                throw new ToolError(ErrorCode.InvalidArgument, $"{NativeAddress.Va(image, siteRva)} is in the middle of an instruction in {fn.Name}.");
        }

        // Displace whole instructions from the site until there is room for the jump.
        uint at = siteRva;
        int covered = 0;
        while (covered < JmpSize)
        {
            if (index.Decode(at) is not { Length: > 0 } insn)
                throw new ToolError(ErrorCode.InvalidArgument,
                    $"no_space_at_site: only {covered} byte(s) at {NativeAddress.Va(image, siteRva)} decode before an undecodable byte, less than the {JmpSize} a jump needs.");
            if (owner is { } f && at + (uint)insn.Length > f.End)
                throw new ToolError(ErrorCode.Conflict,
                    $"no_space_at_site: reaching {JmpSize} bytes would run past the end of {f.Name} ({NativeAddress.Va(image, f.End)}); the site is too small for a jump to a stub.");
            at += (uint)insn.Length;
            covered += insn.Length;
        }
        uint siteEnd = siteRva + (uint)covered;
        uint returnRva = siteEnd;

        RejectBranchIntoSite(index, siteRva, siteEnd);
        RejectDisplacedRelocations(image, siteRva, siteEnd);
        RejectUnwindProlog(image, siteRva, siteEnd);

        // Disassemble the displaced instructions as numeric text so the assembler recomputes their relative branches and
        // RIP-relative operands at the stub address.
        var displacedLines = DisassembleDisplaced(image, siteRva, siteEnd, covered);
        string jmpBack = $"jmp 0x{image.ImageBase + returnRva:X}";
        string newCode = newAssembly ?? ("db " + Convert.ToHexString(newBytes));
        var program = mode switch
        {
            StubMode.Before => string.Join('\n', new[] { newCode }.Concat(displacedLines).Append(jmpBack)),
            StubMode.After => string.Join('\n', displacedLines.Concat([newCode, jmpBack])),
            _ => string.Join('\n', newCode, jmpBack),
        };

        // Size the stub far from the return address so the jump back is a rel32 upper bound, then place it and encode at
        // the real stub address (never larger than the upper bound).
        int upperBound = Assemble(image.Arch, image.ImageBase + image.SizeOfImage + 0x1000, program, resolve, "stub").Length;
        var caveRva = FindCave(index, siteRva, returnRva, upperBound)
            ?? throw new ToolError(ErrorCode.Conflict,
                $"no_space: no file-backed code cave of {upperBound} byte(s) within reach of {NativeAddress.Va(image, siteRva)} was found in an executable section.",
                "free space by shortening the new code, or add a code cave");
        if (!image.TryRvaToFileOffset(caveRva, out long stubFileOffset))
            throw new ToolError(ErrorCode.Conflict, "no_space: the chosen code cave is not backed by file bytes.");

        var stubBytes = Assemble(image.Arch, image.ImageBase + caveRva, program, resolve, "stub");
        if (stubBytes.Length > upperBound)
            throw new ToolError(ErrorCode.Conflict, "no_space: the stub did not fit the cave after final encoding.");

        var stubOriginal = new byte[stubBytes.Length];
        image.Read(caveRva, stubOriginal);

        // Site bytes: a near jump to the stub, the rest int3-padded.
        var jmp = Assemble(image.Arch, image.ImageBase + siteRva, $"jmp 0x{image.ImageBase + caveRva:X}", null, "site jump");
        if (jmp.Length > covered)
            throw new ToolError(ErrorCode.Conflict, "no_space_at_site: the jump to the stub does not fit the displaced range.");
        var siteReplacement = new byte[covered];
        jmp.CopyTo(siteReplacement, 0);
        for (int i = jmp.Length; i < covered; i++) siteReplacement[i] = 0xCC; // int3 pad
        var siteOriginal = new byte[covered];
        if (image.Read(siteRva, siteOriginal) < covered)
            throw new ToolError(ErrorCode.InvalidArgument, $"Only part of the {covered}-byte site at {NativeAddress.Va(image, siteRva)} is mapped.");

        string placement = $"cave in section '{image.SectionAt(caveRva)?.Name ?? "?"}'";
        var stub = new NativeStub(caveRva, stubFileOffset, stubOriginal, stubBytes, returnRva, mode.ToString().ToLowerInvariant(), placement);
        var patch = new NativePatch(siteRva, siteFileOffset, siteOriginal, siteReplacement, description) { Stub = stub };
        return new Result(patch, DisasmStub(image, caveRva, stubBytes), placement, covered - jmp.Length);
    }

    /// <summary>A branch targeting inside the displaced range (not its start) would land on int3 padding after the move.</summary>
    private static void RejectBranchIntoSite(NativeCodeIndex index, uint siteRva, uint siteEnd)
    {
        var image = index.Image;
        for (uint rva = siteRva + 1; rva < siteEnd; rva++)
            foreach (var x in index.RefsTo(rva, 8))
                if (x.IsCodeFlow)
                    throw new ToolError(ErrorCode.Conflict,
                        $"branch_target_in_site: {NativeAddress.Va(image, x.From)} branches to {NativeAddress.Va(image, rva)} inside the displaced range; moving those bytes to the stub would break it.",
                        "choose a site with no branch target inside it");
    }

    /// <summary>A displaced instruction with an absolute operand carries a base relocation that cannot be moved to the stub.</summary>
    private static void RejectDisplacedRelocations(INativeImage image, uint siteRva, uint siteEnd)
    {
        foreach (var r in image.RelocationRvas)
        {
            if (r >= siteEnd) break;
            if (r >= siteRva)
                throw new ToolError(ErrorCode.Unsupported,
                    $"displaced_absolute_reloc: a displaced instruction has an absolute operand at {NativeAddress.Va(image, r)} with a base relocation; moving it to the stub would require moving the relocation, which is not supported.",
                    "patch in place (no extend), or pick a site whose instructions use relative / RIP-relative operands");
        }
    }

    /// <summary>On x64, splitting the prologue described by unwind data breaks stack unwinding.</summary>
    private static void RejectUnwindProlog(INativeImage image, uint siteRva, uint siteEnd)
    {
        if (image.Arch != NativeArch.X64) return;
        foreach (var rf in image.RuntimeFunctions)
        {
            if (rf.BeginRva > siteRva) break;
            if (siteRva >= rf.EndRva || rf.UnwindInfoRva == 0) continue;
            Span<byte> head = stackalloc byte[2];
            if (image.Read(rf.UnwindInfoRva, head) < 2) continue;
            uint prologEnd = rf.BeginRva + head[1]; // UNWIND_INFO.SizeOfProlog
            if (siteRva < prologEnd && siteEnd > rf.BeginRva)
                throw new ToolError(ErrorCode.Unsupported,
                    $"unwind_data: the site at {NativeAddress.Va(image, siteRva)} is inside the {head[1]}-byte prologue of the x64 function at {NativeAddress.Va(image, rf.BeginRva)} described by unwind info; moving it to a stub would break stack unwinding.",
                    "extend a site past the prologue");
        }
    }

    private static List<string> DisassembleDisplaced(INativeImage image, uint siteRva, uint siteEnd, int count)
    {
        var dis = new NativeDisassembler(image); // no symbols: numeric targets the assembler can re-encode
        var lines = new List<string>();
        foreach (var line in dis.Disassemble(siteRva, count + 4, siteEnd))
        {
            if (line.Facts.Flow == FlowKind.Invalid || line.Text.StartsWith("(bad)"))
                throw new ToolError(ErrorCode.InvalidArgument,
                    $"displaced_not_relocatable: a displaced instruction at {NativeAddress.Va(image, line.Rva)} does not decode.");
            lines.Add(line.Text);
        }
        return lines;
    }

    private static byte[] Assemble(NativeArch arch, ulong va, string program, Func<string, ulong?>? resolve, string what)
    {
        try { return X86Assembler.Assemble(arch, va, program, resolve).Bytes; }
        catch (ToolError ex)
        {
            throw new ToolError(ErrorCode.InvalidArgument, $"displaced_not_relocatable: the {what} could not be assembled: {ex.Message}");
        }
    }

    /// <summary>
    /// A file-backed run of filler bytes (int3 / zero / nop) of at least <paramref name="size"/> bytes in an executable
    /// section, outside any known function, within a rel32 of the site and the return address. The site's own section is
    /// preferred. Null when none is found.
    /// </summary>
    private static uint? FindCave(NativeCodeIndex index, uint siteRva, uint returnRva, int size)
    {
        var image = index.Image;
        uint? best = null;
        bool bestInSiteSection = false;
        var siteSection = image.SectionAt(siteRva);
        long scanned = 0;
        foreach (var sec in image.Sections)
        {
            if (!sec.IsExecutable || sec.RawSize == 0) continue;
            uint extent = Math.Min(sec.MappedSize, sec.RawSize);
            if (extent < size) continue;
            var buf = new byte[extent];
            if (image.Read(sec.Rva, buf) < extent) continue;
            scanned += extent;
            if (scanned > MaxCaveScanBytes) break;

            int runStart = -1;
            byte runByte = 0;
            for (int i = 0; i <= buf.Length; i++)
            {
                bool filler = i < buf.Length && FillerBytes.Contains(buf[i]) && (runStart < 0 || buf[i] == runByte);
                if (filler)
                {
                    if (runStart < 0) { runStart = i; runByte = buf[i]; }
                    continue;
                }
                if (runStart >= 0 && i - runStart >= size)
                {
                    uint caveRva = sec.Rva + (uint)runStart;
                    if (TryCave(index, caveRva, size, siteRva, returnRva, out uint picked))
                    {
                        bool inSite = siteSection != null && sec.Rva == siteSection.Rva;
                        if (inSite && picked > siteRva) return picked; // same section, after the site: ideal
                        if (best == null || (inSite && !bestInSiteSection)) { best = picked; bestInSiteSection = inSite; }
                    }
                }
                runStart = i < buf.Length && FillerBytes.Contains(buf[i]) ? i : -1;
                runByte = runStart >= 0 ? buf[i] : (byte)0;
            }
        }
        return best;
    }

    /// <summary>Whether a <paramref name="size"/>-byte stub fits at <paramref name="caveRva"/>: file-backed, outside any function, in rel32 reach.</summary>
    private static bool TryCave(NativeCodeIndex index, uint caveRva, int size, uint siteRva, uint returnRva, out uint picked)
    {
        picked = caveRva;
        var image = index.Image;
        // Fully file-backed and contiguous.
        if (!image.TryRvaToFileOffset(caveRva, out long start)) return false;
        if (!image.TryRvaToFileOffset(caveRva + (uint)size - 1, out long end) || end != start + size - 1) return false;
        // Not inside a known function anywhere in the range.
        for (uint r = caveRva; r < caveRva + (uint)size; r = index.FunctionAt(r)?.End ?? (r + 1))
            if (index.FunctionAt(r) != null) return false;
        // rel32 reachable from the site (jmp there) and from the stub (jmp back).
        return Rel32(image.ImageBase + siteRva, image.ImageBase + caveRva)
            && Rel32(image.ImageBase + caveRva, image.ImageBase + returnRva);
    }

    private static bool Rel32(ulong from, ulong to)
    {
        long diff = (long)to - (long)from;
        return diff >= int.MinValue + 0x20 && diff <= int.MaxValue - 0x20;
    }

    private static string DisasmStub(INativeImage image, uint rva, byte[] bytes)
    {
        var synthetic = new ByteImage(image, rva, bytes);
        var dis = new NativeDisassembler(synthetic);
        var sb = new System.Text.StringBuilder();
        foreach (var line in dis.Disassemble(rva, bytes.Length, rva + (uint)bytes.Length))
            sb.AppendLine($"  {line.Address:X}  {line.Bytes,-24} {line.Text}");
        return sb.ToString();
    }
}
