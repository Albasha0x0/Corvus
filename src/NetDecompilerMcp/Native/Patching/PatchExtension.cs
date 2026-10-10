using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Native.Patching;

/// <summary>Where a patch-site extension places its stub: reuse a code cave, grow a new section, or let the tool decide.</summary>
public enum StubPlacement
{
    /// <summary>A reusable cave if one fits, otherwise a new section.</summary>
    Auto,
    /// <summary>A file-backed code cave only; refuse with no_space when none fits.</summary>
    Cave,
    /// <summary>A new executable section only.</summary>
    Section,
}

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
/// Patch-site extension for a patch larger than its site: the site becomes a 5-byte near jump (rest int3-padded) to a
/// stub holding the new code, unless <see cref="StubMode.Replace"/> the site's displaced instructions re-encoded for the
/// stub address, and a jump back to the instruction after the site. The stub goes in a file-backed code cave, else in
/// a new section (<see cref="GrowSection"/>). One <see cref="NativePatch"/> holds site and <see cref="NativeStub"/>, so
/// undo, export and save treat them as a unit. The stub gets no CFG flags (a jmp target, not an indirect-call target)
/// and on x64 no .pdata entry (no frame, entered and left by jmp): injected code that calls or faults and must unwind
/// needs a RUNTIME_FUNCTION added by hand. Refused with a reason code when a branch targets inside the displaced range,
/// a displaced instruction cannot be relocated, no cave fits (placement=cave), an x64 unwind prologue would be split,
/// the architecture is not x86/x64, or the section growth is refused.
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

    public static StubPlacement ParsePlacement(string? text) => (text ?? "").Trim().ToLowerInvariant() switch
    {
        "" or "auto" => StubPlacement.Auto,
        "cave" => StubPlacement.Cave,
        "section" => StubPlacement.Section,
        _ => throw new ToolError(ErrorCode.InvalidArgument, $"placement must be auto, cave or section, not '{text}'."),
    };

    /// <summary>The built extension: the recorded patch, the stub disassembly for the report, and placement facts.</summary>
    public sealed record Result(NativePatch Patch, string StubDisasm, string Placement, int SitePad);

    /// <summary>
    /// Builds a stub-extended patch at <paramref name="siteRva"/>. <paramref name="newAssembly"/> (patch_asm) is the
    /// new code assembled at the stub address; when it is null the raw <paramref name="newBytes"/> are emitted verbatim
    /// in the stub (patch_bytes). <paramref name="resolve"/> resolves symbols in the new assembly to VAs.
    /// </summary>
    public static Result Build(NativeCodeIndex index, uint siteRva, byte[] newBytes, string? newAssembly,
        StubMode mode, string description, Func<string, ulong?>? resolve, StubPlacement placement = StubPlacement.Auto)
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

        // Pick a cave unless the caller asked for a section; fall back to growing a section when no cave fits.
        uint? caveRva = placement == StubPlacement.Section ? null : FindCave(index, siteRva, returnRva, upperBound);
        if (caveRva == null && placement == StubPlacement.Cave)
            throw new ToolError(ErrorCode.Conflict,
                $"no_space: no file-backed code cave of {upperBound} byte(s) within reach of {NativeAddress.Va(image, siteRva)} was found in an executable section.",
                "free space by shortening the new code, pass placement=auto or section to grow a new section, or add a code cave");

        if (caveRva is { } cave)
        {
            if (!image.TryRvaToFileOffset(cave, out long stubFileOffset))
                throw new ToolError(ErrorCode.Conflict, "no_space: the chosen code cave is not backed by file bytes.");
            var stubBytes = Assemble(image.Arch, image.ImageBase + cave, program, resolve, "stub");
            if (stubBytes.Length > upperBound)
                throw new ToolError(ErrorCode.Conflict, "no_space: the stub did not fit the cave after final encoding.");
            var stubOriginal = new byte[stubBytes.Length];
            image.Read(cave, stubOriginal);
            string placementText = $"cave in section '{image.SectionAt(cave)?.Name ?? "?"}'";
            var stub = new NativeStub(cave, stubFileOffset, stubOriginal, stubBytes, returnRva, mode.ToString().ToLowerInvariant(), placementText)
                { NewCode = (byte[])newBytes.Clone(), NewAssembly = newAssembly };
            var (siteReplacement, pad) = SiteJump(image, siteRva, cave, covered);
            var patch = new NativePatch(siteRva, siteFileOffset, SiteOriginal(image, siteRva, covered), siteReplacement, description) { Stub = stub };
            return new Result(patch, DisasmStub(image, cave, stubBytes), placementText, pad);
        }

        var grown = GrowSection(index, siteRva, siteFileOffset, returnRva, covered, program, resolve, mode, description);
        return grown with { Patch = grown.Patch with { Stub = grown.Patch.Stub! with { NewCode = (byte[])newBytes.Clone(), NewAssembly = newAssembly } } };
    }

    /// <summary>The site's replacement bytes: a near jump to <paramref name="targetRva"/>, the rest int3-padded. Returns the pad count.</summary>
    private static (byte[] Replacement, int Pad) SiteJump(INativeImage image, uint siteRva, uint targetRva, int covered)
    {
        var jmp = Assemble(image.Arch, image.ImageBase + siteRva, $"jmp 0x{image.ImageBase + targetRva:X}", null, "site jump");
        if (jmp.Length > covered)
            throw new ToolError(ErrorCode.Conflict, "no_space_at_site: the jump to the stub does not fit the displaced range.");
        var replacement = new byte[covered];
        jmp.CopyTo(replacement, 0);
        for (int i = jmp.Length; i < covered; i++) replacement[i] = 0xCC; // int3 pad
        return (replacement, covered - jmp.Length);
    }

    private static byte[] SiteOriginal(INativeImage image, uint siteRva, int covered)
    {
        var original = new byte[covered];
        if (image.Read(siteRva, original) < covered)
            throw new ToolError(ErrorCode.InvalidArgument, $"Only part of the {covered}-byte site at {NativeAddress.Va(image, siteRva)} is mapped.");
        return original;
    }

    /// <summary>
    /// Places the stub in a new executable section appended to the file: a new section header in a free table slot, the
    /// stub bytes as the section's raw data past the end of file, and the header fields (section count, SizeOfImage,
    /// SizeOfCode) updated; the PE checksum is recomputed on save. Refused with a reason code when a
    /// header slot is unavailable (no_header_space), the stub would need a base relocation that is not added
    /// (stub_needs_reloc), or the jump cannot reach the new section (unreachable_section).
    /// </summary>
    private static Result GrowSection(NativeCodeIndex index, uint siteRva, long siteFileOffset, uint returnRva, int covered,
        string program, Func<string, ulong?>? resolve, StubMode mode, string description)
    {
        if (index.Image is not PeFile pe)
            throw new ToolError(ErrorCode.Unsupported, "section_growth_unsupported: growing a section needs the built-in PE parser.");
        uint sa = pe.Optional.SectionAlignment, fa = pe.Optional.FileAlignment;
        if (sa == 0 || fa == 0 || (sa & (sa - 1)) != 0 || (fa & (fa - 1)) != 0)
            throw new ToolError(ErrorCode.Unsupported, $"bad_alignment: SectionAlignment 0x{sa:X} / FileAlignment 0x{fa:X} are not usable powers of two for a new section.");

        // A header slot must be free: after the current section table and inside both SizeOfHeaders and the first raw data.
        int count = pe.Coff.NumberOfSections;
        long slotOffset = pe.SectionTableOffset + (long)count * 40;
        long firstRaw = pe.Sections.Where(s => s.RawSize != 0).Select(s => (long)s.RawOffset).DefaultIfEmpty(long.MaxValue).Min();
        long headerLimit = Math.Min(pe.Optional.SizeOfHeaders, firstRaw);
        if (slotOffset + 40 > headerLimit)
            throw new ToolError(ErrorCode.Conflict,
                $"no_header_space: the section table has no free 40-byte slot before the first section's raw data (slot at 0x{slotOffset:X}, limit 0x{headerLimit:X}); a new section header does not fit.",
                "use placement=cave if a code cave exists, or patch in place without extend");

        // The new section maps right after the current image and its raw data is appended at the aligned end of file.
        uint newRva = AlignU(pe.SizeOfImage, sa);
        long appendOffset = AlignUp(pe.FileSize, fa);

        var stubBytes = Assemble(index.Image.Arch, index.Image.ImageBase + newRva, program, resolve, "stub");
        RejectStubRelocation(pe, newRva, stubBytes);
        if (!Rel32(index.Image.ImageBase + siteRva, index.Image.ImageBase + newRva) || !Rel32(index.Image.ImageBase + newRva, index.Image.ImageBase + returnRva))
            throw new ToolError(ErrorCode.Conflict,
                $"unreachable_section: the new section at {NativeAddress.Va(index.Image, newRva)} is not within a rel32 near jump of {NativeAddress.Va(index.Image, siteRva)}; the stub cannot be reached.",
                "patch in place, or use a code cave within reach");

        uint virtualSize = (uint)stubBytes.Length;
        uint rawSize = AlignU(virtualSize, fa);
        var rawData = new byte[rawSize];
        stubBytes.CopyTo(rawData, 0);
        uint newSizeOfImage = newRva + AlignU(virtualSize, sa);

        // Header edits: the new section header, the section count, SizeOfImage and SizeOfCode.
        string name = NewSectionName(pe);
        var header = BuildSectionHeader(name, newRva, virtualSize, rawSize, (uint)appendOffset);
        var edits = new List<HeaderEdit>
        {
            MakeEdit(pe, slotOffset, header),
            MakeEdit(pe, pe.PeHeaderOffset + 6, U16le((ushort)(count + 1))),
            MakeEdit(pe, pe.OptionalHeaderOffset + 56, U32le(newSizeOfImage)),
            MakeEdit(pe, pe.OptionalHeaderOffset + 4, U32le(pe.Optional.SizeOfCode + rawSize)),
        };
        var growth = new SectionGrowth(name, newRva, virtualSize, appendOffset, rawData, edits);

        var (siteReplacement, pad) = SiteJump(index.Image, siteRva, newRva, covered);
        string placementText = $"new section '{name}' at {NativeAddress.Va(index.Image, newRva)}";
        var stub = new NativeStub(newRva, appendOffset, new byte[stubBytes.Length], stubBytes, returnRva, mode.ToString().ToLowerInvariant(), placementText);
        var patch = new NativePatch(siteRva, siteFileOffset, SiteOriginal(index.Image, siteRva, covered), siteReplacement, description)
        {
            Stub = stub,
            Growth = growth,
        };
        return new Result(patch, DisasmStub(index.Image, newRva, stubBytes), placementText, pad);
    }

    /// <summary>Refuses the growth when the stub holds an in-image absolute operand that would need a base relocation (not added for a new section).</summary>
    private static void RejectStubRelocation(PeFile pe, uint stubRva, byte[] stubBytes)
    {
        if (!PatchRelocations.IsRelocatable(pe)) return; // fixed base: absolute operands are correct as written
        int bitness = pe.Is64Bit ? 64 : 32;
        foreach (var o in PatchRelocations.Decode(bitness, pe.ImageBase + stubRva, stubBytes))
        {
            ulong value = o.Size == 4 ? o.Value & 0xFFFFFFFF : o.Value;
            if (value >= pe.ImageBase && value - pe.ImageBase < pe.SizeOfImage)
                throw new ToolError(ErrorCode.Unsupported,
                    $"stub_needs_reloc: the stub holds the absolute in-image address 0x{value:X}, which needs a base relocation; a stub in a new section is not given one, so under ASLR / a rebase it would be wrong.",
                    pe.Is64Bit ? "write the reference RIP-relative (e.g. 'lea rax, [target]'), or load it from already-relocated data" : "load the address from already-relocated data (an existing pointer / IAT slot)");
        }
    }

    private static HeaderEdit MakeEdit(PeFile pe, long fileOffset, byte[] replacement)
    {
        var original = new byte[replacement.Length];
        pe.FileBytes.Span.Slice((int)fileOffset, replacement.Length).CopyTo(original);
        return new HeaderEdit(fileOffset, original, replacement);
    }

    /// <summary>A distinct 8-byte section name (".ndm", then ".ndm1", ".ndm2", ... when taken).</summary>
    private static string NewSectionName(PeFile pe)
    {
        var taken = pe.Sections.Select(s => s.Name).ToHashSet(StringComparer.Ordinal);
        if (!taken.Contains(".ndm")) return ".ndm";
        for (int i = 1; i < 1000; i++)
            if (!taken.Contains($".ndm{i}")) return $".ndm{i}";
        return ".ndm";
    }

    private static byte[] BuildSectionHeader(string name, uint rva, uint virtualSize, uint rawSize, uint rawOffset)
    {
        var h = new byte[40];
        var nameBytes = System.Text.Encoding.ASCII.GetBytes(name);
        nameBytes.AsSpan(0, Math.Min(8, nameBytes.Length)).CopyTo(h);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(8), virtualSize);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(12), rva);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(16), rawSize);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(20), rawOffset);
        // PointerToRelocations/Linenumbers and their counts stay zero.
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(36), 0x60000020); // CNT_CODE | MEM_EXECUTE | MEM_READ
        return h;
    }

    private static byte[] U16le(ushort v) => [(byte)v, (byte)(v >> 8)];
    private static byte[] U32le(uint v) => [(byte)v, (byte)(v >> 8), (byte)(v >> 16), (byte)(v >> 24)];
    private static uint AlignU(uint value, uint alignment) => (value + alignment - 1) & ~(alignment - 1);
    private static long AlignUp(long value, uint alignment) => (value + alignment - 1) & ~(long)(alignment - 1);

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
        if (!image.TryRvaToFileOffset(caveRva, out long start)) return false;
        if (!image.TryRvaToFileOffset(caveRva + (uint)size - 1, out long end) || end != start + size - 1) return false;
        for (uint r = caveRva; r < caveRva + (uint)size; r = index.FunctionAt(r)?.End ?? (r + 1))
            if (index.FunctionAt(r) != null) return false;
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
