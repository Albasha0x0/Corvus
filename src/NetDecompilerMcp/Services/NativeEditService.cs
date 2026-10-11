using System.Buffers.Binary;
using System.Text;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Patching;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Native annotations (rename / comment, persisted per file hash) and in-memory byte patching (patch_bytes / patch_asm,
/// recorded as undoable edits and written out by save_native). Patches are overlaid on a snapshot of the original file
/// bytes; after a change the image the workspace holds is replaced with one parsed from the patched bytes and its
/// analysis is discarded, so every read path (disassembly, strings, search_bytes, read_bytes, the code index) sees the
/// patched bytes. All mutating calls run under the workspace write lock.
/// </summary>
public sealed class NativeEditService(AssemblyWorkspace workspace, NativeCodeService code)
{
    public NativeAnnotations Annotations(LoadedNative native) => code.Annotations(native);

    public string Rename(LoadedNative native, NativeCodeIndex index, uint rva, string name, bool allowDuplicate)
    {
        var ann = Annotations(native);
        var valid = NativeName.Validate(name);
        workspace.Write(() =>
        {
            ann.SetName(rva, valid, allowDuplicate);
            code.Ready(native)?.SetUserName(rva, valid);
            index.SetUserName(rva, valid);
            return 0;
        });
        var where = index.FunctionAt(rva) is { } f && f.Start == rva ? "function" : index.FunctionAt(rva) != null ? "address in a function" : "address";
        return $"Named {where} {NativeAddress.Va(index.Image, rva)} '{valid}'.{StaleNote(ann)}";
    }

    public string ClearName(LoadedNative native, NativeCodeIndex index, uint rva)
    {
        var ann = Annotations(native);
        workspace.Write(() => { ann.SetName(rva, null); code.Ready(native)?.SetUserName(rva, null); index.SetUserName(rva, null); return 0; });
        return $"Cleared the name at {NativeAddress.Va(index.Image, rva)}.";
    }

    public string Comment(LoadedNative native, NativeCodeIndex index, uint rva, string? text)
    {
        var ann = Annotations(native);
        workspace.Write(() => { ann.SetComment(rva, text); code.Ready(native)?.SetUserComment(rva, text); index.SetUserComment(rva, text); return 0; });
        return string.IsNullOrWhiteSpace(text)
            ? $"Cleared the comment at {NativeAddress.Va(index.Image, rva)}."
            : $"Commented {NativeAddress.Va(index.Image, rva)}.{StaleNote(ann)}";
    }

    /// <summary>Records names (null or empty: cleared) with one sidecar write and shows them in the code index; refused as a whole on a duplicate.</summary>
    public void ApplyNames(LoadedNative native, NativeCodeIndex index, IReadOnlyList<(uint Rva, string? Name)> names, bool allowDuplicate)
    {
        var ann = Annotations(native);
        workspace.Write(() =>
        {
            ann.Apply(names, [], [], allowDuplicate);
            foreach (var (rva, _) in names)
            {
                var now = ann.NameAt(rva);
                code.Ready(native)?.SetUserName(rva, now);
                index.SetUserName(rva, now);
            }
            return 0;
        });
    }

    /// <summary>A comment change at an address: <see cref="Line"/> the disassembly / function comment, <see cref="Pseudo"/> the decompiler comment; null leaves one, "" removes it.</summary>
    public sealed record CommentChange(uint Rva, string? Line, string? Pseudo)
    {
        /// <summary>With <see cref="Line"/>: the engine comment kind (<see cref="NativeCommentKinds"/>); null: repeatable.</summary>
        public string? Kind { get; init; }
    }

    /// <summary>Records <paramref name="changes"/> with one sidecar write and shows the line comments in the code index.</summary>
    public void ApplyComments(LoadedNative native, NativeCodeIndex index, IReadOnlyList<CommentChange> changes)
    {
        var ann = Annotations(native);
        var lines = changes.Where(c => c.Line != null).Select(c => (c.Rva, Text: (string?)c.Line!.Trim())).ToList();
        var pseudo = changes.Where(c => c.Pseudo != null).Select(c => (c.Rva, (string?)c.Pseudo)).ToList();
        workspace.Write(() =>
        {
            ann.Apply([], lines, pseudo, kinds: changes.Where(c => c.Line != null).Select(c => (c.Rva, c.Kind)).ToList());
            foreach (var (rva, text) in lines)
            {
                var shown = string.IsNullOrEmpty(text) ? null : ann.CommentAt(rva);
                code.Ready(native)?.SetUserComment(rva, shown);
                index.SetUserComment(rva, shown);
            }
            return 0;
        });
    }

    /// <summary>
    /// <paramref name="text"/> appended to <paramref name="current"/> on a new line; with <paramref name="dedupe"/> a text
    /// already one of its lines is not added again (null: nothing to change).
    /// </summary>
    public static string? AppendComment(string? current, string text, bool dedupe)
    {
        var line = text.Trim();
        if (string.IsNullOrEmpty(current)) return line.Length == 0 ? null : line;
        if (line.Length == 0 || (dedupe && current.Split('\n').Any(l => l.Trim() == line))) return null;
        return current.TrimEnd('\n') + "\n" + line;
    }

    private static string StaleNote(NativeAnnotations ann) => ann.StaleSiblingHashes.Count == 0 ? ""
        : $" (note: a sidecar of annotations exists for this path under {ann.StaleSiblingHashes.Count} other file hash(es); this file's current bytes are a separate, clean annotation set.)";

    /// <summary>Plans a patch over code: validates the start boundary, the file mapping and the function end; returns the file offset and the NOP-padded length.</summary>
    private (long FileOffset, int PaddedLength, int Covered, string? Note) Plan(NativeCodeIndex index, uint rva, int newLength, bool force)
    {
        var image = index.Image;
        if (!image.TryRvaToFileOffset(rva, out var fileOffset))
            throw new ToolError(ErrorCode.InvalidArgument, $"{NativeAddress.Va(image, rva)} is not backed by file bytes (zero-fill or outside the image); there is nothing to patch there.");
        if (!force && rva < image.Sections.Where(s => s.Rva > 0).DefaultIfEmpty().Min(s => s?.Rva ?? uint.MaxValue))
            throw new ToolError(ErrorCode.InvalidArgument, $"{NativeAddress.Va(image, rva)} is in the PE headers.", "pass force=true to patch header bytes");

        // Require [rva, rva+newLength) to be contiguous in the file.
        if (!image.TryRvaToFileOffset(rva + (uint)newLength - 1, out var lastOffset) || lastOffset != fileOffset + newLength - 1)
            throw new ToolError(ErrorCode.InvalidArgument, $"The {newLength}-byte range at {NativeAddress.Va(image, rva)} crosses an unmapped gap or section boundary in the file.");

        var section = image.SectionAt(rva);
        bool isCode = section is { IsExecutable: true } && index.Support == CodeSupport.Full;
        if (!isCode) return (fileOffset, newLength, newLength, null); // data: exact overwrite, no padding

        // The patch must start on an instruction boundary of its function (otherwise it splits an instruction).
        if (!force && index.FunctionAt(rva) is { } owner && owner.Start != rva)
        {
            uint scan = owner.Start;
            while (scan < rva && index.Decode(scan) is { Length: > 0 } s) scan += (uint)s.Length;
            if (scan != rva)
                throw new ToolError(ErrorCode.InvalidArgument, $"{NativeAddress.Va(image, rva)} is in the middle of an instruction in {owner.Name}.", "pass force=true to patch mid-instruction");
        }

        // Decode from rva to find the instruction boundary at/after rva+newLength.
        int covered = 0;
        while (covered < newLength)
        {
            if (index.Decode(rva + (uint)covered) is not { } insn || insn.Length == 0)
            {
                if (force) { covered = newLength; break; }
                throw new ToolError(ErrorCode.InvalidArgument, $"The bytes at {NativeAddress.Va(image, rva + (uint)covered)} do not decode, so the overwrite boundary is unknown.", "pass force=true to patch anyway");
            }
            covered += insn.Length;
        }
        if (!force && index.FunctionAt(rva) is { } fn && rva + (uint)covered > fn.End)
            throw new ToolError(ErrorCode.InvalidArgument, $"The patch would overwrite past the end of {fn.Name} ({NativeAddress.Va(image, fn.End)}).", "pass force=true to overwrite past the function end");

        int pad = covered - newLength;
        var note = pad > 0 ? $"padded {pad} trailing byte(s) with NOPs to the next instruction boundary" : null;
        return (fileOffset, covered, covered, note);
    }

    public sealed record PatchResult(NativePatch Patch, string BeforeDisasm, string AfterDisasm, string Note, string StubPreview = "");

    /// <summary>
    /// Prepares a patch-site extension: the site becomes a jump to a stub in slack space that runs the new code (and,
    /// unless the mode is replace, the displaced original instructions) and returns after the site. See
    /// <see cref="PatchExtension"/> for the safety rules and reason codes.
    /// </summary>
    public PatchResult PrepareExtendedPatch(NativeCodeIndex index, uint rva, byte[] newBytes, string? assembly,
        StubMode mode, string description, Func<string, ulong?>? resolve, StubPlacement placement = StubPlacement.Auto)
    {
        var ext = PatchExtension.Build(index, rva, newBytes, assembly, mode, description, resolve, placement);
        var image = index.Image;
        var before = Disasm(index, rva, ext.Patch.Length);
        var after = DisasmBytes(image, rva, ext.Patch.Replacement);
        var stub = ext.Patch.Stub!;
        var preview = new StringBuilder();
        preview.AppendLine($"Stub ({stub.Mode}) at {NativeAddress.Va(image, stub.Rva)} ({ext.Placement}), returns to {NativeAddress.Va(image, stub.ReturnRva)}:");
        preview.Append(ext.StubDisasm);
        if (ext.SitePad > 0) preview.AppendLine($"  site: {ext.SitePad} int3 pad byte(s) after the jump");
        return new PatchResult(ext.Patch, before, after, "extended with a relocation stub", preview.ToString());
    }

    /// <summary>Fills <paramref name="replacement"/> after <paramref name="used"/> bytes with the architecture's NOP.</summary>
    internal static void PadWithNops(INativeImage image, byte[] replacement, int used)
    {
        if (used == replacement.Length) return;
        switch (image.Arch)
        {
            case NativeArch.X86 or NativeArch.X64:
                replacement.AsSpan(used).Fill(0x90);
                return;
            case NativeArch.Arm64 when used % 4 == 0 && (replacement.Length - used) % 4 == 0:
                for (int i = used; i < replacement.Length; i += 4)
                    BinaryPrimitives.WriteUInt32LittleEndian(replacement.AsSpan(i), 0xD503201F); // nop
                return;
            case NativeArch.Arm64:
                throw new ToolError(ErrorCode.InvalidArgument,
                    $"ARM64 instructions are 4 bytes: a {used}-byte patch over {replacement.Length} bytes cannot be padded with whole NOPs.",
                    "give a whole number of instructions");
            default:
                throw new ToolError(ErrorCode.Unsupported, $"Padding a patch is not supported for {image.Arch} code; give bytes covering whole instructions.");
        }
    }

    /// <summary>Parses the relocations option of patch_bytes / patch_asm (auto, keep, neutralize; default auto).</summary>
    public static RelocationMode ParseRelocationMode(string? text) => (text ?? "").Trim().ToLowerInvariant() switch
    {
        "" or "auto" => RelocationMode.Auto,
        "keep" => RelocationMode.Keep,
        "neutralize" or "neutralise" => RelocationMode.Neutralize,
        _ => throw new ToolError(ErrorCode.InvalidArgument, $"relocations must be auto, keep or neutralize, not '{text}'."),
    };

    /// <summary>
    /// Prepares a patch of <paramref name="newBytes"/> at <paramref name="rva"/>: the NOP-padded replacement, the
    /// before/after disassembly, and the base-relocation plan. <paramref name="assembled"/> are the operand constants
    /// the assembler produced (with which ones came from symbols); null for raw bytes, whose constants are decoded.
    /// </summary>
    public PatchResult PreparePatch(NativeCodeIndex index, uint rva, byte[] newBytes, bool force, string description,
        RelocationMode relocations = RelocationMode.Auto, IReadOnlyList<OperandConstant>? assembled = null, string? assembly = null)
    {
        var image = index.Image;
        var (fileOffset, paddedLength, _, note) = Plan(index, rva, newBytes.Length, force);
        var replacement = new byte[paddedLength];
        newBytes.CopyTo(replacement, 0);
        PadWithNops(image, replacement, newBytes.Length);

        var original = new byte[paddedLength];
        int read = image.Read(rva, original);
        if (read < paddedLength) throw new ToolError(ErrorCode.InvalidArgument, $"Only {read} of {paddedLength} bytes at {NativeAddress.Va(image, rva)} are mapped.");

        var plan = RelocationPlan.None;
        if (image is PeFile pe)
        {
            bool x86 = image.Arch is NativeArch.X86 or NativeArch.X64;
            bool code = image.SectionAt(rva) is { IsExecutable: true } && x86;
            var operands = assembled ?? (code ? PatchRelocations.Decode(image.Is64Bit ? 64 : 32, image.ImageBase + rva, replacement) : null);
            plan = PatchRelocations.Plan(pe, rva, original, replacement, operands, assembled == null, relocations, force);
        }

        var patch = new NativePatch(rva, fileOffset, original, replacement, description, plan) { Assembly = assembly };
        var before = Disasm(index, rva, paddedLength);
        var after = DisasmBytes(image, rva, replacement);
        return new PatchResult(patch, before, after, note ?? "");
    }

    public string ApplyPatch(LoadedNative native, NativeCodeIndex index, PatchResult prepared, bool dryRun)
    {
        var image = index.Image;
        if (native.Patches.Conflicting(prepared.Patch) is { } clash && !dryRun)
            throw new ToolError(ErrorCode.Conflict, $"An existing patch already covers {NativeAddress.Va(image, clash.Rva)} or its relocation entries (#{native.Patches.Patches.ToList().IndexOf(clash) + 1}). undo_native_edit it first.");

        var sb = new StringBuilder();
        sb.AppendLine($"{(dryRun ? "Dry run — would patch" : "Patched")} {prepared.Patch.Length} byte(s) at {NativeAddress.Va(image, prepared.Patch.Rva)}" +
                      (prepared.Note.Length > 0 ? $" ({prepared.Note})" : "") + ":");
        sb.AppendLine("Before:");
        sb.Append(prepared.BeforeDisasm);
        sb.AppendLine("After:");
        sb.Append(prepared.AfterDisasm);
        AppendRelocations(sb, image, prepared.Patch.Relocations, "  ");
        if (prepared.StubPreview.Length > 0) sb.Append(prepared.StubPreview);
        if (dryRun) return sb.ToString();

        workspace.Write(() =>
        {
            native.Patches.Add(prepared.Patch);
            Rebuild(native);
            return 0;
        });
        sb.AppendLine($"Recorded as native edit #{native.Patches.Patches.Count}. list_native_edits shows them; undo_native_edit reverts; save_native writes the file.");
        return sb.ToString();
    }

    /// <summary>Rebuilds the patched image and swaps it in; analysis (code index, sessions) is discarded and rebuilds lazily.</summary>
    private void Rebuild(LoadedNative native) => native.ReplaceImage(native.Patches.ApplyTo(native.FilePath));

    public string List(LoadedNative native)
    {
        var patches = native.Patches.Patches;
        var names = new StringBuilder();
        AppendNames(names, native);
        if (patches.Count == 0) return names.Length == 0 ? $"{native.Id}: no native edits." : $"{native.Id}: no native edits.\n{names}";
        var sb = new StringBuilder($"{native.Id}: {patches.Count} native edit(s)\n");
        int i = 1;
        foreach (var p in patches)
        {
            sb.AppendLine($"  #{i++}  {NativeAddress.Va(native.Image, p.Rva)}  {p.Length} bytes  {Hex(p.Original)} -> {Hex(p.Replacement)}  {p.Description}");
            if (p.Stub is { } s)
                sb.AppendLine($"        stub ({s.Mode}) at {NativeAddress.Va(native.Image, s.Rva)}  {s.Length} bytes  returns to {NativeAddress.Va(native.Image, s.ReturnRva)}  ({s.Placement})");
            AppendRelocations(sb, native.Image, p.Relocations, "      ");
        }
        return sb.Append(names).ToString();
    }

    /// <summary>The user's name and comment counts and every imported name layer: source, counts, origin, saved or restored, and when.</summary>
    private void AppendNames(StringBuilder sb, LoadedNative native)
    {
        code.RestoreImported(native);
        var ann = native.AnnotationsOrNull ?? code.Annotations(native);
        var layers = NativeNameLayers.OfOrNull(native)?.Layers ?? [];
        if (ann.NameCount == 0 && ann.CommentCount == 0 && layers.Count == 0) return;
        sb.AppendLine("Names (priority user > pdb > nativeaot > il2cpp > ida > ghidra > discovered):");
        if (ann.NameCount > 0 || ann.CommentCount > 0)
            sb.AppendLine($"  user: {ann.NameCount} name(s), {ann.CommentCount} comment(s), saved per file hash in {code.AnnotationRoot}");
        foreach (var l in layers)
        {
            var state = l.Info switch
            {
                { Restored: true } info => $"restored on load (imported {info.ImportedUtc:yyyy-MM-dd HH:mm} UTC)",
                { } info => $"imported {info.ImportedUtc:yyyy-MM-dd HH:mm} UTC, saved for the next load",
                null => l.Source == NativeNameSource.Pdb ? "found automatically, not saved (read again on load)" : "this session only",
            };
            var source = l.Info is { SourcePath: { } path } i2 ? $"; source {path}{(i2.SourceIdentity is { } id ? $" ({l.Source switch { NativeNameSource.Pdb => "GUID age ", NativeNameSource.NativeAot => "", _ => "sha256 " }}{id})" : "")}" : "";
            sb.AppendLine($"  {l.Source.Id()}: {l.Names.Count} name(s), {l.Comments.Count} comment(s) from {l.Origin}; {state}{source}");
        }
    }

    /// <summary>The relocation side of a patch: one line per kept / neutralized / added / unrelocated entry, then notes.</summary>
    private static void AppendRelocations(StringBuilder sb, INativeImage image, RelocationPlan? plan, string indent)
    {
        if (plan == null || (plan.Changes.Count == 0 && plan.Notes.Count == 0)) return;
        if (plan.Changes.Count > 0)
        {
            sb.AppendLine($"{indent}Relocations:");
            foreach (var c in plan.Changes)
                sb.AppendLine($"{indent}  {c.Action,-11} {c.Type.ToString().ToUpperInvariant(),-8} at {NativeAddress.Va(image, c.TargetRva)}" +
                              (c.SlotRva is { } slot ? $"  (entry at rva 0x{slot:X})" : "") + (c.Note is { Length: > 0 } n ? $"  {n}" : ""));
        }
        foreach (var note in plan.Notes) sb.AppendLine($"{indent}Note: {note}");
    }

    public string Undo(LoadedNative native, int? number)
    {
        return workspace.Write(() =>
        {
            if (native.Patches.LaterSlotUser(number) is { } later)
                throw new ToolError(ErrorCode.Conflict,
                    $"Native edit #{later.Number} ({later.Patch.Description}) rewrote a relocation entry this edit also rewrote; undoing this one first would leave the table inconsistent.",
                    $"undo #{later.Number} first");
            var removed = native.Patches.Remove(number);
            if (removed == null) throw new ToolError(ErrorCode.NotFound, number is { } n ? $"There is no native edit #{n}." : "There are no native edits to undo.");
            Rebuild(native);
            return $"Undid the patch at {NativeAddress.Va(native.Image, removed.Rva)} ({removed.Description}). {native.Patches.Patches.Count} native edit(s) remain.";
        });
    }

    public string Save(LoadedNative native, string outputPath, bool overwrite, bool stripSignature)
    {
        if (string.IsNullOrWhiteSpace(outputPath))
            throw new ToolError(ErrorCode.InvalidArgument, "An output path is required.");
        var (target, isOriginal) = SaveTarget.Resolve(outputPath, native.FilePath, native.OriginalSha256, overwrite);

        var notes = new List<string>();
        var bytes = OutputBytes(native, stripSignature, notes);

        string? backup = isOriginal ? SaveTarget.Backup(target, native.Patches.OriginalBytes()) : null;
        string verify = "";
        // Verified on the written temp file, so a file that does not read back or parse never replaces the target.
        SafeFile.WriteAllBytes(target, bytes, overwrite, temp =>
        {
            var written = File.ReadAllBytes(temp);
            if (!written.AsSpan().SequenceEqual(bytes))
                throw new ToolError(ErrorCode.IoError, $"The bytes written for {target} did not read back as written. Nothing was replaced.");
            verify = Verify(native, written, stripSignature);
            if (verify.StartsWith(UnparsableNote, StringComparison.Ordinal))
                throw new ToolError(ErrorCode.Conflict, $"Not saved: {verify} Nothing was replaced.");
        });
        return $"Wrote {target} ({bytes.Length:N0} bytes, {native.Patches.Patches.Count} patch(es))." +
               (backup != null ? $" Original backed up to {backup}." : "") +
               (notes.Count > 0 ? "\n  " + string.Join("\n  ", notes) : "") +
               $"\n{verify}";
    }

    /// <summary>The image's patches in an export format (export_native_patches); the caller holds the workspace lock.</summary>
    public static PatchExportResult RenderPatches(LoadedNative native, PatchExport.Format format)
    {
        var notes = new List<string>();
        var output = OutputBytes(native, stripSignature: false, notes);
        var original = native.Patches.OriginalBytes();
        var pe = native.RequirePe("export_native_patches");
        var appended = native.Patches.Patches.Where(p => p.Growth != null).Select(p =>
        {
            var g = p.Growth!;
            return new AppendedSection(g.SectionName, g.SectionRva, g.SectionVirtualSize, g.AppendFileOffset, g.AppendedData);
        }).ToList();
        var source = new PatchExportSource(native.FilePath, native.OriginalSha256, pe.ImageBase, pe.Arch, native.Patches.Patches.ToList(), original, output,
            pe.OptionalHeaderOffset + 64, offset => pe.TryFileOffsetToRva(offset, out var rva) ? rva : null, appended);
        var rendered = PatchExport.Render(source, format);
        rendered.Notes.InsertRange(0, notes.Where(n => n.StartsWith("The file is Authenticode-signed", StringComparison.Ordinal)));
        return rendered;
    }

    /// <summary>
    /// The bytes save_native writes: the patched bytes, the certificate table removed when <paramref name="stripSignature"/>,
    /// and the PE checksum recomputed when the original had one. export_native_patches exports the same bytes.
    /// </summary>
    public static byte[] OutputBytes(LoadedNative native, bool stripSignature, List<string> notes)
    {
        var bytes = native.Patches.PatchedBytes();
        var patchedImage = PeFile.FromBytes(bytes, native.FilePath);

        if (stripSignature) StripSignature(ref bytes, patchedImage, notes);

        // Recompute the PE checksum when the original had one.
        if (patchedImage.Checksum.Stored != 0)
        {
            var recomputed = PeFile.FromBytes(bytes, native.FilePath);
            uint sum = recomputed.Checksum.Computed;
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan((int)(patchedImage.OptionalHeaderOffset + 64)), sum);
            notes.Add($"PE checksum recomputed to 0x{sum:X8}.");
        }

        if (!stripSignature && patchedImage.CertificateTable is not null)
            notes.Add("The file is Authenticode-signed; after patching the signature no longer matches and the file is effectively unsigned. Pass stripSignature=true to remove the certificate table.");
        return bytes;
    }

    private static void StripSignature(ref byte[] bytes, PeFile image, List<string> notes)
    {
        if (image.CertificateTable is not var (offset, size) || image.CertificateTable is null)
        {
            notes.Add("No certificate table to remove.");
            return;
        }
        // Zero the security data directory entry (address + size) in the optional header.
        long dirEntry = image.OptionalHeaderOffset + (image.Is64Bit ? 112 : 96) + PeDirectory.Security * 8L;
        if (dirEntry + 8 <= bytes.Length)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan((int)dirEntry), 0);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan((int)dirEntry + 4), 0);
        }
        // The certificate table lives in the trailing overlay; drop it (and nothing after it belongs to the image).
        if (offset + size == bytes.Length)
        {
            Array.Resize(ref bytes, (int)offset);
            notes.Add($"Removed the {size}-byte certificate table and zeroed the security directory entry.");
        }
        else
            notes.Add("Zeroed the security directory entry; the certificate bytes are not at the end of the file, so they were left in place.");
    }

    private const string UnparsableNote = "WARNING: the written file could not be re-parsed for verification";

    private string Verify(LoadedNative native, byte[] written, bool strippedSignature)
    {
        try
        {
            var reparsed = PeFile.FromBytes(written, native.FilePath);
            var originalBytes = native.Patches.OriginalBytes();
            long checksumField = reparsed.OptionalHeaderOffset + 64;
            var patched = native.Patches.Patches;
            var ranges = patched.Select(p => (Start: p.FileOffset, Length: (long)p.Length))
                .Concat(patched.Where(p => p.Stub != null).Select(p => (Start: p.Stub!.FileOffset, Length: (long)p.Stub!.Length)))
                .Concat(patched.SelectMany(p => p.RelocationEdits).Select(e => (Start: e.FileOffset, Length: 2L)))
                .Concat(patched.Where(p => p.Growth != null).SelectMany(p => p.Growth!.HeaderEdits).Select(h => (Start: h.FileOffset, Length: (long)h.Length)))
                .Concat(patched.Where(p => p.Growth != null).Select(p => (Start: p.Growth!.AppendFileOffset, Length: (long)p.Growth!.AppendedData.Length))).ToList();
            long grownBy = Math.Max(0, (long)written.Length - originalBytes.Length);
            int mismatches = 0;
            for (int i = 0; i < Math.Min(originalBytes.Length, written.Length); i++)
            {
                if (i >= checksumField && i < checksumField + 4) continue;          // checksum field may differ
                if (strippedSignature) continue;                                     // signature strip changes several areas
                if (ranges.Any(r => i >= r.Start && i < r.Start + r.Length)) continue; // inside a patch, a relocation / header rewrite or the appended section
                if (originalBytes[i] != written[i]) mismatches++;
            }
            var grown = grownBy > 0 ? $" (grown by {grownBy:N0} byte(s) for an appended section)" : "";
            var bytesLine = mismatches == 0
                ? $"Verified: every byte outside the patched ranges (and the checksum field) matches the original{grown}."
                : $"WARNING: {mismatches} byte(s) outside the patched ranges differ from the original{grown}.";
            return bytesLine + "\n" + VerifyRelocations(reparsed, PeFile.FromBytes(originalBytes, native.FilePath), patched);
        }
        catch (Exception ex) when (ex is ToolError or IOException)
        {
            return $"{UnparsableNote} ({ex.Message}).";
        }
    }

    /// <summary>
    /// Re-parses the written relocation table and checks it against the patches: inside every patched range exactly the
    /// kept and added entries remain (nothing neutralized survives, nothing unplanned appears), and the table reads with
    /// no more issues than the original's.
    /// </summary>
    private static string VerifyRelocations(PeFile written, PeFile original, IReadOnlyList<NativePatch> patches)
    {
        if (!PatchRelocations.IsRelocatable(original))
            return "Relocations: the image is not relocatable (absolute addresses are fixed); nothing to check.";
        var problems = new List<string>();
        var entries = written.BaseRelocations;
        int checkedPatches = 0, expectedTotal = 0;
        foreach (var p in patches)
        {
            var plan = p.Relocations;
            if (plan == null) continue;
            checkedPatches++;
            var expected = plan.Changes.Where(c => c.Action is "kept" or "added").Select(c => (Rva: c.TargetRva, c.Type)).ToHashSet();
            expectedTotal += expected.Count;
            var actual = entries.Where(e => e.Type != PeRelocationType.Absolute && e.Rva < p.EndRva && e.Rva + (uint)PatchRelocations.Width(e.Type) > p.Rva)
                .Select(e => (e.Rva, e.Type)).ToHashSet();
            foreach (var m in expected.Except(actual)) problems.Add($"missing {m.Type} entry at rva 0x{m.Rva:X}");
            foreach (var x in actual.Except(expected)) problems.Add($"unexpected {x.Type} entry at rva 0x{x.Rva:X}");
        }
        int issuesBefore = original.Issues.Count(i => i.Message.Contains("relocation", StringComparison.OrdinalIgnoreCase));
        int issuesAfter = written.Issues.Count(i => i.Message.Contains("relocation", StringComparison.OrdinalIgnoreCase));
        if (issuesAfter > issuesBefore) problems.Add($"the relocation table reads with {issuesAfter - issuesBefore} new issue(s)");
        return problems.Count == 0
            ? $"Relocations verified: the table re-parses ({entries.Count:N0} entries) and every patched range holds exactly its kept/added entries ({expectedTotal} across {checkedPatches} patch(es))."
            : "WARNING: relocations inconsistent with the patches: " + string.Join("; ", problems.Take(10)) + (problems.Count > 10 ? $" (+{problems.Count - 10} more)" : "");
    }

    private static string Disasm(NativeCodeIndex index, uint rva, int length)
    {
        if (index.Support != CodeSupport.Full) return "  (no disassembly for this architecture)\n";
        var sb = new StringBuilder();
        var dis = index.CreateDisassembler();
        uint at = rva;
        int covered = 0;
        while (covered < length)
        {
            var line = dis.DecodeOne(at);
            if (line == null) break;
            sb.AppendLine($"  {line.Address:X}  {line.Bytes,-24} {line.Text}");
            covered += line.Bytes.Length / 2;
            at += (uint)(line.Bytes.Length / 2);
        }
        return sb.ToString();
    }

    private static string DisasmBytes(INativeImage image, uint rva, byte[] bytes)
    {
        var (support, _) = InstructionSets.For(image.Arch);
        if (support != CodeSupport.Full) return $"  {Hex(bytes)}\n";
        var synthetic = new ByteImage(image, rva, bytes);
        var dis = new NativeDisassembler(synthetic, null, []);
        var sb = new StringBuilder();
        foreach (var line in dis.Disassemble(rva, bytes.Length, rva + (uint)bytes.Length))
            sb.AppendLine($"  {line.Address:X}  {line.Bytes,-24} {line.Text}");
        return sb.ToString();
    }

    private static string Hex(byte[] bytes) => bytes.Length <= 16 ? Convert.ToHexString(bytes) : Convert.ToHexString(bytes, 0, 16) + "...";
}
