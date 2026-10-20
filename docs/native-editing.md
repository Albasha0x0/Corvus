# Native annotations and patching

Tools: `rename_native`, `comment_native`, `export_native_annotations`, `patch_bytes`, `patch_asm`,
`list_native_edits`, `undo_native_edit`, `save_native` (src/Corvus/Tools/NativeEdits/NativeEditTools.cs,
Services/NativeEditService.cs).

## Annotations (names and comments)

- The authoritative in-memory copy is `NativeAnnotations` (per image, keyed by RVA). It is created on first use
  and loaded from a **sidecar** JSON file.
- The sidecar lives under the same per-user root as the analysis cache, a sibling folder:
  `<LocalAppData>/Corvus/annotations/<sha256>.json` (override with `CORVUS_ANNOTATIONS_DIR`). One file per
  image **SHA-256**, written atomically (temp file + move).
- The key is the file's hash **as first loaded** (`LoadedNative.OriginalSha256`); it stays stable even after the
  image is patched in memory, so a session's names and a file's identity do not drift.
- A changed file on disk has a different hash and therefore a different (clean) sidecar. When a sidecar already
  exists for the same path under another hash, the tool says so (the annotations were made against an earlier
  version of that file).
- Names are C-identifier-like (letter/underscore start; letters, digits, `_`, `$`, `@`; <= 255 chars) and unique
  unless `allowDuplicate=true`.
- Names and comments mirror into the code index (`NativeCodeIndex.SetUserName/SetUserComment`): a renamed
  function's `KnownName` is replaced, so the name shows up in `list_functions`, `disassemble` (labels and call
  targets), `find_xrefs`, `native_call_tree` and address lookup. On a fresh index build,
  `NativeCodeService.ApplyAnnotations` replays the saved annotations, so names reappear after a reload or restart.
- `export_native_annotations` writes an IDAPython script, a Ghidra script or JSON. Scripts apply by RVA rebased
  to the database's own image base at run time (`idaapi.get_imagebase()` / `currentProgram.getImageBase()`).

## Patching (patch overlay)

- A patch is recorded as a `NativePatch` (RVA, file offset, original bytes, replacement bytes) on the image's
  `NativePatchSet`, over a one-time snapshot of the original file bytes.
- **Every read path sees the patched bytes.** After a patch is added or undone, the patched bytes are produced by
  overlaying every replacement on the snapshot, a new image (`PeFile`, `ElfFile` or `MachOFile`) is parsed from them, and it **replaces** the one the
  workspace holds (`LoadedNative.ReplaceImage`). Cached analysis (the code index, engine sessions) is discarded and
  rebuilds lazily against the patched image, so `disassemble`, `read_bytes`, `search_bytes`, string scanning and the
  code index all observe the patch. The patch set and annotations survive the swap (they are separate from the
  analysis cache). This is simpler and more reliable than threading an overlay through every reader, at the cost of
  rebuilding the index after a patch.
- Targets must be bytes that exist in the file: the RVA is mapped to a file offset and the range must be contiguous
  in the file. Zero-fill / unmapped addresses are refused; header bytes are refused unless `force=true`.
- Over code, the overwritten span is extended to the next instruction boundary and the trailing bytes are padded
  with NOPs. A patch that would start in the middle of an instruction, or run past the end of the containing
  function, is refused unless `force=true`.
- `patch_asm` assembles x86/x64 MASM/Intel text with Iced (`X86Assembler`), in the form our `disassemble` tool
  prints it, so a line can be copied, edited and patched back. It aims at the whole general-purpose / SSE / AVX /
  AVX-512 / x87 instruction set:
  - **Operands.** Registers of every class (GPR 8/16/32/64 including `r8b`..`r15b`, `xmm`/`ymm`/`zmm`, `mm`, `k`,
    segment, `cr`/`dr`/`tr`, `st(i)`); immediates in hex (`0x..`, `..h`, bare hex, with optional leading `-`) or
    decimal (`#..`); and memory in any addressing form — `[base+index*scale+disp]`, segment overrides (`fs:[..]`),
    size specifiers (`byte`/`word`/`dword`/`qword`/`tbyte`/`xmmword`/`ymmword`/`zmmword ptr`), and `[rip+X]`.
  - **Symbols.** Branch and memory/immediate operands accept our names — `sub_<rva>`, export names, `loc_<rva>`
    labels, and `module!import` (its IAT slot, for `call`/`jmp qword ptr [module!import]`). On x64 a bare absolute
    `[addr]` assembles RIP-relative (as the disassembler prints it), falling back to an absolute `[disp32]` only when
    the target is too far to reach RIP-relative from the patch.
  - **Prefixes / string ops.** `lock`, `rep`/`repe`/`repne`, `bnd`; the sized string instructions
    (`movs`/`stos`/`lods`/`scas`/`cmps` b/w/d/q).
  - **How.** Rather than a per-mnemonic table it parses the operands and searches Iced's `Code` table for a form
    whose operand kinds match, preferring the shortest encoding (and, on a tie, the MSVC-style placement, e.g. `8B`
    over `89`), and rejecting obsolete aliases that do not decode back to themselves. The whole block is laid out with
    `BlockEncoder` at the patch address, so near-branch sizes (short vs near), relative displacements and RIP-relative
    references are correct. A `db <hex>` escape emits raw bytes. A 16-bit operand-size form (66 prefix) is chosen only
    when an operand asks for 16 bits (a 16-bit register or `word ptr`): the shorter `pushw imm16` would push 2 bytes, or
    truncate the value, where `push imm` means the mode's width. `int 3` assembles to the single byte `CC`, `xchg ax, ax`
    to `66 90`, and instructions whose operands are implicit (`monitorx`, `mwaitx`) accept them as printed.
  - **Errors** are typed `ToolError(InvalidArgument)` naming the offending line, never an internal exception — e.g.
    "operand size is ambiguous: add a size specifier such as 'dword ptr'" or "unknown mnemonic".
  - **Round trip.** A property test assembles every instruction our disassembler prints for a set of System32 (x64)
    and SysWOW64 (x86) functions: all 131,831 assemble to an equivalent instruction (same text, and decoding to the same
    mnemonic, operand and address size, operands, immediates at the operation's width, and prefixes), and the test
    requires all of them; 97.5% are byte-for-byte identical. The rest differ only in encoding: the reg,reg store vs load
    form (`89` vs `8B`), an imm32 where an imm8 fits, multi-byte `nop`, or an absolute `[disp32]` that is reachable and
    becomes RIP-relative.
  - **Not supported:** AVX-512 decorators (`{k1}`, `{z}`, `{1toN}`, rounding / SAE), VSIB gather / scatter operands,
    far pointers (`jmp far`, `call far`), address-size overrides, and the explicit-operand string forms
    (`movs byte ptr [rdi], byte ptr [rsi]`; the sized forms such as `rep movsb` work). `notrack` is dropped. Use
    `patch_bytes` or `db` for these.
- `dryRun` shows the before/after disassembly and the relocation changes without recording the patch.
  `list_native_edits` / `undo_native_edit` manage the recorded patches.
- **ELF and Mach-O.** The same overlay, undo and `save_native` apply. Bytes the loader rewrites (ELF dynamic
  relocations, Mach-O rebases and binds, import slots) would not keep a patch: such a range is refused with
  `relocated_range` unless `force=true`. FairPlay-encrypted bytes hold ciphertext and are refused (`encrypted_range`).
  A Mach-O code signature no longer matches once a byte changes: the patch result and the save say so (re-sign with
  `codesign -f -s -`). A universal Mach-O is patched per slice; `save_native` writes the whole file with that slice
  replaced and checks every byte outside it. Relocation planning, `extend` stubs and `export_native_patches` are PE only.

## Relocations

Under ASLR or a rebase the Windows loader adds (actual base - preferred base) to every location a base relocation
names (HIGHLOW: 4 bytes on x86, DIR64: 8 bytes on x64), whatever bytes are there. A patch therefore has two ways to
break at a non-preferred base: an entry still covers bytes that are no longer an address (a `push offset X`, `mov
eax, [abs]`, `call [IAT]`, jump-table or `mov r64, imm64` overwritten by something else: the loader corrupts the new
code), or the new bytes hold an absolute address with no entry (the assembler resolves names to absolute addresses
on x86, so `mov eax, [global]` is one). x64 code is mostly RIP-relative and unaffected. `PatchRelocations`
(Native/Patching) plans both sides for every `patch_bytes` / `patch_asm`:

- **Which entries are under the patch**: the relocation directory is walked as the loader walks it (block = page RVA,
  size, 16-bit entries; a HIGHADJ parameter slot is not an entry); every entry whose target bytes overlap the patched
  (NOP-padded) range.
- **Which addresses the new bytes hold**: the displacements and immediates of the new instructions, by Iced
  `ConstantOffsets` (branch displacements and RIP-relative operands are relative and left out). For `patch_asm` the
  assembler marks the operands written as a symbol or with `offset`; those are addresses. Otherwise an operand is an
  address when its value lies in [ImageBase, ImageBase+SizeOfImage) and it is an x86 absolute `[disp32]` with no base
  register, an x64 64-bit constant (`mov r64, imm64`, `moffs64`), or sits exactly where an entry of the same type was
  (a copied instruction). A numeric in-image x86 immediate written by hand is not relocated, with a note saying to
  write `offset 0x...` or a name. Raw `patch_bytes` has no symbol intent: over code the new bytes are decoded and an
  in-image x86 imm32 counts as an address too; over data an entry stays when the new pointer-sized value is still an
  in-image address.
- **`relocations` option** (`auto` default, `keep`, `neutralize`): `auto` keeps an entry whose position still holds an
  address of the same type, neutralizes the others and adds entries for new addresses; `keep` leaves every entry
  untouched (and lists new addresses as unrelocated); `neutralize` neutralizes every entry under the patch.
- **Neutralize** = rewrite the entry's type to IMAGE_REL_BASED_ABSOLUTE (type 0, offset bits kept): a 2-byte in-place
  edit inside `.reloc`. **Add** = rewrite an ABSOLUTE slot of the relocation block of the same 4 KB page (a slot just
  neutralized by this patch first, else block padding or an earlier neutralized entry) to `type << 12 | offset`. The
  directory never grows or moves.
- **No slot**: when the page's block has no ABSOLUTE slot (or the page has no block), the patch is refused with
  `conflict` / reason `no_relocation_slot`; the remediation is to write the reference RIP-relative (x64), load the
  address from data that is already relocated (an existing pointer or IAT slot), or pass `force=true` to accept a
  patch that is only correct at the preferred base (reported as `unrelocated`). Clearing DYNAMIC_BASE would also avoid
  it but weakens the binary's ASLR; that is never done automatically.
- **Not relocatable** images (no relocation directory, or IMAGE_FILE_RELOCS_STRIPPED): "image is not relocatable:
  absolute addresses are fixed (no action needed)".
- **Recording**: the entry rewrites belong to the patch (`NativePatch.Relocations`: edits + a per-entry report of
  kept / neutralized / added / unrelocated with the target and the entry's RVA in `.reloc`). They are overlaid with the
  patch bytes, so every read path (and `RelocationRvas`) sees the new table, and `undo_native_edit` restores it. A
  later patch may reuse a slot an earlier one neutralized; undoing the earlier one first is refused (`conflict`, "undo
  #n first"). A patch whose bytes overlap another patch's entry rewrites is refused like an overlapping patch.
- **Reports**: the patch / dry-run output and `list_native_edits` list the relocation changes per patch.

Measured (Slow tests, NativeRelocationPatchTests): copies of SysWOW64 `version.dll` and `msvcrt.dll` with (a) a `push
offset X` made `push 1234h` (entry neutralized) and (b) a `push offset X` made `nop ; mov eax, [X]` (entry neutralized,
its slot retargeted one byte on), saved, then rebased in memory by +0xA30000 applying every entry as the loader does:
the push keeps 1234h and the mov reads X at its new address. An MSVC x86 DLL (`/DYNAMICBASE /Od`, built through
vswhere): `GetValue` rewritten to read another global (`added 0x1001, neutralized 0x1004`) and `GetText`'s `mov eax,
offset str` made a number; after the rebase both decode to the intended operation. The test process is x64, so the
x86 DLL is not loaded with LoadLibraryEx; the in-memory rebase is the check.

## Patch export (export_native_patches)

Tool in Tools/NativePatchTools.cs, renderer `PatchExport` (Native/Patching). The exported bytes are save_native's
bytes (`NativeEditService.OutputBytes`, without stripping the signature): every patch, its relocation-table entry
rewrites (2-byte edits in `.reloc`) and the recomputed PE checksum when the original had one.

- `ida`: an IDAPython script. A `PATCHES` list of (label, RVA, original hex, replacement hex): one entry per patch, per
  relocation entry rewrite and for the checksum. Each is applied at `idaapi.get_imagebase() + rva` with
  `ida_bytes.patch_bytes` only when the database holds the original bytes (entries already applied count as such; others
  are reported with the expected and found bytes; bytes not loaded in the database are skipped: IDA loads neither the PE
  header nor `.reloc` by default). Then `ida_auto.plan_range` + `auto_wait`, and a summary line.
- `dif`: IDA's format, as IDA writes it (checked against `gen_file(OFILE_DIF)` of a patched idalib database): `This
  difference file was created by IDA`, a blank line, the file name, then `%016X: %02X %02X` (file offset, original,
  patched) per changed byte, LF line ends.
- `ips`: `PATCH`, records of 3-byte big-endian file offset + 2-byte size + data, `EOF`. Runs of changed bytes separated
  by up to 4 unchanged bytes are merged into one record; records are at most 0xFFFE bytes. A record that would start
  at 0x454F46 (whose offset bytes read `EOF`) starts one byte earlier. Offsets past 16 MB are refused with a pointer to
  `ips32` (`IPS32`, 4-byte offsets, `EEOF`; 0x45454F46 moved the same way).
- `json`: kind `corvus.native_patches`, the image (path, SHA-256 of the original, arch, preferred base, file
  size, SHA-256 of the patched output), every patch (RVA, file offset, original / replacement hex, description, origin
  `asm` / `bytes`, the assembly text, relocation edits and changes) and the checksum change. migrate_native_patches
  reads it.

Tests (NativePatchExportTests): independent appliers for .dif, IPS / IPS32 and the JSON reproduce save_native's file
byte for byte (an x86 image with relocation edits and a stored checksum; a copy of System32 `version.dll`), the IPS
end-marker offset and the 16 MB limit; under idalib (Slow, when IDA is present) the script applies to a fresh
database of the original (2 applied, the checksum entry not loaded, 0 differing; a second run applies nothing), every
patched database byte equals the saved file's byte, and IDA's own .dif of that database is our .dif minus the header
bytes it does not load.

## Patch migration (migrate_native_patches)

`PatchMigration` (Native/Patching) carries an old build's byte patches to a new build. Source: the old build's
in-memory patches (default) or a json patch set from export_native_patches (`patchSet`). For each patch:

- **Map the old address to the new build** through `AddressMapper` (the compare_native_images matcher: function match
  + instruction alignment). The old build is matched on its *pristine* bytes (`NativeCodeService.IndexOfOriginal`
  rebuilds the index over `NativePatchSet.OriginalBytes` when it is dirty), so an in-memory patch does not hide the
  function's identity. No mapping → refused with the mapper's reason (`function_not_matched`, `ambiguous`,
  `changed_region`, `not_an_instruction`, ...).
- **Check the expected pre-patch bytes** against the new build's original bytes at the mapped address: exact for raw
  patch_bytes; for patch_asm, both sides are decoded and the bytes each marks as an address (branch / RIP-relative
  displacements, relocated / in-image absolute operands) are masked, so a legitimately relocated operand does not count
  as a difference. Otherwise refused `original_bytes_differ` with the expected and found bytes (`??` = masked).
- **Produce the replacement**: patch_asm re-assembles its recorded assembly text at the new address (new branch and
  RIP-relative targets; symbols resolved against the new build), raw patches apply their recorded bytes verbatim. A
  failed re-assembly is refused `assemble_failed`.
- **Reapply through the normal patch path** (PreparePatch: boundary and function-end checks, relocation planning). A
  safety or relocation failure is refused with `relocation_slot_unavailable`, `mid_instruction`, `past_function_end`,
  `conflicts_with_existing_patch` or `cannot_prepare`. Applied patches are rebuilt into the new image between each one,
  so later patches see earlier ones.

Every patch is reported applied / would_apply (dryRun) / refused with a reason and evidence; dryRun (the default)
changes nothing. Tests (NativePatchMigrationTests): a synthetic pair of builds covers migrate / refuse-on-differing-
bytes / unmatched-function / json-source; a Slow test migrates a patch_asm and a patch_bytes between real consecutive
builds (C:\symbols versions and side-by-side .NET runtimes) and verifies the applied bytes at the mapped addresses.

## save_native

- Writes the patched bytes. Everything not inside a patched range is byte-for-byte identical to the original.
- The PE checksum is recomputed (ImageHlp algorithm) when the original had a non-zero one, and written into the
  checksum field.
- A signed file becomes unsigned: the note says so. `stripSignature=true` zeroes the security data-directory entry
  and drops the trailing certificate-table overlay.
- Atomic write (temp file + move). Another existing file is replaced only with `overwrite=true`; the input only with
  `replaceOriginal=true` on a server started with `--allow-replace-original`, keeping a `.bak`. `versioned=true` writes `<name>.1.dll`, `<name>.2.dll`, ... instead.
- Verified by re-parsing the written file and comparing every byte outside the patched ranges, the relocation entry
  rewrites and the checksum field to the original; then the relocation table of the written file is re-parsed and
  checked against the patches: inside every patched range exactly the kept and added entries remain (nothing
  neutralized survives, nothing unplanned appears), and the table reads with no more issues than the original's.
