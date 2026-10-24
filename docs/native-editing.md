# Native annotations and patching

Tools: `rename_native`, `comment_native`, `export_native_annotations`, `patch_bytes`, `patch_asm`,
`list_native_edits`, `undo_native_edit`, `save_native` (src/Corvus/Tools/NativeEdits/NativeEditTools.cs,
Services/NativeEdits/NativeEditService.cs). Every edit is in memory, `dryRun=true` by default, and undoable by
`editId` (`list_native_edits`, `undo_native_edit`).

## Annotations (names and comments)

- **Storage.** `NativeAnnotations` per image, keyed by RVA, loaded from a sidecar JSON file:
  `<LocalAppData>/Corvus/annotations/<sha256>.json` (beside the analysis cache; override with
  `CORVUS_ANNOTATIONS_DIR`), written atomically (temp file + move).
- **Key.** The SHA-256 of the file as first loaded (`LoadedNative.OriginalSha256`); in-memory patches do not change
  it. A file changed on disk has a new hash and a clean sidecar; when a sidecar exists for the same path under
  another hash, the tool says the annotations were made against an earlier version.
- **Names.** Letter or `_` first, then letters, digits, `_`, `$`, `@`; at most 255 characters; unique unless
  `allowDuplicate=true`.
- **Comments.** `scope`: `line` (repeatable: also shown where referenced), `eol`, `pre`, `plate` (engine kinds),
  `pseudocode`, `function`, or `auto` (default: function at a function start, else line and pseudocode).
- **Where they show.** Names and comments mirror into the code index (`NativeCodeIndex.SetUserName/SetUserComment`):
  a renamed function's `KnownName` is replaced in `list_functions`, `disassemble` (labels, call targets),
  `find_xrefs`, `native_call_tree` and address lookup. A fresh index build replays them
  (`NativeCodeService.ApplyAnnotations`), so they survive a reload or restart. Both are pushed to IDA / Ghidra.
- **Export.** `export_native_annotations` formats: `json` (default), `ida` (IDAPython), `ghidra`, `header` (C header
  of declared types, prototypes, typed globals), `objc-header` (Mach-O). Scripts apply by RVA rebased to the
  database's image base at run time (`idaapi.get_imagebase()` / `currentProgram.getImageBase()`).

## Patching (patch overlay)

- **Architectures.** `patch_bytes` works on any architecture (`hex`, or `value` + `type`: `i8`-`i64`, `u8`-`u64`,
  `f32`, `f64`, `ptr`; `be` suffix for big-endian). `patch_asm` and `extend` stubs assemble x86 / x64 only; on other
  architectures `patch_asm` is refused (`unsupported`, reason `not-assembled`): assemble elsewhere and pass the bytes
  to `patch_bytes`.
- **Recording.** A `NativePatch` (RVA, file offset, original bytes, replacement bytes) on the image's
  `NativePatchSet`, over a one-time snapshot of the original file.
- **Every read path sees the patched bytes.** After a patch or undo, the replacements are overlaid on the snapshot, a
  new image (`PeFile`, `ElfFile` or `MachOFile`) is parsed and replaces the workspace's (`LoadedNative.ReplaceImage`).
  Cached analysis (code index, engine sessions) is discarded and rebuilds lazily, so `disassemble`, `read_bytes`,
  `search_bytes`, string scans and the index all see the patch. Patch set and annotations survive the swap. Cost: the
  index rebuilds after each patch.
- **Targets** must be file bytes: the RVA maps to a contiguous file range. Zero-fill / unmapped addresses are refused.
- **Safety.** Over code the overwritten span extends to the next instruction boundary, padded with NOPs. A patch
  starting mid-instruction, running past the containing function's end, or touching header bytes or bytes the loader
  rewrites is refused unless `allowUnsafe=true`.
- **`dryRun`** shows before/after disassembly and the relocation changes without recording.
- **`extend=true`** puts code larger than the site in a stub that the site jumps to and back from. `stubMode`:
  `replace` (default; replaces the displaced instructions), `before` or `after` them. `placement`: `auto` (default:
  a code cave, else a new section), `cave` or `section` (a new PE section or ELF / Mach-O segment; ELF only
  little-endian x86 / x64; not in a slice of a universal Mach-O).

### patch_asm

Assembles x86 / x64 MASM/Intel text with Iced (`X86Assembler`) in the form `disassemble` prints, so a line can be
copied, edited and patched back. Covers general-purpose, SSE, AVX, AVX-512 and x87:

- **Operands.** Every register class (GPR 8/16/32/64 incl. `r8b`..`r15b`, `xmm`/`ymm`/`zmm`, `mm`, `k`, segment,
  `cr`/`dr`/`tr`, `st(i)`); immediates in hex (`0x..`, `..h`, bare hex, optional leading `-`) or decimal (`#..`);
  memory in any form: `[base+index*scale+disp]`, segment overrides (`fs:[..]`), size specifiers
  (`byte`/`word`/`dword`/`qword`/`tbyte`/`xmmword`/`ymmword`/`zmmword ptr`), `[rip+X]`.
- **Symbols.** `sub_<rva>`, export names, `loc_<rva>` labels, `module!import` (its IAT slot, for
  `call`/`jmp qword ptr [module!import]`). On x64 a bare `[addr]` assembles RIP-relative, falling back to absolute
  `[disp32]` only when out of RIP-relative reach.
- **Prefixes / string ops.** `lock`, `rep`/`repe`/`repne`, `bnd`; sized string instructions
  (`movs`/`stos`/`lods`/`scas`/`cmps` b/w/d/q).
- **Encoding.** Operands are matched against Iced's `Code` table, preferring the shortest encoding (ties: MSVC-style
  placement, e.g. `8B` over `89`) and rejecting obsolete aliases that do not decode back to themselves. The block is
  laid out with `BlockEncoder` at the patch address, so branch sizes, relative displacements and RIP-relative
  references are correct. `db <hex>` emits raw bytes. A 16-bit operand size (66 prefix) is used only when an operand
  asks for it (16-bit register or `word ptr`): `push imm` means the mode's width. `int 3` is `CC`, `xchg ax, ax` is
  `66 90`; implicit operands (`monitorx`, `mwaitx`) are accepted as printed.
- **Errors** are `invalid_argument` naming the line, e.g. "operand size is ambiguous: add a size specifier such as
  'dword ptr'" or "unknown mnemonic".
- **Round trip.** Every instruction `disassemble` prints for a set of System32 (x64) and SysWOW64 (x86) functions,
  131,831 in all, assembles to an equivalent instruction (same mnemonic, operand / address size, operands,
  immediates at the operation's width, prefixes); the test requires all. 97.5% are byte-identical; the rest differ
  only in encoding (`89` vs `8B` reg,reg form, imm32 where imm8 fits, multi-byte `nop`, a reachable absolute
  `[disp32]` made RIP-relative).
- **Not supported:** AVX-512 decorators (`{k1}`, `{z}`, `{1toN}`, rounding / SAE), VSIB gather / scatter operands,
  far pointers (`jmp far`, `call far`), address-size overrides, explicit-operand string forms
  (`movs byte ptr [rdi], byte ptr [rsi]`; `rep movsb` works). `notrack` is dropped. Use `patch_bytes` or `db`.

### ELF and Mach-O

Same overlay, undo, `extend` and `save_native`. Bytes the loader rewrites (ELF dynamic relocations, Mach-O rebases
and binds, import slots) are refused with `relocated_range` unless `allowUnsafe=true`. FairPlay-encrypted bytes are
refused (`encrypted_range`). A Mach-O code signature stops matching after any change: the patch result and the save
say so (re-sign with `codesign -f -s -`). A universal Mach-O is patched per slice; `save_native` writes the whole file
with that slice replaced and checks every byte outside it. Relocation planning is PE only.

## Relocations

Under ASLR or a rebase the Windows loader adds (actual base - preferred base) at every base-relocation entry
(HIGHLOW: 4 bytes on x86, DIR64: 8 bytes on x64), whatever bytes are there. A patch breaks at a non-preferred base
when an entry still covers bytes that are no longer an address (an overwritten `push offset X`, `mov eax, [abs]`,
`call [IAT]`, jump table or `mov r64, imm64`: the loader corrupts the new code), or when new bytes hold an absolute
address with no entry (on x86 the assembler resolves names to absolute addresses, e.g. `mov eax, [global]`). x64 code
is mostly RIP-relative and unaffected. `PatchRelocations` (Native/Patching) plans both sides for every `patch_bytes` /
`patch_asm`:

- **Entries under the patch**: the relocation directory walked as the loader does (block = page RVA, size, 16-bit
  entries; a HIGHADJ parameter slot is not an entry); every entry overlapping the patched (NOP-padded) range.
- **Addresses in the new bytes**: displacements and immediates by Iced `ConstantOffsets` (branch and RIP-relative
  operands excluded). `patch_asm` marks operands written as a symbol or with `offset` as addresses. Otherwise an
  operand is an address when its value is in [ImageBase, ImageBase+SizeOfImage) and it is an x86 absolute `[disp32]`
  with no base register, an x64 64-bit constant (`mov r64, imm64`, `moffs64`), or sits exactly where an entry of the
  same type was (a copied instruction). A hand-written numeric in-image x86 immediate is not relocated; a note says to
  write `offset 0x...` or a name. Raw `patch_bytes` over code: the new bytes are decoded and an in-image x86 imm32
  counts as an address; over data an entry stays when the new pointer-sized value is still in-image.
- **`relocations`**: `auto` (default) keeps an entry whose position still holds an address of the same type,
  neutralizes the others and adds entries for new addresses; `keep` leaves every entry (new addresses listed as
  unrelocated); `neutralize` neutralizes every entry under the patch.
- **Neutralize** = set the entry's type to IMAGE_REL_BASED_ABSOLUTE (type 0, offset bits kept), a 2-byte edit in
  `.reloc`. **Add** = rewrite an ABSOLUTE slot in the same 4 KB page's block (one this patch just neutralized, else
  block padding or an earlier neutralized entry) to `type << 12 | offset`. The directory never grows or moves.
- **No slot** (no ABSOLUTE slot in the page's block, or no block): refused with `conflict`, reason
  `no_relocation_slot`. Fix: write the reference RIP-relative (x64), load the address from already-relocated data (a
  pointer or IAT slot), or `allowUnsafe=true` to accept a patch correct only at the preferred base (reported
  `unrelocated`). Clearing DYNAMIC_BASE would avoid it but weakens ASLR; it is never done automatically.
- **Not relocatable** (no relocation directory, or IMAGE_FILE_RELOCS_STRIPPED): "image is not relocatable: absolute
  addresses are fixed (no action needed)".
- **Recording**: entry rewrites belong to the patch (`NativePatch.Relocations`: edits plus a per-entry report of
  kept / neutralized / added / unrelocated, with target and entry RVA in `.reloc`). They are overlaid with the patch
  bytes, so every read path (and `RelocationRvas`) sees the new table, and `undo_native_edit` restores it. A later
  patch may reuse a slot an earlier one neutralized; undoing the earlier first is refused (`conflict`, "undo #n
  first"). A patch overlapping another patch's entry rewrites is refused like an overlapping patch.
- **Reports**: patch / dry-run output and `list_native_edits` list the relocation changes per patch.

Measured (Slow, `NativeRelocationPatchTests`): copies of SysWOW64 `version.dll` and `msvcrt.dll` with (a) `push offset
X` made `push 1234h` (entry neutralized) and (b) `push offset X` made `nop ; mov eax, [X]` (entry neutralized, slot
retargeted one byte on), saved, then rebased in memory by +0xA30000 applying every entry as the loader does: the push
keeps 1234h, the mov reads X at its new address. An MSVC x86 DLL (`/DYNAMICBASE /Od`): `GetValue` rewritten to read
another global (`added 0x1001, neutralized 0x1004`) and `GetText`'s `mov eax, offset str` made a number; after the
rebase both decode to the intended operation. The test process is x64, so the in-memory rebase is the check, not
LoadLibraryEx.

## Patch export (export_native_patches)

Tool in Tools/Builds/NativePatchTools.cs, renderer `PatchExport` (Native/Patching); PE, ELF and Mach-O. The exported
bytes are `save_native`'s (`NativeEditService.OutputBytes`, signature kept): every patch, its `.reloc` entry rewrites,
and the recomputed PE checksum when the original had one (ELF and Mach-O have none). `format`:

- `ida`: IDAPython script. A `PATCHES` list of (label, RVA, original hex, replacement hex): one per patch, per
  relocation entry rewrite and for the checksum. Each applies at `idaapi.get_imagebase() + rva` with
  `ida_bytes.patch_bytes` only where the database holds the original bytes (already-applied entries count as such;
  others are reported with expected and found bytes; bytes not in the database are skipped: IDA loads neither the PE
  header nor `.reloc` by default). Then `ida_auto.plan_range` + `auto_wait` and a summary line. Adds a segment for
  `extend` code in a new section.
- `dif`: IDA's format as IDA writes it (checked against `gen_file(OFILE_DIF)` of a patched idalib database):
  `This difference file was created by IDA`, a blank line, the file name, then `%016X: %02X %02X` (file offset,
  original, patched) per changed byte, LF line ends. Refused (`grown_file`) when a new section grows the file.
- `ips`: `PATCH`, records of 3-byte big-endian file offset + 2-byte size + data, `EOF`. Changed runs separated by up
  to 4 unchanged bytes merge; records are at most 0xFFFE bytes. A record that would start at 0x454F46 (offset bytes
  reading `EOF`) starts one byte earlier. Offsets past 16 MB are refused, pointing to `ips32` (`IPS32`, 4-byte
  offsets, `EEOF`; 0x45454F46 moved the same way). Both extend a grown file.
- `json` (default): kind `corvus.native_patches`, the image (path, original SHA-256, arch, preferred base, file size,
  patched output SHA-256), every patch (RVA, file offset, original / replacement hex, description, origin `asm` /
  `bytes`, assembly text, relocation edits and changes) and the checksum change. `migrate_native_patches` reads it.

Tests (`NativePatchExportTests`): independent appliers for .dif, IPS / IPS32 and JSON reproduce `save_native`'s file
byte for byte (an x86 image with relocation edits and a stored checksum; a copy of System32 `version.dll`), plus the
IPS end-marker offset and the 16 MB limit. Under idalib (Slow, when IDA is present) the script applies to a fresh
database of the original (2 applied, checksum entry not loaded, 0 differing; a second run applies nothing), every
patched database byte equals the saved file's, and IDA's own .dif of that database is ours minus the header bytes it
does not load.

## Patch migration (migrate_native_patches)

`PatchMigration` (Native/Patching) carries an old build's byte patches to a new build. Source: the old build's
in-memory patches (default) or a JSON patch set from `export_native_patches` (`patchSet`); the same image as old and
new with `patchSet` replays it. `dryRun=true` (default) changes nothing. Each patch is reported `applied`,
`would_apply` or `refused` with a reason and evidence (codes: docs/migration-reasons.md). Per patch:

1. **Map the address** with `AddressMapper` (the `compare_native_images` matcher: function match + instruction
   alignment), on the old build's original bytes (`NativeCodeService.IndexOfOriginal` rebuilds the index over
   `NativePatchSet.OriginalBytes` when patched), so a patch does not hide the function. No mapping: refused with the
   mapper's reason (`function_not_matched`, `ambiguous`, `changed_region`, `not_an_instruction`, ...).
2. **Check the pre-patch bytes** at the mapped address in the new build: exact for `patch_bytes`; for `patch_asm`
   both sides are decoded and address bytes (branch / RIP-relative displacements, relocated or in-image absolute
   operands) are masked. Mismatch: `original_bytes_differ` with expected and found bytes (`??` = masked).
3. **Build the replacement**: `patch_asm` re-assembles its recorded text at the new address (symbols resolved in the
   new build); raw patches reuse their bytes. Failure: `assemble_failed`.
4. **Reapply** through the normal patch path (boundary and function-end checks, relocation planning). Failures:
   `relocation_slot_unavailable`, `mid_instruction`, `past_function_end`, `conflicts_with_existing_patch`,
   `cannot_prepare`. The image is rebuilt after each applied patch, so later patches see earlier ones.

Tests (`NativePatchMigrationTests`): a synthetic build pair covers migrate, refuse on differing bytes, unmatched
function and JSON source; a Slow test migrates a `patch_asm` and a `patch_bytes` between real consecutive builds (a
local symbol store and side-by-side .NET runtimes) and verifies the bytes at the mapped addresses.

## save_native

- Writes the patched bytes; everything outside patched ranges is byte-identical to the original.
- Recomputes the PE checksum (ImageHlp algorithm) when the original's was non-zero.
- A signed file becomes unsigned (the note says so); `stripSignature=true` zeroes the security directory entry and
  drops the trailing certificate table.
- Atomic (temp file + move). An existing file is replaced only with `overwrite=true`; the input only with
  `replaceOriginal=true` on a server started with `--allow-replace-original` (keeps a `.bak`, refuses a file changed
  on disk). `versioned=true` writes `<name>.1.dll`, `<name>.2.dll`, ... (first free N).
- Verified: the written file is re-parsed and every byte outside the patched ranges, relocation entry rewrites and
  checksum field compared to the original; its relocation table is re-parsed and checked against the patches (inside
  each patched range exactly the kept and added entries; nothing neutralized survives, nothing unplanned appears;
  no more read issues than the original's).
