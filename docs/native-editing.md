# Native annotations and patching

- Tools: `rename_native`, `comment_native`, `export_native_annotations`, `patch_bytes`, `patch_asm`,
  `list_native_edits`, `undo_native_edit`, `save_native`.
- Every edit is in memory, `dryRun=true` by default, and undoable by `editId` (`list_native_edits`,
  `undo_native_edit`).

## Annotations (names and comments)

- **Storage.** Per image, keyed by RVA, in `<LocalAppData>/Corvus/annotations/<sha256>.json`
  (`CORVUS_ANNOTATIONS_DIR` overrides), written atomically.
- **Key.** The SHA-256 of the file as first loaded; in-memory patches do not change it.
- A file changed on disk gets a clean sidecar. When a sidecar exists for the same path under another hash, the tool
  says the annotations were made against an earlier version.
- **Names.** Letter or `_` first, then letters, digits, `_`, `$`, `@`; at most 255 characters; unique unless
  `allowDuplicate=true`.
- **Comments.** `scope`: `line` (repeatable: also shown where referenced), `eol`, `pre`, `plate`, `pseudocode`,
  `function`, or `auto` (default: function at a function start, else line and pseudocode).
- **Where they show.** A renamed function shows under its name in `list_functions`, `disassemble` (labels, call
  targets), `find_xrefs`, `native_call_tree` and address lookup.
- Names and comments survive a reload or restart and are pushed to IDA and Ghidra.
- **Export.** `export_native_annotations` formats: `json` (default), `ida` (IDAPython), `ghidra`, `header` (declared
  types, prototypes, typed globals), `objc-header` (Mach-O).
- Scripts apply by RVA, rebased to the database's image base at run time.

## Patching (patch overlay)

- **Architectures.** `patch_bytes` works on any architecture: `hex`, or `value` + `type` (`i8`-`i64`, `u8`-`u64`,
  `f32`, `f64`, `ptr`; `be` suffix for big-endian).
- `patch_asm` and `extend` stubs assemble x86 and x64 only. Elsewhere `patch_asm` is refused (`unsupported`, reason
  `not-assembled`): assemble elsewhere and pass the bytes to `patch_bytes`.
- **Recording.** Each patch keeps RVA, file offset, original and replacement bytes, over a one-time snapshot of the
  file.
- **Every read sees the patched bytes.** After a patch or undo, the image is parsed again from the overlaid bytes.
  `disassemble`, `read_bytes`, `search_bytes`, string scans and the code index all see the patch.
- Cached analysis is discarded and rebuilt on demand; the index rebuilds after each patch.
- **Targets** must be file bytes: the RVA maps to a contiguous file range. Zero-fill and unmapped addresses are refused.
- **Safety.** Over code, the overwritten span extends to the next instruction boundary, padded with NOPs.
- Refused unless `allowUnsafe=true`: a patch starting mid-instruction, running past the function's end, or touching
  header bytes or bytes the loader rewrites.
- **`dryRun`** shows before and after disassembly and relocation changes without recording.
- **`extend=true`** puts code larger than the site in a stub the site jumps to and back from.
- `stubMode`: `replace` (default; replaces the displaced instructions), `before` or `after` them.
- `placement`: `auto` (default: a code cave, else a new section), `cave` or `section`. A new section is a PE section or
  an ELF or Mach-O segment; ELF only little-endian x86 and x64; not in a slice of a universal Mach-O.

### patch_asm

Assembles x86 and x64 Intel syntax in the form `disassemble` prints, so a line can be copied, edited and patched back.
Covers general-purpose, SSE, AVX, AVX-512 and x87.

- **Operands.** Every register class: GPR 8/16/32/64 incl. `r8b`..`r15b`, `xmm`/`ymm`/`zmm`, `mm`, `k`, segment,
  `cr`/`dr`/`tr`, `st(i)`.
- Immediates in hex (`0x..`, `..h`, bare hex, optional leading `-`) or decimal (`#..`).
- Memory in any form: `[base+index*scale+disp]`, segment overrides (`fs:[..]`), size specifiers
  (`byte`/`word`/`dword`/`qword`/`tbyte`/`xmmword`/`ymmword`/`zmmword ptr`), `[rip+X]`.
- **Symbols.** `sub_<rva>`, export names, `loc_<rva>` labels, `module!import` (its IAT slot, for
  `call`/`jmp qword ptr [module!import]`).
- On x64 a bare `[addr]` assembles RIP-relative; absolute `[disp32]` only when out of reach.
- **Prefixes and string ops.** `lock`, `rep`/`repe`/`repne`, `bnd`; sized string instructions
  (`movs`/`stos`/`lods`/`scas`/`cmps` b/w/d/q).
- **Encoding.** The shortest encoding wins; ties take MSVC-style placement (`8B` over `89`). Aliases that do not decode
  back to themselves are rejected.
- The block is laid out at the patch address, so branch sizes, relative displacements and RIP-relative references are
  correct. `db <hex>` emits raw bytes.
- A 16-bit operand size (66 prefix) is used only when an operand asks for it (16-bit register or `word ptr`):
  `push imm` means the mode's width.
- `int 3` is `CC`; `xchg ax, ax` is `66 90`; implicit operands (`monitorx`, `mwaitx`) are accepted as printed.
- **Errors** are `invalid_argument` naming the line, such as "operand size is ambiguous: add a size specifier such as
  'dword ptr'" or "unknown mnemonic".
- **Round trip.** 131,831 instructions `disassemble` prints for System32 (x64) and SysWOW64 (x86) functions all
  assemble to an equivalent instruction; 97.5% are byte-identical.
- The rest differ only in encoding: `89` vs `8B` reg,reg form, imm32 where imm8 fits, multi-byte `nop`, a reachable
  absolute `[disp32]` made RIP-relative.
- **Not supported:** AVX-512 decorators (`{k1}`, `{z}`, `{1toN}`, rounding, SAE), VSIB gather and scatter operands,
  far pointers, address-size overrides, explicit-operand string forms (`rep movsb` works). `notrack` is dropped. Use
  `patch_bytes` or `db`.

### ELF and Mach-O

- Same overlay, undo, `extend` and `save_native`.
- Bytes the loader rewrites (ELF dynamic relocations, Mach-O rebases and binds, import slots) are refused with
  `relocated_range` unless `allowUnsafe=true`.
- FairPlay-encrypted bytes are refused (`encrypted_range`).
- A Mach-O code signature stops matching after any change; the patch result and the save say so (re-sign with
  `codesign -f -s -`).
- A universal Mach-O is patched per slice; `save_native` writes the whole file with that slice replaced and checks
  every byte outside it.
- Relocation planning is PE only.

## Relocations

Under ASLR or a rebase, the Windows loader adds (actual base - preferred base) at every base-relocation entry (HIGHLOW:
4 bytes on x86, DIR64: 8 bytes on x64), whatever bytes are there. A patch breaks at another base when:

- an entry still covers bytes that are no longer an address (an overwritten `push offset X`, `mov eax, [abs]`,
  `call [IAT]`, jump table or `mov r64, imm64`): the loader corrupts the new code;
- new bytes hold an absolute address with no entry (on x86 names assemble to absolute addresses, as in
  `mov eax, [global]`).

x64 code is mostly RIP-relative and unaffected. Every `patch_bytes` and `patch_asm` plans both sides:

- **Entries under the patch**: the relocation directory walked as the loader does; every entry overlapping the patched
  (NOP-padded) range. A HIGHADJ parameter slot is not an entry.
- **Addresses in the new bytes**: displacements and immediates, branch and RIP-relative operands excluded.
  `patch_asm` marks operands written as a symbol or with `offset` as addresses.
- Otherwise an operand in [ImageBase, ImageBase+SizeOfImage) is an address when it is an x86 absolute `[disp32]` with
  no base register, an x64 64-bit constant (`mov r64, imm64`, `moffs64`), or sits where an entry of the same type was.
- A hand-written numeric in-image x86 immediate is not relocated; a note says to write `offset 0x...` or a name.
- Raw `patch_bytes` over code: the new bytes are decoded, and an in-image x86 imm32 counts as an address. Over data, an
  entry stays when the new pointer-sized value is still in-image.
- **`relocations`**: `auto` (default) keeps entries that still cover an address of the same type, neutralizes the
  others and adds entries for new addresses; `keep` leaves every entry (new addresses listed as unrelocated);
  `neutralize` neutralizes every entry under the patch.
- **Neutralize**: set the entry's type to IMAGE_REL_BASED_ABSOLUTE (type 0, offset bits kept), a 2-byte edit in
  `.reloc`.
- **Add**: rewrite an ABSOLUTE slot in the same 4 KB page's block (one this patch neutralized, else block padding or an
  earlier neutralized entry) to `type << 12 | offset`. The directory never grows or moves.
- **No slot**: refused with `conflict`, reason `no_relocation_slot`. Fixes: write the reference RIP-relative (x64),
  load the address from relocated data (a pointer or IAT slot), or `allowUnsafe=true` for a patch correct only at the
  preferred base (reported `unrelocated`).
- Clearing DYNAMIC_BASE would avoid it but weakens ASLR; it is never done automatically.
- **Not relocatable** (no relocation directory, or IMAGE_FILE_RELOCS_STRIPPED): "image is not relocatable: absolute
  addresses are fixed (no action needed)".
- **Recording**: entry rewrites belong to the patch, with a per-entry report (kept, neutralized, added, unrelocated;
  target and entry RVA). Every read sees the new table; `undo_native_edit` restores it.
- A later patch may reuse a slot an earlier one neutralized; undoing the earlier first is refused (`conflict`,
  "undo #n first"). A patch overlapping another patch's entry rewrites is refused.
- **Reports**: patch and dry-run output and `list_native_edits` list the relocation changes per patch.
- **Verified**: patched copies of SysWOW64 `version.dll` and `msvcrt.dll` and an MSVC x86 DLL, saved and rebased in
  memory by +0xA30000 as the loader does, decode to the intended operations. The rebase is simulated in an x64
  process, not done by LoadLibraryEx.

## Patch export (export_native_patches)

- PE, ELF and Mach-O. The exported bytes are `save_native`'s: every patch, its `.reloc` rewrites, and the recomputed PE
  checksum when the original had one.
- `ida`: an IDAPython script with a `PATCHES` list of (label, RVA, original hex, replacement hex): one per patch, per
  relocation rewrite and for the checksum.
- The script applies each at `idaapi.get_imagebase() + rva` only where the database holds the original bytes; others
  are reported with expected and found bytes. Bytes not in the database are skipped (IDA loads neither the PE header
  nor `.reloc` by default).
- It then reanalyzes the ranges, prints a summary line, and adds a segment for `extend` code in a new section.
- `dif`: IDA's own format: `This difference file was created by IDA`, a blank line, the file name, then
  `%016X: %02X %02X` (file offset, original, patched) per changed byte, LF line ends. Refused (`grown_file`) when a new
  section grows the file.
- `ips`: `PATCH`, records of 3-byte big-endian offset + 2-byte size + data, `EOF`. Runs up to 4 unchanged bytes apart
  merge; records are at most 0xFFFE bytes.
- A record that would start at 0x454F46 (reading `EOF`) starts one byte earlier. Offsets past 16 MB are refused,
  pointing to `ips32` (`IPS32`, 4-byte offsets, `EEOF`; 0x45454F46 moved the same way). Both extend a grown file.
- `json` (default): kind `corvus.native_patches`; the image (path, original SHA-256, arch, preferred base, file size,
  output SHA-256), every patch (RVA, file offset, hex, description, origin `asm` or `bytes`, assembly text, relocation
  changes) and the checksum change. `migrate_native_patches` reads it.
- **Verified**: independent appliers for .dif, IPS, IPS32 and JSON reproduce `save_native`'s file byte for byte. Under
  idalib the script applies to a fresh database, a second run applies nothing, and IDA's own .dif matches ours minus
  the header bytes it does not load.

## Patch migration (migrate_native_patches)

- Carries an old build's byte patches to a new build.
- Source: the old build's in-memory patches (default) or a JSON patch set from `export_native_patches` (`patchSet`).
  The same image as old and new with `patchSet` replays it.
- `dryRun=true` (default) changes nothing.
- Each patch is reported `applied`, `would_apply` or `refused` with a reason and evidence
  ([migration reasons](migration-reasons.md)).

Per patch:

1. **Map the address** with the `compare_native_images` matcher (function match plus instruction alignment), on the
   old build's original bytes, so a patch does not hide the function. No mapping: refused with the matcher's reason
   (`function_not_matched`, `ambiguous`, `changed_region`, `not_an_instruction`, ...).
2. **Check the pre-patch bytes** in the new build: exact for `patch_bytes`. For `patch_asm`, both sides are decoded and
   address bytes masked. Mismatch: `original_bytes_differ` with expected and found bytes (`??` = masked).
3. **Build the replacement**: `patch_asm` reassembles its text at the new address (symbols resolved in the new build);
   raw patches reuse their bytes. Failure: `assemble_failed`.
4. **Reapply** through the normal patch path. Failures: `relocation_slot_unavailable`, `mid_instruction`,
   `past_function_end`, `conflicts_with_existing_patch`, `cannot_prepare`. Later patches see earlier ones.

- **Verified**: a built pair covers migrate, differing bytes, unmatched function and JSON source; a real pair of
  consecutive builds migrates a `patch_asm` and a `patch_bytes`.

## save_native

- Writes the patched bytes; everything outside patched ranges is byte-identical to the original.
- Recomputes the PE checksum (ImageHlp algorithm) when the original's was non-zero.
- A signed file becomes unsigned (the note says so); `stripSignature=true` zeroes the security directory entry and
  drops the certificate table.
- Atomic. An existing file is replaced only with `overwrite=true`.
- The input is replaced only with `replaceOriginal=true` on a server started with `--allow-replace-original`; it keeps
  a `.bak` and refuses a file changed on disk.
- `versioned=true` writes the first free `<name>.1.dll`, `<name>.2.dll`, ...
- The written file is parsed again and checked: every byte outside the patched ranges, relocation rewrites and checksum
  equals the original; the relocation table holds exactly the planned entries; no new read issues.
