# Native annotations and patching

- Tools: `rename_native`, `comment_native`, `export_native_annotations`, `patch_bytes`, `patch_asm`,
  `list_native_edits`, `undo_native_edit`, `save_native`.
- Edits are in memory. `dryRun=true` is the default and shows the before and after without recording. `undo_native_edit`
  reverts an edit by `editId`.

## Annotations

- **Storage.** `<LocalAppData>/Corvus/annotations/<sha256>.json`, keyed by RVA; `CORVUS_ANNOTATIONS_DIR` overrides the
  folder. The key is the SHA-256 of the file as first loaded; in-memory patches do not change it.
- A changed file gets an empty sidecar. A sidecar for the same path under another hash means the annotations were made
  against an earlier version, and the tool says so.
- **Names.** Start with a letter or `_`, then letters, digits, `_`, `$`, `@`. At most 255 characters. Unique unless
  `allowDuplicate=true`.
- **Comments.** `scope`: `line` (repeatable, shown where referenced), `eol`, `pre`, `plate`, `pseudocode`, `function`,
  or `auto` (default: `function` at a function start, else `line` and `pseudocode`).
- A renamed function shows its name in `list_functions`, `disassemble`, `find_xrefs`, `native_call_tree` and address
  lookup. Names and comments survive a restart and are pushed to IDA and Ghidra.
- **Export.** `export_native_annotations` formats: `json` (default), `ida` (IDAPython), `ghidra`, `header` (types,
  prototypes, typed globals), `objc-header` (Mach-O).

## Patching

- **Architectures.** `patch_bytes` works on any architecture: `hex`, or `value` with `type` (`i8`-`i64`, `u8`-`u64`,
  `f32`, `f64`, `ptr`; `be` suffix for big-endian).
- `patch_asm` and `extend` stubs assemble x86 and x64 only. Elsewhere `patch_asm` is refused (`unsupported`, reason
  `not-assembled`). Assemble elsewhere and pass the bytes to `patch_bytes`.
- **Overlay.** Each patch records RVA, file offset, original and replacement bytes, over a one-time snapshot of the
  file. Every read sees the patched bytes; the image is parsed again after each patch or undo.
- **Targets** must be file bytes mapping to a contiguous file range. Zero-fill and unmapped addresses are refused.
- **Safety.** Over code, the span extends to the next instruction boundary, padded with NOPs. Refused unless
  `allowUnsafe=true`: a patch starting mid-instruction, running past the function's end, or touching header bytes or
  loader-rewritten bytes.
- `extend=true` moves code larger than the site into a stub; the site jumps to it and back. `stubMode`: `replace`
  (default), `before` or `after` the displaced instructions.
- `placement`: `auto` (default: a code cave, else a new section), `cave` or `section`. A new section is a PE section or
  an ELF or Mach-O segment. ELF: little-endian x86 and x64 only. Not in a universal Mach-O slice.

### patch_asm

Assembles x86 and x64 Intel syntax in the form `disassemble` prints, so a line can be copied, edited and patched back.
Covers general-purpose, SSE, AVX, AVX-512 and x87.

- **Operands.** GPR 8/16/32/64 (incl. `r8b`..`r15b`), `xmm`/`ymm`/`zmm`, `mm`, `k`, segment, `cr`/`dr`/`tr`, `st(i)`.
  Immediates in hex (`0x..`, `..h`, bare, optional `-`) or decimal (`#..`).
- **Memory.** `[base+index*scale+disp]`, `fs:[..]`, size specifiers (`byte` to `zmmword ptr`), `[rip+X]`. On x64 a bare
  `[addr]` is RIP-relative; absolute `[disp32]` only when out of reach.
- **Symbols.** `sub_<rva>`, export names, `loc_<rva>` labels, `module!import` (its IAT slot).
- **Prefixes.** `lock`, `rep`/`repe`/`repne`, `bnd`; sized string instructions (`movs`/`stos`/`lods`/`scas`/`cmps`
  b/w/d/q).
- The shortest encoding wins; aliases that do not decode back to themselves are rejected. The block is laid out at the
  patch address. `db <hex>` emits raw bytes. A 16-bit operand size is used only when an operand asks for it.
- **Errors.** `invalid_argument`, naming the line (for example "operand size is ambiguous: add a size specifier such as
  'dword ptr'").
- **Not supported:** AVX-512 decorators (`{k1}`, `{z}`, `{1toN}`, rounding, SAE), VSIB, far pointers, address-size
  overrides, explicit-operand string forms (`rep movsb` works). `notrack` is dropped. Use `patch_bytes` or `db`.

### ELF and Mach-O

- Same overlay, undo, `extend` and `save_native`. Relocation planning is PE only.
- Bytes the loader rewrites (ELF dynamic relocations, Mach-O rebases and binds, import slots) are refused with
  `relocated_range` unless `allowUnsafe=true`. FairPlay-encrypted bytes are refused (`encrypted_range`).
- A Mach-O code signature stops matching after any change; the result and the save say so. Re-sign with
  `codesign -f -s -`.
- A universal Mach-O is patched per slice.

## Relocations

Under ASLR or a rebase, the loader adds (actual base - preferred base) to every base-relocation entry, whatever bytes
are there (HIGHLOW: 4 bytes on x86, DIR64: 8 bytes on x64). A patch breaks at another base when an entry covers bytes
that are no longer an address (an overwritten `push offset X`, `mov eax, [abs]`, `call [IAT]`, jump table or
`mov r64, imm64`), or new bytes hold an absolute address with no entry. x64 code is mostly RIP-relative and unaffected.

Every `patch_bytes` and `patch_asm` plans both sides:

- **Entries under the patch.** The directory is walked as the loader does; every entry overlapping the NOP-padded range
  counts. A HIGHADJ parameter slot is not an entry.
- **Addresses in new bytes.** An operand in [ImageBase, ImageBase+SizeOfImage) is an address when it is an x86 absolute
  `[disp32]` with no base, an x64 64-bit constant (`mov r64, imm64`, `moffs64`), or sits where an entry of the same type
  was. Displacements and branch and RIP-relative operands are excluded; `patch_asm` marks symbol or `offset` operands as
  addresses. A hand-written numeric x86 immediate is not relocated; the result says to write `offset 0x...` or a name.
- Raw `patch_bytes` over code decodes the new bytes. Over data, an entry stays when the new pointer-sized value is still
  in-image.
- **`relocations`**: `auto` (default) keeps entries that still cover an address of the same type, neutralizes the others
  and adds entries for new addresses. `keep` leaves every entry (new addresses listed as unrelocated). `neutralize`
  neutralizes every entry under the patch.
- **Neutralize** sets the type to IMAGE_REL_BASED_ABSOLUTE (0, offset kept): a 2-byte edit in `.reloc`. **Add** rewrites
  an ABSOLUTE slot in the same 4 KB page block to `type << 12 | offset`. The directory never grows or moves.
- **No slot**: refused with `conflict`, reason `no_relocation_slot`. Fixes: a RIP-relative reference (x64), an address
  loaded from relocated data, or `allowUnsafe=true` for a patch correct only at the preferred base (reported
  `unrelocated`). Clearing DYNAMIC_BASE avoids it but weakens ASLR; it is never done automatically.
- **Not relocatable** (no relocation directory, or IMAGE_FILE_RELOCS_STRIPPED): "image is not relocatable: absolute
  addresses are fixed (no action needed)".
- Entry rewrites are part of the patch, reported per entry (kept, neutralized, added, unrelocated). `undo_native_edit`
  restores the table. A later patch may reuse a slot an earlier one neutralized; undoing the earlier one first is refused
  (`conflict`, "undo #n first"), and so is a patch overlapping another patch's entry rewrites.

## Patch export (export_native_patches)

- PE, ELF and Mach-O. The output is `save_native`'s bytes, with `.reloc` rewrites and the recomputed PE checksum.
- `ida`: IDAPython with a `PATCHES` list of (label, RVA, original hex, replacement hex). It applies each where the
  database holds the original bytes, and reports the rest.
- `dif`: IDA's difference format, LF line ends, `%016X: %02X %02X` (file offset, original, patched) per byte. Refused
  (`grown_file`) when a new section grows the file.
- `ips`: `PATCH`, records of a 3-byte big-endian offset, a 2-byte size and data, then `EOF`; records are at most 0xFFFE
  bytes. Offsets past 16 MB are refused; use `ips32` (`IPS32`, 4-byte offsets, `EEOF`).
- `json` (default): kind `corvus.native_patches`, with the image (path, original SHA-256, arch, preferred base, size,
  output SHA-256), every patch (RVA, file offset, hex, description, origin `asm` or `bytes`, assembly text, relocation
  changes) and the checksum change. `migrate_native_patches` reads it.

## Patch migration (migrate_native_patches)

- Carries an old build's byte patches to a new build. `dryRun=true` (default) changes nothing.
- Source: the old build's in-memory patches, or a JSON set from `export_native_patches` (`patchSet`). Each patch is
  `applied`, `would_apply` or `refused`, with a reason ([migration reasons](migration-reasons.md)).

Per patch, in order:

1. **Map the address** with the `compare_native_images` matcher, on the old build's original bytes. No mapping: refused
   with the matcher's reason (`function_not_matched`, `ambiguous`, `changed_region`, `not_an_instruction`, ...).
2. **Check the pre-patch bytes** in the new build. `patch_asm` compares decoded instructions with address bytes masked.
   Mismatch: `original_bytes_differ` (`??` = masked).
3. **Build the replacement.** `patch_asm` reassembles its text at the new address; raw patches reuse their bytes.
   Failure: `assemble_failed`.
4. **Reapply** through the normal patch path. Failures: `relocation_slot_unavailable`, `mid_instruction`,
   `past_function_end`, `conflicts_with_existing_patch`, `cannot_prepare`.

## save_native

- Writes the patched bytes; everything outside patched ranges is byte-identical to the original.
- Recomputes the PE checksum (ImageHlp algorithm) when the original's was non-zero. A signed file becomes unsigned, and
  the note says so; `stripSignature=true` zeroes the security directory entry and drops the certificate table.
- Atomic. An existing file is replaced only with `overwrite=true`. `versioned=true` writes the first free
  `<name>.1.dll`, `<name>.2.dll`, ...
- The input is replaced only with `replaceOriginal=true` on a server started with `--allow-replace-original`; it keeps a
  `.bak` and refuses a file changed on disk.
- The written file is parsed again and checked against the planned patches and relocation table.
