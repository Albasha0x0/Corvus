# Native annotations and patching

Tools: `rename_native`, `comment_native`, `export_native_annotations`, `patch_bytes`, `patch_asm`,
`list_native_edits`, `undo_native_edit`, `save_native` (src/NetDecompilerMcp/Tools/NativeEditTools.cs,
Services/NativeEditService.cs).

## Annotations (names and comments)

- The authoritative in-memory copy is `NativeAnnotations` (per image, keyed by RVA). It is created on first use
  and loaded from a **sidecar** JSON file.
- The sidecar lives under the same per-user root as the analysis cache, a sibling folder:
  `<LocalAppData>/NetDecompilerMcp/annotations/<sha256>.json` (override with `NDM_ANNOTATIONS_DIR`). One file per
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
  overlaying every replacement on the snapshot, a new `PeFile` is parsed from them, and it **replaces** the one the
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
- `patch_asm` assembles x86/x64 text with Iced (`X86Assembler`): multi-line, labels, numeric and symbol branch
  targets, and a `db <hex>` escape. It encodes each instruction at its running address, iterating to a fixed point,
  so near-branch displacements and RIP-relative references are correct for the patch address.
- `dryRun` shows the before/after disassembly without recording the patch. `list_native_edits` / `undo_native_edit`
  manage the recorded patches.

## save_native

- Writes the patched bytes. Everything not inside a patched range is byte-for-byte identical to the original.
- The PE checksum is recomputed (ImageHlp algorithm) when the original had a non-zero one, and written into the
  checksum field.
- A signed file becomes unsigned: the note says so. `stripSignature=true` zeroes the security data-directory entry
  and drops the trailing certificate-table overlay.
- Atomic write (temp file + move); never overwrites the input without `overwrite=true`, keeping a `.bak`.
- Verified by re-parsing the written file and comparing every byte outside the patched ranges (and the checksum
  field) to the original.
