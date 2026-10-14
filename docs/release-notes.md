# Release notes

## 2.0.1

- **Security.** Built with .NET SDK 10.0.402: the self-contained builds carry runtime 10.0.13 (the October 2026 .NET
  security release), and `System.Security.Cryptography.Pkcs` is 10.0.13 (CVE-2026-84008, CVE-2026-70162). Update
  framework-dependent installs (`dotnet tool`, `dnx`) to a 10.0.13 runtime.
- **nuget.org and the MCP Registry.** The `CorvusRE` .NET tool package carries a README (with the registry's ownership
  line), so it is published on nuget.org (`dotnet tool install -g CorvusRE`, or `dnx CorvusRE --yes`) and listed in the
  MCP Registry as `io.github.Albasha0x0/corvus`.
- **Unsaved-session notice stays one line.** Loading an image with many abandoned edit or patch sessions names the
  newest one with its replay command and counts the older ones, instead of one line per session.
- **Release assets** ship under the `corvus` name only.
- **Docs.** A shorter README; feature detail in [features.md](features.md), server options in
  [installation.md](installation.md#server-options).

## 2.0.0

155 tools (1.3.0 had 158): `decompile_type`, `decompile_assembly_attributes` and `find_overrides` are folded into other
tools. This is the breaking release. Every tool now follows one output contract: a structured record with an output
schema on every tool, a list envelope `{items, offset, limit, total, totalExact, hasMore, nextOffset}` on every list,
a token budget per part (text and structured content are each fitted to it), errors with a `Next:` line, and long or
cut results kept under an id that `read_result` pages. Edit tools preview by default (`dryRun=true`). Parameter names,
paging units and record shapes changed across every family; the checklist below covers what a 1.x caller must change.

### Upgrading from 1.x

- **Edits preview by default.** Every .NET and native edit tool, and `migrate_native_names`, defaults to `dryRun=true`
  and ends with "Nothing changed (dry run); pass dryRun=false to apply". Pass `dryRun=false` to apply.
- **Removed tools.**

  | Removed | Use instead |
  |---|---|
  | `decompile_type` | `decompile_member` with the type |
  | `decompile_assembly_attributes` | `get_attributes format=csharp` |
  | `find_overrides` | `find_references kind=overrides` |

- **Renamed parameters** (no aliases):

  | Tool | 1.x | 2.0 |
  |---|---|---|
  | every tool with a size limit | `maxChars` | `maxTokens` |
  | `find_call_paths` | `maxPaths` | `limit` (with `offset`) |
  | `diff_function` | `maxLines` | `offset`, `limit`, `maxTokens` |
  | `inspect_instruction` | `count` | `limit` |
  | `ida_python` | `maxOutput`, `file` | `maxTokens`, `scriptPath` |
  | `ghidra_script` | `timeout` | `timeoutSeconds` |
  | `find_virtual_calls`, `emulate_native`, `reanalyze_native` | `seconds` | `timeoutSeconds` |
  | `search_decompiled` | `cursor`, `seconds` | `offset`, `timeoutSeconds` |
  | `search_instructions`, `reanalyze_native` | `start`, `end` | `from`, `to` |
  | `list_imports` | `module` | `library` |
  | `load_pdb` | `force` | `allowMismatch` |
  | `patch_bytes`, `patch_asm` | `force` | `allowUnsafe` |
  | `export_engine_database` | `force` | `overwrite` |
  | `get_resource`, `get_android_resource` | `savePath` | `outputPath` |
  | `export_edits`, `save_session` | `path` | `outputPath` (parameter and record) |
  | `undo_native_edit` | `number` | `editId` |

- **Booleans that now default to false**, under a new name with the opposite sense. Omitting them behaves as before.

  | Tool | 1.x | 2.0 |
  |---|---|---|
  | `apply_edits` | `stopOnError=true` | `continueOnError=false` |
  | `compare_assemblies` | `listAddedRemovedTypes=true` | `typeCountsOnly=false` |
  | `decompile_java` | `smaliFallback=true` | `javaOnly=false` |
  | `disassemble` | `function=true` | `fromAddress=false` |
  | `dump_stack` | `exceptionContext=true` | `dumpTimeContext=false` |
  | `install_android_package` | `replace=true` | `keepInstalled=false` |
  | `read_dump_memory` | `imageFallback=true` | `dumpOnly=false` |
  | `trace_native_values` | `followGlobals=true` | `stopAtGlobals=false` |
  | `unpack_container` | `load=true` | `extractOnly=false` |
  | `comment_native` | `dedupe=true` | `repeatLine=false` |
  | `find_call_paths` | `includeVirtual=true` | `directOnly=false` |
  | `find_references` | `includeVirtualCalls=true` | `directOnly=false` |
  | `list_types` | `includeNested=true` | `topLevelOnly=false` |
  | `migrate_native_names` | `comments=true` | `namesOnly=false` |
  | build tools | `useNames=true` | `codeOnly=false` |

  `set_native_type` now defaults `rename` to false, and `get_native_frame` needs `locals=true` for decompiler locals.
- **Lists take arrays.** Parameters that took a separated string are arrays: `record_note` / `update_note` tags,
  `compare_folders` `exclude` (globs), `extract_strings` `types`, `simplify_methods` `passes`, `compare_assemblies`
  `changes`, `migrate_native_names` `sources`, `search_code_pattern` `images`, `update_to_new_build` `include`,
  `oldIl2Cpp` and `newIl2Cpp`.
- **Paging counts rows.** `offset` counts rows, nodes, blocks or bytes as each tool states, never characters; continue
  with the `nextOffset` the result gives. `truncated` is gone from every record: `hasMore`, `nextOffset` and
  `totalExact` say it. Most default page sizes are smaller (listed per family below); `maxTokens` raises a page.
- **Records changed.** Row arrays are named `items` almost everywhere, and many fields were renamed or dropped. The
  full described schema of every tool is in [docs/schemas](schemas/). By default the text part is readable rows, not
  the record's JSON: read values from the structured content (`CORVUS_RESULT_MODE=json` restores a JSON copy in the
  text).
- **Edit ids.** .NET edits are numbered `<assembly>#<n>` and native edits `<image>#<n>`. The ids are stable: undoing
  an edit no longer renumbers the others. `undo_edit` and `diff_edits` take the id in `number`; `undo_native_edit`
  takes `editId` (`image#n`, `#n` or `n`, or a comma list).

### Changes in behaviour

#### .NET read

- **Consolidated tools.** `decompile_member` decompiles a whole type, `get_attributes format=csharp` gives assembly
  attributes as C#, and `find_references kind=overrides` lists overrides.
- **List contract.** Every .NET list tool returns the list envelope, pages by rows with `[More: offset=N]` /
  `[End: …]` footers ("N things (showing a-b)") and takes `maxTokens`. `get_call_tree` and `compare_assemblies` page
  by rows (was characters), `get_call_tree` loses `maxNodes`, and `list_resources` gains `offset` and `limit`.
- **New parameters.** `get_type_info` `section`, `offset`, `limit`; `get_assembly_info` `view` (default `summary`;
  references, tables and heaps only in their views); `get_attributes` `format`, `offset`, `limit`, `maxTokens`;
  `get_type_hierarchy` and `resolve_symbol` `offset`, `limit`; `search_il` `context`; `export_project` `overwrite`.
- **Default limits.** `list_namespaces` 2000 → 200, `list_types` 300 → 150, `find_references` 300 → 150,
  `find_callees` 2000 → 200, `search_strings` and `search_constants` 200 → 100, `get_r2r_code` `maxInstructions`
  5000 → 1500.
- **Records.** `TypeEntry.fullName` → `name`, and `kind` is absent for a plain class; `MemberEntry.ilInstructions` →
  `il`. Member references are flat (`label`, `token`, `assembly`); `find_references` shows the member only where it
  changes and `get_call_tree` rows lose `id`/`parent` and show `depth` only where it changes; `basis` appears only when
  derived. New records for `get_attributes`, `get_type_hierarchy`, `decompile_member`, `get_il`, `get_resource`,
  `get_r2r_code` and `find_r2r_method`.
- **`get_type_info`.** `nestedTypes`, `fields`, `properties`, `events` and `methods` become one `items` array with
  `kind`, plus `counts`. The default `section=summary` lists the first 8 of each kind. The top-level `fullName` moves to
  `type.label`; member rows drop `name` (they carry `token`, `signature`, `kind`, `il`; a constructor shows the type
  name).
- **`export_project`** is annotated destructive. It decompiles a private snapshot outside the workspace lock, writes
  through a staging folder (whole or not at all), replaces a previous export with `overwrite=true` and returns a
  record.

#### .NET edits

- **Preview by default** on `rename_symbol`, `rename_namespace`, `stub_method`, `patch_method_csharp`,
  `patch_method_il`, `add_members_csharp`, `add_types_csharp`, `simplify_methods` and `apply_edits`.
  `patch_method_csharp`, `add_members_csharp`, `add_types_csharp`, `undo_edit` and `apply_edits` are marked
  long-running and report progress.
- **Records.** All 15 edit tools return records. A single edit gives `{applied, dryRun, changes[{kind, target}],
  editIds}`, and its text ends "Edit <id>. Unsaved edits in …". `list_edits` pages rows (`offset`, `limit`,
  `maxTokens`) of `{number, editId, tool, description}`.
- **`apply_edits`.** A rolled-back script, or one where every edit failed, is now an error with code `failed` and
  per-edit items in `partial` (was success); items carry `code` and `basis`.
- **`revert_edits`** returns a `resultId` holding the discarded edits as a script.
- **`simplify_methods`.** `passes` is an array of `fold`, `cfg`, `inline` (omit for all three); `maxDepth` and
  `budget` are plain integers (8 and 100000); the totals line follows the header.
- **`compare_assemblies`** is read-only and in the `readonly` tool list: `tokenMapPath` and `overwrite` are removed and
  `tokenMap=true` returns a `tokenMapResultId` (write it with `read_result outputPath=`). Default page 200 → 100.
- **`find_counterpart`.** `symbol` is optional, `symbols[]` takes up to 100, with `offset`/`limit` and a
  `CounterpartList` record.
- **`patch_method_il`** operand syntax moved from the tool description to the edits guide.
- **`diff_edits`** gives an exact `totalChars` on every page (the "+" after the total in `[More: …]` is gone); a diff
  stops at 200 members with a closing note line.

#### Native analysis

- **Default limits.** `list_imports` 500 → 200, `list_exports` 500 → 300, `list_functions` 300 → 150,
  `list_globals` 300 → 200, `search_native_strings` 300 → 100, `resolve_call_targets` 100 → 75,
  `search_pdb_symbols` 200 → 150, `find_xrefs` 500 → 200, `verify_native_imports` 500 → 100,
  `get_call_arguments` 100 → 50. 17 native list tools take `maxTokens` as their last parameter.
- **`native_call_tree`** returns `NativeTreeNode` rows with a per-page `frontier` of unexpanded nodes. `offset` counts
  nodes (was characters), a new `limit` (200) sets the page and `maxNodes` drops from 500 to 250. `direction=both` is
  caller/callee rows by call site (was two sections).
- **`get_cfg`.** Record `blocks` → `items` with `offset`, `total` and a whole-function `summary`; `truncated` → `cut`;
  `offset` counts blocks, new `limit` (150).
- **`read_bytes`.** `offset` is a byte offset from `address`; the record is a `ByteDump` with `nextOffset` and
  `nextAddress`, paged by whole 16-byte lines within the budget.
- **`disassemble`** returns a body record. **`search_instructions`** has a new list record, `start`/`end` →
  `from`/`to`, and its count reads "N matching instructions" (was "N match(es)"). A page stopped by the scan budget
  has `hasMore=true`, `totalExact=false` and a `nextOffset` that resumes there; `maxInstructions` counts per page, and
  a page scans on to one new match (up to 5,000,000 instructions, then it names `from=`). The stop line reads "Scan
  budget of N instructions reached at X: the next page goes on from there" and `coverage.reason` "the scan budget
  stopped at X; total is a lower bound".
- **Batches.** `resolve_address` drops `more` and `lines`; its batch is `results` (`BatchItem`) with `failed`.
  `search_bytes` `patterns[]` is `BatchItem<{total, items}>` with `failed`. `find_xrefs` batch errors go into
  `targets` / `failed`. When every item fails the call is an error.
- **`find_xrefs`** gains `kind=metadata`: format tables naming an address (`.pdata`, CFG tables, export address
  table).
- **`get_call_arguments`.** `calls` → `items`, `display` dropped. **`get_exception_info`** has a new record.
  **`list_cpp_classes`** returns class rows, `offset` counts classes, new `limit` (100). **`load_pdb`** returns the
  shared edit result.
- **`find_similar_functions`** text is rows, and every view puts its rows in `items`: match rows (was `matches`) in
  `similar`, groups in `duplicates` and `clusters` (`groups` is removed). The list envelope describes those rows.
- **`verify_native_imports`** text is rows; its record keeps the first 20 run-time loads (was 100).
- **New parameters.** `get_pe_info` `view` (`view=code`: function statistics, capabilities, dynamic imports);
  `trace_native_feature` `engine`; `search_native_strings` `maxLength` (default 200); `get_native_type` takes a glob
  and lists every match.
- **Undecoded architectures.** On MIPS, PowerPC, RISC-V and s390x, `find_xrefs`, `native_call_tree` and the other code
  tools refuse with `unsupported` (`details.reason=instructions-not-decoded`, `arch`), instead of succeeding with 0
  rows.
- **`trace_native_feature`** record loses `truncated` (`nextOffset` says it).

#### Native edits and journal

- **Preview by default** on `rename_native`, `comment_native`, `patch_bytes` and `patch_asm`.
- **Journal.** Every applied native edit (bytes, names, comments, engine edits) returns an `editId`. `undo_native_edit`
  takes `editId` and undoes all of them, pushing the undo into an open IDA or Ghidra session. `list_native_edits` shows
  journal rows with `offset`/`limit` (100) and search pages.
- **Records.** The 8 native edit tools return structured records; texts read "Recorded as image#n" and "Dry run: …".
- **`patch_bytes` / `patch_asm`:** `force` → `allowUnsafe`. `patch_asm` on a non-x86 image is `unsupported`.
  **`comment_native`:** `dedupe` → `repeatLine` (default false). **`rename_native`:** `showDecompile` needs
  `dryRun=false`.
- **`export_native_annotations`** takes `format` in lower case. Session files gain `native[].journal`, so restored
  names, comments and engine edits stay undoable on the same build.
- **`export_native_patches`** text is one readable line (was the record's JSON).

#### Engines (IDA and Ghidra)

- **`engine=auto`** follows one rule: the preferred installed engine (IDA, then Ghidra) that has analyzed these bytes,
  live or saved, else ours. It never depends on earlier calls and may open a saved analysis. Engine-only tools use the
  same rule, else the first installed engine; `engine=ours` on an engine-only tool is `invalid_argument`. Note texts
  changed.
- **`decompile_native`.** The text is deterministic: push banners, open time and saved-analysis state moved to
  `_meta`, and the header loses "analyzed in" / "saved analysis". Record `Total` → `Inputs`, `Next` → `NextInput`. With
  `functions` or `callersOf`, `offset` is an input index; unreached inputs are counted, not listed.
- **`emulate_native`**, **`reanalyze_native`**, **`search_decompiled`**: `seconds` → `timeoutSeconds` (out of range is
  an error), new records, elapsed time only in `_meta`. `search_decompiled` `cursor` → `offset`, record fields renamed
  (`FunctionsTotal`, `Offset`, `FunctionsSearched`, `NextOffset`, `HasMore`, `TotalExact`) and `hits` → `items`
  (`offset` still counts functions searched). `reanalyze_native` `start`/`end` → `from`/`to`, and `analyzers=true`
  pages its options by `offset`/`limit` (200) with the list envelope.
- **`ida_python`**: `maxOutput` → `maxTokens`, `file` → `scriptPath`. **`ghidra_script`**: `timeout` →
  `timeoutSeconds`, plus `maxTokens`. In both, a script exception is an error unless `allowError=true`, and output past
  the page is kept under a `resultId`.
- **`get_native_frame`** is structured and row-paged; decompiler locals need `locals=true`, and the text has no
  "Decompiler locals" section. **`list_native_types`** is structured and sorted by name. **`set_native_type`**
  `rename` defaults to false.
- **`export_engine_database`** `force` → `overwrite`; it returns text plus a record.
- **Engine edits** return the shared edit result with `editIds` and are undone with `undo_native_edit`.
- Engine-backed code tools put the engine's version, build and profile in `_meta`; `get_engine_status` reports each
  engine's analysis profile and limitations.

#### Builds

- **`migrate_native_names`** previews by default; `sources` is an array (`user`, `pdb`, `il2cpp`); `comments` →
  `namesOnly`; record `entries` → `items`, `considered` and `truncated` removed, `applied` and `editIds` added. Default
  limit 200 → 100.
- **All build tools:** `useNames` → `codeOnly` (default false). One reason vocabulary
  ([docs/migration-reasons.md](migration-reasons.md)) and one build match on the original bytes, so
  `migrate_native_names` and `update_to_new_build` agree.
- **`compare_native_images`.** One row type in `items` replaces `pairs`, `unmatched` and `ambiguousFunctions`; the
  per-pair `changes` string is gone; default limit 100 → 40; takes `maxTokens`.
- **`map_address_between_builds`** and **`make_code_pattern`**: `address` is optional and `addresses[]` is added;
  records are `{oldImage, newImage, results[], failed}` and `{image, format, results[], failed}`.
- **`diff_function`.** `maxLines` → `offset`/`limit`/`maxTokens`; rows (pseudocode lines too) in `items`, `unified` and
  `truncated` removed; `addresses[]` gives `functions[]` summaries.
- **`search_code_pattern`.** `images` is an array; `hits` → `items` with `offset`; `failed[]`; `length`, `images`
  (count) and `truncated` removed. Default limit 200 → 100.
- **`migrate_native_patches`.** `entries` → `items`; the applied / would-apply counts become `carried`; `applied` is a
  boolean; `editIds` added; `truncated` removed. Default limit 200 → 100.
- **`update_to_new_build`.** `include` (an enum array), `oldIl2Cpp` and `newIl2Cpp` are arrays; categories lose
  `notCarriedBy`; the record loses `category`, `outcome` and `truncated` and gains `editIds` and `maxTokens`.
- `compare_native_images` `view`, `diff_function` `view` and `side`, and `make_code_pattern` `anchor` and `format` are
  no longer nullable in the schema; their defaults (`pairs`, `asm`, `old`, `auto`, `ida`) are stated.

#### Containers

- **`summarize_file`** takes `view` (default `overview`). The record is `{path, size, type, sha256, container, view,
  views, md5, sha1, entropy, signature, assemblies, highlights, highlightTotal, entryPoints, values, detail, notes}`:
  the signature is one line, highlights are the first 25, and the typed sections (NativeAOT, native image, packers,
  Android, triage, Electron, Go, full assembly lists) move into `detail` under their view.
- **`survey_features`** default rows are `{name, category, matches, attack?, basis?}` without evidence; `category=` (a
  category, technique prefix or `all`) adds `evidence[]` and `attackName`. Evidence from a string or argument constant
  is `basis=derived`. `image` accepts an unloaded path.
- **`extract_strings`** is read-only: `savePath`, `format` and `overwrite` are removed; `types` is an enum array (was a
  comma string); rows page by `offset`/`limit` (100). The record holds `items`, `byType`, `valuesResultId` and `notes`
  (`values` and `savedTo` are gone); export with `read_result id=<valuesResultId> outputPath=…`.
- **`extract_embedded`.** `contents` → `items` with the list envelope, `offset`/`limit` (100), `basis=inferred`;
  accepts a container path, with sources prefixed by the inner path.
- **`search_container`.** `matches` → `items` `{path, name, kind, assembly?, detail?}`, `assembliesSearched` →
  `searched`, `truncated` removed, `offset`/`nextOffset`, default limit 200 → 100, new `kind=file`.
- **`unpack_container`.** `files` → `items` paged by `offset`/`limit` (100) with paths relative to the output
  directory; host and apphost rows read `extracted:false`; a `next {tool, arguments, reason}` when nothing was
  extracted; data that is not a container is `unsupported` (was success with no files). Text is readable rows (was a
  table) and the "N files written; 100 listed" note is gone. `load=true` → `extractOnly=false`.
- **`unity_overview`**: the not-Unity message changed (same code; the looked-for list is in `details`).
- **Unity Il2Cpp packages.** `list_assemblies path=` and `summarize_file` read a Unity Il2Cpp APK or AAB as "Android
  package (Unity Il2Cpp)" (was "(Unity Mono)"). The first page of `list_assemblies path=` is always in list order (app
  first, translations last).
- **`--load`** of a .vsix, .nupkg or .zip unpacks it and loads the assemblies inside (was refused).

#### Android

- **List tools** (`list_dex_classes`, `list_android_resources`, `search_dex`, `find_dex_references`,
  `list_jni_bindings`, `list_android_packages`, `get_android_device_info`) use the list envelope, `truncated` removed,
  and their text is rows, not JSON. Default limits: classes, resources, hits and references 100 (was 500 or 200), JNI
  bindings 75 (200), device packages 150 (500), properties 100 (200).
- **`list_dex_classes`** rows show descriptors only (`javaName` removed); `interfaces` is capped at 3 with
  `interfacesTotal`; R8 map-id source files move to a note; the record gains `packages`.
- **`list_android_resources`** rows: `id` is a hex string (was a number), `isPublic` → `public` (only when true),
  values cut at 200 characters with `valueTruncated`.
- **`get_dex_class`** pages its members as `items` (`kind`, `id`, `declaration`, …) instead of `fields[]` /
  `methods[]`, which are now counts; new `members`, `query`, `offset`, `limit` (150). **`disassemble_dex`** starts a
  class with its method index.
- **`get_android_resource`**: `savePath` → `outputPath`; record `{entry, outputPath, bytes, sha256}` plus page fields.
- **`get_android_manifest`** takes `view`, `offset`, `limit`. The summary has `componentCounts`, `exported` (strings)
  and `exportedTotal` instead of `components`; permissions, declared permissions, queries and meta-data are strings;
  `view=components` gives rows.
- **`read_android_log`**: `maxBytes` removed; `buffer`, `offset` (lines back from the newest) and `limit`; structured
  lines, newest first.
- **`map_java_dotnet`**: an Il2Cpp package is `unsupported` (`details.reason=il2cpp`, with the Il2Cpp route), not
  `not_found`; `offset`/`limit` and the list envelope; `*` / `?` symbols list pairs (`direction=pattern`).
- **`install_android_package`** / **`uninstall_android_package`** return an edit outcome; `replace=true` →
  `keepInstalled=false`. **`decompile_java`** and **`disassemble_dex`** return structured page records;
  `smaliFallback=true` → `javaOnly=false`. **`pull_android_file`** of a missing remote file is `not_found` (was
  `failed`).

#### Dumps, Il2Cpp and NativeAOT

- **`open_minidump`** takes `view=summary|modules|threads|memory|unloaded` with `offset`/`limit` (50);
  `modulesOffset`, `modulesLimit`, `threadsOffset`, `threadsLimit` are removed. The record `DumpSummary` becomes
  `DumpReport {id, view, summary fields, counts, faultingModule, faultingThread | items, offset, total}`; the streams
  list is removed, handle types are strings and comments move to `notes`; `system` is `{architecture, os, processors,
  buildString}`; the exception instruction carries its bytes and `instructionBytes`, `moduleOffset`, `threadName`,
  `nestedRecord` are removed; module rows lose `end` and `checkSum`.
- **`inspect_process`** takes `view=summary|modules|regions|threads|stacks`, `offset`/`limit` (50) and `thread` for
  the stacks view; `sections` and the per-section offset/limit pairs are removed; `maxFrames` defaults to 64; thread
  rows lose `frames`, `registers` and `basePriority` (registers are in `view=stacks`).
- **`dump_stack`**: `frames` → `items`; `heuristic` → `basis` (`derived` or `inferred`, absent when observed);
  `heuristicFrames` → `scannedFrames`; `truncated` removed. `exceptionContext=true` → `dumpTimeContext=false`.
- **`dump_heap`**: `types` / `objects` → `items` (`HeapRow {type, size, count?, address?, value?, assembly?,
  token?}`); `walkStopped` → `totalExact=false`; `truncated` removed. `dump_heap` and `dump_object` leave `token` out
  for a type without a TypeDef (was `0x02000000`).
- **`symbolize_stack_text`**: `frames` → `items`; default limit 200 → 50; three or more matching native frames of one
  image fold into one row (`folded[]`; `allFrames=true` lists each); `frames` is the input frame count and `total` the
  row count.
- **`bucket_minidumps`**: `buckets` → `items`; `truncated` removed.
- **`read_dump_memory`**: record `{code, offset, nextOffset, nextAddress}` holding the page as hex; `hex` and `bytes`
  removed; new `offset` in bytes; 32 bytes per line in 4-byte groups, 64-bit addresses without the backtick.
  `imageFallback=true` → `dumpOnly=false`.
- **`get_il2cpp_info`**, **`find_method_by_address`**, **`export_il2cpp_symbols`** and **`apply_il2cpp_names`** return
  structured records; `apply_il2cpp_names` no longer shows timings in its text.
- **`get_nativeaot_info`**: `offset` counts rows in every view (was characters for summary and type); limit 200 → 75;
  the type view lists slots as rows; `truncated` removed. NativeAOT statics without field metadata read as
  `Owner::field_0xN`.
- `maxTokens` on every list tool of the family. The `generate_cpp_binding` host-API function-table details moved from
  the tool description to the Il2Cpp guide.

#### Session and notes

- **`load_assembly`**, **`unload_assembly`**, **`reload_assembly`**, **`add_search_directory`** return a record
  `{ids, text}`.
- **`list_assemblies`** returns `{items, offset, total, searchDirectories, backgroundIndexing, container?}` with the
  list envelope. `assemblies` and `nativeImages` merge into `items` with `kind` (`assembly`, `native`, `contained`,
  `file`); inapplicable fields are absent (`readyToRun` and `il2CppDummy` only when true, `unsavedEdits` only when some).
  With `path`, the container's assemblies or files are the rows (`container.files` and `fileTotal` removed). The count
  reads "assemblies", or "images" when native images are loaded (was "files").
- **`save_session`**: `path` → `outputPath` (parameter and record); returns a summary line plus the record.
  **`load_session`**: text rows with a header, the list envelope instead of `truncated`, progress notifications.
- **`record_note`** / **`update_note`**: `tags`, `addTags`, `removeTags` are string arrays; `evidence` / `addEvidence`
  are arrays of `{tool, args, resultSha256}` or `{text}`; a missing `resultSha256` is filled from the latest identical
  call in this process; one entry is at most 1,000 characters of JSON.
- **Note files** use format `corvus-notes/2`; format 1 is still read, with evidence strings becoming `{text}`.
- **`list_notes`**: text rows with the list envelope; `truncated` removed.
- **`read_result`** ids are content ids (`r-` + 12 hex), kept in memory and on disk for 7 days across restarts
  (`CORVUS_RESULT_CACHE`, `_MB`, `_DAYS`). It pages by `maxTokens`, searches with `query` and writes the whole result
  with `outputPath`. Its output class is bytes (the record gains `code` on query and outputPath results) and the record
  `format` field is removed.

#### Server and catalog

- **Output budget per part.** Text and structured content are each fitted to a token budget set by the client's
  profile (`--client`, `CORVUS_CLIENT`, `CORVUS_MAX_OUTPUT_TOKENS`); `maxTokens` asks for more up to that ceiling. A
  call answers 5 s before the client's own limit with a `timeout` whose `details.stillRunning` says the work goes on,
  and the same read-only call made again picks up the running work.
- **Cut warnings.** A record cut to fit carries one warning per cut array: "Cut to fit: <path> <kept> of <total> kept;
  read_result id=…". The cut trims the outermost arrays toward a common size in a few passes, so kept counts per array
  can differ from 1.x's one-row-at-a-time cut.
- **Errors** always carry a `Next:` line; an error over the budget sends its head and keeps the whole error under
  `details.resultId`. Every missing input path gives the same `not_found` text with its Next. Errors carry
  `_meta["corvus/provenance"]` too.
- **Output schemas on every tool** (the CLI's `--structured` refusal is unreachable). In `tools/list`, output schemas
  are compact: no `required` lists and objects below the rows are `{"type":"object"}` (depth 2, was 3).
  [docs/schemas](schemas/) keeps the full described form, and the tests validate results against both.
- **Input schemas.** Optional parameters have no `null` in `type` or `enum` (`"type":"string"`, was
  `["string","null"]`); a null sent anyway is treated as omitted. Booleans no longer declare `"default": false` (absent
  means false) and `offset` no longer declares `"default": 0`; other defaults stay.
- **Annotations.** No `annotations.title` (the top-level `title` stays); read-only tools omit `destructiveHint` and
  `idempotentHint`.
- **Descriptions.** The long-running suffix is " [Long-running.]" (was " [Long-running: can exceed 10 s.]"). The native
  `image` parameter reads "Native image id, file name or path." and `engine` "auto (default): IDA, else Ghidra, if it
  has analyzed these bytes, else ours. ida / ghidra: that engine, started when needed." Behaviour is unchanged.
- **Paging texts.** Character-paged text counts the LF-normalized text in "offset … past the end of the output (N
  chars)", as `totalChars` does. Generic record text reads "1 row (showing 1-1)" (was "1 rows").
- **Profiles.** `--toolsets core` (at most 100 tools) and `lean` (at most 40) sit beside `full`, and combine with
  families (`lean,dumps`). Clients that cap tool counts get `lean` by default. The MCP bundle offers the profile as a
  setting.
- **Catalog size.** `tools/list` fell from 349,663 to 297,064 bytes and the model-facing catalog from 167,541 to
  157,565 bytes; output schemas total 102,990 bytes.
- **`server_status`.** `unavailableTools` rows are `{tools[], reason, remediation}`; paths under the data folder read
  `<dataDir>\…`, with `run.dataDir` added. New sections for the budget, kept results, caches, leftover calls and lock
  holders, worker processes and the run id.
- **Token estimate.** A hex word counts 0.6 tokens per character (was 0.67), so `read_bytes`, `read_dump_memory` and
  other hex records carry about 10% more bytes per page.

### Improvements

#### Speed

- **Engine output cache.** Pseudocode and frames with decompiler locals are kept across processes, keyed by the engine
  build, the input and the database state. A decompile that took 169.7 s answers in 87 ms from a fresh process,
  byte-identical (`CORVUS_ENGINE_OUTPUT_MB`, default 1024).
- **Record cut.** Fitting a 20,000-node record took over 10 minutes; now 0.7 s.
- **`get_pe_info`** computes its record once per image: 38 → 7 ms warm.
- **.NET edits.** Each tree compiles once per edit. On a large assembly a warm `patch_method_csharp` drops from 7 s to
  2–4 s, `add_members_csharp` from 19–34 s to 3–7 s and `undo_edit` from 36 s to 5–10 s. A no-op write keeps the
  decompiler caches.
- **Constructors.** The constructors of one type share one decompile: 12.7 → 6.1 s for a batch, 0.06–0.6 s each.
- **Startup.** Tools are built on all cores: `initialize` takes about 0.8 s and the first `tools/list` about 8 ms
  (was 85 ms).
- **ARM64 late-bound imports.** Each function's call sites are analyzed once: 10–16 s → 3 s on a single-file host.
- **Smaller default pages.** `summarize_file` 8,094 → 1,881 tokens, `survey_features` 5,155 → 470, `open_minidump`
  summary 1,113, `inspect_process` summary 576.

#### Accuracy (our engine against IDA)

- **x86 / x64.** x86 call and jump references 76.1 / 87.7% → 100%; x64 calls, jumps and data 100%; x64 function-start
  F1 100 (IDA 99.3). Retpolines, return thunks and i386 PIC PLT stubs no longer mark functions no-return; i386 PIC and
  x64 relative switch tables resolve through tracked registers and stack slots.
- **ARM32.** Function starts on Debian armhf F1 86.9 → 97.8 (IDA 96.1); calls 100%; tail-jump-only targets become
  functions when their frame balances (misses 243 → 136).
- **ARM64.** `.pdata` fragments join their function (start F1 96.7 → 98.9); calls, jumps and data 98.3 / 98.3 / 96.1%
  → 99.99 / 99.91 / 99.67%.
- **NativeAOT.** Handler and filter funclets join their method and nop/int3 padding is not a function: 6,771 → 5,429
  functions on the reference app (PDB: 4,990 plus 87 helpers).
- **ELF.** A GNU hash table that names no symbol no longer reads as one symbol and no imports.
- **Ghidra** creates a function on request where our index starts one and its analysis does not.
- Code index persist format 14; older indexes are rebuilt on first use.

#### Reliability

- **`export_project`** works on a private snapshot outside the workspace lock, so edits, reloads and unloads no longer
  wait for it; a client deadline leaves a partial result.
- **Lock-scope check.** `CORVUS_LOCK_CHECK=1` fails a call that reads a module or decompiler reader without the
  workspace lock; the test suite runs with it on, and the call-graph build and indexing were fixed under it.
- **Cancellable waits.** Build-once caches (ReadyToRun, DEX code index, JADX sessions, minidump name tables, Il2Cpp
  string indexes, PDB type models, provider probes) and the edit journal sync stop waiting when their call is
  cancelled.
- **Engine opens** report progress every 4 s; a deadline during an open is a `timeout` with `stillRunning` and
  `retryAfterMs`, and the retry joins the same open.
- **Temporary files.** Dump decoders, the 32-bit CLR helper, engine patched-image and Mach-O slice folders, and ClrMD's
  `%TEMP%\symbols` are cleaned up.

#### Android

- **`decompile_java`** finds member, anonymous, local and lambda classes where JADX writes them, reads jars of
  `.class` files, and reports progress while JADX starts.
- **Il2Cpp builds** are recognized and routed to the Il2Cpp tools; dotted Java names and crc64 wrappers map between
  Java and .NET.

#### Containers

- **`summarize_file`** views and **`--load`** of .vsix, .nupkg and .zip (see Changes in behaviour);
  **`extract_embedded`** searches every assembly in an .apk or package.

### Fixes

- `map_java_dotnet` walked modules after releasing the workspace lock; a parallel edit or reload could dispose them
  (`NullReferenceException`).
- `export_project` on an .apk failed before the tool ran.
- `find_method_by_address` and `get_il2cpp_info` printed a negative `[More: offset=]` when `offset + limit` overflowed.
- `pull_android_file` reported a missing remote file as `failed`.
- On Linux and macOS, percentages printed as "0 %" (culture-dependent); every host now prints "0%". PDB object names
  recorded as Windows paths kept their folders on Linux and macOS.
- `server_status` on a server without IDA or Ghidra was cut to fit; an engine value missing on many tools is now one entry.
- `patch_asm` on an image it cannot assemble named the architecture "Other" (s390x); it now names the machine and
  carries `details.arch`.
- C# edits: enclosing namespaces' types bind first again (CS0115 / CS1503), and a reference newer than the runtime's
  assembly of the same name is kept (CS1705).
- `export_native_patches format=ida` failed in IDA 9 for an appended segment.
- Undoing a native edit in an engine restores the export name (not `sub_`) and the engine's own prototype.
- `get_call_tree` text marks native-to-managed transitions again; `dump_stack` text was missing `token` and
  `ilOffset`.
- Budget overruns: the token estimate undercounted packed strings, UTF-16 and hex; parts are now fitted 5% under the
  budget.
- POSIX engine workers lead their own process group, so a killed server ends them under `dash` too.
- `analyze_native_function` answered a repeated call from its cache without the "body may be cut" warning and, on
  undecoded architectures, without the partial-coverage note.
- `search_instructions` gave no continuation for a page stopped by the scan budget.
- `list_assemblies` on a container gave overlapping pages: 16 of 69 assemblies in a .vsix were never listed.
- `diff_edits` `totalChars` changed from page to page.
- Unity Il2Cpp APKs were labelled Unity Mono.
- `find_similar_functions` duplicates and clusters showed 0 rows to a client reading the list envelope.

### Known limitations

- Android list tools do not take `maxTokens` yet.
- The engine output cache drops a whole database's entries on any change, and misses across processes when IDA
  downloaded a PDB during the first open.
- `undo_edit` and `apply_edits` can still take 8–30 s on a large assembly, since each replayed C# edit writes the image.
- Code tools on MIPS, PowerPC, RISC-V and s390x refuse with `unsupported`; `patch_asm` there gives no Next.
- Three x86 switch patterns (index bounded in another block, constant slots) stay unresolved; hand-written ARM32
  runtime routines with computed jumps can split into several functions.
- tar, gzip and xz archives are not read as containers.
- Il2Cpp generic method bodies with runtime-filled registration are not mapped, and NativeAOT field names are not in
  the name layer.
- Token estimates are calibrated against the o200k tokenizer only.

## 1.3.0

158 tools (1.2.0 had 155). New are look-alike function search, p-code emulation and folder comparison. The release
also adds Electron, Objective-C / Swift and Go metadata, a faster and parallel code index (results are the same at any
thread count), faster IDA sessions, and reliability work across the server: calls that hold or wait on the workspace,
leftover calls, worker lifetime and logs.

### Changes in behaviour

- **Busy server.** Calls cancelled or past their deadline that keep running are capped (`CORVUS_MAX_LEFTOVER_CALLS`,
  default 2). At the cap a new call is refused as `provider_unavailable` with `retryAfterMs`. A call that times out
  waiting for the workspace lock names the calls holding it (`details.blockedBy`). `server_status` lists both and no
  longer takes the lock.
- **Errors.** Save tools report only IO faults as `io_error`; unclassified faults are `internal` with a Next (also per
  item in `apply_edits`). `decompile_java` without JADX or Java is not retryable (`details.reason` `not_configured`).
  A Blazor folder whose boot manifest lists none of the present assemblies is `not_found`.
- **`rename_symbol`** keeps a generic type's arity suffix and refuses a different arity.
- **`set_native_local` (Ghidra)** checks that the rename took effect: a local without storage in use, or a name the
  decompiler kept, fails instead of succeeding.
- **Deterministic records.** `unity_overview`, `compare_native_images`, `update_to_new_build` and
  `find_similar_functions` no longer carry elapsed time, so two identical calls give identical bytes.
- **Code index** persist format 11. Older indexes are rebuilt on first use.
- **IDA cache keys** are short (16 hex characters). Existing entries migrate. Input paths over 259 characters fail up
  front and give their length.

### New tools

- **`find_similar_functions`** ranks look-alike functions using MinHash sketches of instruction shapes, then rescores
  them exactly. It searches across all loaded images and also reports duplicate groups and near-duplicate clusters.
- **`emulate_native`** runs a function or range in Ghidra's p-code emulator over the program's bytes, with a private
  stack, arguments by calling convention, stubs for calls, and instruction and time budgets.
- **`compare_folders`** compares two folders or zip-family archives entry by entry by streaming SHA-256. It reports
  moves and case-only renames, and gives a next call per changed binary and inline diffs of small text files.
- **`update_to_new_build`** now also takes two .NET assemblies: member notes follow their `find_counterpart` match and
  file notes move to the new build.

### Formats and metadata

- **Electron:** ASAR archives with integrity checks, unpacked entries and links; `summarize_file` reports Electron,
  Chromium and Node versions, fuses, the entry point and `webPreferences` values. Node-API add-on callbacks are named
  after their JavaScript names.
- **Unity WebGL** data files and **HAR / mitmproxy** captures open as containers.
- **Mach-O:** Objective-C and Swift metadata readers and a Swift demangler; `list_cpp_classes` and `get_native_type` list
  Objective-C classes, categories and protocols and Swift types.
- **Go:** build info for PE, ELF and Mach-O; function sizes from each function's own tables; noreturn runtime functions.
- **ELF and Mach-O** patch-site extension stubs (`patch_asm` beyond a site's size).

### Native analysis

- **ARM:** functions found in gaps from ARM32 and ARM64 prologues; `.ARM.exidx` / `.ARM.extab` exception data; ARM64X
  and ARM64EC images decoded in both instruction sets; ARM32 crypto instructions; JNIEnv / JavaVM calls named with their
  parameters; floating-point and System V call arguments (struct return, variadic vector count, 16-byte structs).
- **Index speed:** discovery, sorting, noreturn propagation, RTTI, `.pdata` and virtual call resolution run on several
  threads. Allocation on a 130 MB NativeAOT image drops from 3.1 GB to 0.32 GB.
- **IDA:** function and string lists are kept per session. Rename pushes are journaled and re-decompile only the
  affected functions. A first decompile on a large ELF drops from 7–10 s to 0.6 s. `find_xrefs`, `resolve_address` and
  `search_bytes` take lists of targets. An `.i64` beside the input starts the cache as a copy, and the user's file is
  never written. A script loop is interrupted in place at its cancel or deadline.

### Operations

- Engine workers end within a second of a killed server on Linux and macOS.
- The engine database cache is bounded (`CORVUS_ANALYSIS_CACHE_MB` / `_DAYS`).
- Each call writes one info log line (`CORVUS_LOG_FORMAT=json`). `--trace` records argument values only with
  `--trace-args`, with secrets masked.
- Per-RID publishes are ReadyToRun, so each cold CLI call is about 0.4 s faster.
- `verify_native_imports` reports progress, never rebuilds stubs per call (300 s to 7 s cold on a large app) and no
  longer hits dnlib's `LockException`.
- `export_project` decompiles outside the workspace lock.
- New: a CorvusRE NuGet .NET tool package, MCP bundles (`.mcpb`) per desktop target, and an updated SECURITY.md.

## 1.2.0

155 tools (1.1.0 had 101) and 13 prompts (9). The project takes its current name, **Corvus**. This
release adds a second decompiler engine (Ghidra), ELF and Mach-O images, our own ARM64 and ARM32 / Thumb-2 analysis,
NativeAOT and mobile Il2Cpp builds, Android packages and devices, deeper crash-dump decoding, and a round of reliability
work across the server and its engine workers.

### Renamed to Corvus

- **Program and registration.** The program is `corvus` (`corvus.exe`), installed under `Corvus`, and registers with
  clients under the MCP key `corvus`. Release archives are `corvus-<rid>` from the `Albasha0x0/Corvus` repository.
- **Names.** Environment variables are `CORVUS_*` and resources use the `corvus://` scheme.
- **Earlier installs.** On first start, data, client entries and skill folders of an earlier install move to the new
  names; files saved by earlier versions (sessions, edit scripts, patch sets, notes, engine databases) are still read.

### Changes in behaviour

- **Exports never overwrite by default.** Files written by export and save tools are written atomically and refuse to
  replace an existing file unless `overwrite=true`; links and device names are refused as targets. `save_assembly`
  recognizes the original through links and hard links, refuses an original that changed on disk since it loaded, and
  `save_native` verifies the written file before renaming it into place.
- **`uninstall` keeps user data.** Annotations, caches and symbols stay; `--purge-data` removes them.
- **Call deadline.** A tool not marked long-running ends with a timeout error after twice `--timeout`; cancelled calls
  stop waiting for the workspace lock. New error codes `cancelled` and `changed_on_disk` ([docs/errors.md](errors.md)).
- **Closed argument values** are advertised as enums and checked before the tool runs, with aliases and a
  did-you-mean suggestion; `limit < 1` is `invalid_argument` on every paged native tool.
- **Native names.** A name on several addresses is an ambiguous error listing them; hex-shaped names (`Bach`, `...h`)
  resolve as names before MASM numbers; a name on a jump thunk and on its body resolves to the body.
- **Incomplete results say so.** Regex searches that time out report what was not evaluated; a cut-short `read_bytes`
  says so; `read_bytes` shows bytes with no file data (`.bss`, virtual size past raw size) as `??` with a gap list.
- **Member labels carry generic parameters** (`Method<T>(string)`), so generic and non-generic overloads differ in
  diffs and replays; older edit scripts resolve their bare labels as before.
- **Native patches** pad with the architecture's NOP (whole NOPs on ARM64) and are refused where none is defined.
- **IDA before 9.0 is refused** with the reason; the reported idalib version shows in `server_status`.
- **Inputs:** FIFOs, sockets, devices and directories are refused as input files.

### Second engine: Ghidra

- **`engine=ghidra` everywhere an engine is used:** `decompile_native`, the code tools (`list_functions`, `disassemble`,
  `get_cfg`, `find_xrefs`, `native_call_tree`, `resolve_call_targets`, `trace_native_values`, `inspect_instruction`),
  the type, frame and local edit tools, `crossCheck` and `find_xrefs Type::member`. A session per engine and image;
  `auto` takes a complete IDA analysis, then Ghidra's, else ours. Ghidra 12.0 or newer through `CORVUS_GHIDRA_DIR` and a
  JDK; the worker is built on first use.
- **Saved projects** per file SHA-256 and profile key, warm reopen, rebase, damaged-project rebuild, an analysis budget
  with a partial save that `reanalyze_native` completes, and a background function pass after the open.
- **Large functions decompile:** 200 MB decompiler payload, one retry with four times the time on a fresh decompiler,
  `timeoutSeconds` per call.
- **Ghidra's names** (loader and analysis names, function identification included) form a name layer below the others;
  `FUN_` / `LAB_` / `DAT_` and IDA default names resolve as addresses.
- **`ghidra_script`** runs a Java GhidraScript in the worker in one transaction, rolled back on failure (opt-in,
  `--ghidra-scripting`). `export_engine_database` writes a `.gzf` archive, or Ghidra's own types as `.h` / `.gdt`.

### IDA and engine depth

- **New edit tools:** `define_native` (code, functions, data, undefined bytes), `set_native_operand` (number base, char,
  offset, stack variable, enum member, struct offset), `reanalyze_native`; enum, struct and union member upsert,
  type delete and rename (followed into the other edits), stack member delete, `clear=true` to restore the engine's
  own local. All kept per file hash, replayed on a new database, exported and carried to new builds.
- **Comments:** kinds `eol`, `pre`, `plate` and pseudocode comments placed on the statement, with append and dedupe;
  `rename_native` and `comment_native` take batches with `dryRun`, `stopOnError` and per-item results;
  `showDecompile=after|diff` on the type and name edits.
- **Views:** `list_globals`, `search_instructions`, `convert_number`, `get_engine_status`, `search_decompiled` (regex
  over every function's pseudocode, resumable by cursor), `decompile_native functions=[...]` and `callersOf=`,
  `list_functions view=candidates`, `find_xrefs direction=from|both` and `kind=`, `list_native_types` filters,
  `related=true` and members, `list_cpp_classes engine=ida|ghidra`, typed reads (`get_native_type read=true`,
  `read_bytes type=`), `export_engine_database` (`.i64` copy), `make_code_pattern` in IDA / x64dbg / mask formats.
- **Worker control:** cancel and deadlines inside the IDA and Ghidra workers (partial results with a cursor; the worker
  is killed only past a grace period), `CORVUS_ENGINE_REQUEST_TIMEOUT` / `CORVUS_ENGINE_OPEN_TIMEOUT`,
  `CORVUS_ENGINE_ANALYSIS=none` for huge or hostile inputs, a read-only snapshot when another server holds the
  database, batch mode so no dialog waits, engine sessions and open-stage timings in `server_status`.

### Own engine: ELF, Mach-O, ARM64 and ARM32

- **ELF and Mach-O images** load beside PE (universal files by slice) through every native tool: relocations, PLT and
  GOT, symbol versions, chained fixups, exports trie, function starts, compact unwind, code signature and encryption.
  IDA and Ghidra open them too. Itanium C++ demangler, Itanium RTTI (single, multiple and virtual bases) for classes,
  type push and virtual calls, Itanium exception tables in `get_exception_info`, System V x64 calling convention.
- **ARM64** decoder, function discovery, jump tables, call arguments (integer and floating-point), value tracing and
  call targets; `inspect_instruction` on the built-in decoder; ARM64X / ARM64EC images from their CHPE metadata.
- **ARM32 / Thumb-2:** own A32 / T32 decoder (VFP and NEON included) with per-function state, cross-references through
  literal pools and MOVW / MOVT, TBB / TBH and PC-relative jump tables, IT blocks, AAPCS call arguments and value
  traces, fixed-address executables.
- **Discovery:** Go function tables (Go 1.2 to 1.24, ELF / PE / Mach-O) as a function and name source; static and
  fixed-address ELF (a static x86-64 Linux executable: 194 to 3,112 functions; its i386 build: 19 to 3,173); x64
  absolute switch tables; jump thunks named `j_<target>`. Image-scope `resolve_call_targets` on a 3.8 MB library:
  1,474 s to 12 s (ARM32), over 900 s to 7 s (ARM64).
- **Patching ELF and Mach-O:** `patch_bytes`, `patch_asm`, undo and `save_native` (universal files keep their other
  slices); bytes the loader rewrites are refused unless forced, encrypted bytes refused.
- **Packers and protectors** reported with evidence in `summarize_file` and `get_pe_info` (detection only).

### Native analysis

- **`inspect_instruction`**, **`get_native_type`** (PDB, RTTI, Il2Cpp and engine types; field paths at an offset),
  **`trace_native_values`** (interprocedural value slices across functions and loaded images, struct fields, switch
  case selection) and **`resolve_call_targets`** (targets with basis and confidence).
- **`analyze_native_function`** (a function dossier in bounded sections, up to 16 at once, `component=true`),
  **`trace_native_feature`** (from a text to the ranked functions behind it), native goals in **`find_call_paths`**,
  **`diff_function`** (aligned instruction and pseudocode diff of a matched pair), `get_cfg` switch cases,
  `native_call_tree direction=both`, `summarize_file` triage for native images.

### NativeAOT

- **`get_nativeaot_info`** and a nativeaot name layer from the image's own metadata: method bodies, MethodTables,
  vtable slots, frozen strings, statics and interface dispatch cells, ranked below PDB names, pushed to IDA and Ghidra
  and exported. .NET 7 to 11 layouts, PE, ELF and Mach-O, 64- and 32-bit.

### Il2Cpp and Unity

- **Mobile and desktop layouts:** Android, iOS, macOS and Linux games, read from `.apk` / `.xapk` / `.apks` / `.aab` /
  `.ipa`; ELF and Mach-O game binaries; metadata up to v39; builds that fill the code registration at run time.
- 32-bit games get headers and prototypes pushed to IDA and Ghidra; Il2Cpp games and minidumps are kept in sessions;
  `unity_overview` reads packages and iOS layouts.

### Android

- **Packages:** manifest and resources (binary XML, `resources.arsc`, app bundle protobuf), APK signature verification
  (v1 to v4 with rotation and several signers, content digests recomputed), .NET for Android assembly stores.
- **Code:** DEX reader and Dalvik disassembler (`list_dex_classes`, `get_dex_class`, `disassemble_dex`, `search_dex`,
  `find_dex_references`), `decompile_java` through JADX, `map_java_dotnet` (also Unity Mono C# to Java),
  `list_jni_bindings`, `export_project` to a Gradle project skeleton.
- **Devices** through adb: read-only by default; install and uninstall behind `--allow-device-changes`.

### Crash dumps

- **.NET decoding:** managed exception, mixed frames, `dump_heap` and `dump_object`; DAC lookup with signature check and
  opt-in download; .NET Framework and 32-bit dumps through a bundled 32-bit decoder (Windows); IL offsets mapped to the
  C# statement.
- **`symbolize_stack_text`** (Unity, Mono, Il2Cpp, .NET, WER, Event Log, debugger, Android tombstone and logcat stacks,
  with build checks) and **`bucket_minidumps`**; WoW64 32-bit side, frame-pointer-less x86 frames, modules found by
  timestamp and size.

### Also since 1.1.0

- **.NET builds:** `compare_assemblies` / `find_counterpart` report every change of a matched member, members moved
  between types, and optional C# or IL diffs; provenance (file SHA-256, MVID, IL hashes); metadata and exception-clause
  health in `get_assembly_info`.
- **.NET export and patching:** `export_project` builds more real projects (framework inference, package references, preserialized resources);
  Blazor WebAssembly Webcil modules load and unpack; many C# patch compile fixes; `diff_edits` first page of a
  whole-assembly simplify 27 s to 4 s.
- **Sessions and notes:** `save_session` / `load_session` (files by SHA-256, edits, patches, names, notes), an edit
  journal that offers unsaved work for replay, `record_note` / `update_note` / `list_notes`, shown in IDA and Ghidra.
- **Setup:** `corvus install` plans and edits client files in place (comments kept, `--dry-run`, `--json`), more
  clients and config homes, `corvus status` checks each registration with its own args and env; the agent skill
  (`install --skill`); `SHA256SUMS` checked by the installers and `update`.
- **CLI:** a generic tool runner (`corvus call`, `describe`), `batch`, prompts and resources, shell completions.
- **Server:** `--toolsets` and `--tools-file` to register fewer tools (`core`, `readonly`, `triage`), `--trace` JSONL
  call trace, `--log-level`, resource subscriptions, a development reload relay that also serves 2026-07-28 clients.
  Tool descriptions and schemas were trimmed from 225,472 to 165,631 bytes (-26.5%) at 155 tools.
- **Reliability:** cross-process locks and merges for annotation sidecars and notes; one ordered writer per engine
  worker; child-process output and exits read off the thread pool; a deadlock between the edit journal and saves fixed.

## 1.1.0

101 tools (1.0.1 had 54). This release adds the native PE track (analysis, IDA engine, PDB, patching, crash dumps,
build migration) and a batch of usability and analysis-depth work on top of it.

### Changes in behaviour

- **Unknown argument names are errors.** A parameter a tool does not declare is `invalid_argument` with the closest
  declared names ("unknown parameter 'max_chars'. Did you mean 'maxChars'?"; `details.suggestions`), instead of being
  ignored while the tool ran with its defaults. Clients that sent extra arguments must drop them.
- `load_pdb` is marked destructive: `clear=true` removes imported PDB names and their saved copy.
- With `engine=auto` (the default), `list_functions`, `disassemble`, `get_cfg`, `find_xrefs` and `native_call_tree`
  answer from IDA for an image once IDA has finished analyzing it in the session; pass `engine=ours` for the built-in
  index only.

### New in this batch

- **Persistent native code index.** Each image's code index is saved per user, keyed by the file's SHA-256 and the build
  options; reopening the same bytes loads it (msedge.dll, 334 MB: 2.6 s instead of 36 s; GameAssembly.dll, 206 MB:
  1.8 s instead of 54 s). Changed, damaged or older-format entries are rebuilt; bounded by size (8 GB) and age (30 days),
  least recently used first. `--index-cache <dir|off>`, `--index-cache-mb`, `--index-cache-days`; shown in `server_status`.
- **Imported names survive restarts.** Names from `load_pdb` and `apply_il2cpp_names` are saved beside user renames and
  reapplied when the same file loads again, also with the PDB moved or deleted (434,680 names on an Il2Cpp title restored in 0.8 s).
  `list_native_edits` lists each layer and whether it was restored; `clear=true` removes a layer.
- **Engine preference** `engine=auto|ours|ida` (server default `--engine` / `CORVUS_ENGINE`): see above; `auto` never starts
  IDA and costs about 0.1 µs per call. With IDA, our names still win and RTTI virtual-call edges IDA lacks are added.
  Every result names its engine.
- **PDB types in IDA.** `decompile_native` loads the PDB's structs, enums, typedefs and prototypes into the IDA database
  once per PDB, through IDA's PDB loader or the server's own PDB type reader, so pseudocode uses real struct and member
  names (`return source->flags;` instead of `return *(unsigned int *)(a1 + 712);`).
- **Virtual calls through RTTI.** `obj->vfunc()` sites are resolved from MSVC RTTI class hierarchies into
  `virtual_exact` / `virtual_possible` call-graph edges (+11,041 edges on Qt6Widgets.dll, +15,026 on Acrobat.dll).
  `find_virtual_calls` lists the sites; `crossCheck=true` compares with IDA (98-100% agreement on Qt6Widgets and
  steamclient). `native_call_tree calls=direct|virtual`.
- **Built-in Il2Cpp metadata reader.** `load_assembly` on an Il2Cpp game folder or `global-metadata.dat` reads metadata
  versions 24-31 through LibCpp2IL, also from a memory dump of GameAssembly.dll; no external dumper. On a v31 title every method,
  RVA, vtable slot, field and field offset matches Il2CppDumper's output. Unreadable metadata is an error with a reason;
  unreadable items are listed by reason.
- **`unity_overview`.** One call on a Unity title: engine version per source, Mono or Il2Cpp with evidence and metadata
  state (readable, encrypted, header tampered), toolchain and middleware markers (optional Detect
  It Easy), and the next tool calls. Under 0.2 s on the titles tested.
- **`inspect_process`.** Read-only view of a running local process (Windows): modules, memory regions, threads and
  stacks, named through PE, PDB, Il2Cpp and user names. Opens only query and read handles, writes and suspends nothing,
  closes every handle before returning (docs/live-inspection.md).
- **Patch-site extension.** `patch_asm` / `patch_bytes` `extend=true` turn a site that is too small into a jump to a
  relocation stub that runs the new code (and the displaced instructions, `stubMode=before|after`) and returns after the
  site. `placement=auto|cave|section`: a code cave when one fits, else a new executable section (undo removes it byte
  for byte). Exports describe grown files (JSON v2, IDAPython, IPS / IPS32; `.dif` refuses them with `grown_file`).
- **`update_to_new_build`.** One call carries names, comments, PDB / Il2Cpp layers, patches (stubs re-created), code
  patterns with drift and the Il2Cpp method mapping to a new build, with one report: what carried, what did not and why.

### Also since 1.0.1

- **Native PE images:** own PE parser; x86 / x64 code index (functions, xrefs, CFGs, strings); MSVC demangler, RTTI and
  exception metadata; PDB reader with opt-in symbol download; Win32 resources; ReadyToRun code; P/Invoke verification
  with verdicts; late-bound imports and call-site arguments; navigation across loaded images and between managed and
  native code; ARM / ARM64 through IDA.
- **IDA (idalib) engine:** `decompile_native`, analysis cached per file hash, names, patches and types pushed in,
  library-function names, optional background analysis (`--ida-prewarm`).
- **Native editing:** renames and comments kept per file hash, `patch_bytes` / `patch_asm` (full MASM assembler,
  relocation-correct under ASLR), undo, `save_native`, `export_native_patches`, `migrate_native_patches`.
- **Builds and dumps:** `compare_native_images`, address and name migration, rebuild-stable code patterns; minidumps
  (`open_minidump`, `dump_stack`, `read_dump_memory`).
- **Il2Cpp:** string literals, metadata <-> native navigation both ways, complete struct layouts and prototypes, C++
  bindings in Il2Cpp style with generic templates.
- **Protocol:** typed errors with a JSON copy, structured output for list / search / info tools, response-size guard with
  `read_result`, `server_status` with a tool-catalog digest, one audited annotations table.
- **.NET:** normalized IL hash, tiered unique-only member matching, many `simplify_methods` readability passes.
