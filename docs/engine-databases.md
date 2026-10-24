# Engine databases

What Corvus keeps of an IDA or Ghidra analysis, and when it is reused or made again. The first open of an image
analyzes it; every later open of the same bytes under the same configuration (any session, server process or
command-line call) reopens the saved database.

## Where

One cache entry per input and engine under the analysis cache (`CORVUS_ANALYSIS_CACHE`, default
`<data folder>/analysis`): a private copy of the input with the engine's databases beside it. Engines never write
next to the user's file. Eviction: entries unused for `CORVUS_ANALYSIS_CACHE_DAYS` (default 60), then least recently
used past `CORVUS_ANALYSIS_CACHE_MB` (default 32,768); an entry open in any process is never touched. Engine answers
(pseudocode, frames with decompiler locals) are kept separately in `engine-output` (`CORVUS_ENGINE_OUTPUT_MB`,
default 1,024) and served without starting the engine.

## Identity

A saved database is reused only when every part of its identity matches; otherwise another database is made (and
analyzed), and the earlier one stays until evicted.

| Part | IDA | Ghidra |
|---|---|---|
| Input | SHA-256 of the file's bytes (the entry); IDA's own record of its input is checked on open, and a database made from other bytes is rebuilt | SHA-256 of the file's bytes (the entry) |
| Engine | IDA version and build digest, in the file name `ida-<profile>-<version>-<digest>.i64` | Ghidra version and revision, and the worker protocol, in the project key |
| Analysis profile | symbols on or off (`default` / `nopdb`); no auto-analysis (`CORVUS_ENGINE_ANALYSIS=none`: `-noauto`) | `CORVUS_GHIDRA_ANALYSIS` (`standard`, `full`, `minimal`), loader arguments, analyzer options (`CORVUS_GHIDRA_OPTIONS`), extension zips by hash, in the project key; `-noauto` as for IDA |
| Import overrides | `load_assembly` `processor`, `compilerSpec`, `seeds`, `disableAnalyzers`: their key in the name | `language`, `compilerSpec`, `seeds`, `disableAnalyzers`: their key in the project name |
| Raw layout | `format=raw` architecture and base in the name | the same, in the project name |
| Archive input | - | a `.gzf` (also one packed from a `.gpr`): its SHA-256 in the project name |

`get_engine_status` reports per open image `reusedDatabase`, `openSeconds`, the profile and the import overrides.

## Reuse

- **Across sessions and processes.** The database is saved after the first analysis and after edits (names,
  comments, types, patches; journaled until saved, replayed after a worker crash). A later server or
  `corvus <tool> --load <file>` call finds it by the input's SHA-256 and opens it without analysis.
- **Within a session.** One worker per image and engine; reads run concurrently (Ghidra) or in order (IDA). Cached
  answers are keyed by the database state, so a stale answer is never served. A change confined to one function (a
  local or stack member renamed, no signature committed) invalidates only that function's answers.
- **Two processes, one image.** The process using the cache entry locks it. A second process opens a read-only
  snapshot of the last saved database or project (edits neither journaled nor saved; status says so); with nothing
  saved yet it answers `conflict` naming the owning process, retryable after `details.retryAfterMs`.
- **Edits outlive the database.** Names, comments, types and patches are also kept per file hash in sidecars and
  pushed into a new database, so invalidating one loses no user work.

## Partial analyses

- **Saved as it stands.** An open analyzes within `CORVUS_ENGINE_OPEN_TIMEOUT` (seconds). When it runs out, the
  database is saved with the analysis so far and marked partial; later opens in any process reopen it as is.
- **Reported.** A native tool's Engine line names the partial analysis and `reanalyze_native`; `get_engine_status`
  reports it as partial.
- **Completed on request.** `reanalyze_native` completes it within its own limit (`background=true` returns at once).
  Nothing completes it unasked: a background run would hold the entry's lock (a second server would get a read-only
  snapshot or a conflict), use the processor unasked, and change the database state, and the kept answers, between
  two calls.

## Invalidation

- `reanalyze_native` reruns auto-analysis over the image or a range, with analyzer options for that run
  (`background=true` returns at once; `preset=` picks a saved option set). Every kept answer of the image is then
  asked again.
- A different engine build, profile, option set, extension set, override or raw layout is a different identity
  (above): a new database is made once and reused from then on.
- A damaged database (an unreadable `.i64`, a broken project) is rebuilt from the input copy.
- Deleting the entry's folder under the analysis cache forgets the analysis; the sidecars bring the edits back.

## The user's own databases

- **IDA `.i64` beside the input** (`app.i64` or `app.dll.i64`): copied into a new cache entry as its starting point;
  IDA accepts it only when its record of the input matches the bytes. The original is not changed.
- **Ghidra archive** (`load_assembly path=app.gzf`): loads the file it was made from (the bytes the archive keeps,
  else the file beside it, checked against the recorded SHA-256); Ghidra opens the archive as the database without
  analysis.
- **Ghidra project** (`load_assembly path=Project.gpr program=/app.exe`; `program` optional when the project holds
  one): the `.gpr` and its `.rep` folder (lock files left out) are copied into the cache, the program is packed into
  an archive, and that opens as above. The user's project is only read and may stay open in Ghidra. The copy is keyed
  by project path, program and every file's size and write time: an unchanged project reuses its archive and
  database, a changed one is copied again.
- **Hand-off.** `export_engine_database` writes the database with everything pushed into it, for the engine's GUI:
  a compressed `.i64` (IDA) or a `.gzf` (Ghidra).

## Cold and warm times

Two public x64 DLLs, empty analysis cache, over MCP on one Windows machine (20 logical processors, loaded by other
jobs at or near 100 % CPU), IDA 9.3 and Ghidra 12.1.4 with default profiles (2026-10-15). Seconds. First open: the
session's first `decompile_native`, analysis included. Warm call: a second function. Second session: new server
process, `load_assembly`, a function not decompiled before (worker start, reopen, decompile). Command-line call:
`corvus decompile_native --load <file> image=<name> address=<function>` for a new function, process start to exit,
median of three.

| Image | Engine | First open | Warm call | Second session | Command-line call | First open / second session |
|---|---|---:|---:|---:|---:|---:|
| `e_sqlite3.dll` (SQLitePCLRaw.lib.e_sqlite3 2.1.11, 1.8 MB) | IDA | 39.7 | 0.53 | 1.5 | 4.7 | 26× |
| `libSkiaSharp.dll` (SkiaSharp.NativeAssets.Win32 2.88.9, 9.4 MB) | IDA | 121.1 | 0.02 | 2.0 | 3.6 | 61× |
| `e_sqlite3.dll` | Ghidra | 170.2 | 0.34 | 10.0 | 17.5 | 17× |
| `libSkiaSharp.dll` | Ghidra | 494.0 | 0.03 | 10.3 | 15.9 | 48× |

A repeated question comes from the output cache in about 0.01 s, also in a new process. Reproduce with any two images: an empty `CORVUS_ANALYSIS_CACHE`, then the four steps above.

## Tests

The contract is held by tests in `tests/Corvus.Tests/Engines`: `NativeGhidraProviderTests`
(`Cold_open_then_warm_reopen_of_the_saved_project`, `A_damaged_project_is_rebuilt`), `NativeIdaProviderTests`
(`Database_is_keyed_by_the_IDA_build_and_rebuilt_when_made_from_other_input`,
`Leftovers_of_a_killed_worker_do_not_break_the_next_open`), `EngineOutputTests` (answers across processes),
`ReanalyzeNativeTests` (a run drops the kept pseudocode), `ImportOverrideEngineTests` and `PackedDatabaseTests`
(`.gzf` and `.gpr` inputs; the project's files unchanged).
