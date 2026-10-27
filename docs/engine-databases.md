# Engine databases

What Corvus keeps of an IDA or Ghidra analysis, and when it reuses or rebuilds it.

- The first open of an image analyzes it.
- Later opens of the same bytes under the same configuration reopen the saved database, from any session, server or command-line call.

## Where

- One cache entry per input and engine under `CORVUS_ANALYSIS_CACHE` (default `<data folder>/analysis`): a private copy of the input with the engine's databases beside it.
- Engines never write next to the user's file.
- Eviction: entries unused for `CORVUS_ANALYSIS_CACHE_DAYS` (default 60), then least recently used past `CORVUS_ANALYSIS_CACHE_MB` (default 32,768). An entry open in any process is never touched.
- Engine answers (pseudocode, frames) are kept in `engine-output` (`CORVUS_ENGINE_OUTPUT_MB`, default 1,024) and served without starting the engine.

## Identity

A saved database is reused only when every part matches; otherwise a new one is made and the old one stays until evicted.

| Part | IDA | Ghidra |
|---|---|---|
| Input | SHA-256 of the file; IDA's input record checked on open | SHA-256 of the file |
| Engine | version and build digest: `ida-<profile>-<version>-<digest>.i64` | version, revision and worker protocol |
| Analysis profile | symbols on or off (`default` / `nopdb`); `-noauto` | `CORVUS_GHIDRA_ANALYSIS`, loader arguments, options, extensions |
| Import overrides | `processor`, `compilerSpec`, `seeds`, `disableAnalyzers` | `language`, `compilerSpec`, `seeds`, `disableAnalyzers` |
| Raw layout | `format=raw` architecture and base | the same |
| Archive input | - | the `.gzf`'s SHA-256 (also one packed from a `.gpr`) |

- An IDA database made from other bytes is rebuilt.
- `-noauto` comes from `CORVUS_ENGINE_ANALYSIS=none`; Ghidra options are `CORVUS_GHIDRA_OPTIONS`, and extension zips count by hash.
- `get_engine_status` reports per image `reusedDatabase`, `openSeconds`, the profile and the import overrides.

## Reuse

- **Across sessions and processes.** The database is saved after the first analysis and after edits (journaled until saved, replayed after a worker crash). A later server or `corvus <tool> --load <file>` opens it without analysis.
- **Within a session.** One worker per image and engine; reads run concurrently (Ghidra) or in order (IDA).
- Kept answers are keyed by database state, so a stale answer is never served. A change inside one function (a local renamed, no signature committed) drops only that function's answers.
- **Two processes, one image.** The first process locks the entry. A second opens a read-only snapshot of the last saved database (edits neither journaled nor saved; status says so). With nothing saved yet, it gets a `conflict` naming the owner, retryable after `details.retryAfterMs`.
- **Edits outlive the database.** Names, comments, types and patches are also kept per file hash and pushed into a new database, so invalidating one loses no user work.

## Partial analyses

- An open analyzes within `CORVUS_ENGINE_OPEN_TIMEOUT` seconds. Past it, the database is saved as it stands and marked partial; later opens reopen it as is.
- A native tool's Engine line names the partial analysis and `reanalyze_native`; `get_engine_status` reports it.
- `reanalyze_native` completes it (`background=true` returns at once). Nothing completes it unasked: that would hold the entry's lock, use the processor and change kept answers between calls.

## Invalidation

- `reanalyze_native` reruns auto-analysis over the image or a range, with options for that run (`preset=` picks a saved set). Every kept answer of the image is then asked again.
- A different engine build, profile, option set, extension set, override or raw layout is a new identity: a new database is made once and reused.
- A damaged database (unreadable `.i64`, broken project) is rebuilt from the input copy.
- Deleting the entry's folder forgets the analysis; saved edits come back.

## The user's own databases

- **IDA `.i64` beside the input** (`app.i64` or `app.dll.i64`): copied into a new entry as its start; IDA accepts it only when its input record matches. The original is not changed.
- **Ghidra archive** (`load_assembly path=app.gzf`): loads the file it was made from (kept in the archive, else beside it, checked by SHA-256) and opens the archive without analysis.
- **Ghidra project** (`load_assembly path=Project.gpr program=/app.exe`; `program` optional for a one-program project): copied into the cache with lock files left out; the program is packed and opened as above.
- The user's project is only read and may stay open in Ghidra. The copy is keyed by path, program and each file's size and write time: an unchanged project reuses its archive and database; a changed one is copied again.
- **Hand-off.** `export_engine_database` writes the database with every edit, for the engine's GUI: a compressed `.i64` (IDA) or a `.gzf` (Ghidra).
