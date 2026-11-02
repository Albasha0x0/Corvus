# Command line

Every tool, prompt and resource also runs from a terminal, with the same argument checks, limits and errors as an
agent's call. Tool reference: [tools.md](tools.md). Setup commands (`install`, `status`, ...): [installation.md](installation.md).

## Commands

| Command | What it does |
|---|---|
| `<tool> [name=value ...]` | call a tool: `corvus decompile_member --load app.dll member=Ns.Type::Method` |
| `call <tool> [name=value ...]` | the same, with the tool name after `call` |
| `tools [filter]` | tools by toolset with their effect and first sentence; `--json` prints a table |
| `describe <tool\|prompt>` | description, parameters, annotations, output and an example; also `help <name>` |
| `batch <file\|->` | run several calls in one session ([below](#batch)) |
| `batch --file <path> --json` | one JSON document from fixed read-only steps ([below](#file-batch)) |
| `prompts` | prompts and their arguments |
| `prompt <name> [name=value ...]` | a prompt's text, ready to pipe into an agent |
| `resources` | resources and resource templates |
| `read <uri>` | one resource, such as `corvus://guide/native` |
| `completion <bash\|zsh\|pwsh>` | a shell completion script |
| `rules [list]`, `rules fetch <pack>` | list or install YARA rule packs (malcontent, yara-forge-core) |
| `rules import <archive> [pack]` | install a pack from a local copy of its pinned archive; no network |
| `ida-script [folder]` | write `corvus_connect.py` for using a database open in IDA |
| `analyze <image> [--wait] [name=value ...]` | run auto-analysis of a native image; takes the `reanalyze_native` arguments |
| `serve --session NAME [server options]` | keep a named session open for routed calls ([below](#session)) |

- Tool names take snake case or kebab case (`decompile-member`). `corvus help` lists these and the setup commands.
- `rules fetch` and `rules import` refuse a pack unless its SHA-256 matches the pinned value. They install under
  `rules/<pack>/<version>/` in the data folder.
- `ida-script` writes to `<IDA user directory>/corvus` by default. Run the script in IDA (File > Script file), then start
  Corvus with `CORVUS_IDA_CONNECT=1`.
- `analyze --wait` blocks until the first analysis of the image ends, or, for an image with a saved analysis, until one reanalysis ends; it prints the outcome on stderr and exits by it ([exit codes](#exit-codes)).
- `analyze` takes `--session NAME` or `CORVUS_SESSION` and shares the analysis with that session.
- A one-shot `call` whose early answer leaves work running adds a Next line (`corvus serve --session NAME`, `corvus analyze <image> --wait`); with `--json` it is appended to `error.next`.

## Arguments

| Form | Meaning |
|---|---|
| `name=value` | typed by the parameter's schema (below) |
| `name:=<json>` | the value as raw JSON |
| `name=@file` | the value read from a file, such as a C# body |
| `name=@-` | the value read from standard input |
| `--args '<json object>'` | all arguments as one JSON object (also `--json '{...}'`); `name=value` pairs override it |
| `--args-file F` | the JSON object from a file (`-` for standard input) |

- Types: integers (also `0x` hex), numbers, `true`/`false` (also `1`/`0`, `yes`/`no`), arrays as JSON (`[1,2]`) or
  comma-separated (`a,b`), objects as JSON. Anything else is text.
- Text starting with `@` goes as JSON: `name:='"@xml/config"'`. An undeclared parameter is `invalid_argument`.
- Quote values with spaces or shell characters: `member='Ns.Type::Method(int, string)'`.

## Server options

Every server option applies ([configuration.md](configuration.md#server-options)). Most used:

- `--load PATH` preloads a file or folder (repeatable): `corvus get_type_info --load app.dll type=Ns.Type`.
- `--no-index` skips background indexing in a `batch` session; a routed batch uses the session's options. A single call skips it unless its tool needs the index.
- `--max-output N` restores paging. Without it, the command line prints whole results.
- `--timeout S`, `--engine E`, `--toolsets T`, `--log-level L`: as for the server.
- `--audit F` appends one JSON line per call to `F`; a path outputs may not reach stops start-up.
- Logs go to stderr at `warning` unless `--log-level` or `CORVUS_LOG_LEVEL` says otherwise. Files are not watched for changes.

## Output

- Default: the result's text on stdout. An error's text and workspace notices (`[workspace] ...`) go to stderr.
- Output to a file or pipe, and piped input, is UTF-8, whatever the console code page.
- `--json`: one object `{tool, isError, text, structured, error}`. `error` is the parsed record
  (`{code, retryable, message, next, partial, details}`, [errors.md](errors.md)). Indented on a terminal, one line when piped.
- `--structured`: only the structured content, for `jq`. A tool without structured output is a usage error.
- Progress is one updating line on stderr in a terminal.
- Piped stderr gets one `tool: [n/total] message` line per second, including `batch` steps.
- The 1-second interval is fixed; the final step is always written.

## Session

- `serve --session NAME [server options]` keeps loaded images in a named session until Ctrl+C.
- `--session NAME` (or `CORVUS_SESSION=NAME`) routes a tool call to it; IDs and unsaved edits carry over between calls.
- With `CORVUS_SESSION` set, every `call` is a routed call and needs `serve` running.
- Server options belong to `serve`; a routed call with `--session` and one is a usage error, with `CORVUS_SESSION` they are ignored.
- `batch steps.jsonl --session NAME` runs each step in the session; `batch --file` and `analyze` stay in-process.
- `serve` on a name already in use is a usage error (exit code 2).
- Only the starting account can reach a session.
- Calls run one at a time, except `server_status`, `read_result` and the instant read-only tools such as `get_engine_status` and `list_assemblies`.
- Progress prints on stderr.
- A step abandoned by `--step-timeout` or Ctrl+C is cancelled before the next one starts.
- A routed call to a name with no running session is exit code 3.

## Batch

- `batch steps.jsonl` runs every step in one session. IDs (`app.dll#2`) and unsaved edits carry over.
- `batch steps.jsonl --sarif <file>` writes the findings new in each `compare_folders` step as one SARIF run, located on the new side.
- The file is a JSON array or JSON Lines of `{"tool": "...", "args": {...}}` (`arguments` also accepted).
  `#` starts a comment line. Every tool name is checked before the first step runs.
- With `--json`, one line per step: `{step, tool, isError, state, text, structured, error}`; `state` is `ok`, `failed` or `running`.
- Later steps run after a failed one unless `--stop-on-error` is given. The exit code is the first failed step's.
- `--keep-going` runs the valid steps and names each invalid line on stderr (not in `--json` output); exit 2 if no step failed.
  A malformed JSON array still fails the batch.
- `--step-timeout <seconds>`: ends a step that runs longer (above 0, at most 86400); it counts as failed with exit code 124, and `--json` writes `error.code` `timeout` for it.

### File batch

`batch --file sample.bin --json` reads one file with fixed read-only steps and prints one JSON document, for pipelines
without an agent. Nothing in the file runs; no network calls are made.

| Section | Reads | Runs when |
|---|---|---|
| `summary` | `summarize_file`: type, hashes, signature, container, highlights | always |
| `container` | `search_container kind=file`: the files inside | the summary names a container |
| `strings` | `extract_strings`: typed values, by assembly or asset | .NET code, or serialized asset files |
| `yara` | `search_container kind=yara`: matching rules; `unavailable` when `CORVUS_WORKER_HOST=0` | `--rules` names a rule file or folder |
| `build` | `summarize_build`: version, scripting backend, metadata state | a build folder, package or zip |

- Each section has `status`: `complete`, `partial`, `not_applicable`, `unavailable`, `error` or `timeout`.
  `result` is the tool's structured output; `error` is the tool's error record.
- A `partial` section keeps every row it read. `limit` names the limit reached; `reason` names what stopped it.
- `complete` is true only when every section is `complete` or `not_applicable`. Each step pages through all of its results.
- `ruleTable` is the digest of the rule table the levels come from; `unknown` when the summary step gave no result.
- `rulePacks` names each installed rule pack with its version and digest (`corvus rules list`); empty when none is installed.
- `read_result format=verify` on a kept `summarize_file` overview names "rules changed", both digests, and the matches new or gone.
- `summary.level`: `noteworthy`, `review`, `info`, `none`, or `unknown` when the summary step gave no result.
  `summary.reasons` lists the findings at that level, each with `level`, `rule`, `category`, `evidence`, `location` and `source`.
- `findings` lists every finding of the overview, each with a `key`: file SHA-256, rule, level and a hash of evidence and location.
- `--recurse` reads every file under a folder through the same steps; `records` replaces `sections` and `findings`.
  - A container's members are extracted (`unpack_container`, nested containers within its limits) and read the same way.
  - One record per SHA-256 across files and members: `file.paths` lists every path, a member as `container!/inner/path`.
  - A container record's `unread` names members past an unpack limit; any entry makes the record incomplete.
  - Each record has `complete`, `summary`, `counts` (findings per level), `findings` and `sections`.
  - Records are ordered by noteworthy count, then review count, then first path.
  - `summary` holds the strongest record level, `records`, `files`, `members` and `byLevel` (records per level).
  - `unread` names folders and files not read: links are not followed. Any entry makes `complete` false.
- `--fail-on noteworthy|review` adds `gate` (`failOn`, `allowIncomplete`, `failed`, `reasons`) and sets the exit code.
  - Each finding at or above the level is a reason, so two findings of one rule are two reasons.
  - A section that is not `complete` or `not_applicable`, an `unread` entry, or unlisted findings that may reach the level are reasons too.
  - `--allow-incomplete` keeps only the finding reasons.
- `--extract <folder>` (new or empty) writes decoded payloads under `<folder>/<sha256>/` and adds two sections.
  - `embedded`: `extract_embedded save=true` on .NET code; each item keeps its encoding chain (`base64`, `gzip`, ...).
  - `script`: the `script` view's plain text, layers peeled and constants folded, as `script.txt`; the chain names each layer.
  - `extracted` lists each file written with `path`, `kind`, `source` and `chain`; `index.json` holds the same per SHA-256.
- `--dump-modules <folder>` (new or empty) with a minidump as `--file` writes each module image to `<folder>`.
  - `dumpModules` lists `written` (`file`, `base`, `size`, `sha256`, `capturedPercent`) and `skipped` with the reason.
  - A .NET image adds `metadata` (`readable`, `partial` or `unreadable`) and, unless readable, `metadataReason`; a native image carries neither.
  - An image is rebuilt from the memory the dump holds, at most 128 MB each and 1 GB in all.
- `--password-file <file>` with `--recurse` reads the password of encrypted members from the first line of `<file>`.
- `--baseline <file>` drops known findings by `key` before the levels, counts and gate are set.
  - The file: `{"schema": "corvus.baseline/1", "entries": [{"key", "reason", "owner", "expires": "yyyy-MM-dd"}]}`.
  - An earlier `corvus.batch/1` result works too: each finding is an entry with reason `from <file name>`, no owner, no expiry.
  - A dropped finding moves to `suppressed` with its entry's `reason`, `owner` and `expires`.
  - An entry applies through its `expires` day; after it, the finding stays with `baseline.expired`.
  - A level rise changes the key: the finding stays with `baseline.rose` naming the earlier level.
  - `baseline` counts `entries`, `suppressed`, `expired`, `rose` and `unused`.
- `--report <file>` also writes Markdown: one section per record in record order, with level, paths, findings and indicators; read text is escaped.
- `--sarif <file>` also writes SARIF 2.1.0: one run, the rules of its results, `error` for noteworthy, `warning` for review, `note` for info.
  - Locations are paths relative to the current folder; `partialFingerprints` holds the finding `key`.
  - Results past 25,000 or a 10 MB gzip are cut, weakest levels first; `runs[0].properties.cut` and a run notification name the cut.
- `batch --file log.evtx --evtx-jsonl events.jsonl` writes each event of an event log, recovered ones included, as a JSON line for Timesketch (`message`, `datetime`, `timestamp_desc`) and Zircolite `--json-input` (`Event.System`, `Event.EventData`).
- `--jsonl` in place of `--json` writes one record per line, files and members alike, no envelope; `--out <file>` instead of stdout.
- `--time-limit <seconds>`: the whole run (default 600, at most 86400).
- `--step-timeout <seconds>`: one step (above 0, at most 86400); the step is a `timeout` section and the run goes on.
- `--limit containerFiles=N`, `strings=N`, `yaraMatches=N`: default 500 each.
- `--limit members=N`: files `--recurse` reads under the folder (default 10000).
  `containerFiles` also bounds the members it reads from one container.
- `--limit embeddedItems=N`: items the `embedded` section lists (default 500).
- `--limit assetBytes=N`: asset bytes the `strings` step reads (default 1 GiB; a direct `extract_strings` call reads up to 4 GiB).
  The `strings` step reads assets for at most half the time left.
- At most 25 summary highlights. The `limits` record holds the values used.
- The schema becomes `corvus.batch/2` only when a field is renamed or removed; new fields keep `/1`.
- Exit codes: 0 when the document is written, whatever the section statuses; 124 when the time limit ended the run
  (finished sections kept, the rest `timeout`); 2 for a missing file or bad option, nothing on stdout.
- With `--fail-on`: 1 when the gate fails, else 0, including after the time limit.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success; a partial result shows `error.partial` with `--json` |
| 1 | tool error: `not_found`, `ambiguous`, `conflict`, `not_loaded`, `limit_exceeded`, `internal`, ...; also a failed analysis (`analyze --wait`) |
| 2 | usage error (unknown command, tool or option, malformed `name=value`), or the server's `invalid_argument` |
| 3 | environment: `provider_unavailable` or `unsupported` (no IDA, `inspect_process` off Windows) |
| 4 | analysis ended `partial` (`analyze --wait`) |
| 5 | `timeout` with `details.stillRunning` (`call`, `batch`): the work goes on in the engine; a batch step records `running` |
| 6 | analysis `cancelled` (`analyze --wait`) |
| 7 | analysis outcome unknown: no result reported, or `running` unchanged for 300 s (`analyze --wait`) |
| 124 | `timeout`, as `timeout(1)` |
| 130 | Ctrl+C: the first cancels the call and waits; a second ends the process |

`install`, `uninstall`, `status`, `config` and `update` print failures and usage errors to stderr; stdout keeps results and the `--json` report.

## Examples

```sh
corvus search_strings --load app.dll query=password --json
corvus list_types --load app.dll namespace=Ns --structured | jq '.items[].fullName'
corvus patch_method_csharp --load app.dll method=Ns.Type::Check code=@check.cs dryRun=true
source <(corvus completion bash)
```
