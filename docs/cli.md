# Command line

Every tool, prompt and resource also runs from a terminal, with the same argument checks, limits and errors as an
agent's call. Tool reference: [tools.md](tools.md). Setup commands (`install`, `status`, ...):
[installation.md](installation.md).

## Commands

| Command | What it does |
|---|---|
| `<tool> [name=value ...]` | call a tool: `corvus decompile_member --load app.dll member=Ns.Type::Method` |
| `call <tool> [name=value ...]` | the same, with the tool name after `call` |
| `tools [filter]` | tools by toolset with their effect and first sentence; `--json` prints a table |
| `describe <tool\|prompt>` | description, parameters, annotations, output and an example; also `help <name>` |
| `batch <file\|->` | run several calls in one session ([below](#batch)) |
| `batch --file <path> --json` | read one file with fixed read-only steps into one JSON document ([below](#file-batch)) |
| `prompts` | prompts and their arguments |
| `prompt <name> [name=value ...]` | a prompt's text, ready to pipe into an agent |
| `resources` | resources and resource templates |
| `read <uri>` | one resource, such as `corvus://guide/native` |
| `completion <bash\|zsh\|pwsh>` | a shell completion script |
| `rules [list]`, `rules fetch <pack>` | list or install YARA rule packs (malcontent, yara-forge-core) |
| `ida-script [folder]` | write `corvus_connect.py` for using a database open in IDA |

- Tool names are accepted in snake case or kebab case (`decompile-member`).
- `corvus help` lists the setup commands and these.
- `rules fetch` downloads a pack from GitHub, refuses it unless its SHA-256 matches the pinned value, and installs it
  under the data folder's `rules/<pack>/<version>/` for `search_container kind=yara query=pack:<name>`.
- `ida-script` writes to `<IDA user directory>/corvus` by default. Run the script in IDA (File > Script file) and start
  Corvus with `CORVUS_IDA_CONNECT=1`.

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
  comma-separated (`a,b`), objects as JSON; anything else is text.
- Text starting with `@` (such as `@xml/config`) goes as JSON: `name:='"@xml/config"'`.
- An undeclared parameter is `invalid_argument` with the closest declared names.
- Quote values with spaces or shell characters: `member='Ns.Type::Method(int, string)'`.

## Server options

Every server option applies ([configuration.md](configuration.md#server-options)). Most used:

- `--load PATH` preloads a file or folder (repeatable), so one line loads and calls:
  `corvus get_type_info --load app.dll type=Ns.Type`.
- `--no-index` skips background indexing in a `batch` session; a single call already skips it unless its tool needs
  the index.
- `--max-output N` restores paging. Without it the command line prints whole results.
- `--timeout S`, `--engine E`, `--toolsets T`, `--log-level L` as for the server. Logs go to stderr at `warning` unless
  `--log-level` or `CORVUS_LOG_LEVEL` says otherwise.

Files are not watched for changes in a command-line session.

## Output

- Default: the result's text on stdout; an error result's text and workspace notices (`[workspace] ...`) on stderr.
- Output to a file or pipe is UTF-8, and so is piped input, whatever the console's code page.
- `--json`: one object `{tool, isError, text, structured, error}`, where `error` is the parsed error record
  (`{code, retryable, message, next, partial, details}`, [errors.md](errors.md)). Indented on a terminal, one line
  when piped.
- `--structured`: only the structured content, for `jq`; a tool without structured output is a usage error.
- Progress shows as one updating line on stderr when stderr is a terminal.

## Batch

- `batch steps.jsonl` runs every step in one session; ids (`app.dll#2`) and unsaved edits carry over.
- The file is a JSON array or JSON Lines of `{"tool": "...", "args": {...}}` (`arguments` also accepted); `#` starts a
  comment line.
- Every tool name is checked before the first step runs.

```json
{"tool": "load_assembly", "args": {"path": "app.dll"}}
{"tool": "rename_symbol", "args": {"symbol": "Ns.a::b", "newName": "Decode", "dryRun": false}}
{"tool": "save_assembly", "args": {"assembly": "app", "outputPath": "app.patched.dll"}}
```

- Each step's output follows a `=== [n/total] tool` header; with `--json`, one line per step
  `{step, tool, isError, text, structured, error}`.
- Later steps run after a failed one unless `--stop-on-error` is given.
- The exit code is the first failed step's.

### File batch

`batch --file sample.bin --json` reads one file with fixed read-only steps and prints one JSON document, for pipelines
without an agent. Nothing in the file runs; no network calls are made.

| Section | Reads | Runs when |
|---|---|---|
| `summary` | `summarize_file`: type, hashes, signature, container, highlights | always |
| `container` | `search_container kind=file`: the files inside | the summary names a container |
| `strings` | `extract_strings`: typed values, by assembly or asset | .NET code, or serialized asset files |
| `yara` | `search_container kind=yara`: matching rules | `--rules` names a rule file or folder |
| `build` | `summarize_build`: version, scripting backend, metadata state | a build folder, package or zip |

- `yara` is `unavailable`, with the reason, when `CORVUS_WORKER_HOST=0`.

```json
{"schema": "corvus.batch/1", "corvus": "2.5.1",
 "file": {"path": "...", "size": 887, "sha256": "...", "type": "zip"},
 "complete": false,
 "limits": {"timeSeconds": 120, "containerFiles": 500, "strings": 500, "yaraMatches": 500, "assetBytes": 1073741824, "summaryHighlights": 25},
 "sections": [
   {"name": "summary", "tool": "summarize_file", "status": "complete", "result": {...}},
   {"name": "container", "tool": "search_container", "status": "partial", "limit": "containerFiles", "result": {...}},
   {"name": "strings", "tool": "extract_strings", "status": "not_applicable", "reason": "..."},
   {"name": "yara", "tool": "search_container", "status": "not_applicable", "reason": "..."},
   {"name": "build", "tool": "summarize_build", "status": "not_applicable", "reason": "..."}]}
```

- `result` is the tool's structured output, as `--structured` prints it; `error` is the tool's error record.
- `status`: `complete`, `partial`, `not_applicable`, `unavailable`, `error` or `timeout`.
- A `partial` section keeps every row it read; `limit` names the limit reached, or `reason` names what stopped it.
- `complete` is true only when every section is `complete` or `not_applicable`.
- Each step pages through its tool's results; `result` holds the rows of every page.
- `--time-limit <seconds>`: the whole run (default 120, at most 86400).
- `--limit containerFiles=N`, `strings=N`, `yaraMatches=N`: default 500 each.
- `--limit assetBytes=N`: asset bytes the `strings` step reads (default 1 GiB; a direct `extract_strings` call reads
  up to 4 GiB).
- The `strings` step reads assets for at most half the time left, then keeps the rows read.
- At most 25 summary highlights. The `limits` record holds the values used.
- Exit codes: 0 when the document is written, whatever the section statuses; 124 when the time limit ended the run (finished sections kept, the rest
  `timeout`); 2 for a missing file or bad option, nothing on stdout.
- The schema becomes `corvus.batch/2` only when a field is renamed or removed; new fields keep `/1`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success; a partial result shows `error.partial` with `--json` |
| 1 | tool error: `not_found`, `ambiguous`, `conflict`, `not_loaded`, `limit_exceeded`, `internal`, ... |
| 2 | usage error (unknown command, tool or option, malformed `name=value`), or the server's `invalid_argument` |
| 3 | environment: `provider_unavailable` or `unsupported` (no IDA, `inspect_process` off Windows) |
| 124 | `timeout`, as `timeout(1)` |
| 130 | Ctrl+C: the first cancels the call and waits; a second ends the process |

## Examples

```sh
corvus tools native
corvus describe find_references
corvus search_strings --load app.dll query=password --json
corvus list_types --load app.dll namespace=Ns --structured | jq '.items[].fullName'
corvus patch_method_csharp --load app.dll method=Ns.Type::Check code=@check.cs dryRun=true
corvus prompt getting_started | some-agent-cli
source <(corvus completion bash)
```
