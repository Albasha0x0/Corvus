# Command line

Every tool, prompt and resource also runs from a terminal. Commands and argument types come from the tool catalog,
and each call runs the server in process, so a terminal call gets the same argument checks, limits and errors as an
agent's. Tool reference: [tools.md](tools.md); setup commands (`install`,
`status`, ...): [installation.md](installation.md).

## Commands

| Command | What it does |
|---|---|
| `<tool> [name=value ...]` | Call a tool: `corvus decompile_member --load app.dll member=Ns.Type::Method`. |
| `call <tool> [name=value ...]` | The same, with the tool name after `call`. |
| `tools [filter]` | The tools by toolset, with their effect (read-only, edit, destructive; long-running) and first sentence. `--json` prints a table. |
| `describe <tool\|prompt>` | Description, parameters (type, required, default, values), annotations, structured output and an example call. `help <name>` is the same. `--json` prints the catalog entry. |
| `batch <file\|->` | Run several calls in one session ([below](#batch)). |
| `batch --file <path> --json` | Read one file with a fixed set of read-only steps and print one JSON document ([below](#file-batch)). |
| `prompts` | The prompts and their arguments. |
| `prompt <name> [name=value ...]` | A prompt's text, ready to pipe into any agent. |
| `resources` | The resources and resource templates. |
| `read <uri>` | One resource, e.g. `corvus://guide/native`. |
| `completion <bash\|zsh\|pwsh>` | A shell completion script for commands, tools and parameter names. |
| `rules [list]`, `rules fetch <pack>` | List the installed and known YARA rule packs (malcontent, yara-forge-core); `fetch` downloads one from GitHub, refuses it unless its SHA-256 equals the pinned one, and installs its rules and license under the data folder's `rules/<pack>/<version>/` for `search_container kind=yara query=pack:<name>`. |
| `ida-script [folder]` | Write `corvus_connect.py` and the worker it imports (default folder: `<IDA user directory>/corvus`). Run it in IDA with File > Script file: with `CORVUS_IDA_CONNECT=1`, Corvus reads and edits that open database instead of analyzing its own copy. |

Tool names are accepted in snake case or kebab case (`decompile-member`). `corvus help` lists the setup commands and
these.

## Arguments

| Form | Meaning |
|---|---|
| `name=value` | Typed by the parameter's schema: integers (also `0x` hex), numbers, `true`/`false` (also `1`/`0`, `yes`/`no`), arrays as JSON (`[1,2]`) or comma-separated (`a,b`), objects as JSON; anything else is text. |
| `name:=<json>` | The value as raw JSON. |
| `name=@file` | The value read from a file, e.g. a C# body for `patch_method_csharp`. Text that starts with `@` (an Android resource such as `@xml/config`) goes as JSON: `name:='"@xml/config"'`. |
| `name=@-` | The value read from standard input. |
| `--args '<json object>'` | All arguments as one JSON object (`--json '{...}'` is the same); `name=value` pairs override its members. |
| `--args-file F` | The JSON object from a file (`-` for standard input). |

An undeclared parameter is reported as `invalid_argument` with the closest declared names. Quote values that hold
spaces or shell characters: `member='Ns.Type::Method(int, string)'`.

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

`batch steps.jsonl` runs every step in one session, so ids (`app.dll#2`) and unsaved in-memory edits carry over. The
file is a JSON array or JSON Lines; each step is `{"tool": "...", "args": {...}}` (`arguments` also accepted); lines
starting with `#` are comments. Every tool name is checked before the first step runs.

```json
{"tool": "load_assembly", "args": {"path": "app.dll"}}
{"tool": "rename_symbol", "args": {"symbol": "Ns.a::b", "newName": "Decode", "dryRun": false}}
{"tool": "save_assembly", "args": {"assembly": "app", "outputPath": "app.patched.dll"}}
```

Each step's output follows a `=== [n/total] tool` header; with `--json`, each step is one line
`{step, tool, isError, text, structured, error}`. Later steps run after a failed one unless `--stop-on-error` is given.
The exit code is the first failed step's.

### File batch

`batch --file sample.bin --json` reads one file with a fixed set of read-only steps and prints one JSON document, for
pipelines that scan files without an agent. Nothing in the file runs; no network calls are made.

| Section | Reads | Runs when |
|---|---|---|
| `summary` | `summarize_file`: type, hashes, signature, container, assemblies, highlights | always |
| `container` | `search_container kind=file`: the files inside, not extracted | the summary names a container |
| `strings` | `extract_strings`: typed values (URLs, domains, IPs, paths, registry keys, encoded values); in a container, from its own assemblies, each location prefixed with the assembly's path; in Unity data, from MonoBehaviour string fields and config TextAssets, each location naming the file and asset | the file is a .NET assembly, a container that holds them, a Unity serialized file or bundle, or a folder, package or zip that holds a Unity build |
| `yara` | `search_container kind=yara`: the rules that matched the file and its members, in a worker process | `--rules` names a rule file or folder; `unavailable`, with the reason, when `CORVUS_WORKER_HOST=0` |
| `unity` | `unity_overview`: engine version, scripting backend (Il2Cpp or Mono), Il2Cpp metadata version and state, markers | the input is a folder, package or zip that holds a Unity build |

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
   {"name": "unity", "tool": "unity_overview", "status": "not_applicable", "reason": "..."}]}
```

- `result` is the tool's structured output, as `--structured` prints it; `error` is the tool's error record.
- `status`: `complete`, `partial`, `not_applicable`, `unavailable`, `error` or `timeout`. A `partial` section keeps
  every row it read; `limit` names the limit reached, or `reason` names what else stopped it: the tool's own partial or
  unknown coverage, an unavailable facet, a response cut to fit, a failed page. `complete` is true only when every
  section is `complete` or `not_applicable`.
- Each step pages through its tool's results until its limit or the last row; `result` holds the rows of every page.
- Limits: `--time-limit <seconds>` for the whole run (default 120, at most 86400); `--limit containerFiles=N`,
  `--limit strings=N`, `--limit yaraMatches=N` (default 500 each); `--limit assetBytes=N` for the Unity asset files
  the `strings` step reads (default 1 GiB; a direct `extract_strings` call reads up to 4 GiB); at most 25 summary
  highlights. The `strings` step reads Unity assets for at most half the time left, then keeps the rows read. The
  `limits` record holds the values used.
- Exit code 0 when the document is written, whatever the section statuses; 124 when the time limit ended the run (the
  document is still written, finished sections kept, the rest marked `timeout`); 2 for a missing file or a bad option,
  with nothing on stdout.
- The schema name changes to `corvus.batch/2` only when a field is renamed or removed; new fields keep `/1`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. A result can still be partial; `--json` shows `error.partial` when it is. |
| 1 | The tool returned an error: `not_found`, `ambiguous`, `conflict`, `not_loaded`, `limit_exceeded`, `internal`, ... |
| 2 | Usage error: unknown command, tool or option, malformed `name=value`, or the server's `invalid_argument`. |
| 3 | Environment: `provider_unavailable` or `unsupported` (for example no IDA, or `inspect_process` off Windows). |
| 124 | `timeout` (the convention of `timeout(1)`). |
| 130 | Cancelled with Ctrl+C. The first Ctrl+C cancels the call in flight and waits for the tool to stop; a second ends the process. |

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
