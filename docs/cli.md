# Command line

Every tool, prompt and resource of the server also runs from a terminal. There is no per-tool code: commands and
argument types come from the live tool catalog, and each call runs the server in the same process over in-memory
streams, so a call from the terminal takes the same argument checks, limits and error results as a call from an agent.
The full tool reference is [tools.md](tools.md); setup commands (`install`, `status`, ...) are in
[installation.md](installation.md).

## Commands

| Command | What it does |
|---|---|
| `<tool> [name=value ...]` | Call a tool: `corvus decompile_member --load app.dll member=Ns.Type::Method`. |
| `call <tool> [name=value ...]` | The same, with the tool name after `call`. |
| `tools [filter]` | The tools by toolset, with their effect (read-only, edit, destructive; long-running) and first sentence. `--json` prints a table. |
| `describe <tool\|prompt>` | Description, parameters (type, required, default, values), annotations, structured output and an example call. `help <name>` is the same. `--json` prints the catalog entry. |
| `batch <file\|->` | Run several calls in one session (below). |
| `batch --file <path> --json` | Read one file with a fixed set of read-only steps and print one JSON document ([below](#file-batch)). |
| `prompts` | The prompts and their arguments. |
| `prompt <name> [name=value ...]` | A prompt's text, ready to pipe into any agent. |
| `resources` | The resources and resource templates. |
| `read <uri>` | One resource, e.g. `corvus://guide/native`. |
| `completion <bash\|zsh\|pwsh>` | A shell completion script for commands, tools and parameter names. |

Tool names are accepted in snake case or kebab case (`decompile-member`). `corvus help` lists the setup
commands and these.

## Arguments

| Form | Meaning |
|---|---|
| `name=value` | Typed by the parameter's schema: integers (also `0x` hex), numbers, `true`/`false` (also `1`/`0`, `yes`/`no`), arrays as JSON (`[1,2]`) or comma-separated (`a,b`), objects as JSON; anything else is text. |
| `name:=<json>` | The value as raw JSON. |
| `name=@file` | The value read from a file, e.g. a C# body for `patch_method_csharp`. Text that starts with `@` (an Android resource such as `@xml/config`) goes as JSON: `name:='"@xml/config"'`. |
| `name=@-` | The value read from standard input. |
| `--args '<json object>'` | All arguments as one JSON object (`--json '{...}'` is the same); `name=value` pairs override its members. |
| `--args-file F` | The JSON object from a file (`-` for standard input). |

A parameter the tool does not declare is reported by the server as `invalid_argument` with the closest declared
names. Quote values that hold spaces or shell characters: `member='Ns.Type::Method(int, string)'`.

## Server options

Every server option applies to the session ([configuration.md](configuration.md#server-options)). The ones used most:

- `--load PATH` preloads a file or folder (repeatable), so one line loads and calls:
  `corvus get_type_info --load app.dll type=Ns.Type`.
- `--no-index` skips background indexing, which a single call rarely needs.
- `--max-output N` restores paging. Without it the command line prints whole results: paging is for agents.
- `--timeout S`, `--engine E`, `--toolsets T`, `--log-level L` as for the server. Logs go to stderr at `warning` unless
  `--log-level` or `CORVUS_LOG_LEVEL` says otherwise.

Files are not watched for changes in a command-line session.

## Output

- Default: the result's text on stdout. An error result's text goes to stderr. Workspace notices (`[workspace] ...`)
  go to stderr.
- Output to a file or pipe is UTF-8, and so is piped input, whatever the console's code page.
- `--json`: one object `{tool, isError, text, structured, error}`, where `error` is the parsed error record
  (`{code, retryable, message, next, partial, details}`, [errors.md](errors.md)). Indented on a terminal, one line
  when piped.
- `--structured`: only the structured content, for `jq`; a tool without structured output is a usage error.
- Progress notifications show as one updating line on stderr when stderr is a terminal.

## Batch

`batch steps.jsonl` runs every step in one session, so ids (`app.dll#2`) and unsaved in-memory edits carry from step
to step. The file is a JSON array or JSON Lines; each step is `{"tool": "...", "args": {...}}` (`arguments` is accepted
too), and lines starting with `#` are comments. Every tool name is checked before the first step runs.

```json
{"tool": "load_assembly", "args": {"path": "app.dll"}}
{"tool": "rename_symbol", "args": {"symbol": "Ns.a::b", "newName": "Decode", "dryRun": false}}
{"tool": "save_assembly", "args": {"assembly": "app", "outputPath": "app.patched.dll"}}
```

Each step's output follows a `=== [n/total] tool` header; with `--json`, each step is one line
`{step, tool, isError, text, structured, error}`. Later steps run after a failed one unless `--stop-on-error` is given.
The exit code is the first failed step's.

### File batch

`batch --file sample.bin --json` reads one file with a fixed set of read-only steps and prints one JSON document,
for a pipeline that scans files without an agent. Nothing in the file runs, and Corvus makes no network calls.

| Section | Reads | Runs when |
|---|---|---|
| `summary` | `summarize_file`: type, hashes, signature, container, assemblies, highlights | always |
| `container` | `search_container kind=file`: the files inside, not extracted | the summary names a container |
| `strings` | `extract_strings`: typed values (URLs, domains, IPs, paths, registry keys) | the file is a .NET assembly |
| `yara` | YARA rule matches | reported as `unavailable` until YARA support ships |

```json
{"schema": "corvus.batch/1", "corvus": "2.4.0",
 "file": {"path": "...", "size": 887, "sha256": "...", "type": "zip"},
 "complete": false,
 "limits": {"timeSeconds": 120, "containerFiles": 500, "strings": 500, "summaryHighlights": 25},
 "sections": [
   {"name": "summary", "tool": "summarize_file", "status": "complete", "result": {...}},
   {"name": "container", "tool": "search_container", "status": "partial", "limit": "containerFiles", "result": {...}},
   {"name": "strings", "tool": "extract_strings", "status": "not_applicable", "reason": "..."},
   {"name": "yara", "status": "unavailable", "reason": "..."}]}
```

- `result` is the tool's structured output, as `--structured` prints it; `error` is the tool's error record.
- `status` is `complete`, `partial` (the section keeps every row it read and `limit` names the limit it reached),
  `not_applicable`, `unavailable`, `error` or `timeout`. `complete` is true only when every section is `complete` or
  `not_applicable`.
- Limits: `--time-limit <seconds>` for the whole run (default 120, at most 86400), `--limit containerFiles=N` and
  `--limit strings=N` (default 500 each); the summary shows at most 25 highlights. The `limits` record holds the
  values used.
- Exit code 0 when the document is written, whatever the section statuses; 124 when the time limit ended the run (the
  document is still written, with finished sections kept and the rest marked `timeout`); 2 for a missing file or a
  bad option, with nothing on stdout.
- The schema name changes to `corvus.batch/2` only when a field is renamed or removed; new fields keep `/1`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. A result can still be partial; `--json` shows `error.partial` when it is. |
| 1 | The tool returned an error: `not_found`, `ambiguous`, `conflict`, `not_loaded`, `limit_exceeded`, `internal`, ... |
| 2 | Usage error: unknown command, tool or option, malformed `name=value`, or the server's `invalid_argument`. |
| 3 | Environment: `provider_unavailable` or `unsupported` (for example no IDA, or `inspect_process` off Windows). |
| 124 | `timeout` (the convention of `timeout(1)`). |
| 130 | Cancelled with Ctrl+C. The first Ctrl+C cancels the call in flight and waits for the tool to stop; a second one ends the process. |

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
