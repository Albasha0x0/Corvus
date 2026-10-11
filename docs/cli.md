# Command line

Every tool, prompt and resource of the server also runs from a terminal. There is no per-tool code: commands and
argument types come from the live tool catalog, and each call runs the server in the same process over in-memory
streams, so a call from the terminal takes the same argument checks, limits and error results as a call from an agent.
The full tool reference is [tools.md](tools.md); setup commands (`install`, `status`, ...) are in
[installation.md](installation.md).

## Commands

| Command | What it does |
|---|---|
| `<tool> [name=value ...]` | Call a tool: `NetDecompilerMcp decompile_member --load app.dll member=Ns.Type::Method`. |
| `call <tool> [name=value ...]` | The same, with the tool name after `call`. |
| `tools [filter]` | The tools by toolset, with their effect (read-only, edit, destructive; long-running) and first sentence. `--json` prints a table. |
| `describe <tool\|prompt>` | Description, parameters (type, required, default, values), annotations, structured output and an example call. `help <name>` is the same. `--json` prints the catalog entry. |
| `batch <file\|->` | Run several calls in one session (below). |
| `prompts` | The prompts and their arguments. |
| `prompt <name> [name=value ...]` | A prompt's text, ready to pipe into any agent. |
| `resources` | The resources and resource templates. |
| `read <uri>` | One resource, e.g. `corvus://guide/native`. |
| `completion <bash\|zsh\|pwsh>` | A shell completion script for commands, tools and parameter names. |

Tool names are accepted in snake case or kebab case (`decompile-member`). `NetDecompilerMcp help` lists the setup
commands and these.

## Arguments

| Form | Meaning |
|---|---|
| `name=value` | Typed by the parameter's schema: integers (also `0x` hex), numbers, `true`/`false` (also `1`/`0`, `yes`/`no`), arrays as JSON (`[1,2]`) or comma-separated (`a,b`), objects as JSON; anything else is text. |
| `name:=<json>` | The value as raw JSON. |
| `name=@file` | The value read from a file, e.g. a C# body for `patch_method_csharp`. |
| `name=@-` | The value read from standard input. |
| `--args '<json object>'` | All arguments as one JSON object (`--json '{...}'` is the same); `name=value` pairs override its members. |
| `--args-file F` | The JSON object from a file (`-` for standard input). |

A parameter the tool does not declare is reported by the server as `invalid_argument` with the closest declared
names. Quote values that hold spaces or shell characters: `member='Ns.Type::Method(int, string)'`.

## Server options

Every server option applies to the session (README, "Server options"). The ones used most:

- `--load PATH` preloads a file or folder (repeatable), so one line loads and calls:
  `NetDecompilerMcp get_type_info --load app.dll type=Ns.Type`.
- `--no-index` skips background indexing, which a single call rarely needs.
- `--max-output N` restores paging. Without it the command line prints whole results: paging is for agents.
- `--timeout S`, `--engine E`, `--toolsets T`, `--log-level L` as for the server. Logs go to stderr at `warning` unless
  `--log-level` or `CORVUS_LOG_LEVEL` says otherwise.

Files are not watched for changes in a command-line session.

## Output

- Default: the result's text on stdout. An error result's text goes to stderr. Workspace notices (`[workspace] ...`)
  go to stderr.
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
NetDecompilerMcp tools native
NetDecompilerMcp describe find_references
NetDecompilerMcp search_strings --load app.dll query=password --json
NetDecompilerMcp list_types --load app.dll namespace=Ns --structured | jq '.items[].fullName'
NetDecompilerMcp patch_method_csharp --load app.dll method=Ns.Type::Check code=@check.cs dryRun=true
NetDecompilerMcp prompt getting_started | some-agent-cli
source <(NetDecompilerMcp completion bash)
```
