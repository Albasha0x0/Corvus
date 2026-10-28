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
| `ida-script [folder]` | write `corvus_connect.py` for using a database open in IDA |

- Tool names take snake case or kebab case (`decompile-member`). `corvus help` lists these and the setup commands.
- `rules fetch` refuses a pack unless its SHA-256 matches the pinned value. It installs under `rules/<pack>/<version>/`
  in the data folder.
- `ida-script` writes to `<IDA user directory>/corvus` by default. Run the script in IDA (File > Script file), then start
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
  comma-separated (`a,b`), objects as JSON. Anything else is text.
- Text starting with `@` goes as JSON: `name:='"@xml/config"'`. An undeclared parameter is `invalid_argument`.
- Quote values with spaces or shell characters: `member='Ns.Type::Method(int, string)'`.

## Server options

Every server option applies ([configuration.md](configuration.md#server-options)). Most used:

- `--load PATH` preloads a file or folder (repeatable): `corvus get_type_info --load app.dll type=Ns.Type`.
- `--no-index` skips background indexing in a `batch` session. A single call skips it unless its tool needs the index.
- `--max-output N` restores paging. Without it, the command line prints whole results.
- `--timeout S`, `--engine E`, `--toolsets T`, `--log-level L`: as for the server.
- Logs go to stderr at `warning` unless `--log-level` or `CORVUS_LOG_LEVEL` says otherwise. Files are not watched for changes.

## Output

- Default: the result's text on stdout. An error's text and workspace notices (`[workspace] ...`) go to stderr.
- Output to a file or pipe, and piped input, is UTF-8, whatever the console code page.
- `--json`: one object `{tool, isError, text, structured, error}`. `error` is the parsed record
  (`{code, retryable, message, next, partial, details}`, [errors.md](errors.md)). Indented on a terminal, one line when piped.
- `--structured`: only the structured content, for `jq`. A tool without structured output is a usage error.
- Progress is one updating line on stderr when stderr is a terminal.

## Batch

- `batch steps.jsonl` runs every step in one session. IDs (`app.dll#2`) and unsaved edits carry over.
- The file is a JSON array or JSON Lines of `{"tool": "...", "args": {...}}` (`arguments` also accepted).
  `#` starts a comment line. Every tool name is checked before the first step runs.
- With `--json`, one line per step: `{step, tool, isError, text, structured, error}`.
- Later steps run after a failed one unless `--stop-on-error` is given. The exit code is the first failed step's.

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
  - One record per SHA-256: `file.paths` lists every path it was seen at, relative to the folder.
  - Each record has `complete`, `summary`, `counts` (findings per level), `findings` and `sections`.
  - Records are ordered by noteworthy count, then review count, then first path.
  - `summary` holds the strongest record level, `records`, `files` and `byLevel` (records per level).
  - `unread` names folders and files not read: links are not followed. Any entry makes `complete` false.
- `--fail-on noteworthy|review` adds `gate` (`failOn`, `allowIncomplete`, `failed`, `reasons`) and sets the exit code.
  - Each finding at or above the level is a reason, so two findings of one rule are two reasons.
  - A section that is not `complete` or `not_applicable`, an `unread` entry, or unlisted findings that may reach the level are reasons too.
  - `--allow-incomplete` keeps only the finding reasons.
- `--time-limit <seconds>`: the whole run (default 120, at most 86400).
- `--limit containerFiles=N`, `strings=N`, `yaraMatches=N`: default 500 each.
- `--limit members=N`: files `--recurse` reads (default 10000).
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
| 1 | tool error: `not_found`, `ambiguous`, `conflict`, `not_loaded`, `limit_exceeded`, `internal`, ... |
| 2 | usage error (unknown command, tool or option, malformed `name=value`), or the server's `invalid_argument` |
| 3 | environment: `provider_unavailable` or `unsupported` (no IDA, `inspect_process` off Windows) |
| 124 | `timeout`, as `timeout(1)` |
| 130 | Ctrl+C: the first cancels the call and waits; a second ends the process |

## Examples

```sh
corvus search_strings --load app.dll query=password --json
corvus list_types --load app.dll namespace=Ns --structured | jq '.items[].fullName'
corvus patch_method_csharp --load app.dll method=Ns.Type::Check code=@check.cs dryRun=true
source <(corvus completion bash)
```
