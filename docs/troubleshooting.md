# Troubleshooting

Start with `corvus status` (alias `doctor`): it is read-only, starts each client's registration with that
entry's own args and env, and names a state and a fix per client. `--client <id>` narrows it to one client and
`--json` prints the report. The sections below go by symptom.

## The tools do not show up in the client

| Cause | Check | Fix |
|---|---|---|
| The client has not been restarted since `install`. | `status --client <id>` says `registered`. | Restart the client or reload its MCP servers. |
| The client has no registration. | `status --client <id>` says `not_registered`. | `corvus install --client <id>` |
| The entry is turned off in the client. | `status` says `disabled`. | Turn `corvus` on in the client's settings; install keeps an entry off on purpose. |
| The configuration file cannot be read (a syntax error, an unknown format). | `status` says `config_unreadable`. | Fix the file, or move it away and run `install`; a backup is kept as `<file>.corvus.bak`. |
| The registered program is gone (moved or deleted). | `status` says `missing_program`. | `corvus install --client <id>` |
| The server does not start with the registered args or env. | `status` says `start_failed` and shows the error. | Run the registered command by hand; fix or remove the args and env that fail. |
| The client is not one install knows. | `corvus help` lists the client ids. | Add the output of `corvus config` to the client's MCP settings. |
| The client lists only some tools. | `server_status` names the toolsets. | Remove `--toolsets` from the entry's args, or add the family you need. |

## The client runs another copy or an old version

- `status` says `other_copy`: the client is registered with a different program than the one you ran.
  `corvus install --client <id>` points it at this copy.
- `status` says `relay`: the client runs the development reload relay (`install --dev-reload`); the row names the
  publish folder and the build it serves. A relay whose folder is gone is `missing_program`. Every `install` removes
  staged relay copies that no client configuration names any more.
- `status` says `stale_catalog`: the registered program is this copy, but the running server's tool catalog differs
  from this build. Restart the client; a server started before an update keeps running the old build.
- In a session, `server_status expectedCatalogDigest=<digest>` compares the running server with a known build, and
  `expectedExecutable=<path>` names a client that started a different copy than the one it was registered with.

## The server is slow to start, or the client gives up waiting

`status` says `slow_start` when a client with a start deadline (Codex, Grok Build: 10 s by default) would stop waiting.
Set `startup_timeout_sec = 30` in the server's table of the client's TOML file. A large `--load` folder in the
entry's args also delays the start: load it from the session instead.

## A tool says IDA, Python or Ghidra is not available

`corvus status --engine all` (with `--deep` it also starts IDA's worker) names what is missing and how to
fix it:

- IDA: install IDA 9 with idalib, or point `CORVUS_IDA_DIR` at its folder.
- Python for IDA: `CORVUS_IDA_PYTHON` names the interpreter when the one found is not the one IDA was set up with.
- Ghidra: `CORVUS_GHIDRA_DIR` (Ghidra 12 or newer) and a JDK (`CORVUS_GHIDRA_JAVA`, `JAVA_HOME` or `PATH`).

Only `decompile_native`, the engine tools and `engine=ida|ghidra` need an engine; everything else is built in. From the
command line such errors exit with code 3.

## A result ends with a paging footer

Each part of a result (the text, and the structured content) is kept within a page of estimated tokens: 6,000 for
lists, 8,000 for code, 6,000 for bytes, 4,000 for reports and 3,000 for edits, or the call's `maxTokens` (500 or more)
up to the client's ceiling (`CORVUS_MAX_OUTPUT_TOKENS`). Lists return fewer rows with `hasMore` and `nextOffset`, and the
text ends with `[More: offset=N]`; pass that offset to continue. Code and other long text ends at a line with the same
footer. A result with no natural order sends its head and names the whole result: `read_result id=<id>` pages through
it, searches it (`query=`) or writes it to a file (`outputPath=`); kept results stay on disk for 7 days, and an evicted
id says so and names the call to repeat. Read-only calls never fail for size. Narrow the call where you can (one member
instead of a type, a filter).

## Claude Code saves a result to a file instead of showing it

Claude Code keeps tool results up to 50,000 characters in context unless the tool raises that limit. Every tool of
this server declares `anthropic/maxResultSizeChars` above its largest page, so a page stays in context.

## An IDA or Ghidra request stops early or opens read-only

Each engine request may take `CORVUS_ENGINE_REQUEST_TIMEOUT` seconds (default 120; `decompile_native` and `resolve_call_targets` take `timeoutSeconds` per call), and an engine's start plus auto-analysis `CORVUS_ENGINE_OPEN_TIMEOUT` seconds (default 1200); an analysis that needs longer is saved as it stands, marked partial in `server_status` and decompile headers, and `reanalyze_native` completes it. A request that runs out of time or is cancelled by the client is stopped inside the worker, which keeps the database open: scans answer with what they found, marked partial with where to continue, and only a worker that does not stop within 10 s is killed (the next request restarts it from the saved database). `server_status` reports both limits. For huge or hostile inputs, `CORVUS_ENGINE_ANALYSIS=none` opens images in IDA and Ghidra without auto-analysis: functions are made where a tool asks for one, the database is kept apart from the fully analyzed one, and output headers say so. A second server process opening an image whose IDA database another process holds gets a read-only snapshot of the last saved database (edits are neither journaled nor saved; decompile headers and `server_status` say so), or, when none is saved yet, a conflict naming the owning process. Limits: [configuration.md](configuration.md#ida-and-ghidra).

## A call ends with timeout

Calls to tools not marked long-running end after twice `--timeout` (default 180 s) with a retryable `timeout` error
and, when the tool kept one, its partial result. Narrow the call, or start the server with a larger `--timeout`.

## Windows SmartScreen or macOS blocks a downloaded archive

The install scripts download with tools that do not mark files as downloaded, so this concerns archives downloaded by
a browser. On Windows, unblock the archive before extracting it (file properties, or `Unblock-File <archive>`). On macOS,
remove the quarantine attribute from the extracted folder: `xattr -dr com.apple.quarantine <folder>`. Check the
archive against the release's `SHA256SUMS` first.

## The install script or update cannot find the release

Check the network and proxy, and that a version given with `--version` is on the releases page. GitHub limits
anonymous API requests per address (60 an hour); set `GITHUB_TOKEN` to raise the limit, then run the script or
`corvus update` again.

## The install script stops with a checksum error

The release's `SHA256SUMS` does not list the archive, or the download does not match it. Run the script again; if it
persists, report it. An offline install verifies a local archive only when `CORVUS_SHA256SUMS` names a manifest
([installation.md](installation.md)).

## Reporting a problem

Include `corvus version`, the OS, the client, the tool and its arguments, and the `status --json` output
with paths you do not want to share removed. Security problems go through the repository's Security tab
([SECURITY.md](../SECURITY.md)).
