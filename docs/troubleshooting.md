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

## A result says limit_exceeded, or the text ends with a paging footer

A result over the response limit is kept, and the error names its id: `read_result id=<id>` pages through it (`query=` searches it, `outputPath=` writes it to a file). Kept results stay on disk for 7 days; an evicted id says so and names the call to repeat. A tool
that changes state (an edit, a save) still succeeds: it sends the head of its result and the id. Long
text pages end with a footer naming the next `offset`. Narrow the call where you can (one member instead of a type, a
`limit`, a filter). The page size is the server option `--max-output`. From the command line, whole results are
printed unless `--max-output` is given.

## Claude Code saves a result to a file instead of showing it

Claude Code keeps tool results up to 50,000 characters in context unless the tool raises that limit. Every tool of
this server declares `anthropic/maxResultSizeChars` above its default page, so a default page stays in context. A
larger `maxChars` on a call, or a larger `--max-output`, can pass the client's limit again.

## A call ends with timeout

Calls to tools not marked long-running end after twice `--timeout` (default 180 s) with a retryable `timeout` error
and, when the tool kept one, its partial result. Narrow the call, or start the server with a larger `--timeout`.

## Windows SmartScreen or macOS blocks a downloaded archive

The install scripts download with tools that do not mark files as downloaded, so this concerns archives downloaded by
a browser. On Windows, unblock the archive before unpacking it (file properties, or `Unblock-File <archive>`). On macOS,
remove the quarantine attribute from the unpacked folder: `xattr -dr com.apple.quarantine <folder>`. Check the
archive against the release's `SHA256SUMS` first.

## The install script or update cannot find the release

While the repository is private, downloads need a token with read access: set `GITHUB_TOKEN` (for example
`GITHUB_TOKEN=$(gh auth token)`) and run the script or `corvus update` again.

## The install script stops with a checksum error

The release's `SHA256SUMS` does not list the archive, or the download does not match it. Run the script again; if it
persists, report it. An offline install verifies a local archive only when `CORVUS_SHA256SUMS` names a manifest
([installation.md](installation.md)).

## Reporting a problem

Include `corvus version`, the OS, the client, the tool and its arguments, and the `status --json` output
with paths you do not want to share removed. Security problems go through the repository's Security tab
([SECURITY.md](../SECURITY.md)).
