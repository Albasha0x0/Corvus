# Troubleshooting

- Start with `corvus status` (alias `doctor`): read-only, it starts each client's entry with its own args and env, and names
  a state and a fix per client. `--client <id>` narrows it; `--json` prints the report.

## The tools do not show up in the client

| Cause | Check | Fix |
|---|---|---|
| client not restarted since `install` | `status --client <id>`: `registered` | restart the client or reload its MCP servers |
| no registration | `status --client <id>`: `not_registered` | `corvus install --client <id>` |
| entry turned off in the client | `status`: `disabled` | turn `corvus` on in the client, or `corvus install --enable` |
| configuration file unreadable | `status`: `config_unreadable` | fix the file, or move it away and run `install` |
| registered program moved or deleted | `status`: `missing_program` | `corvus install --client <id>` |
| server fails with the registered args or env | `status`: `start_failed`, with the error | run the command by hand; fix the args and env |
| client unknown to `install` | `corvus help` lists client ids | add the output of `corvus config` to the client |
| client lists only some tools | `server_status` names the toolsets | remove `--toolsets`, or add the family you need |

- `install` keeps an entry the user turned off as it is, and keeps a backup of a client file as `<file>.corvus.bak`.

## The client runs another copy, an old version or starts slowly

- `other_copy`: the client runs a different program than the one you ran; `corvus install --client <id>` fixes it.
- `relay`: the client runs the dev reload relay; a missing folder is `missing_program`; `install` removes unused copies.
- `stale_catalog`: the server's catalog differs from this build. Restart the client; a server started before an update keeps running the old build.
- `server_status expectedCatalogDigest=<digest>` or `expectedExecutable=<path>` detects a different running copy.
- `slow_start`: a client's start deadline (Codex, Grok Build: 10 s by default) would pass. Set `startup_timeout_sec = 30`
  in the server's table of the client's TOML file; `corvus install --client <id>` sets it.

## A tool says IDA, Python or Ghidra is not available

`corvus status --engine all` (`--deep` also starts IDA's worker) names what is missing and the fix:

- IDA: install IDA 9 with idalib, or set `CORVUS_IDA_DIR`.
- Python for IDA: set `CORVUS_IDA_PYTHON` when the one found is not the one IDA uses.
- Ghidra: `CORVUS_GHIDRA_DIR` (Ghidra 12 or newer) and a JDK (`CORVUS_GHIDRA_JAVA`, `JAVA_HOME` or `PATH`).
- Only `decompile_native`, the engine tools and `engine=ida|ghidra` need an engine. On the command line these errors exit with code 3.

## A result ends with a paging footer, or a call times out

- Each part of a result fits a page of estimated tokens: lists 6,000, code 8,000, bytes 6,000, reports 4,000, edits 3,000.
- `maxTokens` (500 or more) sets the page, up to `CORVUS_MAX_OUTPUT_TOKENS`. Lists return `hasMore` and `nextOffset`;
  continue from `[More: offset=N]`.
- `read_result id=<id>` pages a kept result, searches it (`query=`) or writes it to a file (`outputPath=`). Kept results stay
  on disk 7 days; an evicted id names the call to repeat.
- Read-only calls never fail for size. Narrow the call where you can.
- Claude Code saves results over 50,000 characters to a file unless the tool raises `anthropic/maxResultSizeChars`.
- Tools not marked long-running end after twice `--timeout` (default 180 s) with a retryable `timeout` error and any partial
  result. Narrow the call, or raise `--timeout`.

## An IDA or Ghidra request stops early or opens read-only

- Each engine request gets `CORVUS_ENGINE_REQUEST_TIMEOUT` seconds (default 120); `decompile_native` and
  `resolve_call_targets` take `timeoutSeconds`.
- Start plus auto-analysis gets `CORVUS_ENGINE_OPEN_TIMEOUT` seconds (default 1200). `server_status` reports both.
- A longer analysis is saved as it stands and marked partial; `reanalyze_native` completes it.
- A request that runs out of time or is cancelled stops inside the worker, which keeps the database open. Scans return
  what they found, marked partial, with where to continue.
- A worker that does not stop within 10 s is ended; the next request restarts it from the saved database.
- Huge or malformed inputs: `CORVUS_ENGINE_ANALYSIS=none` opens images without auto-analysis; functions go to a separate database.
- A second server opening an image whose IDA database another process holds gets a read-only snapshot of the last saved
  database, or a conflict naming the owner when none is saved. Limits: [configuration.md](configuration.md#ida-and-ghidra).

## A save or export is refused

- Output paths resolve links, junctions and short names before the check; a link at the target is refused.
- Refused: the data folder outside `exports/`, `corvus.json` or `CORVUS_CONFIG`, the install folder, and files directly
  in a `PATH` folder.
- Refused: `--live-allow` entries, the relay's publish folder, Startup folders, shell profiles and start files, and
  autostart folders.
- Refused: any `.git/` or `.claude/` folder, `~/.gitconfig`, `~/.ssh/`, MCP client configurations, and agent instruction
  and editor task files.
- An unpack skips a refused entry and names it in its notes.

## Install or update fails

- Cannot find the release: check the network, the proxy, and that the `--version` exists on the releases page. GitHub
  allows 60 anonymous API requests an hour per address; set `GITHUB_TOKEN` to raise it.
- Checksum error: `SHA256SUMS` does not list the archive, or the download does not match. Run the script again; report it
  if it stays. An offline install checks a local archive only when `CORVUS_SHA256SUMS` names a manifest
  ([installation.md](installation.md)).
- Windows SmartScreen or macOS blocks the archive: only browser downloads are affected; the install scripts do not mark files.
  Check it against `SHA256SUMS`; `gh attestation verify <archive> --repo Albasha0x0/Corvus` also checks where it was built.
  Windows: `Unblock-File <archive>`. macOS: `xattr -dr com.apple.quarantine <folder>`.

## Reporting a problem

Include `corvus version`, the OS, the client, the tool and its arguments, and `status --json` with private paths removed.
Security problems: the repository's Security tab ([SECURITY.md](../SECURITY.md)).
