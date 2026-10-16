# Installation

Corvus is one self-contained program: an MCP server over stdio, the setup commands that register it with MCP
clients, and a command line that runs every tool ([cli.md](cli.md)). No .NET installation, admin rights or network port
are needed.

## Install script

**Windows** (PowerShell):

```powershell
irm https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.ps1 | iex
```

**Linux / macOS:**

```sh
curl -fsSL https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.sh | sh
```

While the repository is private, the scripts and `update` need a GitHub token with read access in `GITHUB_TOKEN`
(for example `GITHUB_TOKEN=$(gh auth token)`); an anonymous download fails with "not found".

Then restart your MCP client. The script:

1. Downloads the latest release for your system (Windows, Linux glibc / musl, macOS; x64 and arm64) and checks it
   against the release's `SHA256SUMS`; a missing manifest or a mismatch stops the install.
2. Extracts it into a per-user folder (`%LOCALAPPDATA%\Corvus` on Windows, `~/.local/share/Corvus`
   elsewhere) as `versions/<version>/`, points `current` at it and puts `corvus` on PATH.
3. Starts the server once and checks that it answers (MCP handshake and tool list).
4. Runs `corvus install`: existing registrations are refreshed, and detected clients without one are listed
   with each file that would change and registered after one confirmation (Enter = yes). The scripts install
   1.2.0 and later, the releases published as Corvus.

| Script option (PowerShell / sh) | Environment | Effect |
|---|---|---|
| `-Version X` / `--version X` | `CORVUS_VERSION` | Install release X: pin a version or roll back. |
| `-DryRun` / `--dry-run` | | Show the release, the checksum source, the install folder and every client file it would change; change nothing. |
| `-Yes` / `--yes` | `CORVUS_YES=1` | Register new clients without asking (needed when there is no terminal). |
| `-Client a,b` / `--client a,b` | | Register only these clients (ids from the table below). |
| `-Uninstall` / `--uninstall` | | Run `corvus uninstall`; add `-PurgeData` / `--purge-data` to delete your data too. |
| | `CORVUS_REPO` | Download from another repository (`owner/name`). |
| | `GITHUB_TOKEN` | Token for a private repository. |
| | `CORVUS_HOME` | Install folder (sh only). |
| | `CORVUS_ARCHIVE`, `CORVUS_SHA256SUMS` | Offline install from a local archive, checked against a local manifest when one is given. |

With options: `& ([scriptblock]::Create((irm <url>))) -DryRun` in PowerShell, `curl -fsSL <url> | sh -s -- --dry-run`
with sh. Piped into `sh`, the confirmation is read from the terminal.

**Offline install.** Download the archive for your system and `SHA256SUMS` from the release page, then run the script
with `CORVUS_ARCHIVE=<archive>` and `CORVUS_SHA256SUMS=<manifest>`.

**From source.** `./publish.ps1` (add `-SelfContained` for a build that needs no .NET), then
`publish/corvus install`.

If `update` cannot reach the release (a private repository: the old program loses the token on GitHub's redirect to
the renamed repository), run the install script above with `GITHUB_TOKEN` set; it takes over the old install.

## MCP bundle

Each release also has an MCP bundle per desktop target, `corvus-<rid>.mcpb` (win-x64, win-arm64, osx-x64, osx-arm64,
linux-x64, linux-arm64), listed in `SHA256SUMS` like the archives. Clients that install bundles (Claude Desktop:
open the file, or Settings, Extensions) extract it and run the server inside; the bundle carries the same
self-contained build as the archive, so it needs no .NET. A bundle is updated by installing the next release's
bundle; `corvus update` and the install scripts manage only the script install. The bundle runs with the Claude
Desktop profile (`--client claude-desktop`) and asks for a tool profile: `full` (default), `core` or `lean`.

## .NET tool

Corvus is also a NuGet .NET tool, `CorvusRE` (command `corvus`), for machines with the .NET 10 SDK. It is not on
nuget.org yet: download `CorvusRE.<version>.nupkg` from a release (listed in `SHA256SUMS`) into a folder, or pack it
from a clone, and install it from that folder:

```sh
dotnet pack src/Corvus -c Release -o feed
dotnet tool install -g CorvusRE --add-source feed
corvus install
```

`dotnet tool exec CorvusRE --add-source feed --yes` (`dnx` for short) runs it without installing. The tool is
framework-dependent and the same for every platform; the release archives remain the self-contained builds.
`corvus status` names the install kind (`script`, `dotnet-tool`, `dnx`, `source`), and `corvus update` on a
.NET tool names the dotnet command that updates it (`dotnet tool update -g CorvusRE`). The package also carries the
MCP Registry entry (`.mcp/server.json`).

## Registering with clients

`corvus install [client...]` registers the program it is run from (an installed copy registers its stable
`current` path, so updates need no client changes):

- Existing `corvus` entries keep your arguments (for example `--load`), env and other keys; only the command and the
  client options below are set. Only the entry's text changes, so comments and formatting elsewhere in the file are kept. Each changed
  file is backed up once as `<file>.corvus.bak`; a file that cannot be parsed is left untouched and reported.
- Clients without an entry are added after confirmation, or with `--yes` / `--all-detected`.
- An entry the client has turned off (`disabled`, `enabled: false`, a disable list, Claude Code's per-project
  `disabledMcpServers`) is reported and kept off; `--enable` turns it on.
- Every entry gets `--client <id>` ([Client profiles](#client-profiles)); clients that cap the number of tools also get
  `--toolsets lean` unless the entry sets its own `--toolsets`. A Codex entry whose `tool_timeout_sec` differs from
  Codex's 60 s default gets `--client-timeout <seconds>`; install never changes the client's own limits. The one
  exception is the start: when the server check took over half of the 10 s Codex and Grok Build wait for a server,
  their table gets `startup_timeout_sec = 30`.

| Option | Effect |
|---|---|
| `--client X` | Only these clients (repeatable or comma-separated), detected or not. |
| `--dry-run` | Print the plan and write nothing (`--check` also runs the server check). |
| `--json` | Print the plan and the result as JSON (needs `--yes` to add new clients). |
| `--yes`, `--all-detected` | Add detected clients without asking. |
| `--strict` | Write nothing when any client's file cannot be read. |
| `--no-check` | Skip the server check. |
| `--skill` | Also write the agent skill for clients that read skills (below). |
| `--enable` | Turn on an entry the client has turned off. |
| `--command PATH` | Register this program instead of the running one. |
| `--dev-reload DIR` | Development: register the reload relay (README, "Development reload"). |

Any other client: add the output of `corvus config` to its MCP settings; `corvus config <client>`
prints the entry for a listed client.

### Client profiles

`--client <id>` tells the server which client runs it, and so its limits (the Limits column below): the most it sends
per result (`maxTokens` asks for more up to this ceiling), how long the client waits for a call, and the default tool
profile (`lean`, the 40 most used tools, for clients that cap the number of tools). A call answers 5 s before the
client's limit, with a `timeout` error whose `details.stillRunning` says the work goes on; the same read-only call made
again picks the running work up instead of starting it over. Without `--client` the server recognizes the client by
the name it sends when it connects; an unrecognized client gets 9,500 tokens and no call limit.

| Setting | Effect |
|---|---|
| `--client <id>`, `CORVUS_CLIENT` | The client's profile (an id from the table, or `unknown`). |
| `--client-timeout <seconds>`, `CORVUS_CLIENT_TIMEOUT` | The client's per-call limit, when raised from its default. |
| `CORVUS_MAX_OUTPUT_TOKENS` | The output ceiling in place of the client's (500 or more). |
| `--toolsets <list>`, `CORVUS_TOOLSETS` | The tool profile in place of the client's default (`lean`, or families: README, "Server options"). |

### Clients

Where each client keeps its user-level server list (`~` is the home folder, `%APPDATA%` the roaming application data
folder), the shape of the entry, and the environment variables that move the file. `-` means the client is not
supported on that system.

<!-- clients:begin (generated from Setup/ClientCatalog.cs; CORVUS_UPDATE_DOCS=1 updates it) -->
| Id | Client | Entry | Windows | macOS | Linux | Moved by | Limits |
|---|---|---|---|---|---|---|---|
| `claude-code` | Claude Code | JSON `mcpServers` | `~/.claude.json` | `~/.claude.json` | `~/.claude.json` | `CLAUDE_CONFIG_DIR` | 24,000 tokens, 100,000 chars; no call limit; full |
| `claude-desktop` | Claude Desktop | JSON `mcpServers` | `%APPDATA%/Claude/claude_desktop_config.json` | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` | `XDG_CONFIG_HOME` | 24,000 tokens, 140,000 chars; 240 s per call; full |
| `cursor` | Cursor | JSON `mcpServers` | `~/.cursor/mcp.json` | `~/.cursor/mcp.json` | `~/.cursor/mcp.json` |  | 9,500 tokens; no call limit; full |
| `windsurf` | Windsurf | JSON `mcpServers` | `~/.codeium/windsurf/mcp_config.json` | `~/.codeium/windsurf/mcp_config.json` | `~/.codeium/windsurf/mcp_config.json` |  | 9,500 tokens; no call limit; full |
| `vscode` | VS Code | JSON `servers` | `%APPDATA%/Code/User/mcp.json` | `~/Library/Application Support/Code/User/mcp.json` | `~/.config/Code/User/mcp.json` | `XDG_CONFIG_HOME` | 9,500 tokens; no call limit; lean |
| `vscode-insiders` | VS Code Insiders | JSON `servers` | `%APPDATA%/Code - Insiders/User/mcp.json` | `~/Library/Application Support/Code - Insiders/User/mcp.json` | `~/.config/Code - Insiders/User/mcp.json` | `XDG_CONFIG_HOME` | 9,500 tokens; no call limit; lean |
| `vscodium` | VSCodium | JSON `servers` | `%APPDATA%/VSCodium/User/mcp.json` | `~/Library/Application Support/VSCodium/User/mcp.json` | `~/.config/VSCodium/User/mcp.json` | `XDG_CONFIG_HOME` | 9,500 tokens; no call limit; lean |
| `cline` | Cline | JSON `mcpServers` | `%APPDATA%/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | `XDG_CONFIG_HOME` | 9,500 tokens; no call limit; full |
| `roo-code` | Roo Code | JSON `mcpServers` | `%APPDATA%/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json` | `~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json` | `~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json` | `XDG_CONFIG_HOME` | 9,500 tokens; no call limit; full |
| `kilo-code` | Kilo Code | JSON `mcpServers` | `%APPDATA%/Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json` | `~/Library/Application Support/Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json` | `~/.config/Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json` | `XDG_CONFIG_HOME` | 9,500 tokens; no call limit; full |
| `visual-studio` | Visual Studio | JSON `servers` | `~/.mcp.json` | - | - |  | 9,500 tokens; no call limit; lean |
| `codex` | Codex | TOML `[mcp_servers]` | `~/.codex/config.toml` | `~/.codex/config.toml` | `~/.codex/config.toml` | `CODEX_HOME` | 9,500 tokens; 60 s per call; full |
| `gemini-cli` | Gemini CLI | JSON `mcpServers` | `~/.gemini/settings.json` | `~/.gemini/settings.json` | `~/.gemini/settings.json` | `GEMINI_CLI_HOME` | 9,500 tokens, 38,000 chars; 600 s per call; full |
| `qwen-code` | Qwen Code | JSON `mcpServers` | `~/.qwen/settings.json` | `~/.qwen/settings.json` | `~/.qwen/settings.json` | `QWEN_HOME` | 9,500 tokens; no call limit; full |
| `copilot-cli` | GitHub Copilot CLI | JSON `mcpServers` | `~/.copilot/mcp-config.json` | `~/.copilot/mcp-config.json` | `~/.copilot/mcp-config.json` | `COPILOT_HOME` | 9,500 tokens; no call limit; lean |
| `opencode` | OpenCode | JSON `mcp` | `~/.config/opencode/opencode.json` | `~/.config/opencode/opencode.json` | `~/.config/opencode/opencode.json` | `OPENCODE_CONFIG`, `OPENCODE_CONFIG_DIR`, `XDG_CONFIG_HOME` | 9,500 tokens; no call limit; full |
| `crush` | Crush | JSON `mcp` | `~/.config/crush/crush.json` | `~/.config/crush/crush.json` | `~/.config/crush/crush.json` | `XDG_CONFIG_HOME` | 9,500 tokens; no call limit; full |
| `zed` | Zed | JSON `context_servers` | `%APPDATA%/Zed/settings.json` | `~/.config/zed/settings.json` | `~/.config/zed/settings.json` | `XDG_CONFIG_HOME` | 9,500 tokens; no call limit; full |
| `lm-studio` | LM Studio | JSON `mcpServers` | `~/.lmstudio/mcp.json` | `~/.lmstudio/mcp.json` | `~/.lmstudio/mcp.json` |  | 9,500 tokens; no call limit; full |
| `amazon-q` | Amazon Q | JSON `mcpServers` | `~/.aws/amazonq/mcp.json` | `~/.aws/amazonq/mcp.json` | `~/.aws/amazonq/mcp.json` |  | 9,500 tokens; no call limit; full |
| `kiro` | Kiro | JSON `mcpServers` | `~/.kiro/settings/mcp.json` | `~/.kiro/settings/mcp.json` | `~/.kiro/settings/mcp.json` |  | 9,500 tokens; no call limit; full |
| `antigravity` | Antigravity | JSON `mcpServers` | `~/.gemini/antigravity/mcp_config.json` | `~/.gemini/antigravity/mcp_config.json` | `~/.gemini/antigravity/mcp_config.json` |  | 9,500 tokens; no call limit; full |
| `devin` | Devin | JSON `mcpServers` | `%APPDATA%/devin/mcp_config.json` | `~/.config/devin/mcp_config.json` | `~/.config/devin/mcp_config.json` | `XDG_CONFIG_HOME` | 9,500 tokens; no call limit; full |
| `command-code` | Command Code | JSON `mcpServers` | `~/.commandcode/mcp.json` | `~/.commandcode/mcp.json` | `~/.commandcode/mcp.json` |  | 9,500 tokens; no call limit; full |
| `grok-build` | Grok Build | TOML `[mcp_servers]` | `~/.grok/config.toml` | `~/.grok/config.toml` | `~/.grok/config.toml` | `GROK_HOME` | 9,500 tokens; no call limit; full |
| `omp` | OMP | JSON `mcpServers` | `~/.omp/agent/mcp.json` | `~/.omp/agent/mcp.json` | `~/.omp/agent/mcp.json` | `OMP_PROFILE`, `PI_CODING_AGENT_DIR`, `PI_CONFIG_DIR`, `PI_PROFILE` | 9,500 tokens; no call limit; full |
| `pi` | Pi | JSON `mcpServers` | `~/.pi/agent/mcp.json` | `~/.pi/agent/mcp.json` | `~/.pi/agent/mcp.json` | `PI_CODING_AGENT_DIR` | 9,500 tokens; no call limit; full |
<!-- clients:end -->

## The agent skill

`install --skill` also writes a skill (`SKILL.md` and one reference file per guide topic) for clients that read skills:
Claude Code (`~/.claude/skills/corvus`, or under `CLAUDE_CONFIG_DIR`), Codex, Gemini CLI, Cursor, GitHub
Copilot CLI, OpenCode and Cline (`~/.agents/skills/corvus`), Antigravity (`~/.gemini/config/skills/corvus`), Roo Code
(`~/.roo/skills/corvus`), Kilo Code (`~/.kilocode/skills/corvus`), and Windsurf, Qwen Code, Crush, Command Code and Pi
(a `skills/corvus` folder beside the client's MCP configuration file in the table above).
It is generated from the server's own guidance, so it describes only tools the server has, and it tells an agent how to
check the registration and how to use the command line when the tools are not connected. The skill does not include the
server: install the program first.

The skill is optional; the server already sends its guidance to every client. Folders written by install carry a
`.corvus-skill` marker: every later `install` and `update` keeps them current, `status` reports them as
`aligned` or `stale`, and `uninstall` removes them. A folder of the same name without the marker is never touched. The
repository holds the same files in `skills/corvus`.

## Checking an installation

`corvus status` (alias `doctor`) is read-only. It starts each client's registered command with that entry's
own args and env, compares the tool catalog with this build's, checks the engines (IDA, Python, Ghidra) and reports
installed skills. `--client X`, `--engine ida|python|ghidra|all` (`--deep` starts IDA's worker) and `--target PATH`
narrow it, and only what is in scope can fail; `--json` prints the report. Exit codes: 0 healthy, 1 a failure in scope,
2 usage error. Symptoms and fixes: [troubleshooting.md](troubleshooting.md).

## Update

`corvus update` installs the latest release of an installed copy (checked against `SHA256SUMS`) and refreshes
existing registrations and skills; it never adds clients. `--version X` installs release X, also an older one (with a downgrade warning);
`--dry-run` shows the release, asset and checksum manifest it would use. A copy the install scripts did not install
is not replaced; `update` names the command that updates it instead ([.NET tool](#net-tool)).

## Uninstall

`corvus uninstall` removes the registration from every client (or the named ones), removes skill folders it
wrote, and deletes the program files (`--keep-files` keeps them). Your data is kept: annotations, code-index and
analysis caches, downloaded symbols and reference packs under `%LOCALAPPDATA%\Corvus` (Windows) or the local
application data folder. `--purge-data` deletes it as well; `--dry-run` lists what would be removed.

## Environment variables

Server options and their environment variables are in the README ("Server options"). The others:

| Variable | Effect |
|---|---|
| `CORVUS_DATA_DIR` | The per-user data folder (default `<LocalAppData>/Corvus`); the caches and folders below default to entries in it. |
| `CORVUS_YES` | `1`: `install` adds new clients without asking. |
| `CORVUS_REPO` | Repository `update` and the scripts download from (`owner/name`). |
| `CORVUS_RELAY_DIR` | Folder of the development reload relay's staged copies. |
| `CORVUS_OFFLINE` | `1`: never download reference packs, symbols or a runtime DAC. |
| `CORVUS_IDA_DIR`, `CORVUS_IDA_PYTHON` | IDA installation folder and the Python interpreter for idalib (found automatically otherwise). |
| `CORVUS_GHIDRA_DIR`, `CORVUS_GHIDRA_JAVA`, `CORVUS_GHIDRA_ANALYSIS`, `CORVUS_GHIDRA_COMPLETION`, `CORVUS_GHIDRA_MAXMEM`, `CORVUS_GHIDRA_OPTIONS`, `CORVUS_GHIDRA_EXTENSIONS`, `CORVUS_GHIDRA_DECOMPILE_TIMEOUT`, `CORVUS_GHIDRA_DECOMPILE_PAYLOAD_MB` | Ghidra installation, JDK, analysis profile, JVM heap, analyzer options, extension zips and decompiler limits (README, "Server options"). |
| `CORVUS_ENGINE_MEMORY_MB` | Memory limit of each IDA or Ghidra worker in MB (`0` removes it). |
| `CORVUS_ENGINE_ANALYSIS` | `none`: IDA and Ghidra open images without auto-analysis (functions are made where a tool asks), kept in a database or project of their own; default `full`. |
| `CORVUS_ENGINE_REQUEST_TIMEOUT`, `CORVUS_ENGINE_OPEN_TIMEOUT` | Seconds each IDA or Ghidra request may take (default 120) and an engine's start plus auto-analysis (default 1200). |
| `CORVUS_CODE_INDEX_CACHE`, `CORVUS_CODE_INDEX_CACHE_MB`, `CORVUS_CODE_INDEX_CACHE_DAYS` | Folder and bounds of saved native code indexes (`--index-cache`, `--index-cache-mb`, `--index-cache-days`). |
| `CORVUS_ANALYSIS_CACHE` | Folder of saved engine databases (IDA, Ghidra), keyed by file hash. |
| `CORVUS_ANALYSIS_CACHE_MB`, `CORVUS_ANALYSIS_CACHE_DAYS` | Bounds of that folder (default 32768 MB and 60 days unused): after an engine opens an image, entries unused that long, then the least recently used beyond the size, are deleted; an entry open in any server is kept. |
| `CORVUS_ENGINE_OUTPUT_MB` | Bound of the engine output kept in that folder's `engine-output` (default 1024 MB, least recently used first; `0` turns it off): pseudocode and frames with decompiler locals, keyed by the engine build, the input and the database state, so a later server answers them without starting the engine until the database or what the server pushes into it changes. |
| `CORVUS_RESULT_CACHE`, `CORVUS_RESULT_CACHE_MB`, `CORVUS_RESULT_CACHE_DAYS` | Folder of kept results (`read_result` ids; default `results` in the data folder, `off` keeps them in memory only) and its bounds (default 512 MB and 7 days unused). |
| `CORVUS_LOCK_CHECK` | `1`: a tool call that reads a loaded assembly's module or decompiler reader without holding the workspace lock fails (a development check; the test suite turns it on). |
| `CORVUS_MAX_LEFTOVER_CALLS` | Calls cancelled by the client or past their deadline that may still run in the background (default 2); at that many, a new call waits for one to finish until its own deadline, then is refused with a retryable `provider_unavailable` and `details.retryAfterMs`. |
| `CORVUS_MAX_OUTPUT_TOKENS` | Ceiling of a result's text and structured content, each, in estimated tokens; a call's `maxTokens` and the per-class default page stay below it. |
| `CORVUS_RESULT_MODE` | `json`: the text block of a structured result is its compact JSON (the MCP spec's suggestion) instead of readable text. |
| `CORVUS_LOG_FORMAT` | `json`: stderr log entries as JSON lines (each value of the per-call line its own field); single text lines otherwise. |
| `CORVUS_ANNOTATIONS_DIR` | Folder of saved native names, comments and imported name layers. |
| `CORVUS_IL2CPP_CACHE` | Folder of the dummy assemblies made by the built-in Il2Cpp metadata reader. |
| `CORVUS_SYMBOL_CACHE` | Folder of downloaded PDBs and runtime DACs (`open_minidump downloadDac=true`). |
| `CORVUS_DEBUG_DIRS` | Folders (a path list) searched for the separate DWARF of ELF and Mach-O images: `.build-id` trees, `.gnu_debuglink` names, dSYM bundles. |
| `CORVUS_DEBUGINFOD_URLS` | debuginfod servers (space-separated) that `load_pdb download=true` asks for an ELF image's debug file by build-id; `DEBUGINFOD_URLS` when unset; none by default. |
| `CORVUS_CLR32` | Path of the 32-bit .NET decoder (`Corvus.Clr32.exe`) that decodes 32-bit dumps; default `clr32/` beside the server. |
| `CORVUS_DUMP_BUCKET_CACHE` | Folder of the signatures `bucket_minidumps` keeps per dump file, so a re-run parses only new dumps. |
| `CORVUS_AUTO_PDB` | `0`: do not read a matching local PDB, or an ELF or Mach-O image's DWARF, automatically. |
| `CORVUS_AUTO_NATIVEAOT` | `0`: do not name NativeAOT images from their metadata automatically. |
| `CORVUS_AUTO_APPLE_NAMES` | `0`: do not name Mach-O images from their Objective-C and Swift metadata automatically. |
| `CORVUS_DIE` | Detect It Easy's `diec` (the file or its folder) for `unity_overview detectItEasy=true`. |
| `CORVUS_CLEANUP_LOG` | Set: record the decompiler cleanup's rewrite decisions (diagnostics). |

## Development reload

For work on the server itself: `publish/corvus install --dev-reload publish` registers a relay instead of the
server (`config --dev-reload publish` prints it). The relay runs from a staged copy under
`<LocalAppData>/Corvus/relay` (`CORVUS_RELAY_DIR`), speaks MCP to the client and runs the server published in
that folder as a child, itself from a staged copy. Each `./publish.ps1` writes `publish/.build-complete` last; once
it is stable and no call is in flight, the relay starts the new build, repeats the client's `initialize`, replays
the workspace calls that succeeded (`load_assembly`, `unload_assembly`, `add_search_directory`, `load_pdb`,
`unpack_container`, log level, resource subscriptions), switches over and sends `tools`, `prompts` and `resources`
`list_changed`, so the client sees the new build without reconnecting. Clients on the 2026-07-28 protocol (per-request
metadata, no session) are served too: the relay sends the new build `server/discover` with the client's metadata instead
of `initialize`, moves open `subscriptions/listen` streams to it, and sends `list_changed` on the streams that asked for it.
A `[relay]` line on the next tool result names the build, its catalog digest and what was replayed. In-memory edits and native engine sessions are not
carried over: with unsaved edits or patches the switch waits until they are saved or reverted, and the added tool
`relay_apply` switches at once. A build that fails to start or to replay is reported and the old server stays.
Arguments after the relay's own (`relay --target <dir> [--state <dir>] [--poll-ms <n>] [--] ...`) go to the server;
a plain `install` switches the registration back. publish.ps1 renames files of a running server aside
(`*.aside-*`) and deletes them once free.

## Server options

Options go after the command in a client's configuration (`args`), e.g. to preload a folder:
`"args": ["--load", "D:\\App\\App_Data\\Managed"]`.

| Option | Meaning |
|---|---|
| `--load <path>` | Assembly file or folder to load at startup (repeatable). The `CORVUS_LOAD` env var takes `;`-separated paths. |
| `--search-dir <dir>` | Extra directory for resolving references (repeatable). |
| `--max-output <chars>` | Page size for long results (default 60000). |
| `--timeout <seconds>` | Per-call decompilation timeout (default 180; `export_project` gets 10×). Calls to tools not marked long-running end after twice this. |
| `--no-index` | Don't index method bodies and build the call graph in the background after loading. |
| `--no-watch` | Don't watch loaded files or reload them when they change on disk. |
| `--allow-device-changes` | Allow `install_android_package` and `uninstall_android_package`, which change a connected Android device (`CORVUS_ALLOW_DEVICE_CHANGES=1`). Off by default; the other device tools only read. |
| `--allow-live` | Allow the session tools (`live_session`, `live_break`, `live_read`, `live_events`) on programs running on this machine (`CORVUS_ALLOW_LIVE=1`). Off by default. |
| `--allow-live-spawn` | With `--allow-live`, allow `live_session action=spawn`, which starts a program under a session (`CORVUS_ALLOW_LIVE_SPAWN=1`). Off by default. |
| `--ida-scripting` | Allow `ida_python` (arbitrary Python in the IDA worker, with the server's rights; `CORVUS_IDA_SCRIPTING=1`). Off by default. |
| `--ghidra-scripting` | Allow `ghidra_script` (arbitrary Java in the Ghidra worker, with the server's rights; `CORVUS_GHIDRA_SCRIPTING=1`). Off by default. |
| `--engine <auto\|ours\|ida\|ghidra>` | Default engine for the native function, cross-reference and CFG tools, and for `decompile_native` when it names one (default `auto`; `CORVUS_ENGINE`); see Engine preference above. |
| `--prewarm <ida\|ghidra\|auto>` | Analyze each native image in that engine in the background as it loads, one at a time (`auto`: IDA when installed, else Ghidra; `CORVUS_PREWARM`; `--ida-prewarm` / `CORVUS_IDA_PREWARM=1` mean `ida`). Off by default. |
| `--index-cache <dir\|off>` | Where native code indexes are saved (default `<LocalAppData>/Corvus/code-index`; `CORVUS_CODE_INDEX_CACHE`). Entries are keyed by the file's SHA-256 and the build options, so reopening the same bytes loads the index in seconds (msedge.dll, 334 MB: 2.6 s instead of 36 s); changed, damaged or older-format entries are rebuilt. |
| `--index-cache-mb <n>`, `--index-cache-days <n>` | Bounds of that cache (default 8192 MB and 30 days unused; least recently used entries go first; `CORVUS_CODE_INDEX_CACHE_MB` / `_DAYS`). |
| `--binding-style <mono\|hostapi>` | `generate_cpp_binding` style when a call gives none and no host table is detected (default `mono`). |
| `--binding-project <dir>` | Project directory `generate_cpp_binding` scans for a host table when a call gives no `projectDir`. |
| `--toolsets <list>` | Register only a profile or these tool families (`CORVUS_TOOLSETS`), for clients with little context. Profiles: `full` (every tool; also `all`), `core` (at most 100: .NET read and edit, containers, Il2Cpp, native analysis and native edits, the session tools) and `lean` (at most 40: load, find, read, follow and edit for .NET and native, notes, the session basics). Families: `session`, `dotnet`, `containers`, `edit`, `il2cpp`, `native`, `native-edit`, `builds`, `notes`, `engine` (engine status, IDA or Ghidra type, local, frame and declaration edits, `ida_python`, `ghidra_script`), `android`, `dumps` and `live`; a family brings `session` along. Combine names, e.g. `lean,dumps` or `core,builds`. Without the option every tool is registered, and clients that cap tool counts (VS Code, VS Code Insiders, VSCodium, Visual Studio, Copilot CLI) are listed `lean`; a tool left out of a list still answers a call. `server_status` names the families. |
| `--tools-file <file\|readonly\|triage>` | Register only the tools a whitelist names, applied after `--toolsets`; the session tools stay (`CORVUS_TOOLS_FILE`). The file holds tool names separated by spaces, commas or lines, `#` starts a comment; an unknown name stops the server at startup. Built-in lists: `readonly` (every analysis tool that changes nothing and writes no file, without device and live-process tools) and `triage` (a small first-look set). |
| `--log-level <level>` | Stderr log level: `trace`, `debug`, `information` (default), `warning`, `error` or `none` (`CORVUS_LOG_LEVEL`). At `information` and below, every tool call logs one line: `call tool=<name> outcome=<ok or error code> ms=<n> in=<argument characters> out=<result characters> engine=<ida, ghidra or ->`, never the arguments themselves; `CORVUS_LOG_FORMAT=json` writes JSON lines. |
| `--trace <file>` | Append one JSON line per tool call to this file (`CORVUS_TRACE`): time, tool, argument names, milliseconds, error code (`null` when it succeeded) and result characters. Off by default. An engine database path is refused. |
| `--trace-args` | The trace records argument values too (`CORVUS_TRACE_ARGS=1`); they can hold paths and code. Secrets are masked as `[redacted]`: values of parameters named like a password, token, key or cookie, `NAME=value` pairs whose name says password, secret, token or key, Bearer / Basic credentials, passwords in URLs and common token shapes (best effort). |

Logs go to stderr; stdout is reserved for the protocol.

Each IDA or Ghidra worker is capped at three quarters of the memory available to the server (Windows Job Object; `CORVUS_ENGINE_MEMORY_MB`
sets the limit in MB, `0` removes it). A worker that reaches it fails its request with the limit named and restarts on the next one.

Each engine request may take `CORVUS_ENGINE_REQUEST_TIMEOUT` seconds (default 120; `decompile_native` and `resolve_call_targets`
take `timeoutSeconds` per call), and an engine's start plus auto-analysis `CORVUS_ENGINE_OPEN_TIMEOUT` seconds (default 1200).
A request that runs out of time or is cancelled by the client is stopped inside the worker, which keeps the database open:
scans answer with what they found, marked partial with where to continue, and only a worker that does not stop within 10 s
is killed (the next request restarts it from the saved database). `server_status` reports both limits.
For huge or hostile inputs, `CORVUS_ENGINE_ANALYSIS=none` opens images in IDA and Ghidra without auto-analysis: functions are made where a
tool asks for one, the database is kept apart from the fully analyzed one, and output headers say so.
A second server process opening an image whose IDA database another process holds gets a read-only snapshot of the last
saved database (edits are neither journaled nor saved; decompile headers and `server_status` say so), or, when none is
saved yet, a conflict naming the owning process.

Ghidra (12.0 or newer) is found through `CORVUS_GHIDRA_DIR` (else `GHIDRA_INSTALL_DIR`) and a JDK through `CORVUS_GHIDRA_JAVA` (else
`JAVA_HOME`, else `PATH`); the worker is compiled from its embedded sources on first use. `CORVUS_GHIDRA_ANALYSIS` picks the
analysis profile (`standard`, `full` or `minimal`); after a `standard` analysis a background completion pass runs the analyzers
it caps again uncapped, and the stack analysis it leaves to the pass, while the worker is idle, reads continuing beside it, and status then reads `standard→full`
(`CORVUS_GHIDRA_COMPLETION=off` skips it). `CORVUS_GHIDRA_MAXMEM` the JVM heap, `CORVUS_GHIDRA_OPTIONS` extra analyzer
options (`Name=value;...`), and `CORVUS_GHIDRA_EXTENSIONS` a directory of Ghidra extension zips built for that Ghidra (a NativeAOT
analyzer, for example), installed into the workers' private settings; nothing is downloaded. Projects are kept per file hash
and configuration, so a changed profile or extension set analyzes again once. `CORVUS_GHIDRA_DECOMPILE_TIMEOUT` (seconds, default 60)
and `CORVUS_GHIDRA_DECOMPILE_PAYLOAD_MB` (default 200) bound one decompilation; a timeout or an oversized result is retried once
with four times the time and twice the data.

Other external programs are optional and each is found through one variable (a file or its folder), then as listed;
`server_status` reports where each was found, its version, or the fix. They run in their own process tree with a minimal
environment (path, temp, home and Android / Java variables only).

| Variable | Program | Used for |
|---|---|---|
| `CORVUS_JAVA` | `java`, JDK 17+ (else `JAVA_HOME`, else `PATH`) | running the Java decompiler |
| `CORVUS_JAVA_DECOMPILER` | the [jadx-headless-mcp](https://github.com/1013503897/jadx-headless-mcp) fat jar (Apache-2.0), started with `java -jar` | Java / Kotlin source |
| `CORVUS_ADB` | `adb` (else `PATH`, else the Android SDK's `platform-tools`) | the Android device tools |
| `CORVUS_TSHARK` | `tshark` 3+ (else `PATH`, else the default Wireshark folder on Windows and macOS) | `search_container kind=packet` filters naming fields not decoded in-process |
| `CORVUS_AAPT2`, `CORVUS_APKSIGNER`, `CORVUS_DEX_DISASSEMBLER`, `CORVUS_PROTO_COMPILER` | aapt2, the apksigner jar, the baksmali jar, protoc (else the Grpc.Tools package's) | test oracles only |
| `CORVUS_WASM_TO_TEXT`, `CORVUS_WASM_VALIDATOR` | WABT's wasm2wat and wasm-validate | test oracles only |
| `CORVUS_HBC_DISASSEMBLER` | Hermes's hbcdump, or a folder of builds (one per bytecode version) | test oracle only |

Code that targets a .NET version not installed on the machine is read against that version's reference pack, which
is downloaded once from nuget.org into the local app data folder. Set `CORVUS_OFFLINE=1` to never download; such code is
then read against the nearest installed version.
