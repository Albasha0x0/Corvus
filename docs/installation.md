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
2. Unpacks it into a per-user folder (`%LOCALAPPDATA%\Corvus` on Windows, `~/.local/share/Corvus`
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

**Upgrading from NetDecompilerMcp (1.1.0 and earlier).** The project was renamed; nothing needs to be done by hand:

- `NetDecompilerMcp update` reaches the first Corvus release, which moves the program from the old folder
  (`%LOCALAPPDATA%\NetDecompilerMcp`, `~/.local/share/net-decompiler-mcp`) to the one above and puts `corvus` on PATH
  instead. Running the install script above does the same for an old install.
- Every client entry named `net-decompiler` becomes `corvus`, pointing at the new program with its own arguments and
  env; `NDM_*` variables in those entries become `CORVUS_*`. A development relay entry stays a relay for the same
  publish folder. Skill folders written by `install --skill` move from `net-decompiler` to `corvus`.
- On first start the data (annotations, notes, caches, code indexes, engine databases, symbols, relay state) moves
  from the old data folder to the new one; an entry in use is copied and the original kept. Engine databases and
  files saved before the rename (sessions, edit scripts, patch sets, notes) are still read.
- Environment variables are only read under their new names: rename `NDM_*` and `NETDECOMP_LOAD` you set yourself
  to `CORVUS_*` and `CORVUS_LOAD`.

If `update` cannot reach the release (a private repository: the old program loses the token on GitHub's redirect to
the renamed repository), run the install script above with `GITHUB_TOKEN` set; it takes over the old install.

## Registering with clients

`corvus install [client...]` registers the program it is run from (an installed copy registers its stable
`current` path, so updates need no client changes):

- Existing `corvus` entries keep your arguments (for example `--load`), env and other keys; only the command is
  re-pointed. Only the entry's text changes, so comments and formatting elsewhere in the file are kept. Each changed
  file is backed up once as `<file>.corvus.bak`; a file that cannot be parsed is left untouched and reported.
- Clients without an entry are added after confirmation, or with `--yes` / `--all-detected`.
- An entry the client has turned off (`disabled`, `enabled: false`, a disable list) is reported and kept off.

| Option | Effect |
|---|---|
| `--client X` | Only these clients (repeatable or comma-separated), detected or not. |
| `--dry-run` | Print the plan and write nothing (`--check` also runs the server check). |
| `--json` | Print the plan and the result as JSON (needs `--yes` to add new clients). |
| `--yes`, `--all-detected` | Add detected clients without asking. |
| `--strict` | Write nothing when any client's file cannot be read. |
| `--no-check` | Skip the server check. |
| `--skill` | Also write the agent skill for clients that read skills (below). |
| `--command PATH` | Register this program instead of the running one. |
| `--dev-reload DIR` | Development: register the reload relay (README, "Development reload"). |

Any other client: add the output of `corvus config` to its MCP settings; `corvus config <client>`
prints the entry for a listed client.

### Clients

Where each client keeps its user-level server list (`~` is the home folder, `%APPDATA%` the roaming application data
folder), the shape of the entry, and the environment variables that move the file. `-` means the client is not
supported on that system.

<!-- clients:begin (generated from Setup/ClientCatalog.cs; CORVUS_UPDATE_DOCS=1 updates it) -->
| Id | Client | Entry | Windows | macOS | Linux | Moved by |
|---|---|---|---|---|---|---|
| `claude-code` | Claude Code | JSON `mcpServers` | `~/.claude.json` | `~/.claude.json` | `~/.claude.json` | `CLAUDE_CONFIG_DIR` |
| `claude-desktop` | Claude Desktop | JSON `mcpServers` | `%APPDATA%/Claude/claude_desktop_config.json` | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` | `XDG_CONFIG_HOME` |
| `cursor` | Cursor | JSON `mcpServers` | `~/.cursor/mcp.json` | `~/.cursor/mcp.json` | `~/.cursor/mcp.json` |  |
| `windsurf` | Windsurf | JSON `mcpServers` | `~/.codeium/windsurf/mcp_config.json` | `~/.codeium/windsurf/mcp_config.json` | `~/.codeium/windsurf/mcp_config.json` |  |
| `vscode` | VS Code | JSON `servers` | `%APPDATA%/Code/User/mcp.json` | `~/Library/Application Support/Code/User/mcp.json` | `~/.config/Code/User/mcp.json` | `XDG_CONFIG_HOME` |
| `vscode-insiders` | VS Code Insiders | JSON `servers` | `%APPDATA%/Code - Insiders/User/mcp.json` | `~/Library/Application Support/Code - Insiders/User/mcp.json` | `~/.config/Code - Insiders/User/mcp.json` | `XDG_CONFIG_HOME` |
| `vscodium` | VSCodium | JSON `servers` | `%APPDATA%/VSCodium/User/mcp.json` | `~/Library/Application Support/VSCodium/User/mcp.json` | `~/.config/VSCodium/User/mcp.json` | `XDG_CONFIG_HOME` |
| `cline` | Cline | JSON `mcpServers` | `%APPDATA%/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | `XDG_CONFIG_HOME` |
| `roo-code` | Roo Code | JSON `mcpServers` | `%APPDATA%/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json` | `~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json` | `~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json` | `XDG_CONFIG_HOME` |
| `kilo-code` | Kilo Code | JSON `mcpServers` | `%APPDATA%/Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json` | `~/Library/Application Support/Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json` | `~/.config/Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json` | `XDG_CONFIG_HOME` |
| `visual-studio` | Visual Studio | JSON `servers` | `~/.mcp.json` | - | - |  |
| `codex` | Codex | TOML `[mcp_servers]` | `~/.codex/config.toml` | `~/.codex/config.toml` | `~/.codex/config.toml` | `CODEX_HOME` |
| `gemini-cli` | Gemini CLI | JSON `mcpServers` | `~/.gemini/settings.json` | `~/.gemini/settings.json` | `~/.gemini/settings.json` | `GEMINI_CLI_HOME` |
| `qwen-code` | Qwen Code | JSON `mcpServers` | `~/.qwen/settings.json` | `~/.qwen/settings.json` | `~/.qwen/settings.json` | `QWEN_HOME` |
| `copilot-cli` | GitHub Copilot CLI | JSON `mcpServers` | `~/.copilot/mcp-config.json` | `~/.copilot/mcp-config.json` | `~/.copilot/mcp-config.json` | `COPILOT_HOME` |
| `opencode` | OpenCode | JSON `mcp` | `~/.config/opencode/opencode.json` | `~/.config/opencode/opencode.json` | `~/.config/opencode/opencode.json` | `OPENCODE_CONFIG`, `OPENCODE_CONFIG_DIR`, `XDG_CONFIG_HOME` |
| `crush` | Crush | JSON `mcp` | `~/.config/crush/crush.json` | `~/.config/crush/crush.json` | `~/.config/crush/crush.json` | `XDG_CONFIG_HOME` |
| `zed` | Zed | JSON `context_servers` | `%APPDATA%/Zed/settings.json` | `~/.config/zed/settings.json` | `~/.config/zed/settings.json` | `XDG_CONFIG_HOME` |
| `lm-studio` | LM Studio | JSON `mcpServers` | `~/.lmstudio/mcp.json` | `~/.lmstudio/mcp.json` | `~/.lmstudio/mcp.json` |  |
| `amazon-q` | Amazon Q | JSON `mcpServers` | `~/.aws/amazonq/mcp.json` | `~/.aws/amazonq/mcp.json` | `~/.aws/amazonq/mcp.json` |  |
| `kiro` | Kiro | JSON `mcpServers` | `~/.kiro/settings/mcp.json` | `~/.kiro/settings/mcp.json` | `~/.kiro/settings/mcp.json` |  |
| `antigravity` | Antigravity | JSON `mcpServers` | `~/.gemini/antigravity/mcp_config.json` | `~/.gemini/antigravity/mcp_config.json` | `~/.gemini/antigravity/mcp_config.json` |  |
| `devin` | Devin | JSON `mcpServers` | `%APPDATA%/devin/mcp_config.json` | `~/.config/devin/mcp_config.json` | `~/.config/devin/mcp_config.json` | `XDG_CONFIG_HOME` |
| `command-code` | Command Code | JSON `mcpServers` | `~/.commandcode/mcp.json` | `~/.commandcode/mcp.json` | `~/.commandcode/mcp.json` |  |
| `grok-build` | Grok Build | TOML `[mcp_servers]` | `~/.grok/config.toml` | `~/.grok/config.toml` | `~/.grok/config.toml` | `GROK_HOME` |
| `omp` | OMP | JSON `mcpServers` | `~/.omp/agent/mcp.json` | `~/.omp/agent/mcp.json` | `~/.omp/agent/mcp.json` | `OMP_PROFILE`, `PI_CODING_AGENT_DIR`, `PI_CONFIG_DIR`, `PI_PROFILE` |
| `pi` | Pi | JSON `mcpServers` | `~/.pi/agent/mcp.json` | `~/.pi/agent/mcp.json` | `~/.pi/agent/mcp.json` | `PI_CODING_AGENT_DIR` |
<!-- clients:end -->

## The agent skill

`install --skill` also writes a skill (`SKILL.md` and one reference file per guide topic) for clients that read skills:
Claude Code (`~/.claude/skills/corvus`, or under `CLAUDE_CONFIG_DIR`), Codex, Gemini CLI, Cursor, GitHub
Copilot CLI and OpenCode (`~/.agents/skills/corvus`), and Antigravity (`~/.gemini/config/skills/corvus`).
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
existing registrations and skills; it never adds clients. `--version X` installs release X, also an older one;
`--dry-run` shows the release, asset and checksum manifest it would use.

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
| `CORVUS_GHIDRA_DIR`, `CORVUS_GHIDRA_JAVA`, `CORVUS_GHIDRA_ANALYSIS`, `CORVUS_GHIDRA_MAXMEM`, `CORVUS_GHIDRA_OPTIONS`, `CORVUS_GHIDRA_EXTENSIONS`, `CORVUS_GHIDRA_DECOMPILE_TIMEOUT`, `CORVUS_GHIDRA_DECOMPILE_PAYLOAD_MB` | Ghidra installation, JDK, analysis profile, JVM heap, analyzer options, extension zips and decompiler limits (README, "Server options"). |
| `CORVUS_ENGINE_MEMORY_MB` | Memory limit of each IDA or Ghidra worker in MB (`0` removes it). |
| `CORVUS_ENGINE_ANALYSIS` | `none`: IDA and Ghidra open images without auto-analysis (functions are made where a tool asks), kept in a database or project of their own; default `full`. |
| `CORVUS_ENGINE_REQUEST_TIMEOUT`, `CORVUS_ENGINE_OPEN_TIMEOUT` | Seconds each IDA or Ghidra request may take (default 120) and an engine's start plus auto-analysis (default 1200). |
| `CORVUS_CODE_INDEX_CACHE`, `CORVUS_CODE_INDEX_CACHE_MB`, `CORVUS_CODE_INDEX_CACHE_DAYS` | Folder and bounds of saved native code indexes (`--index-cache`, `--index-cache-mb`, `--index-cache-days`). |
| `CORVUS_ANALYSIS_CACHE` | Folder of saved engine databases (IDA, Ghidra), keyed by file hash. |
| `CORVUS_ANNOTATIONS_DIR` | Folder of saved native names, comments and imported name layers. |
| `CORVUS_IL2CPP_CACHE` | Folder of the dummy assemblies made by the built-in Il2Cpp metadata reader. |
| `CORVUS_SYMBOL_CACHE` | Folder of downloaded PDBs and runtime DACs (`open_minidump downloadDac=true`). |
| `CORVUS_CLR32` | Path of the 32-bit .NET decoder (`Corvus.Clr32.exe`) that decodes 32-bit dumps; default `clr32/` beside the server. |
| `CORVUS_DUMP_BUCKET_CACHE` | Folder of the signatures `bucket_minidumps` keeps per dump file, so a re-run parses only new dumps. |
| `CORVUS_AUTO_PDB` | `0`: do not read a matching local PDB automatically. |
| `CORVUS_AUTO_NATIVEAOT` | `0`: do not name NativeAOT images from their metadata automatically. |
| `CORVUS_DIE` | Detect It Easy's `diec` (the file or its folder) for `unity_overview detectItEasy=true`. |
| `CORVUS_CLEANUP_LOG` | Set: record the decompiler cleanup's rewrite decisions (diagnostics). |
