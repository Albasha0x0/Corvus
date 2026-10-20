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
| | `GITHUB_TOKEN` | Optional token for GitHub API requests (a higher rate limit). |
| | `CORVUS_HOME` | Install folder (sh only). |
| | `CORVUS_ARCHIVE`, `CORVUS_SHA256SUMS` | Offline install from a local archive, checked against a local manifest when one is given. |

With options: `& ([scriptblock]::Create((irm <url>))) -DryRun` in PowerShell, `curl -fsSL <url> | sh -s -- --dry-run`
with sh. Piped into `sh`, the confirmation is read from the terminal.

**Offline install.** Download the archive for your system and `SHA256SUMS` from the release page, then run the script
with `CORVUS_ARCHIVE=<archive>` and `CORVUS_SHA256SUMS=<manifest>`.

**Verifying a release.** Every asset has a signed SLSA build provenance attestation made by the release workflow
(`gh attestation verify corvus-win-x64.zip --repo Albasha0x0/Corvus`), and `corvus-sbom.cdx.json` is the release's
CycloneDX SBOM (the server's NuGet package graph), attested against the archives, bundles and the .NET tool package
(`gh attestation verify <asset> --repo Albasha0x0/Corvus --predicate-type https://cyclonedx.org/bom`). The workflow
pins every action by commit SHA.

**From source.** `./publish.ps1` (add `-SelfContained` for a build that needs no .NET), then
`publish/corvus install`.

If `update` cannot reach the release, run the install script above; it takes over the existing install.

## MCP bundle

Each release also has an MCP bundle per desktop target, `corvus-<rid>.mcpb` (win-x64, win-arm64, osx-x64, osx-arm64,
linux-x64, linux-arm64), listed in `SHA256SUMS` like the archives. Clients that install bundles (Claude Desktop:
open the file, or Settings, Extensions) extract it and run the server inside; the bundle carries the same
self-contained build as the archive, so it needs no .NET. A bundle is updated by installing the next release's
bundle; `corvus update` and the install scripts manage only the script install. The bundle runs with the Claude
Desktop profile (`--client claude-desktop`) and asks for a tool profile: `full` (default), `core` or `lean`.

## Claude Code and Codex plugins

The repository is a plugin marketplace for Claude Code and Codex (`.claude-plugin/marketplace.json`). The `corvus`
plugin registers the server and installs the skill (`skills/corvus`):

```text
/plugin install corvus --marketplace Albasha0x0/Corvus      # Claude Code
codex plugin marketplace add Albasha0x0/Corvus              # Codex, then install corvus from /plugins
```

The plugin runs the .NET tool of its own release, `dotnet tool exec CorvusRE@<version> --yes -- --client <client>`
(`.claude-plugin/plugin.json`, `.codex-plugin/plugin.json`), so it needs the .NET 10 SDK; NuGet downloads and caches the
package on first start. A plugin is updated through the client's plugin manager, not `corvus update`. If Corvus is
also registered by the install script, the client lists two servers: remove one (`corvus uninstall` or the plugin).

## .NET tool

Corvus is also a .NET tool on nuget.org, `CorvusRE` (command `corvus`), for machines with the .NET 10 SDK:

```sh
dotnet tool install -g CorvusRE
corvus install
```

`dotnet tool exec CorvusRE --yes` (`dnx` for short) runs it without installing. Each release also attaches the
package (`CorvusRE.<version>.nupkg`, listed in `SHA256SUMS`); a clone packs one with
`dotnet pack src/Corvus -c Release -o feed`, installed with `--add-source feed`. The tool is framework-dependent and the
same for every platform; the release archives remain the self-contained builds.
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
| `--set S`, `--unset S` | Add or remove a [security switch](configuration.md#security-switches) on every entry (repeatable or comma-separated). |
| `--project DIR` | With `--set` / `--unset`: only this folder's Claude Code local entry, made from the global one when missing ([examples](configuration.md#claude-code)). |
| `--command PATH` | Register this program instead of the running one. |
| `--dev-reload DIR` | Development: register the reload relay ([Development reload](#development-reload)). |

Any other client: add the output of `corvus config` to its MCP settings; `corvus config <client>`
prints the entry for a listed client.

### Client profiles

`--client <id>` tells the server which client runs it, and so its limits (the Limits column below): the most it sends
per result (`maxTokens` asks for more up to this ceiling), how long the client waits for a call, and the default tool
profile (`lean`, the 40 most used tools, for clients that cap the number of tools). A call answers 5 s before the
client's limit, with a `timeout` error whose `details.stillRunning` says the work goes on; the same read-only call made
again picks the running work up instead of starting it over. Without `--client` the server recognizes the client by
the name it sends when it connects; an unrecognized client gets 9,500 tokens and no call limit.

`--client`, `--client-timeout`, `CORVUS_MAX_OUTPUT_TOKENS` and `--toolsets` change these:
[configuration.md](configuration.md#server-options).

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

## Configuration

Server options, environment variables and safety switches: [configuration.md](configuration.md).

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
