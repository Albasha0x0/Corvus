# Installation

Corvus is one program: an MCP server (stdio), setup commands that register it with clients, and a [command line](cli.md).
The release archives need no .NET installation, admin rights or network port.

## Install script

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.ps1 | iex
```

Linux and macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.sh | sh
```

Restart the MCP client afterwards. The script:

1. Downloads the latest release (Windows, Linux glibc or musl, macOS; x64 or arm64) and checks it against `SHA256SUMS`.
   A missing manifest or a mismatch stops the install.
2. Extracts it to `versions/<version>/` under `%LOCALAPPDATA%\Corvus` or `${XDG_DATA_HOME:-~/.local/share}/Corvus`,
   points `current` at it and puts `corvus` on PATH (`~/.local/bin`).
3. Starts the server once and checks the MCP handshake and tool list.
4. Runs `corvus install`: refreshes existing registrations and registers detected clients after one confirmation.

- Installs 1.2.0 and later.
- Dry run: `& ([scriptblock]::Create((irm <url>))) -DryRun` (PowerShell), `curl -fsSL <url> | sh -s -- --dry-run` (sh).
- Piped into `sh`, the confirmation is read from the terminal.

| Option (PowerShell / sh) | Environment | Effect |
|---|---|---|
| `-Version X` / `--version X` | `CORVUS_VERSION` | install release X (pin or roll back) |
| `-DryRun` / `--dry-run` | | show the release, checks, folder and client files; change nothing |
| `-Yes` / `--yes` | `CORVUS_YES=1` | register new clients without asking (needed without a terminal) |
| `-Client a,b` / `--client a,b` | | register only these clients ([ids](#clients)) |
| `-WithLive` / `--with-live` | | install the pinned Frida and turn on `--live-install-frida` ([Frida](live-inspection.md#frida)) |
| `-Uninstall` / `--uninstall` | | run `corvus uninstall`; `-PurgeData` / `--purge-data` deletes data too |
| | `CORVUS_REPO` | download from another repository (`owner/name`) |
| | `GITHUB_TOKEN` | optional token for GitHub API requests (higher rate limit) |
| | `CORVUS_HOME` | install folder (sh only) |
| | `CORVUS_ARCHIVE`, `CORVUS_SHA256SUMS` | offline install from a local archive and manifest |
| | `CORVUS_REQUIRE_ATTESTATION` | `1` refuses an unchecked build; `0` skips the check; also read by `corvus update` |

Offline install: download the archive and `SHA256SUMS` from the release page and set `CORVUS_ARCHIVE` and
`CORVUS_SHA256SUMS`. Without a manifest the archive is trusted as is.

### Verifying a release

- `SHA256SUMS` comes from the same release, so it detects a corrupted download, not a tampered release.
- Every asset has signed SLSA build provenance (Sigstore). With `gh` signed in, the scripts and `corvus update` check it.

| Outcome | When | Result |
|---|---|---|
| `Provenance verified` | `gh` verified the attestation | installs |
| `Provenance not checked (<reason>)` | no `gh`, not signed in or too old, GitHub or Sigstore unreachable | installs; `CORVUS_REQUIRE_ATTESTATION=1` refuses |
| `Provenance check failed` | no attestation from this workflow, another tag, or another `gh` failure | refuses |

A local archive (`CORVUS_ARCHIVE`) follows the same rules. A self-built archive has no attestation: install it with
`CORVUS_REQUIRE_ATTESTATION=0`. Check by hand:

```sh
gh attestation verify corvus-win-x64.zip --repo Albasha0x0/Corvus --signer-workflow Albasha0x0/Corvus/.github/workflows/release.yml
```

Also released, each listed in `SHA256SUMS`: `corvus-sbom.cdx.json` (CycloneDX SBOM of the NuGet packages),
`corvus-tests.json` (test record: commit, date, families, skipped tools, OS, SDK) and `corvus-docs.zip` (this documentation
as a static HTML site).

From source: `./publish.ps1` (`-SelfContained` for a build that needs no .NET), then `publish/corvus install`.

## MCP bundle

- Each release has `corvus-<rid>.mcpb` for win-x64, win-arm64, osx-x64, osx-arm64, linux-x64 and linux-arm64.
- Open it in Claude Desktop (or Settings, Extensions). It runs with `--client claude-desktop` and asks for a tool profile:
  `full` (default), `core` or `lean`.
- Update by installing the next bundle; `corvus update` manages only the script install.

## Claude Code and Codex plugins

```text
/plugin install corvus --marketplace Albasha0x0/Corvus      # Claude Code
codex plugin marketplace add Albasha0x0/Corvus              # Codex, then install corvus from /plugins
```

- The plugin runs `dotnet tool exec CorvusRE@<version> --yes -- --client <client>`; it needs the .NET 10 SDK.
- Update it in the client's plugin manager. If the install script also registered Corvus, remove one entry.

## .NET tool

`CorvusRE` on nuget.org (command `corvus`), for machines with the .NET 10 SDK:

```sh
dotnet tool install -g CorvusRE
corvus install
```

- `dotnet tool exec CorvusRE --yes` (`dnx`) runs it without installing.
- Each release attaches `CorvusRE.<version>.nupkg`. From a clone: `dotnet pack src/Corvus -c Release -o feed`, then
  `--add-source feed`.
- Framework-dependent; the release archives are self-contained.
- `corvus status` names the install kind (`script`, `dotnet-tool`, `dnx`, `source`).

## Scoop and Homebrew

```powershell
scoop bucket add corvus https://github.com/Albasha0x0/scoop-corvus
scoop install corvus/corvus
```

```sh
brew install albasha0x0/corvus/corvus
```

- Both install the release archive, checked against its SHA-256.
- Run `corvus install` afterwards to register clients.
- Update with `scoop update corvus` or `brew upgrade corvus`.

## Container image

`ghcr.io/albasha0x0/corvus:<version>` (and `latest`) for linux/amd64 and linux/arm64 ([Dockerfile](../Dockerfile)): Microsoft's
chiseled runtime-deps base pinned by digest, no shell, non-root user 1654.

```sh
docker run -i --rm --read-only --tmpfs /tmp --network none -v "$PWD:/work:ro" ghcr.io/albasha0x0/corvus
```

- Paths are container paths: a mounted file is `/work/<name>`.
- Caches and kept results go to `/data` (`CORVUS_DATA_DIR`); `-v corvus-data:/data` keeps them.
- IDA, Ghidra, Python and live sessions are not in the image.
- `docker build -f Dockerfile out` packages a published Linux build the same way.

## Registering with clients

`corvus install [client...]` registers the program it runs from. An installed copy registers its stable `current` path,
so updates need no client changes.

- Existing `corvus` entries keep their arguments, env and other keys; only the command and client options change.
- Comments and formatting are kept. Each changed file is backed up once as `<file>.corvus.bak`. An unparseable file is
  left untouched and reported.
- Every entry gets `--client <id>`. Clients that cap the tool count also get `--toolsets lean`, unless the entry sets its own.
- An entry the client turned off stays off. A Codex entry whose `tool_timeout_sec` is not 60 s gets `--client-timeout`.
- When the server check takes over half of the 10 s Codex or Grok Build start wait, `startup_timeout_sec = 30` is set.

| Option | Effect |
|---|---|
| `--client X` | only these clients (repeatable or comma-separated) |
| `--dry-run` | print the plan, write nothing (`--check` also runs the server check) |
| `--json` | plan and result as JSON (needs `--yes` to add clients) |
| `--yes`, `--all-detected` | add detected clients without asking |
| `--strict` | write nothing when any client file cannot be read |
| `--no-check` | skip the server check |
| `--skill` | also write the [agent skill](#the-agent-skill) |
| `--enable` | turn on an entry the client turned off |
| `--set S`, `--unset S` | add or remove a [security switch](configuration.md#security-switches) on every entry |
| `--with-live` | install the pinned Frida and add `--live-install-frida` to every entry |
| `--project DIR` | with `--set` / `--unset`: one folder's Claude Code entry ([examples](configuration.md#claude-code)) |
| `--command PATH` | register this program instead of the running one |
| `--dev-reload DIR` | register the [development reload](#development-reload) relay |

Any other client: add the output of `corvus config` to its MCP settings. `corvus config <client>` prints a listed
client's entry.

## Clients

Supported clients: Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, VS Code Insiders, VSCodium, Cline,
Roo Code, Kilo Code, Visual Studio, Codex, Gemini CLI, Qwen Code, GitHub Copilot CLI, OpenCode, Crush, Zed, LM Studio,
Amazon Q, Kiro, Antigravity, Devin, Command Code, Grok Build, OMP, Pi, Kimi Code, Qoder, Factory Droid, Trae,
CodeBuddy, Hermes and DeepSeek Harness.

Each client's user-level configuration file (`~` home, `%APPDATA%` roaming application data), entry shape, and the
variables that move the file; `-`: not supported.

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
| `kimi-code` | Kimi Code | JSON `mcpServers` | `~/.kimi-code/mcp.json` | `~/.kimi-code/mcp.json` | `~/.kimi-code/mcp.json` | `KIMI_CODE_HOME` | 9,500 tokens; no call limit; full |
| `qoder` | Qoder | JSON `mcpServers` | `~/.qoder/settings.json` | `~/.qoder/settings.json` | `~/.qoder/settings.json` |  | 9,500 tokens; no call limit; full |
| `factory-droid` | Factory Droid | JSON `mcpServers` | `~/.factory/mcp.json` | `~/.factory/mcp.json` | `~/.factory/mcp.json` |  | 9,500 tokens; no call limit; full |
| `trae` | Trae | JSON `mcpServers` | `%APPDATA%/Trae/User/mcp.json` | `~/Library/Application Support/Trae/User/mcp.json` | `~/.config/Trae/User/mcp.json` | `XDG_CONFIG_HOME` | 9,500 tokens; no call limit; full |
| `codebuddy` | CodeBuddy | JSON `mcpServers` | `~/.codebuddy/.mcp.json` | `~/.codebuddy/.mcp.json` | `~/.codebuddy/.mcp.json` |  | 9,500 tokens; no call limit; full |
| `hermes` | Hermes | YAML `mcp_servers` | `%LOCALAPPDATA%/hermes/config.yaml` | `~/.hermes/config.yaml` | `~/.hermes/config.yaml` | `HERMES_DATA_DIR_SUFFIX`, `HERMES_HOME` | 9,500 tokens; no call limit; full |
| `deepseek-harness` | DeepSeek Harness | YAML `insert` row | `~/.dsh/cordis.patch.yml` | `~/.dsh/cordis.patch.yml` | `~/.dsh/cordis.patch.yml` | `DSH_HOME` | 9,500 tokens; no call limit; full |
<!-- clients:end -->

### Client profiles

`--client <id>` sets the client's limits (Limits column above): output size per result, call deadline and default tool
profile (`lean`: the 40 most used tools).

- A call answers 5 s before the client's limit with a `timeout` error; `details.stillRunning` says the work goes on.
- Repeating the same read-only call picks up the running work.
- Without `--client`, the server matches the name the client sends. An unknown client gets 9,500 tokens and no call limit.
- Overrides: `--client-timeout`, `CORVUS_MAX_OUTPUT_TOKENS`, `--toolsets` ([server options](configuration.md#server-options)).

## The agent skill

`install --skill` writes `SKILL.md` and one reference file per guide topic for clients that read skills:

| Clients | Folder |
|---|---|
| Claude Code | `~/.claude/skills/corvus`, or under `CLAUDE_CONFIG_DIR` |
| Codex, Gemini CLI, Cursor, GitHub Copilot CLI, OpenCode, Cline | `~/.agents/skills/corvus` |
| Antigravity | `~/.gemini/config/skills/corvus` |
| Roo Code | `~/.roo/skills/corvus` |
| Kilo Code | `~/.kilocode/skills/corvus` |
| Windsurf, Qwen Code, Crush, Command Code, Pi | `skills/corvus` beside the client's MCP configuration file |

- Optional, since every client receives the server's guidance. The skill does not include the server.
- Folders carry a `.corvus-skill` marker. `install` and `update` keep them current, `status` reports `aligned` or `stale`,
  and `uninstall` removes them. A folder without the marker is never touched.

## Checking an installation

`corvus status` (alias `doctor`) is read-only: it starts each registered command, compares its tool catalog with this
build's, checks the engines and reports skills.

- `--client X`, `--engine ida|python|ghidra|all` (`--deep` starts IDA's worker) and `--target PATH` narrow the check.
- `--json` prints the report. Exit codes: 0 healthy, 1 a failure in scope, 2 usage error.

Symptoms and fixes: [troubleshooting.md](troubleshooting.md).

## Update and uninstall

- `corvus update` installs the latest release (checked against `SHA256SUMS`), refreshes registrations and skills, and
  never adds clients.
- `--version X` installs release X, older ones too, with a warning. `--dry-run` shows what it would use.
- A copy the install scripts did not install is not replaced; `update` names its update command: `dotnet tool update -g CorvusRE`
  for a [.NET tool](#net-tool). If `update` cannot reach the release, run the install script; it takes over the existing install.
- `corvus uninstall` removes the registration from every client (or the named ones), its skill folders and the program
  files. `--keep-files` keeps the program files.
- Data is kept: annotations, caches, symbols and reference packs under `%LOCALAPPDATA%\Corvus` or the local application
  data folder. `--purge-data` deletes it too. `--dry-run` lists what would be removed.

## Configuration

Server options, environment variables and security switches: [configuration.md](configuration.md).

## Development reload

For work on the server itself: `publish/corvus install --dev-reload publish` registers a relay instead of the server.
The client sees each new build without reconnecting.

- The relay runs from a staged copy under `<LocalAppData>/Corvus/relay` (`CORVUS_RELAY_DIR`) and runs the published
  server as a child.
- When a build is stable and no call runs, the relay switches to it, replays the workspace calls that succeeded and sends
  `list_changed`. A build that fails to start keeps the old server.
- Unsaved edits and engine sessions wait until they are saved or reverted; `relay_apply` switches at once.
- A `[relay]` line on the next tool result names the build, its catalog digest and what was replayed.
- Arguments after `relay --target <dir> [--state <dir>] [--poll-ms <n>] [--]` go to the server. A plain `install` switches back.
