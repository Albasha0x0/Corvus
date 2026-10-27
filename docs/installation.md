# Installation

Corvus is one self-contained program: the MCP server (stdio), setup commands that register it with clients, and a
[command line](cli.md). It needs no .NET installation, admin rights or network port.

## Install script

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.ps1 | iex
```

Linux and macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.sh | sh
```

Then restart the MCP client. The script:

1. Downloads the latest release for the system (Windows, Linux glibc / musl, macOS; x64 and arm64) and checks it
   against `SHA256SUMS`; a missing manifest or a mismatch stops the install. With `gh` it also checks build provenance.
2. Extracts it to `versions/<version>/` in a per-user folder (`%LOCALAPPDATA%\Corvus`, or
   `${XDG_DATA_HOME:-~/.local/share}/Corvus`), points `current` at it and puts `corvus` on PATH (`~/.local/bin`).
3. Starts the server once and checks the MCP handshake and tool list.
4. Runs `corvus install`: refreshes existing registrations, lists detected clients and registers them after one
   confirmation.

- The scripts install 1.2.0 and later.
- Options: `& ([scriptblock]::Create((irm <url>))) -DryRun` in PowerShell, `curl -fsSL <url> | sh -s -- --dry-run`.
- Piped into `sh`, the confirmation is read from the terminal.

| Option (PowerShell / sh) | Environment | Effect |
|---|---|---|
| `-Version X` / `--version X` | `CORVUS_VERSION` | install release X (pin or roll back) |
| `-DryRun` / `--dry-run` | | show the release, checks, folder and client files; change nothing |
| `-Yes` / `--yes` | `CORVUS_YES=1` | register new clients without asking (needed without a terminal) |
| `-Client a,b` / `--client a,b` | | register only these clients ([ids](#clients)) |
| `-WithLive` / `--with-live` | | install the tested Frida and turn on `--live-install-frida` ([Frida](live-inspection.md#frida)) |
| `-Uninstall` / `--uninstall` | | run `corvus uninstall`; `-PurgeData` / `--purge-data` deletes data too |
| | `CORVUS_REPO` | download from another repository (`owner/name`) |
| | `GITHUB_TOKEN` | optional token for GitHub API requests (higher rate limit) |
| | `CORVUS_HOME` | install folder (sh only) |
| | `CORVUS_ARCHIVE`, `CORVUS_SHA256SUMS` | offline install from a local archive and manifest |
| | `CORVUS_REQUIRE_ATTESTATION` | `1` refuses an unchecked build; `0` skips the check; also read by `corvus update` |

Offline install: download the archive and `SHA256SUMS` from the release page, then set `CORVUS_ARCHIVE` and
`CORVUS_SHA256SUMS`. Without a manifest the archive is trusted as is.

### Verifying a release

- `SHA256SUMS` comes from the same release, so it catches a corrupted download, not a tampered release.
- Every asset carries signed SLSA build provenance (Sigstore) from the release workflow.
- With `gh` signed in (`gh auth login`, `GH_TOKEN` or `GITHUB_TOKEN`), the scripts and `corvus update` verify that the
  archive was built by this repository's `release.yml`, from the requested tag when one is known.

| Outcome | When | Result |
|---|---|---|
| `Provenance verified` | `gh` verified the attestation | installs |
| `Provenance not checked (<reason>)` | no `gh`, `gh` not signed in or too old, GitHub or Sigstore unreachable | installs; `CORVUS_REQUIRE_ATTESTATION=1` refuses |
| `Provenance check failed` | no attestation from this workflow, another tag, or another `gh` failure | refuses |

A local archive (`CORVUS_ARCHIVE`) follows the same rules; a self-built one has no attestation: install it with `CORVUS_REQUIRE_ATTESTATION=0`. The same check by hand:

```sh
gh attestation verify corvus-win-x64.zip --repo Albasha0x0/Corvus --signer-workflow Albasha0x0/Corvus/.github/workflows/release.yml
```

Other release assets, each in `SHA256SUMS` and covered by provenance:

- `corvus-sbom.cdx.json`: CycloneDX SBOM of the server's NuGet packages (`--predicate-type https://cyclonedx.org/bom`).
- `corvus-tests.json`: the full test pass the release shipped on (commit, date, families, skipped tools, OS, SDK).
- `corvus-docs.zip`: this documentation as a static HTML site.

From source: `./publish.ps1` (`-SelfContained` for a build that needs no .NET), then `publish/corvus install`.

If `update` cannot reach the release, run the install script; it takes over the existing install.

## MCP bundle

- Each release has `corvus-<rid>.mcpb` for win-x64, win-arm64, osx-x64, osx-arm64, linux-x64 and linux-arm64.
- Clients that install bundles (Claude Desktop: open the file, or Settings, Extensions) extract and run it.
- It runs with `--client claude-desktop` and asks for a tool profile: `full` (default), `core` or `lean`.
- Update it by installing the next bundle; `corvus update` manages only the script install.

## Claude Code and Codex plugins

The repository is a plugin marketplace (`.claude-plugin/marketplace.json`). The `corvus` plugin registers the server
and installs the skill:

```text
/plugin install corvus --marketplace Albasha0x0/Corvus      # Claude Code
codex plugin marketplace add Albasha0x0/Corvus              # Codex, then install corvus from /plugins
```

- It runs `dotnet tool exec CorvusRE@<version> --yes -- --client <client>`, so it needs the .NET 10 SDK.
- Update it through the client's plugin manager, not `corvus update`.
- If the install script also registered Corvus, remove one of the two entries.

## .NET tool

`CorvusRE` on nuget.org (command `corvus`), for machines with the .NET 10 SDK:

```sh
dotnet tool install -g CorvusRE
corvus install
```

- `dotnet tool exec CorvusRE --yes` (`dnx`) runs it without installing.
- Each release attaches `CorvusRE.<version>.nupkg`. From a clone: `dotnet pack src/Corvus -c Release -o feed`, then
  install with `--add-source feed`.
- The tool is framework-dependent; the release archives are the self-contained builds.
- `corvus status` names the install kind (`script`, `dotnet-tool`, `dnx`, `source`); on a .NET tool `corvus update`
  names the update command (`dotnet tool update -g CorvusRE`).

## Container image

`ghcr.io/albasha0x0/corvus:<version>` (and `latest`) for linux/amd64 and linux/arm64 ([Dockerfile](../Dockerfile)):
Microsoft's chiseled runtime-deps image pinned by digest, no shell, non-root user 1654.

```sh
docker run -i --rm --read-only --tmpfs /tmp --network none -v "$PWD:/work:ro" ghcr.io/albasha0x0/corvus
```

- Paths are container paths: a mounted file is `/work/<name>`.
- Caches and kept results go to `/data` (`CORVUS_DATA_DIR`); `-v corvus-data:/data` keeps them.
- IDA, Ghidra, Python and live sessions are not in the image.
- `docker build -f Dockerfile out` packages a published Linux build the same way.

## Registering with clients

`corvus install [client...]` registers the program it runs from; an installed copy registers its stable `current`
path, so updates need no client changes.

- Existing `corvus` entries keep their arguments, env and other keys; only the command and client options change.
- Comments and formatting elsewhere are kept; each changed file is backed up once as `<file>.corvus.bak`.
- A file that cannot be parsed is left untouched and reported.
- New clients are added after confirmation, or with `--yes` / `--all-detected`.
- An entry the client turned off stays off; `--enable` turns it on.
- Every entry gets `--client <id>`; clients that cap the tool count also get `--toolsets lean`, unless the entry sets its own.
- A Codex entry whose `tool_timeout_sec` differs from 60 s gets `--client-timeout <seconds>`.
- Install never changes a client's own limits, with one exception: when the server check takes over half of the 10 s
  Codex and Grok Build wait for a start, their table gets `startup_timeout_sec = 30`.

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
| `--with-live` | install the tested Frida and add `--live-install-frida` to every entry |
| `--project DIR` | with `--set` / `--unset`: one folder's Claude Code entry ([examples](configuration.md#claude-code)) |
| `--command PATH` | register this program instead of the running one |
| `--dev-reload DIR` | register the [development reload](#development-reload) relay |

Any other client: add the output of `corvus config` to its MCP settings; `corvus config <client>` prints a listed
client's entry.

### Client profiles

`--client <id>` sets the client's limits (Limits column below): the most sent per result, the call deadline and the
default tool profile (`lean`: the 40 most used tools).

- A call answers 5 s before the client's limit with a `timeout` error; `details.stillRunning` says the work goes on.
- Repeating the same read-only call picks up the running work.
- Without `--client`, the server matches the name the client sends; an unknown client gets 9,500 tokens and no call
  limit.
- Overrides: `--client`, `--client-timeout`, `CORVUS_MAX_OUTPUT_TOKENS`, `--toolsets`
  ([server options](configuration.md#server-options)).

### Clients

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

- Generated from the server's guidance; optional, since every client receives that guidance.
- It does not include the server: install the program first.
- Folders it writes carry a `.corvus-skill` marker: `install` and `update` keep them current, `status` reports them
  `aligned` or `stale`, `uninstall` removes them. A folder without the marker is never touched.
- The repository holds the same files in `skills/corvus`.

## Checking an installation

`corvus status` (alias `doctor`) is read-only: it starts each registered command, compares its tool catalog with this
build's, checks the engines and reports skills.

- `--client X`, `--engine ida|python|ghidra|all` (`--deep` starts IDA's worker) and `--target PATH` narrow it; only what is in scope can fail.
- `--json` prints the report.
- Exit codes: 0 healthy, 1 a failure in scope, 2 usage error.

Symptoms and fixes: [troubleshooting.md](troubleshooting.md).

## Update

- `corvus update` installs the latest release (checked against `SHA256SUMS`) and refreshes registrations and skills;
  it never adds clients.
- `--version X` installs release X, older ones too, with a warning; `--dry-run` shows what it would use.
- A copy the install scripts did not install is not replaced; `update` names its update command ([.NET tool](#net-tool)).

## Uninstall

- `corvus uninstall` removes the registration from every client (or the named ones), its skill folders and the
  program files (`--keep-files` keeps them).
- Data is kept: annotations, caches, symbols and reference packs under `%LOCALAPPDATA%\Corvus` or the local application
  data folder.
- `--purge-data` deletes the data too; `--dry-run` lists what would be removed.

## Configuration

Server options, environment variables and security switches: [configuration.md](configuration.md).

## Development reload

For work on the server itself: `publish/corvus install --dev-reload publish` registers a relay instead of the server
(`config --dev-reload publish` prints it). The client sees each new build without reconnecting.

- The relay runs from a staged copy under `<LocalAppData>/Corvus/relay` (`CORVUS_RELAY_DIR`) and runs the published
  server as a child.
- `./publish.ps1` writes `publish/.build-complete` last. When it is stable and no call runs, the relay starts the new
  build, replays the workspace calls that succeeded, switches over and sends `list_changed`.
- On the 2026-07-28 protocol the relay sends `server/discover` instead of `initialize` and moves open
  `subscriptions/listen` streams.
- A `[relay]` line on the next tool result names the build, its catalog digest and what was replayed.
- Unsaved edits and engine sessions are not carried over: the switch waits until they are saved or reverted;
  `relay_apply` switches at once. A build that fails to start keeps the old server.
- Arguments after `relay --target <dir> [--state <dir>] [--poll-ms <n>] [--]` go to the server.
- A plain `install` switches the registration back.
- `publish.ps1` renames a running server's files aside (`*.aside-*`) and deletes them once free.
