# Gate packages in CI or a package proxy

Decide whether an npm or PyPI package may enter a build: pass it, block it, or send it to review. Corvus reviews the
package file and its signed provenance without installing or running anything; the gate reads fields of its JSON.

Tested: Linux (Ubuntu 24.04), jq 1.7.

## Prerequisites

- Corvus ([installation](../installation.md)) and jq.
- The package file: `npm pack <name>@<version>`; a wheel with `pip download <name>==<version> --no-deps --only-binary
  :all: -d pkgs`; an sdist by its URL from `https://pypi.org/pypi/<name>/<version>/json` (`pip download` of an sdist
  runs its build backend to read the metadata).
- Optional: the registry's provenance saved beside it ([provenance](guarddog.md#check-provenance)), GuardDog
  ([GuardDog](guarddog.md)) and the malcontent rule pack (`corvus rules fetch malcontent`).

## Fields

`corvus summarize_file path=<file> view=package --json` writes `{tool, isError, text, structured, error}`. The gate
reads `structured.detail`:

| Field | Values |
|---|---|
| `review` | `noteworthy`, `worth reviewing` or `none`: the strongest finding. |
| `findings[]` | `level`, `category`, `detail`, `path`, `line`: install scripts, network, process and credential access, transformed code, GuardDog rule matches, failed provenance checks. |
| `provenance[]` | `format`, `digest`, `signature`, `chain`, `log`: `verified (...)`, `failed: ...` or `unknown: ...`; `repository`, `commit`, `workflow`, `signer`. |
| `scripts[]` | `name`, `command`, `atInstall`. |

`compare_folders oldPath=<old> newPath=<new> --json` reads two versions: `structured.notes[0]` is the policy line,
`structured.changes[]` the rows (`kind` added or removed, `key` such as `install script: postinstall: node setup.js`,
`endpoint: example.invalid`, `signed provenance: ...`).

## Gate one package

```sh
#!/bin/sh
# gate.sh <package file> [expected source repository]
# Exit 0: pass. 1: block. 2: review.
set -eu
detail=$(corvus summarize_file path="$1" view=package --json | jq '.structured.detail')
review=$(printf '%s' "$detail" | jq -r '.review')
if [ -n "${2:-}" ]; then
  # Require one attestation that verifies on every check and names the expected repository.
  signed=$(printf '%s' "$detail" | jq --arg repo "$2" '[.provenance[]? | select(.repository == $repo
    and (.digest | startswith("verified")) and (.signature == "verified")
    and (.chain | startswith("verified")) and (.log | startswith("verified")))] | length')
  [ "$signed" -gt 0 ] || { echo "block: no verified provenance from $2"; exit 1; }
fi
case "$review" in
  none) echo "pass"; exit 0 ;;
  noteworthy) printf '%s' "$detail" | jq -r '.findings[] | select(.level == "noteworthy") | "block: \(.category): \(.detail)"'; exit 1 ;;
  *) printf '%s' "$detail" | jq -r '.findings[] | "review: \(.category): \(.detail)"'; exit 2 ;;
esac
```

```text
$ ./gate.sh helper-1.0.1.tgz
review: install script: postinstall: node setup.js
review: network: at install: opens network connections
```

## Gate an update

Compare the version in use with the candidate; block what the policy line names:

```sh
corvus compare_folders oldPath=helper-1.0.0.tgz newPath=helper-1.0.1.tgz --json | jq -r '.structured.notes[0], (.structured.changes[]? | "\(.kind) \(.key)")'
```

```text
package policy: review none -> worth reviewing; added: 1 install script(s), 1 endpoint(s), 1 network, process or credential finding(s); removed: nothing
added install script: postinstall: node setup.js
added network: at install: opens network connections
added endpoint: example.invalid
```

A row `removed signed provenance: ...` means the new version is no longer signed by the workflow that signed the old
one.

## Review queue

Exit code 2 goes to a reviewer. An agent connected to Corvus over MCP reads the same package with `summarize_file
view=package`, opens the flagged files with `search_container` and `extract_strings`, and writes its decision back to
the queue; the gate itself never runs package code.
