# Gate packages in CI or a package proxy

Pass, block or send to review an npm or PyPI package before it enters a build. Corvus reads the package and its signed provenance without installing or running anything.

Requires Corvus ([installation](../installation.md)), jq 1.7, a POSIX shell, and the package file (`npm pack <name>@<version>`, or `pip download <name>==<version> --no-deps --only-binary :all: -d pkgs`).

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

```sh
corvus compare_folders oldPath=helper-1.0.0.tgz newPath=helper-1.0.1.tgz --json | jq -r '.structured.notes[0]'
```

```text
package policy: review none -> worth reviewing; added: 1 install script(s), 1 endpoint(s), 1 network, process or credential finding(s); removed: nothing
```
