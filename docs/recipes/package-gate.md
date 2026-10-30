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

## Gate a dependency pull request

Read the packages a pull request changes, fail the check on a noteworthy finding and report findings in code scanning.

- `--fail-on noteworthy` exits 1 when a finding reaches the level.
- `--baseline known.json` drops reviewed findings by `key` ([baseline file](../cli.md)).
- `known.json` is committed to the repository; the check refuses a missing file, so start from `{"schema": "corvus.baseline/1", "entries": []}`.
- `--sarif corvus.sarif` writes the findings for code scanning.
- `npm ci --ignore-scripts` installs without running package scripts.

The analysis job has no token and no secrets. A separate job holds `security-events: write` and uploads the SARIF it receives as an artifact.

```yaml
name: package-gate
on: pull_request
permissions: {}
jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Install Corvus
        run: curl -fsSL https://github.com/Albasha0x0/Corvus/releases/latest/download/install.sh | sh
      - name: Pack the changed packages
        env:
          BASE: origin/${{ github.base_ref }}
        run: |
          list() { jq -r '.packages | to_entries[] | select(.key != "") | "\(.key | sub(".*node_modules/"; ""))@\(.value.version)"' | sort -u; }
          git show "$BASE:package-lock.json" | list > base.txt
          list < package-lock.json > head.txt
          npm ci --ignore-scripts
          mkdir pkgs
          comm -13 base.txt head.txt | xargs -r npm pack --pack-destination pkgs
      - name: Gate
        run: corvus batch --file pkgs --recurse --fail-on noteworthy --baseline known.json --sarif corvus.sarif
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        if: always()
        with:
          name: sarif
          path: corvus.sarif
  upload:
    needs: analyze
    if: always() && github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: sarif
      - uses: github/codeql-action/upload-sarif@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1
        with:
          sarif_file: corvus.sarif
```
