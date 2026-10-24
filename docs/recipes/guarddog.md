# Review packages with GuardDog's rules

Review an npm or PyPI package before installing it, with GuardDog's rule matches beside Corvus's own findings in one
report. Nothing in the package runs.

Tested: GuardDog 3.2.0 on Linux (Ubuntu 24.04). GuardDog does not build on Windows (its rule engine and sandbox are
Unix-only); there, run Corvus under WSL or use the GuardDog container image and read its JSON yourself.

## Prerequisites

- Corvus ([installation](../installation.md)).
- GuardDog 3.2.0: `uv tool install guarddog==3.2.0`, `pipx install guarddog==3.2.0`, or a venv of its own. Corvus finds
  it on `PATH`, or set `CORVUS_GUARDDOG` to the program.
- The package files: `npm pack <name>@<version>`; a wheel with `pip download <name>==<version> --no-deps --only-binary
  :all: -d pkgs`; an sdist by its URL from `https://pypi.org/pypi/<name>/<version>/json` (`pip download` of an sdist
  runs its build backend to read the metadata). A source folder of the package works too.

## Review a package

```sh
CORVUS_GUARDDOG=~/guarddog-venv/bin/guarddog corvus summarize_file path=helper-1.0.1.tgz view=package
```

```text
review: noteworthy
  noteworthy  rule match  GuardDog threat-process-download-exec: Detects download-and-execute patterns: ... (exec("curl)  package/setup.js      1
  noteworthy  rule match  GuardDog threat-process-hooks: Detects LOLBAS usage in install hooks ... ("postinstall":"node setup.js)  package/package.json  1
  review      rule match  GuardDog capability-process-spawn: Detects process execution and spawning (exec(")  package/setup.js      1
notes: GuardDog 3.2.0: 5 rule match(es)
```

GuardDog's `threat-*` rules are noteworthy and its other rules worth reviewing; each match keeps its file and line. The
same report lists the install scripts and what their code reaches, entry points, native binaries and names close to
popular packages. A GuardDog that fails or times out (3 minutes) is named in the notes, and its rules are not checked.

## Check provenance

Save the registry's provenance beside the package file, and the same review checks it offline:

```sh
curl -sS https://registry.npmjs.org/-/npm/v1/attestations/helper@1.0.1 -o helper-1.0.1.tgz.attestations.json
curl -sS https://pypi.org/integrity/helper/1.0.1/helper-1.0.1-py3-none-any.whl/provenance -o helper-1.0.1-py3-none-any.whl.provenance
```

```text
Provenance (npm attestations): digest verified (sha512), signature verified, chain verified (sigstore, at 2025-02-04 20:35:47Z),
  log verified (https://rekor.sigstore.dev, index 168704762); built from https://github.com/example/helper at 06cd267cbdc2.
```

A Sigstore bundle (`<file>.sigstore.json`) works the same way. A digest, signature, chain or log check that fails is a
noteworthy finding; a check that could not run says why.

## Review an update

```sh
corvus compare_folders oldPath=helper-1.0.0.tgz newPath=helper-1.0.1.tgz
```

The first note is the policy summary: the review level before and after, then the install scripts, endpoints, native
files, permissions, runs on open, signed provenance, and GuardDog rule matches added and removed. A version that no
longer carries signed provenance shows it as removed.

## Many packages

```sh
for f in pkgs/*; do corvus summarize_file path="$f" view=package --json > "$f.corvus.json"; done
```

`--json` writes `{tool, isError, text, structured, error}`; `structured` is the summary record
([output](../cli.md#output)).
