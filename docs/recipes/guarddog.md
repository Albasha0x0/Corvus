# Review packages with GuardDog's rules

Review an npm or PyPI package with GuardDog's rule matches beside Corvus's findings. Nothing in the package runs.

Requires Corvus ([installation](../installation.md)) and GuardDog 3.2.0 on Linux (`uv tool install guarddog==3.2.0`). GuardDog does not build on Windows; use WSL there. Corvus finds GuardDog on `PATH` or through `CORVUS_GUARDDOG`.

## Review a package

```sh
CORVUS_GUARDDOG=~/guarddog-venv/bin/guarddog corvus summarize_file path=helper-1.0.1.tgz view=package
```

```text
review: noteworthy
  noteworthy  rule match  GuardDog threat-process-download-exec: Detects download-and-execute patterns: ... (exec("curl)  package/setup.js      1
  review      rule match  GuardDog capability-process-spawn: Detects process execution and spawning (exec(")  package/setup.js      1
```

A GuardDog that fails or times out (3 minutes) is named in the notes, and its rules are not checked.

## Check provenance

```sh
curl -sS https://registry.npmjs.org/-/npm/v1/attestations/helper@1.0.1 -o helper-1.0.1.tgz.attestations.json
```

```text
Provenance (npm attestations): digest verified (sha512), signature verified, chain verified (sigstore, at 2025-02-04 20:35:47Z),
  log verified (https://rekor.sigstore.dev, index 168704762); built from https://github.com/example/helper at 06cd267cbdc2.
```

A failed digest, signature, chain or log check is a noteworthy finding. For PyPI, save the wheel's `/integrity/.../provenance` document the same way; a Sigstore bundle (`<file>.sigstore.json`) works too.

## Review an update

```sh
corvus compare_folders oldPath=helper-1.0.0.tgz newPath=helper-1.0.1.tgz
```

## Many packages

```sh
for f in pkgs/*; do corvus summarize_file path="$f" view=package --json > "$f.corvus.json"; done
```
