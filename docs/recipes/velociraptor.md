# Scan collected files with a Velociraptor artifact

Run Corvus's file batch on each file a Velociraptor collection matches: one row per file, with the `corvus.batch/1`
document as a column. The batch runs read-only steps; nothing in the file runs and Corvus makes no network request
([file batch](../cli.md#file-batch)).

Tested: Velociraptor 0.77.3 (local collection), Corvus 2.5.1; Linux (Ubuntu 24.04) and Windows.

## Prerequisites

- Corvus on each endpoint, at the path the artifact names ([installation](../installation.md)).
- Velociraptor 0.77.3 ([release](https://github.com/Velocidex/velociraptor/releases/tag/v0.77.3)).

## Command per file

```sh
corvus batch --file <path> --json --time-limit 120
```

Exit code 0 when the document is written; 124 when the time limit ended the run (document still written). `complete`
and each section's `status` say what was read.

## Artifact

Save as `Custom.Corvus.FileBatch.yaml`:

```yaml
name: Custom.Corvus.FileBatch
description: Runs corvus batch --file --json on each matched file and returns its corvus.batch/1 document.
type: CLIENT
parameters:
  - name: Glob
    default: C:\Users\*\Downloads\*.exe
  - name: CorvusPath
    default: C:\Users\Public\corvus\corvus.exe
  - name: TimeLimit
    default: "120"
sources:
  - query: |
      LET files = SELECT OSPath, Size FROM glob(globs=Glob) WHERE NOT IsDir
      SELECT * FROM foreach(row=files, query={
        SELECT OSPath, Size, ReturnCode, parse_json(data=Stdout) AS Batch
        FROM execve(argv=[CorvusPath, "batch", "--file", OSPath, "--json", "--time-limit", TimeLimit],
                    length=100000000)
        WHERE Stdout
      })
```

On Linux, set `Glob` and `CorvusPath` at collection time. `length` keeps each document in one row; piped output is one
line.

## Collect on one machine

```sh
velociraptor --definitions . artifacts collect Custom.Corvus.FileBatch --args Glob='/srv/inbox/*' --args CorvusPath=/usr/local/bin/corvus --format json
```

Each row:

```json
{"OSPath": "/srv/inbox/app.zip", "Size": 120, "ReturnCode": 0,
 "Batch": {"schema": "corvus.batch/1", "file": {"sha256": "...", "type": "zip"}, "complete": true, "sections": [...]}}
```

A Velociraptor server can hunt the same artifact across endpoints (not run for this page).
