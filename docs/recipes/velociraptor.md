# Scan collected files with a Velociraptor artifact

Run Corvus's file batch on each file a Velociraptor collection matches: one row per file, with the `corvus.batch/1` document as a column. Nothing in the file runs and Corvus makes no network request ([file batch](../cli.md#file-batch)).

Requires:

- Velociraptor 0.77.3 ([release](https://github.com/Velocidex/velociraptor/releases/tag/v0.77.3)).
- Corvus 2.5.1 on each endpoint, at the path the artifact names ([installation](../installation.md)), in a folder only administrators can write: the client runs it as SYSTEM.

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
    default: C:\Program Files\Corvus\corvus.exe
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

On Linux, set `Glob` and `CorvusPath` at collection time.

## Collect on one machine

```sh
velociraptor --definitions . artifacts collect Custom.Corvus.FileBatch --args Glob='/srv/inbox/*' --args CorvusPath=/usr/local/bin/corvus --format json
```

Each row has `OSPath`, `Size`, `ReturnCode` and `Batch`, the `corvus.batch/1` document. The batch's exit code is 0 when the document is written, 124 when `--time-limit` ended the run.
