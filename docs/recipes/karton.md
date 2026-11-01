# Read each sample in a Karton pipeline

Run Corvus's file batch on each sample a Karton task carries and send the `corvus.batch/1` document on as a task resource. Nothing in the file runs and Corvus makes no network request ([file batch](../cli.md#file-batch)).

Requires:

- Corvus 2.5 ([installation](../installation.md)) on each consumer host.
- Karton (`pip install karton-core`) with a running Karton system.

## Consumer

Save as `corvus_karton.py`:

```python
import os
import subprocess
import tempfile

from karton.core import Karton, Resource, Task


class CorvusReader(Karton):
    identity = "corvus.reader"
    filters = [{"type": "sample"}]

    def process(self, task: Task) -> None:
        sample = task.get_resource("sample")
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "sample.bin")
            with open(path, "wb") as file:
                file.write(sample.content)
            run = subprocess.run(
                ["corvus", "batch", "--file", path, "--json", "--time-limit", "120"],
                capture_output=True, text=True, check=False)
        if run.returncode not in (0, 124):
            raise RuntimeError(f"exit {run.returncode}: {run.stderr.strip()}")
        self.send_task(Task(
            {"type": "analysis", "kind": "corvus"},
            payload={"parent": sample,
                     "batch": Resource("batch.json", run.stdout.encode())}))


if __name__ == "__main__":
    CorvusReader().loop()
```

```sh
python corvus_karton.py --config-file karton.ini
```

## Notes

- Check one sample by hand with `corvus batch --file sample.bin --json`.
- The exit code is 0 when the document is written and 124 when `--time-limit` ended the run; a 124 document keeps the finished sections and marks the rest `timeout`.
- `complete` is false when any section is not `complete`; read it before treating an empty `findings` list as clean.
- `--time-limit` defaults to 600 and accepts at most 86400; the consumer sets 120.
- Add `--rules <file or folder>` to run YARA rules in the same document.
