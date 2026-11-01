# Import a file's indicators into OpenCTI

Write a STIX 2.1 bundle of a file, its members and their indicators with Corvus and import it into OpenCTI.

Requires:

- Corvus 2.9 ([installation](../installation.md)).
- OpenCTI with a user token that may import files (`pip install pycti` for the script).

## Write the bundle

```sh
corvus summarize_file path=sample.bin stixPath=sample.stix.json
```

An existing file is refused unless `overwrite=true`. The bundle holds the file, its members and the values of every view ([features](../features.md)).

## Import

Import `sample.stix.json` from a script:

```python
import os
from pycti import OpenCTIApiClient

client = OpenCTIApiClient(os.environ["OPENCTI_URL"], os.environ["OPENCTI_TOKEN"])
client.stix2.import_bundle_from_file("sample.stix.json")
```

## Notes

- A bundle of an incomplete read keeps what was read; run `corvus summarize_file path=sample.bin view=indicators` to see the rows before importing.
- Network and fingerprint observables carry `x_corvus_evidence` (`reference`, `decoded`, `traffic`) and `x_corvus_confidence` (50, 70, 85).
- Values found only as strings are left out of the bundle; `view=indicators` lists them as `string`.
- The bundle states what the file contains, not a verdict.
