# Find devices that run an image with a compiled-in component

Write the libraries compiled into an image as rows for a Log Analytics custom table, then join them to Defender XDR events in KQL.

Requires:

- Corvus ([installation](../installation.md)).
- A Log Analytics workspace, a data collection rule and an identity with the Monitoring Metrics Publisher role on it ([Logs Ingestion API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview)).

## Write the rows

```sh
corvus summarize_file path=App.exe componentsPath=components.jsonl
corvus summarize_file path=publish/ componentsPath=components.jsonl
```

- One JSON line per component; a folder writes the rows of each image under its relative name.
- Reads version strings (zlib, OpenSSL, Mbed TLS, wolfSSL), Go modules and Rust crates, plus the other dependency sources.
- A container's rows carry the container's hashes; `unpack_container` extracts the images, whose rows carry their own.
- An existing file needs `overwrite=true`.

| Column | Content |
| --- | --- |
| `TimeGenerated` | UTC time of the run |
| `ImageSHA1`, `ImageSHA256` | hashes of the image |
| `ImageName` | file name, or path under the folder |
| `Component`, `Version`, `Ecosystem` | as read; empty `Version` is unknown |
| `Purl`, `Cpe` | package URL; CPE 2.3 name from the NVD CPE dictionary, empty when none is confirmed |
| `Evidence` | where the component was read |
| `Advisories` | OSV ids and aliases (`CORVUS_OSV_DATABASE`) |
| `AdvisoryState` | `matched`, `none`, or `unknown: <reason>`; C libraries are unknown, no OSV source covers them |

## Declare the stream

Create the table `CompiledComponents_CL` ([custom tables](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/create-custom-table)) and declare the stream in the data collection rule ([DCR structure](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-rule-structure)):

```json
"streamDeclarations": {
  "Custom-CompiledComponents": {
    "columns": [
      { "name": "TimeGenerated", "type": "datetime" }, { "name": "ImageSHA1", "type": "string" }, { "name": "ImageSHA256", "type": "string" },
      { "name": "ImageName", "type": "string" }, { "name": "Component", "type": "string" }, { "name": "Version", "type": "string" },
      { "name": "Ecosystem", "type": "string" }, { "name": "Purl", "type": "string" }, { "name": "Cpe", "type": "string" },
      { "name": "Evidence", "type": "string" }, { "name": "Advisories", "type": "dynamic" }, { "name": "AdvisoryState", "type": "string" }
    ]
  }
}
```

Data flow: stream `Custom-CompiledComponents`, `transformKql` `source`, `outputStream` `Custom-CompiledComponents_CL`.

## Upload

The Logs Ingestion API takes a JSON array, so join the lines first:

```sh
jq -s . components.jsonl > components.json
```

A call holds at most 1 MB ([limits](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/service-limits#logs-ingestion-api)), so split a larger file into arrays under that size. Send each with `POST {endpoint}/dataCollectionRules/{dcrImmutableId}/streams/Custom-CompiledComponents?api-version={apiVersion}` ([request format](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview)).

## List the devices

Run in the workspace that also holds the Defender XDR tables ([Defender XDR connector](https://learn.microsoft.com/en-us/azure/sentinel/connect-microsoft-365-defender)).

```kusto
let Components = CompiledComponents_CL | where Component == "OpenSSL" and Version startswith "3.0.";
DeviceProcessEvents
| join kind=inner Components on $left.SHA1 == $right.ImageSHA1
| summarize LastSeen = max(Timestamp) by DeviceId, DeviceName, ImageName, Version
```

```kusto
let Components = CompiledComponents_CL | where Component == "zlib" and Version == "1.2.13";
DeviceImageLoadEvents
| join kind=inner Components on $left.SHA1 == $right.ImageSHA1
| summarize LastSeen = max(Timestamp) by DeviceId, DeviceName, FileName, Version
```

- `SHA1` in [DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) and [DeviceImageLoadEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceimageloadevents-table) is the file's hash; `SHA256` is usually not populated there.
