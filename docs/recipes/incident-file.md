# Read the file of a Defender XDR or Sentinel incident

Add what a file contains to the hash and prevalence Microsoft's tools report, in one agent session.

Requires Corvus ([installation](../installation.md)) and an MCP client that connects both servers.

- Microsoft's tools read the incident, devices and prevalence; Corvus reads the file.
- Corvus never downloads the file; you collect it.
- Triage collection: your home tenant only; no guest or delegated access; no query of the Sentinel data lake.
- Triage collection: Sentinel users cannot choose the workspace; it uses the permissions you already hold.
- Other Sentinel collections: most tools need data lake onboarding; listing and calling them needs the Security reader role.
- Setup: [Get started with the Microsoft Sentinel MCP server](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-get-started).

## Connect both servers

- Add `https://sentinel.microsoft.com/mcp/triage` as described in the [triage collection](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-triage-tool).
- Add Corvus as the `corvus` MCP server ([installation](../installation.md)).

## Read the incident

| Tool | Returns |
|---|---|
| `GetIncidentById` | The incident and its alerts (`includeAlertsData`). |
| `GetAlertByID` | The alert and its evidence entities, including the file. |
| `GetDefenderFileInfo` | Hashes, size, type, publisher, signer and global prevalence. |
| `GetDefenderFileStatistics` | Organization prevalence and device count. |
| `GetDefenderFileRelatedMachines` | Devices that encountered the file. |

- `GetDefenderFileAlerts` and `GetDefenderFileRelatedMachines` take a SHA-1 only; give a SHA-1 to every file tool.

## Get the file

- Start a [live response session](https://learn.microsoft.com/en-us/defender-endpoint/live-response#initiate-a-live-response-session-on-a-device) on the device.
- Run `getfile <file_path>` ([get a file from the device](https://learn.microsoft.com/en-us/defender-endpoint/live-response#get-a-file-from-the-device)); the limit is 3 GB.
- The investigation package holds device state, not the file.
- Store the sample where only Corvus reads it; every Corvus call below only reads it.

## Read its content

```sh
corvus summarize_file path=sample.bin
corvus summarize_file path=sample.bin view=indicators
corvus summarize_file path=sample.bin view=hunts huntsPath=case/hunts.json
```

- `summarize_file`: hashes to compare with `GetDefenderFileInfo`, type, signature verdict and the views that apply.
- `indicators`: URLs, domains, addresses and strings, one row per value with its sources.
- `hunts`: advanced hunting queries from the hash, signer, original file name, hosts, pipes and library names.
- For a managed file with encoded strings, `simplify_methods` decodes them ([simplification](../simplify.md)).
- For a native decoder, `emulate_native` runs the function in an emulator, not the file.

## Run the hunts

- Pass each query from `view=hunts` to `RunAdvancedHuntingQuery` as `kqlQuery`.
- Check the queries before enabling a rule: `view=hunts cleanFolder=<clean files> priorBuildsFolder=<earlier builds>`.
- Record what the check kept: `view=hunts cleanFolder=<clean files> indicatorsPath=case/indicators.json policyPath=case/audit.xml`; nothing is blocked, and nothing is posted or applied.
- Run the `tenant-` query of the hunts to read catalog signature, signer and devices that wrote, started or loaded the file; save the JSON and pass `tenantResultPath=<result>` with `view=hunts` to label the file report.
- Run `FetchAdvancedHuntingTablesDetailedSchema` first when a query reports an unknown column.
- Hunts match on SHA-1: the `SHA256` columns of device tables are usually not populated ([DeviceEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table)).
- Matches on the signer, file name and hosts show other devices that the hash alone misses.
- An empty result is unknown, not absent: the tenant may not populate the table or have Defender for Endpoint.

## Record the findings

- The triage collection has no tool that comments on an incident; paste the summary into the incident in the Defender portal.
- `summarize_file stixPath=case/sample.stix.json` writes the file's indicators as a STIX 2.1 bundle to attach.
