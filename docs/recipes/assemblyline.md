# Run Corvus beside Assemblyline's MCP server

Register Corvus and an Assemblyline MCP server in one client: Assemblyline submits and scores a file, Corvus reads the file and its extracted children.

Requires:

- Corvus 2.5 ([installation](../installation.md)).
- An Assemblyline MCP server and its credentials, started as its own documentation describes.

## Register both

Install Corvus for the client ([installation](../installation.md)), then add the Assemblyline server to the same `mcpServers` object with its own documented launch command:

```json
{
  "mcpServers": {
    "corvus": { "command": "corvus", "args": [] },
    "assemblyline": { "command": "<launch command from the server documentation>" }
  }
}
```

## Read an extracted file

Download a file Assemblyline extracted, then read it with Corvus:

```sh
corvus summarize_file path=extracted.bin
```

For a pipeline without a client, the [file batch](../cli.md#file-batch) writes one JSON document per file:

```sh
corvus batch --file extracted.bin --json --out extracted.batch.json
```

## Notes

- The two servers share no state; pass a file path from one to the other.
