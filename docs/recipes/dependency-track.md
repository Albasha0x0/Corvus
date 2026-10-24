# Track a binary's dependencies in Dependency-Track

Write a CycloneDX SBOM with Corvus and upload it to Dependency-Track for component inventory and vulnerability
matching. Corvus writes the file; Dependency-Track's REST API takes the upload.

Tested: Dependency-Track 4.14.5 (Docker Compose), Corvus 2.5.1; uploads from Linux (Ubuntu 24.04) and Windows.

## Prerequisites

- Corvus ([installation](../installation.md)).
- Dependency-Track 4.14.5: its
  [Docker Compose file](https://github.com/DependencyTrack/dependency-track/blob/4.14.5/src/main/docker/docker-compose.yml)
  with the images pinned to `dependencytrack/apiserver:4.14.5` and `dependencytrack/frontend:4.14.5`. The API server
  takes up to 4 GB of memory.
- An API key of a team with `BOM_UPLOAD` and `PROJECT_CREATION_UPLOAD` (Administration, Access Management, Teams). The
  default Automation team has `BOM_UPLOAD` only; without `PROJECT_CREATION_UPLOAD` an upload that creates the project is
  refused with 401.

## Write the SBOM

```sh
corvus summarize_file path=publish/App.dll view=dependencies sbomPath=App.cdx.json
```

CycloneDX 1.6 JSON. Components come from the deps.json beside the assembly or bundled in it
([dependencies view](../features.md#dependencies-view)). An existing file is refused unless `overwrite=true`.

## Upload

Linux:

```sh
curl -sS -X POST "$DT_URL/api/v1/bom" -H "X-Api-Key: $DT_API_KEY" \
  -F autoCreate=true -F projectName=App -F projectVersion=1.0.0 -F bom=@App.cdx.json
```

Windows (PowerShell 7):

```powershell
Invoke-RestMethod -Method Post "$env:DT_URL/api/v1/bom" -Headers @{ 'X-Api-Key' = $env:DT_API_KEY } `
  -Form @{ autoCreate = 'true'; projectName = 'App'; projectVersion = '1.0.0'; bom = Get-Item App.cdx.json }
```

The response is a processing token: `{"token": "3c2a8f9e-..."}`. `GET /api/v1/bom/token/<token>` returns
`{"processing": false}` when the components are stored. The project's Components tab lists them with Corvus's package
URLs. Vulnerability matching uses the sources the server mirrors (not checked for this page).

## Notes

- A component without a version has no package URL; Dependency-Track lists it but cannot match it.
- For each new build, keep `projectName` and change `projectVersion`.
