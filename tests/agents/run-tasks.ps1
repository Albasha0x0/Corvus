# Runs known-answer tasks (tasks.json) through agent clients (clients.json) against MCP servers and records, per run,
# the answer and its grade, the tools called, input and output tokens, cost and wall time.
# Usage:  ./tests/agents/run-tasks.ps1                         # client check: one question per client, Corvus only
#         ./tests/agents/run-tasks.ps1 -Set bench -Client claude -Server corvus,reference -Runs 3   # token benchmark
# Servers: corvus is this repository's build (CORVUS_AGENT_SERVER overrides it); reference is CORVUS_REFERENCE_SERVER.
# Both variables hold JSON: {"command": "...", "args": ["..."]}. A client or server that is missing is skipped with the
# reason. Model calls cost tokens: nothing here runs in the test sets unless CORVUS_CLIENT_CHECKS=1.
#Requires -Version 7.0
param(
    [ValidateSet('check', 'bench')][string]$Set = 'check',
    [string[]]$Client = @('claude', 'codex', 'gemini'),
    [string[]]$Server = @('corvus'),
    [string[]]$Task,
    [int]$Runs = 1,
    [string]$Out,
    [int]$TimeoutSeconds = 900
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$root = (Resolve-Path (Join-Path $here '../..')).Path
$tasks = (Get-Content (Join-Path $here 'tasks.json') -Raw | ConvertFrom-Json -AsHashtable).tasks |
    Where-Object { $Set -in $_.sets -and (-not $Task -or $_.id -in ($Task -split ',')) }
$clients = (Get-Content (Join-Path $here 'clients.json') -Raw | ConvertFrom-Json -AsHashtable).clients
$Client = $Client -split ','; $Server = $Server -split ','
if (-not $Out) { $Out = Join-Path ([IO.Path]::GetTempPath()) "corvus-agents-$(Get-Date -Format 'yyyyMMdd-HHmmss')" }
New-Item -ItemType Directory -Force $Out | Out-Null
$records = Join-Path $Out 'results.jsonl'

# The inputs: each Notes build alone in a folder, so no source sits beside it.
$data = Join-Path $Out 'data'
$inputs = @{}
foreach ($v in 'v1', 'v2') {
    $dll = Join-Path $root "samples/Notes/$v/bin/Notes.dll"
    if (-not (Test-Path $dll)) { throw "$dll is missing: build the solution first (dotnet build Corvus.slnx)." }
    New-Item -ItemType Directory -Force (Join-Path $data $v) | Out-Null
    Copy-Item $dll (Join-Path $data "$v/Notes.dll")
    $inputs[$v] = (Join-Path $data "$v/Notes.dll") -replace '\\', '/'
}

function Get-ServerCommand([string]$name) {
    $variable = @{ corvus = 'CORVUS_AGENT_SERVER'; reference = 'CORVUS_REFERENCE_SERVER' }[$name]
    if (-not $variable) { return @{ skip = "unknown server '$name' (corvus or reference)" } }
    $value = [Environment]::GetEnvironmentVariable($variable)
    if ($value) { $s = $value | ConvertFrom-Json -AsHashtable; return @{ command = $s.command; args = @($s.args) } }
    if ($name -eq 'reference') { return @{ skip = 'CORVUS_REFERENCE_SERVER is not set (JSON {"command": ..., "args": [...]} of the server to compare against)' } }
    foreach ($config in 'Release', 'Debug') {
        $dll = Join-Path $root "src/Corvus/bin/$config/net10.0/corvus.dll"
        if (Test-Path $dll) { return @{ command = 'dotnet'; args = @($dll) } }
    }
    return @{ skip = 'no build of src/Corvus (dotnet build Corvus.slnx), and CORVUS_AGENT_SERVER is not set' }
}

function ConvertTo-Toml([object]$value) {
    if ($value -is [array]) { return '[' + (($value | ForEach-Object { ConvertTo-Toml $_ }) -join ',') + ']' }
    return '"' + ($value -replace '\\', '\\' -replace '"', '\"') + '"'
}

# One run: the client's stdout parsed into answer, tools, tokens and cost.
function Read-Output([string]$kind, [string]$stdout) {
    $r = @{ answer = ''; tools = [Collections.Generic.List[string]]::new(); input = 0; cached = 0; output = 0; cost = $null; turns = $null; connected = $null }
    switch ($kind) {
        'claude-stream' {
            foreach ($line in $stdout -split "`n" | Where-Object { $_.TrimStart().StartsWith('{') }) {
                $e = $line | ConvertFrom-Json -AsHashtable -ErrorAction SilentlyContinue
                if (-not $e) { continue }
                if ($e.type -eq 'system' -and $e.subtype -eq 'init') { $r.connected = -not ($e.mcp_servers | Where-Object { $_.status -ne 'connected' }) }
                if ($e.type -eq 'assistant') { foreach ($c in $e.message.content) { if ($c.type -eq 'tool_use') { $r.tools.Add($c.name) } } }
                if ($e.type -eq 'result') {
                    $r.answer = [string]$e.result; $u = $e.usage
                    $r.input = [long]$u.input_tokens + [long]$u.cache_creation_input_tokens + [long]$u.cache_read_input_tokens
                    $r.cached = [long]$u.cache_read_input_tokens; $r.output = [long]$u.output_tokens
                    $r.cost = $e.total_cost_usd; $r.turns = $e.num_turns
                }
            }
        }
        'codex-jsonl' {
            foreach ($line in $stdout -split "`n" | Where-Object { $_.TrimStart().StartsWith('{') }) {
                $e = $line | ConvertFrom-Json -AsHashtable -ErrorAction SilentlyContinue
                if (-not $e) { continue }
                if ($e.type -eq 'item.completed' -and $e.item.type -eq 'agent_message') { $r.answer = [string]$e.item.text }
                if ($e.type -eq 'item.completed' -and $e.item.type -eq 'mcp_tool_call') { $r.tools.Add("$($e.item.server)/$($e.item.tool)") }
                if ($e.type -eq 'turn.completed') { $r.input += [long]$e.usage.input_tokens; $r.cached += [long]$e.usage.cached_input_tokens; $r.output += [long]$e.usage.output_tokens }
            }
        }
        'gemini-json' {
            $start = $stdout.IndexOf('{')
            if ($start -ge 0) {
                $e = $stdout.Substring($start) | ConvertFrom-Json -AsHashtable -ErrorAction SilentlyContinue
                if ($e) {
                    $r.answer = [string]$e.response
                    foreach ($m in $e.stats.models.Values) { $r.input += [long]$m.tokens.prompt; $r.cached += [long]$m.tokens.cached; $r.output += [long]$m.tokens.candidates + [long]$m.tokens.thoughts }
                    foreach ($t in $e.stats.tools.byName.GetEnumerator()) { 1..([int]$t.Value.count) | ForEach-Object { $r.tools.Add($t.Key) } }
                }
            }
        }
    }
    return $r
}

function Test-Answer([string]$answer, [string[]]$expect) {
    $line = ([regex]::Matches($answer, '(?im)^\W*ANSWER:\s*(.+)$') | Select-Object -Last 1)
    $text = if ($line) { $line.Groups[1].Value.Trim() } else { $answer }
    return -not ($expect | Where-Object { $text -notmatch $_ })
}

$failed = 0; $summary = @()
foreach ($clientName in $Client) {
    $c = $clients[$clientName]; $signedOut = $false
    if (-not $c) { Write-Host "unknown client '$clientName'" -ForegroundColor Red; exit 2 }
    $exe = [Environment]::GetEnvironmentVariable($c.variable)
    if (-not $exe) { $exe = (Get-Command $c.command -ErrorAction SilentlyContinue | Select-Object -First 1).Source }
    if (-not $exe) { Write-Host "skipped $($clientName): not found ($($c.command) on PATH, or set $($c.variable))" -ForegroundColor Yellow; continue }
    # npm installs a .cmd and a .ps1 shim on Windows; the .ps1 one passes arguments without cmd.exe parsing them.
    $prefix = @()
    if ($exe -match '\.(cmd|bat)$' -and (Test-Path ($exe -replace '\.(cmd|bat)$', '.ps1'))) { $exe = $exe -replace '\.(cmd|bat)$', '.ps1' }
    if ($exe -like '*.ps1') { $prefix = @('-NoProfile', '-File', $exe); $exe = (Get-Process -Id $PID).Path }
    foreach ($serverName in $Server) {
        $s = Get-ServerCommand $serverName
        if ($s.skip) { Write-Host "skipped $clientName x $($serverName): $($s.skip)" -ForegroundColor Yellow; continue }
        foreach ($t in $tasks) {
            foreach ($run in 1..$Runs) {
                $cwd = Join-Path $Out "work/$clientName-$serverName-$($t.id)-$run"
                New-Item -ItemType Directory -Force $cwd | Out-Null
                $servers = @{ mcpServers = @{ $serverName = @{ command = $s.command; args = $s.args } } } | ConvertTo-Json -Depth 5
                $mcpConfig = Join-Path $cwd 'mcp.json'
                Set-Content $mcpConfig $servers
                if ($c.mcp -eq 'workspace') {
                    $file = Join-Path $cwd $c.workspaceFile
                    New-Item -ItemType Directory -Force (Split-Path $file) | Out-Null
                    Set-Content $file $servers
                }
                $prompt = ($t.prompt -replace '\{v1\}', $inputs.v1 -replace '\{v2\}', $inputs.v2) +
                    " The files are on this machine: read them with the $serverName MCP tools and answer only from what they show, not from assumptions. End your reply with one line that starts with ANSWER: and gives the answer."
                $values = @{ '{prompt}' = $prompt; '{mcpConfig}' = $mcpConfig; '{server}' = $serverName
                    '{tomlCommand}' = (ConvertTo-Toml $s.command); '{tomlArgs}' = (ConvertTo-Toml @($s.args)) }
                $start = [Diagnostics.ProcessStartInfo]::new($exe)
                foreach ($a in $prefix) { $start.ArgumentList.Add($a) }
                foreach ($a in $c.args) { foreach ($k in $values.Keys) { $a = $a.Replace($k, $values[$k]) }; $start.ArgumentList.Add($a) }
                $start.WorkingDirectory = $cwd; $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
                $start.RedirectStandardInput = $true; $start.UseShellExecute = $false
                if ($c.env) { foreach ($kv in $c.env.GetEnumerator()) { $start.Environment[$kv.Key] = [string]$kv.Value } }
                $clock = [Diagnostics.Stopwatch]::StartNew()
                $p = [Diagnostics.Process]::Start($start)
                $p.StandardInput.Close()
                $stdout = $p.StandardOutput.ReadToEndAsync(); $stderr = $p.StandardError.ReadToEndAsync()
                $timedOut = -not $p.WaitForExit($TimeoutSeconds * 1000)
                if ($timedOut) { $p.Kill($true) }
                $p.WaitForExit()
                $seconds = [math]::Round($clock.Elapsed.TotalSeconds, 1)
                Set-Content (Join-Path $cwd 'stdout.txt') $stdout.Result; Set-Content (Join-Path $cwd 'stderr.txt') $stderr.Result
                if ($c.signedOut -and ($stdout.Result + $stderr.Result) -match $c.signedOut) {
                    Write-Host "skipped $($clientName): not signed in (run $($c.command) once interactively to sign in)" -ForegroundColor Yellow
                    $signedOut = $true; break
                }
                $r = Read-Output $c.output $stdout.Result
                $correct = -not $timedOut -and (Test-Answer $r.answer $t.expect)
                if (-not $correct) { $failed++ }
                $record = [ordered]@{ set = $Set; task = $t.id; client = $clientName; server = $serverName; run = $run; correct = $correct
                    exitCode = $p.ExitCode; timedOut = $timedOut; serverConnected = $r.connected; seconds = $seconds; toolCalls = $r.tools.Count; tools = @($r.tools)
                    inputTokens = $r.input; cachedInputTokens = $r.cached; outputTokens = $r.output; costUsd = $r.cost; turns = $r.turns
                    answer = ($r.answer.Trim() -split "`n" | Select-Object -Last 1) }
                Add-Content $records ($record | ConvertTo-Json -Compress -Depth 4)
                $summary += [pscustomobject]$record
                Write-Host (("{0,-16} {1,-7} {2,-9} {3,-5} {4,3} calls {5,9} in {6,7} out {7,7:0.0} s" -f $t.id, $clientName, $serverName, $(if ($correct) { 'ok' } else { 'FAIL' }), $r.tools.Count, $r.input, $r.output, $seconds) + $(if ($r.connected -eq $false) { ' (server did not connect)' } else { '' }))
            }
            if ($signedOut) { break }
        }
        if ($signedOut) { break }
    }
}

if ($summary) {
    Write-Host "`nPer client and server (results in $records):"
    $summary | Group-Object client, server | ForEach-Object {
        $g = $_.Group
        Write-Host ("  {0}: {1}/{2} correct, median {3} input / {4} output tokens, {5} tool calls, {6:0.0} s per task" -f $_.Name,
            @($g | Where-Object correct).Count, $g.Count,
            ($g.inputTokens | Sort-Object)[[int][math]::Floor(($g.Count - 1) / 2)], ($g.outputTokens | Sort-Object)[[int][math]::Floor(($g.Count - 1) / 2)],
            ($g.toolCalls | Sort-Object)[[int][math]::Floor(($g.Count - 1) / 2)], ($g.seconds | Measure-Object -Average).Average)
    }
}
exit $(if ($failed) { 1 } else { 0 })
