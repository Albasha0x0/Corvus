# Checks commit messages against the form in CONTRIBUTING.md; prints one line per problem and exits 1 when any file
# has one. Body presence and the Verified wording stay with review.
param([Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Path)

$Types = 'feat', 'fix', 'perf', 'test', 'docs', 'refactor', 'ci', 'chore'
$Scopes = 'live', 'dumps', 'aot', 'engines', 'native', 'dotnet', 'edits', 'containers', 'mobile', 'web', 'catalog',
    'session', 'tests', 'release'
$Width = 72
# Trailer lines may run past the width; so may a line that is one word (a long test name) or holds a URL.
$Trailer = '^(Co-Authored-By|Signed-off-by|Upstream|BREAKING CHANGE): |^(Fixes|Refs) #\d+$'

function Get-Problems([string]$file) {
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($line in [IO.File]::ReadAllLines($file)) {
        # git commit -v appends the diff below the scissors line; '#' lines are git's own comments.
        if ($line -match '^# -+ >8 -+$') { break }
        if (-not $line.StartsWith('#')) { $lines.Add($line.TrimEnd("`r")) }
    }
    while ($lines.Count -gt 0 -and $lines[0].Trim() -eq '') { $lines.RemoveAt(0) }
    if ($lines.Count -eq 0) { return }
    $subject = $lines[0]
    # Messages git writes itself keep git's form.
    if ($subject -match '^(Merge |Revert "|fixup! |squash! |amend! )') { return }

    if ($subject.Length -gt $Width) { "subject is $($subject.Length) characters; at most $Width" }
    if ($subject -cnotmatch '^([a-z]+)\(([a-z0-9-]+)\)!?: (\S.*)$') {
        "subject is not 'type(scope): summary'"
    } else {
        $type, $scope, $summary = $Matches[1], $Matches[2], $Matches[3]
        if ($type -notin $Types) { "type '$type' is not one of: $($Types -join ', ')" }
        if ($scope -notin $Scopes) { "scope '$scope' is not one of: $($Scopes -join ', ')" }
        if ($summary -cmatch '^[A-Z][a-z]') { 'summary starts with a capital letter; write it in lower case' }
        if ($summary.EndsWith('.')) { 'subject ends with a period' }
    }
    if ($subject -match '#\d') { 'subject names an issue; put it in a Fixes, Refs or Upstream trailer' }

    for ($i = 1; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line.Length -le $Width -or $line -match $Trailer -or $line -match '://' -or $line.Trim() -notmatch '\s' -or
            $line -match '^\s*- \S+$') { continue }
        "line $($i + 1) is $($line.Length) columns; wrap the body at $Width"
    }
}

$failed = $false
foreach ($file in $Path) {
    foreach ($problem in Get-Problems $file) {
        $failed = $true
        if ($Path.Count -gt 1) { "${file}: $problem" } else { "commit-msg: $problem" }
    }
}
if ($failed) { exit 1 }
